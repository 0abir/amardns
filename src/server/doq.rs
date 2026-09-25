// src/server/doq.rs
// Ultra-fast, zero-GC DNS-over-QUIC (DoQ, RFC 9250) server engine for AmarDNS.
// Runs on UDP port 853 with ALPN "doq", eliminating head-of-line blocking and
// providing instant connection migration across cellular/WiFi networks.

use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig, VarInt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, info};

use crate::dns::parser::build_servfail_response;
use crate::state::AppState;

const DOQ_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const DOQ_READ_TIMEOUT: Duration = Duration::from_secs(8);
const DOQ_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Builds a Quinn ServerConfig from a Rustls ServerConfig with DoQ transport tuning.
pub fn create_doq_quinn_config(
    rustls_config: Arc<tokio_rustls::rustls::ServerConfig>,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let quic_crypto = QuicServerConfig::try_from(rustls_config)?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        VarInt::from_u32(DOQ_IDLE_TIMEOUT.as_millis() as u32).into(),
    ));
    // Enable keepalive pings to maintain NAT bindings across mobile networks
    transport.keep_alive_interval(Some(Duration::from_secs(20)));
    // Allow up to 256 concurrent bidirectional streams per QUIC connection
    transport.max_concurrent_bidi_streams(VarInt::from_u32(256));

    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

fn resolve_socket_addr(host: &str, port: u16) -> SocketAddr {
    use std::net::ToSocketAddrs;
    if let Ok(mut addrs) = format!("{}:{}", host, port).to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return addr;
        }
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return SocketAddr::new(ip, port);
    }
    SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), port)
}

/// Spawns the DoQ (RFC 9250) listener on UDP port 853.
pub async fn start_doq_server(
    state: Arc<AppState>,
    bind_host: &str,
    port: u16,
    rustls_config: Arc<tokio_rustls::rustls::ServerConfig>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let quinn_config = create_doq_quinn_config(rustls_config)?;

    let bind_addr = resolve_socket_addr(bind_host, port);

    // Create dual-stack socket with SO_REUSEADDR and standard buffers
    let domain = if bind_addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(
        domain,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    if bind_addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    let _ = socket.set_reuse_address(true);
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    let _ = socket.set_reuse_port(true);
    socket.set_nonblocking(true)?;
    socket.bind(&socket2::SockAddr::from(bind_addr))?;

    let std_socket: std::net::UdpSocket = socket.into();
    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(quinn_config),
        std_socket,
        Arc::new(quinn::TokioRuntime),
    )?;

    info!(
        "[doq] AmarDNS DoQ server listening on udp://{} (RFC 9250, ALPN: doq)",
        bind_addr
    );

    loop {
        tokio::select! {
            incoming_conn = endpoint.accept() => {
                match incoming_conn {
                    Some(incoming) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            match incoming.await {
                                Ok(conn) => {
                                    handle_doq_connection(state, conn).await;
                                }
                                Err(e) => {
                                    debug!("[doq] Handshake failed: {}", e);
                                }
                            }
                        });
                    }
                    None => break,
                }
            }
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    info!("[doq] Shutting down DoQ listener gracefully...");
                    endpoint.close(0u32.into(), b"server shutdown");
                    break;
                }
            }
        }
    }

    endpoint.wait_idle().await;
    info!("[doq] DoQ listener shutdown complete.");
    Ok(())
}

/// Handles a single established QUIC connection for DoQ.
async fn handle_doq_connection(state: Arc<AppState>, conn: quinn::Connection) {
    let client_ip = conn.remote_address().ip();

    // Connection-level rate limit check
    if !state.check_rate_limit(client_ip, None) {
        conn.close(0x01u32.into(), b"rate limit exceeded");
        return;
    }

    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let state_c = state.clone();
                tokio::spawn(async move {
                    handle_doq_stream(state_c, send, recv, client_ip).await;
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. })
            | Err(quinn::ConnectionError::ConnectionClosed { .. })
            | Err(quinn::ConnectionError::TimedOut)
            | Err(quinn::ConnectionError::LocallyClosed) => {
                break;
            }
            Err(e) => {
                debug!("[doq] Stream accept error from {}: {}", client_ip, e);
                break;
            }
        }
    }
}

/// Handles a client-initiated bidirectional stream on a DoQ connection (RFC 9250 Section 4.2).
async fn handle_doq_stream(
    state: Arc<AppState>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    client_ip: std::net::IpAddr,
) {
    // Read 2-octet length prefix in network byte order
    let mut len_buf = [0u8; 2];
    let read_res = tokio::time::timeout(DOQ_READ_TIMEOUT, recv.read_exact(&mut len_buf)).await;
    match read_res {
        Ok(Ok(())) => {}
        Ok(Err(quinn::ReadExactError::FinishedEarly(_))) => {
            return;
        }
        Ok(Err(e)) => {
            debug!("[doq] Stream read prefix error: {:?}", e);
            return;
        }
        Err(_) => {
            debug!("[doq] Stream read timeout");
            return;
        }
    }

    let msg_len = u16::from_be_bytes(len_buf) as usize;
    if msg_len == 0 || msg_len > 4096 {
        debug!("[doq] Invalid message length: {}", msg_len);
        return;
    }

    let mut query = vec![0u8; msg_len];
    let body_res = tokio::time::timeout(DOQ_READ_TIMEOUT, recv.read_exact(&mut query)).await;
    if body_res.is_err() || body_res.unwrap().is_err() {
        debug!("[doq] Stream read query body error");
        return;
    }

    // Per-query rate limit check
    let resp_bytes = if !state.check_rate_limit(client_ip, None) {
        build_servfail_response(&query)
    } else {
        crate::server::doh::process_dns_wire_packet(
            state.clone(),
            &query,
            client_ip,
            None,
            "DoQ",
        )
        .await
    };

    // Write 2-octet length prefix followed by response packet
    let resp_len = resp_bytes.len() as u16;
    let write_fut = async {
        send.write_all(&resp_len.to_be_bytes()).await?;
        send.write_all(&resp_bytes).await?;
        Ok::<(), quinn::WriteError>(())
    };

    if let Ok(Ok(())) = tokio::time::timeout(DOQ_WRITE_TIMEOUT, write_fut).await {
        // In RFC 9250, a stream finishes after one transaction
        let _ = send.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::tls::DynamicCertResolver;

    #[test]
    fn test_create_doq_quinn_config() {
        let resolver = Arc::new(
            DynamicCertResolver::from_self_signed(&["amardns.local".to_string()]).unwrap(),
        );
        let rustls_cfg = crate::server::tls::create_dynamic_doq_server_config(resolver).unwrap();
        let quinn_cfg = create_doq_quinn_config(rustls_cfg);
        assert!(quinn_cfg.is_ok());
    }
}
