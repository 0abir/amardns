// src/server/doq.rs
// DNS-over-QUIC (DoQ, RFC 9250) high-performance async server.
// Runs on UDP port 853 with ALPN "doq", 0-RTT handshakes, and per-stream zero Head-of-Line blocking.

use quinn::{Connection, Endpoint, SendStream, ServerConfig, TransportConfig};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use crate::server::doh::process_dns_wire_packet;
use crate::state::AppState;

const DOQ_STREAM_TIMEOUT: Duration = Duration::from_secs(8);
const DOQ_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Starts the DNS-over-QUIC (RFC 9250) / DoH3 (RFC 9114) UDP listener.
pub async fn start_doq_server(
    state: Arc<AppState>,
    host: &str,
    port: u16,
    tls_config: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    protocol_name: &'static str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Resolve host:port (handles "fly-global-services", "0.0.0.0", "::", IP strings, etc.)
    let addr = match format!("{}:{}", host, port).to_socket_addrs() {
        Ok(mut addrs) => addrs.next().unwrap_or_else(|| {
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port)
        }),
        Err(_) => {
            let host_ip: std::net::IpAddr = host
                .parse()
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            SocketAddr::new(host_ip, port)
        }
    };

    let rustls_cfg = match tls_config {
        Some(cfg) => cfg,
        None => {
            info!(
                "[{}] Native TLS not configured in config; {} server disabled",
                protocol_name.to_lowercase(),
                protocol_name
            );
            return Ok(());
        }
    };

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg)?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));

    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(DOQ_IDLE_TIMEOUT.try_into()?));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    // Allow up to 128 concurrent bidirectional QUIC streams per connection
    transport.max_concurrent_bidi_streams(128u32.into());
    server_config.transport_config(Arc::new(transport));

    // Create dual-stack socket (IPv4 + IPv6) so Fly.io IPv4 & IPv6 ingress UDP packets are both received
    let socket = if addr.is_ipv6() {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        let _ = sock.set_only_v6(false);
        sock.set_nonblocking(true)?;
        let _ = sock.set_reuse_address(true);
        #[cfg(unix)]
        let _ = sock.set_reuse_port(true);
        sock.bind(&addr.into())?;
        sock
    } else {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        sock.set_nonblocking(true)?;
        let _ = sock.set_reuse_address(true);
        #[cfg(unix)]
        let _ = sock.set_reuse_port(true);
        sock.bind(&addr.into())?;
        sock
    };
    let std_sock: std::net::UdpSocket = socket.into();

    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        std_sock,
        Arc::new(quinn::TokioRuntime),
    )?;
    info!(
        "[{}] AmarDNS {} server listening on {} with native QUIC/TLS",
        protocol_name.to_lowercase(),
        protocol_name,
        addr
    );

    loop {
        tokio::select! {
            incoming_res = endpoint.accept() => {
                let incoming = match incoming_res {
                    Some(inc) => inc,
                    None => break,
                };

                let state_clone = state.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            let client_addr = conn.remote_address();
                            debug!("[{}] QUIC connection established from {}", protocol_name.to_lowercase(), client_addr);
                            handle_doq_connection(conn, client_addr, state_clone, protocol_name).await;
                        }
                        Err(e) => {
                            tracing::warn!("[{}] QUIC handshake failed: {}", protocol_name.to_lowercase(), e);
                        }
                    }
                });
            }
            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    info!("[{}] Shutting down {} listener gracefully...", protocol_name.to_lowercase(), protocol_name);
                    endpoint.close(0u32.into(), b"server shutdown");
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn handle_doq_connection(
    conn: Connection,
    client_addr: SocketAddr,
    state: Arc<AppState>,
    protocol_name: &'static str,
) {
    let client_ip = client_addr.ip();

    // Check rate limiter for client IP
    if !state.check_rate_limit(client_ip, None) {
        conn.close(0x02u32.into(), b"Rate limit exceeded");
        return;
    }

    // Accept bidirectional streams for DNS queries (RFC 9250 Section 4)
    while let Ok((mut send_stream, mut recv_stream)) = conn.accept_bi().await {
        let state_clone = state.clone();
        tokio::spawn(async move {
            let mut stream_buf = Vec::with_capacity(512);
            let mut chunk = [0u8; 1024];

            // Read the initial chunk of data
            let read_first =
                tokio::time::timeout(DOQ_STREAM_TIMEOUT, recv_stream.read(&mut chunk)).await;
            let n = match read_first {
                Ok(Ok(Some(n))) if n >= 12 => n,
                _ => {
                    let _ = send_stream.reset(0x01u32.into());
                    return;
                }
            };
            stream_buf.extend_from_slice(&chunk[..n]);

            // Determine framing: RFC 9250 length-prefixed vs raw query wire (AdGuard / draft DoQ)
            let (query_bytes, is_prefixed) = if stream_buf.len() >= 14 {
                let declared_len = u16::from_be_bytes([stream_buf[0], stream_buf[1]]) as usize;
                if declared_len > 0 && declared_len <= 4096 {
                    let target_len = declared_len + 2;
                    while stream_buf.len() < target_len {
                        let read_more =
                            tokio::time::timeout(DOQ_STREAM_TIMEOUT, recv_stream.read(&mut chunk))
                                .await;
                        match read_more {
                            Ok(Ok(Some(m))) if m > 0 => {
                                stream_buf.extend_from_slice(&chunk[..m]);
                            }
                            _ => break,
                        }
                    }
                    if stream_buf.len() >= target_len {
                        (stream_buf[2..target_len].to_vec(), true)
                    } else if crate::dns::parser::parse_dns_query(&stream_buf).is_some() {
                        (stream_buf, false)
                    } else {
                        (stream_buf[2..].to_vec(), true)
                    }
                } else if crate::dns::parser::parse_dns_query(&stream_buf).is_some() {
                    (stream_buf, false)
                } else {
                    let _ = send_stream.reset(0x01u32.into());
                    return;
                }
            } else if crate::dns::parser::parse_dns_query(&stream_buf).is_some() {
                (stream_buf, false)
            } else {
                let _ = send_stream.reset(0x01u32.into());
                return;
            };

            // Per-query rate limit check
            if !state_clone.check_rate_limit(client_ip, None) {
                let fail = crate::dns::parser::build_servfail_response(&query_bytes);
                let _ = send_doq_response(&mut send_stream, &fail, is_prefixed).await;
                return;
            }

            // Process query through unified engine (Filters, Cache, Upstream, DNSSEC)
            let resp_bytes =
                process_dns_wire_packet(state_clone, &query_bytes, client_ip, None, protocol_name)
                    .await;

            // Send response matching client prefix mode and close write side (FIN)
            let _ = send_doq_response(&mut send_stream, &resp_bytes, is_prefixed).await;
        });
    }
}

async fn send_doq_response(
    send_stream: &mut SendStream,
    data: &[u8],
    is_prefixed: bool,
) -> Result<(), std::io::Error> {
    if is_prefixed {
        let len = data.len() as u16;
        send_stream.write_all(&len.to_be_bytes()).await?;
    }
    send_stream.write_all(data).await?;
    let _ = send_stream.finish();
    Ok(())
}
