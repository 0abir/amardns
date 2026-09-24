// src/server/doh3.rs
// Ultra-fast, zero-GC DNS-over-HTTP/3 (DoH3, RFC 9114 / RFC 8484) server engine for AmarDNS.
// Runs on UDP port 443 with ALPN "h3", delivering encrypted DNS resolution over QUIC streams
// with QPACK header compression and zero head-of-line blocking.

use bytes::{Buf, Bytes};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig, VarInt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, info};

use crate::dns::parser::build_servfail_response;
use crate::state::AppState;

const DOH3_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Builds a Quinn ServerConfig from a Rustls ServerConfig with DoH3 transport tuning.
pub fn create_doh3_quinn_config(
    rustls_config: Arc<tokio_rustls::rustls::ServerConfig>,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let quic_crypto = QuicServerConfig::try_from(rustls_config)?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        VarInt::from_u32(DOH3_IDLE_TIMEOUT.as_millis() as u32).into(),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(20)));
    transport.max_concurrent_bidi_streams(VarInt::from_u32(256));

    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

/// Spawns the DoH3 (RFC 9114 / RFC 8484) listener on UDP port 443.
pub async fn start_doh3_server(
    state: Arc<AppState>,
    bind_host: &str,
    port: u16,
    rustls_config: Arc<tokio_rustls::rustls::ServerConfig>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let quinn_config = create_doh3_quinn_config(rustls_config)?;

    let host_ip: std::net::IpAddr = bind_host
        .parse()
        .unwrap_or(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED));
    let bind_addr = SocketAddr::new(host_ip, port);

    let socket = socket2::Socket::new(
        if host_ip.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    if host_ip.is_ipv6() {
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
        "[doh3] AmarDNS DoH3 server listening on udp://{} (RFC 9114, ALPN: h3)",
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
                                    handle_doh3_connection(state, conn).await;
                                }
                                Err(e) => {
                                    debug!("[doh3] Handshake failed: {}", e);
                                }
                            }
                        });
                    }
                    None => break,
                }
            }
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    info!("[doh3] Shutting down DoH3 listener gracefully...");
                    endpoint.close(0u32.into(), b"server shutdown");
                    break;
                }
            }
        }
    }

    endpoint.wait_idle().await;
    info!("[doh3] DoH3 listener shutdown complete.");
    Ok(())
}

/// Handles an established QUIC connection using HTTP/3.
async fn handle_doh3_connection(state: Arc<AppState>, conn: quinn::Connection) {
    let client_ip = conn.remote_address().ip();

    if !state.check_rate_limit(client_ip, None) {
        conn.close(0x01u32.into(), b"rate limit exceeded");
        return;
    }

    let h3_conn = h3_quinn::Connection::new(conn);
    let mut server = match h3::server::Connection::new(h3_conn).await {
        Ok(s) => s,
        Err(e) => {
            debug!("[doh3] H3 connection initialization error from {}: {}", client_ip, e);
            return;
        }
    };

    loop {
        match server.accept().await {
            Ok(Some(resolver)) => {
                let state_c = state.clone();
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            handle_doh3_request(state_c, req, stream, client_ip).await;
                        }
                        Err(e) => {
                            debug!("[doh3] Resolve request error from {}: {}", client_ip, e);
                        }
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                debug!("[doh3] H3 accept stream error from {}: {}", client_ip, e);
                break;
            }
        }
    }
}

/// Handles an incoming HTTP/3 request for /dns-query or JSON API.
async fn handle_doh3_request<S>(
    state: Arc<AppState>,
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<S, Bytes>,
    client_ip: std::net::IpAddr,
) where
    S: h3::quic::BidiStream<Bytes>,
{
    let path = req.uri().path();
    let method = req.method();

    // Check CORS OPTIONS request
    if method == http::Method::OPTIONS {
        let resp = http::Response::builder()
            .status(http::StatusCode::OK)
            .header("access-control-allow-origin", "*")
            .header("access-control-allow-methods", "GET, POST, OPTIONS")
            .header("access-control-allow-headers", "content-type, accept")
            .header("access-control-max-age", "86400")
            .body(())
            .unwrap();
        let _ = stream.send_response(resp).await;
        let _ = stream.finish().await;
        return;
    }

    let is_dns_query = path == "/dns-query" || path == "/";

    if is_dns_query {
        let query_wire = if method == http::Method::POST {
            // Read body wire bytes (up to 4096 bytes)
            let mut body = Vec::new();
            while let Ok(Some(mut chunk)) = stream.recv_data().await {
                let to_read = std::cmp::min(chunk.remaining(), 4096_usize.saturating_sub(body.len()));
                body.extend_from_slice(&chunk.copy_to_bytes(to_read));
                if body.len() >= 4096 {
                    break;
                }
            }
            body
        } else if method == http::Method::GET {
            // Read ?dns= parameter
            let query_str = req.uri().query().unwrap_or("");
            let mut dns_b64 = None;
            for part in query_str.split('&') {
                if let Some(val) = part.strip_prefix("dns=") {
                    dns_b64 = Some(val);
                    break;
                }
            }
            if let Some(val) = dns_b64 {
                // Decode URL-safe base64
                decode_b64_url(val).unwrap_or_default()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        if query_wire.is_empty() {
            let resp = http::Response::builder()
                .status(http::StatusCode::BAD_REQUEST)
                .header(http::header::CONTENT_TYPE, "text/plain")
                .body(())
                .unwrap();
            let _ = stream.send_response(resp).await;
            let _ = stream.send_data(Bytes::from("Missing or empty DNS query wire payload\n")).await;
            let _ = stream.finish().await;
            return;
        }

        // Process DNS query through unified pipeline
        let resp_bytes = if !state.check_rate_limit(client_ip, None) {
            build_servfail_response(&query_wire)
        } else {
            crate::server::doh::process_dns_wire_packet(
                state.clone(),
                &query_wire,
                client_ip,
                None,
                "DoH3",
            )
            .await
        };

        let resp = http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/dns-message")
            .header(http::header::CACHE_CONTROL, "public, max-age=60")
            .header("access-control-allow-origin", "*")
            .body(())
            .unwrap();

        if stream.send_response(resp).await.is_ok() {
            let _ = stream.send_data(Bytes::from(resp_bytes)).await;
            let _ = stream.finish().await;
        }
    } else {
        // Fallback for non-DNS queries on HTTP/3 port
        let resp = http::Response::builder()
            .status(http::StatusCode::NOT_FOUND)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .body(())
            .unwrap();
        let _ = stream.send_response(resp).await;
        let _ = stream.send_data(Bytes::from("AmarDNS HTTP/3 Edge (RFC 9114)\n")).await;
        let _ = stream.finish().await;
    }
}

/// Helper to decode standard and URL-safe base64 without padding.
fn decode_b64_url(input: &str) -> Option<Vec<u8>> {
    let mut s = input.replace('-', "+").replace('_', "/");
    while s.len() % 4 != 0 {
        s.push('=');
    }
    base64_decode_rfc4648(&s)
}

fn base64_decode_rfc4648(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;

    for b in input.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => continue,
        };
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::tls::DynamicCertResolver;

    #[test]
    fn test_create_doh3_quinn_config() {
        let resolver = Arc::new(
            DynamicCertResolver::from_self_signed(&["amardns.local".to_string()]).unwrap(),
        );
        let rustls_cfg = crate::server::tls::create_dynamic_doh3_server_config(resolver).unwrap();
        let quinn_cfg = create_doh3_quinn_config(rustls_cfg);
        assert!(quinn_cfg.is_ok());
    }

    #[test]
    fn test_doh3_decode_b64_url() {
        let original = b"hello dns wire packet";
        let encoded = "aGVsbG8gZG5zIHdpcmUgcGFja2V0";
        let decoded = decode_b64_url(encoded).unwrap();
        assert_eq!(decoded, original);
    }
}
