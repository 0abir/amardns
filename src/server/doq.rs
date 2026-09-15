// src/server/doq.rs
// Unified DNS-over-QUIC (DoQ, RFC 9250) and DNS-over-HTTP/3 (DoH3, RFC 9114) high-performance async server.
// Runs on UDP with ALPN "doq" & "h3", 0-RTT handshakes, QPACK headers, and per-stream zero Head-of-Line blocking.

use quinn::{Connection, Endpoint, SendStream, ServerConfig, TransportConfig};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use crate::server::doh::process_dns_wire_packet;
use crate::state::AppState;

const DOQ_STREAM_TIMEOUT: Duration = Duration::from_secs(8);
const DOQ_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// RFC 9000 Section 16: QUIC / HTTP/3 Variable-Length Integer decoding
pub fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    let tag = first >> 6;
    match tag {
        0 => Some((first as u64, 1)),
        1 => {
            if buf.len() < 2 {
                return None;
            }
            let val = (((first & 0x3f) as u64) << 8) | (buf[1] as u64);
            Some((val, 2))
        }
        2 => {
            if buf.len() < 4 {
                return None;
            }
            let val = (((first & 0x3f) as u64) << 24)
                | ((buf[1] as u64) << 16)
                | ((buf[2] as u64) << 8)
                | (buf[3] as u64);
            Some((val, 4))
        }
        3 => {
            if buf.len() < 8 {
                return None;
            }
            let mut val = (first & 0x3f) as u64;
            for i in 1..8 {
                val = (val << 8) | (buf[i] as u64);
            }
            Some((val, 8))
        }
        _ => unreachable!(),
    }
}

/// RFC 9000 Section 16: QUIC / HTTP/3 Variable-Length Integer encoding
pub fn write_varint(val: u64, out: &mut Vec<u8>) {
    if val < 64 {
        out.push(val as u8);
    } else if val < 16384 {
        out.push(0x40 | ((val >> 8) as u8));
        out.push((val & 0xff) as u8);
    } else if val < 1_073_741_824 {
        out.push(0x80 | ((val >> 24) as u8));
        out.push(((val >> 16) & 0xff) as u8);
        out.push(((val >> 8) & 0xff) as u8);
        out.push((val & 0xff) as u8);
    } else {
        out.push(0xc0 | ((val >> 56) as u8));
        out.push(((val >> 48) & 0xff) as u8);
        out.push(((val >> 40) & 0xff) as u8);
        out.push(((val >> 32) & 0xff) as u8);
        out.push(((val >> 24) & 0xff) as u8);
        out.push(((val >> 16) & 0xff) as u8);
        out.push(((val >> 8) & 0xff) as u8);
        out.push((val & 0xff) as u8);
    }
}

/// Extracts a DNS wire query from HTTP/3 GET QPACK HEADERS payload containing ?dns=<b64url>
pub fn extract_dns_query_from_h3_headers(headers: &[u8]) -> Option<Vec<u8>> {
    // Search for "dns=" in headers payload
    let target = b"dns=";
    let pos = headers.windows(target.len()).position(|w| w == target)?;
    let rem = &headers[pos + target.len()..];
    
    let mut end = 0;
    while end < rem.len() {
        let b = rem[end];
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'%' || b == b'=' {
            end += 1;
        } else {
            break;
        }
    }
    if end == 0 {
        return None;
    }

    let b64_raw = std::str::from_utf8(&rem[..end]).ok()?;
    let clean = b64_raw
        .replace("%3D", "=")
        .replace("%3d", "=")
        .replace('-', "+")
        .replace('_', "/");
    let padded = match clean.len() % 4 {
        2 => format!("{}==", clean),
        3 => format!("{}=", clean),
        _ => clean,
    };

    crate::server::acme::b64url_decode(&padded)
        .ok()
        .or_else(|| {
            // standard base64 fallback
            let bytes = base64_decode_fast(&padded).ok()?;
            Some(bytes)
        })
        .filter(|wire| wire.len() >= 12 && crate::dns::parser::parse_dns_query(wire).is_some())
}

fn base64_decode_fast(input: &str) -> Result<Vec<u8>, &'static str> {
    const TABLE: &[u8; 128] = &[
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  62, 255,  62, 255,  63,
         52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255, 255,   0, 255, 255,
        255,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
         15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255,  63,
        255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
         41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51, 255, 255, 255, 255, 255,
    ];

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);
    let mut buf = 0u32;
    let mut bits = 0;

    for &b in bytes {
        if b == b'=' { break; }
        if b as usize >= TABLE.len() { return Err("Invalid base64 byte"); }
        let val = TABLE[b as usize];
        if val == 255 { return Err("Invalid base64 char"); }
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// Builds RFC 9114 HTTP/3 Response Frames: HEADERS frame (0x01) with QPACK + DATA frame (0x00) with DNS response
pub fn build_h3_response_frames(dns_response: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(dns_response.len() + 128);

    // QPACK Header block:
    // Required Insert Count = 0, Sign bit = 0, Delta Base = 0 -> [0x00, 0x00]
    // Static Table index 25 (:status 200) -> 0xd9 (0b11011001)
    // Literal with literal name: content-type: application/dns-message
    // Literal with literal name: cache-control: no-cache
    let mut qpack = Vec::with_capacity(64);
    qpack.extend_from_slice(&[0x00, 0x00, 0xd9]);

    // content-type: application/dns-message (0x20 = literal field without indexing)
    qpack.push(0x20);
    qpack.push(12);
    qpack.extend_from_slice(b"content-type");
    qpack.push(23);
    qpack.extend_from_slice(b"application/dns-message");

    // cache-control: no-cache
    qpack.push(0x20);
    qpack.push(13);
    qpack.extend_from_slice(b"cache-control");
    qpack.push(8);
    qpack.extend_from_slice(b"no-cache");

    // 1. HEADERS Frame (Type 0x01)
    write_varint(0x01, &mut out);
    write_varint(qpack.len() as u64, &mut out);
    out.extend_from_slice(&qpack);

    // 2. DATA Frame (Type 0x00)
    write_varint(0x00, &mut out);
    write_varint(dns_response.len() as u64, &mut out);
    out.extend_from_slice(dns_response);

    out
}

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
    // Allow unidirectional streams for HTTP/3 control & QPACK streams
    transport.max_concurrent_uni_streams(16u32.into());
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

    // Send HTTP/3 SETTINGS frame on a unidirectional control stream if client opened an H3 connection
    {
        let conn_c = conn.clone();
        tokio::spawn(async move {
            if let Ok(mut uni) = conn_c.open_uni().await {
                // Stream type 0x00 (Control Stream), SETTINGS Frame (Type 0x04, Length 0x00)
                let _ = uni.write_all(&[0x00, 0x04, 0x00]).await;
            }
        });
    }

    // Drain and ignore client unidirectional streams (e.g. QPACK / control)
    {
        let conn_c = conn.clone();
        tokio::spawn(async move {
            while let Ok(mut uni_stream) = conn_c.accept_uni().await {
                tokio::spawn(async move {
                    let mut drain_buf = [0u8; 256];
                    while let Ok(Some(_)) = uni_stream.read(&mut drain_buf).await {}
                });
            }
        });
    }

    // Accept bidirectional streams for DNS queries (RFC 9250 DoQ / RFC 9114 DoH3)
    while let Ok((mut send_stream, mut recv_stream)) = conn.accept_bi().await {
        let state_clone = state.clone();
        tokio::spawn(async move {
            let mut stream_buf = Vec::with_capacity(512);
            let mut chunk = [0u8; 1024];

            // Read the initial chunk of data
            let read_first =
                tokio::time::timeout(DOQ_STREAM_TIMEOUT, recv_stream.read(&mut chunk)).await;
            let n = match read_first {
                Ok(Ok(Some(n))) if n >= 4 => n,
                _ => {
                    let _ = send_stream.reset(0x01u32.into());
                    return;
                }
            };
            stream_buf.extend_from_slice(&chunk[..n]);

            // Case A: Detect HTTP/3 HEADERS Frame (Type 0x01) for DoH3
            if stream_buf[0] == 0x01 {
                if let Some((frame_type, type_len)) = read_varint(&stream_buf) {
                    if frame_type == 0x01 {
                        if let Some((headers_len, len_len)) = read_varint(&stream_buf[type_len..]) {
                            let total_headers_frame = type_len + len_len + headers_len as usize;
                            while stream_buf.len() < total_headers_frame {
                                let read_more = tokio::time::timeout(DOQ_STREAM_TIMEOUT, recv_stream.read(&mut chunk)).await;
                                match read_more {
                                    Ok(Ok(Some(m))) if m > 0 => stream_buf.extend_from_slice(&chunk[..m]),
                                    _ => break,
                                }
                            }

                            let headers_payload = if stream_buf.len() >= total_headers_frame {
                                &stream_buf[type_len + len_len..total_headers_frame]
                            } else {
                                &stream_buf[type_len + len_len..]
                            };

                            // Check if GET query with ?dns=...
                            let query_opt = if let Some(q) = extract_dns_query_from_h3_headers(headers_payload) {
                                Some(q)
                            } else {
                                // Check subsequent DATA frame (Type 0x00) for POST
                                let rem_start = total_headers_frame;
                                let mut data_buf = stream_buf[rem_start..].to_vec();
                                while data_buf.is_empty() {
                                    let read_more = tokio::time::timeout(DOQ_STREAM_TIMEOUT, recv_stream.read(&mut chunk)).await;
                                    match read_more {
                                        Ok(Ok(Some(m))) if m > 0 => data_buf.extend_from_slice(&chunk[..m]),
                                        _ => break,
                                    }
                                }

                                if let Some((data_type, d_type_len)) = read_varint(&data_buf) {
                                    if data_type == 0x00 {
                                        if let Some((data_len, d_len_len)) = read_varint(&data_buf[d_type_len..]) {
                                            let total_data = d_type_len + d_len_len + data_len as usize;
                                            while data_buf.len() < total_data {
                                                let read_more = tokio::time::timeout(DOQ_STREAM_TIMEOUT, recv_stream.read(&mut chunk)).await;
                                                match read_more {
                                                    Ok(Ok(Some(m))) if m > 0 => data_buf.extend_from_slice(&chunk[..m]),
                                                    _ => break,
                                                }
                                            }
                                            if data_buf.len() >= total_data {
                                                Some(data_buf[d_type_len + d_len_len..total_data].to_vec())
                                            } else {
                                                None
                                            }
                                        } else { None }
                                    } else { None }
                                } else { None }
                            };

                            if let Some(query_bytes) = query_opt {
                                if !state_clone.check_rate_limit(client_ip, None) {
                                    let fail = crate::dns::parser::build_servfail_response(&query_bytes);
                                    let h3_resp = build_h3_response_frames(&fail);
                                    let _ = send_stream.write_all(&h3_resp).await;
                                    let _ = send_stream.finish();
                                    return;
                                }

                                let resp_bytes = process_dns_wire_packet(
                                    state_clone,
                                    &query_bytes,
                                    client_ip,
                                    None,
                                    "DoH3",
                                )
                                .await;

                                let h3_resp = build_h3_response_frames(&resp_bytes);
                                let _ = send_stream.write_all(&h3_resp).await;
                                let _ = send_stream.finish();
                                return;
                            }
                        }
                    }
                }
            }

            // Case B: DoQ (RFC 9250 length-prefixed vs raw query wire)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encode_decode_roundtrip() {
        let test_cases = vec![0u64, 1, 25, 63, 64, 1000, 16383, 16384, 1_000_000, 1_073_741_823, 1_073_741_824, 999_999_999_999];
        for val in test_cases {
            let mut encoded = Vec::new();
            write_varint(val, &mut encoded);
            let (decoded, len) = read_varint(&encoded).expect("varint decode should succeed");
            assert_eq!(val, decoded);
            assert_eq!(encoded.len(), len);
        }
    }

    #[test]
    fn test_build_h3_response_frames_validity() {
        let dummy_dns_response = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let h3_bytes = build_h3_response_frames(&dummy_dns_response);

        // Verify HEADERS frame
        let (frame_type, type_len) = read_varint(&h3_bytes).expect("headers frame type");
        assert_eq!(frame_type, 0x01); // HEADERS frame
        let (headers_len, len_len) = read_varint(&h3_bytes[type_len..]).expect("headers length");
        let headers_start = type_len + len_len;
        let headers_end = headers_start + headers_len as usize;
        assert!(h3_bytes.len() > headers_end);

        // Verify DATA frame
        let (data_type, d_type_len) = read_varint(&h3_bytes[headers_end..]).expect("data frame type");
        assert_eq!(data_type, 0x00); // DATA frame
        let (data_len, d_len_len) = read_varint(&h3_bytes[headers_end + d_type_len..]).expect("data length");
        assert_eq!(data_len as usize, dummy_dns_response.len());
        let data_start = headers_end + d_type_len + d_len_len;
        assert_eq!(&h3_bytes[data_start..data_start + data_len as usize], &dummy_dns_response[..]);
    }

    #[test]
    fn test_extract_dns_query_from_h3_headers() {
        // Query wire for google.com A
        let query_wire = crate::dns::parser::build_query_wire("google.com", 1);
        let b64 = crate::server::acme::b64url(&query_wire);
        let header_str = format!(":path=/dns-query?dns={}&client=test", b64);
        let extracted = extract_dns_query_from_h3_headers(header_str.as_bytes())
            .expect("should extract dns query wire");
        assert_eq!(extracted, query_wire);
    }
}
