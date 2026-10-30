// src/server/plain.rs
// Plain DNS (UDP + TCP) listener on port 53 with SO_REUSEPORT multi-worker support.
// High-throughput, zero-lock UDP worker pool + RFC 7873 DNS Cookies + RFC 7766 TCP pipelining.

use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{error, info, warn};

use crate::state::AppState;

const UDP_SOCKET_BUFFER_SIZE: usize = 8 * 1024 * 1024; // 8MB socket buffer for traffic spikes & kernel queue absorption

fn resolve_socket_addr(host: &str, port: u16) -> SocketAddr {
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

/// Creates a high-performance SO_REUSEPORT UDP socket bound to `addr` with 8MB buffers & DSCP prioritization.
fn create_reuseport_udp(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    let _ = socket.set_reuse_address(true);
    let _ = socket.set_reuse_port(true); // Kernel-level multi-worker distribution
    let _ = socket.set_recv_buffer_size(UDP_SOCKET_BUFFER_SIZE);
    let _ = socket.set_send_buffer_size(UDP_SOCKET_BUFFER_SIZE);
    #[cfg(unix)]
    let _ = socket.set_tos_v4(0xB8); // DSCP 46 (Expedited Forwarding) for hardware & kernel packet scheduling
    socket.set_nonblocking(true)?;
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    match socket.bind(&addr.into()) {
        Ok(_) => Ok(socket.into()),
        Err(_e) if addr.is_ipv6() => {
            let v4_addr = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), addr.port());
            let socket_v4 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            let _ = socket_v4.set_reuse_address(true);
            let _ = socket_v4.set_reuse_port(true);
            let _ = socket_v4.set_recv_buffer_size(UDP_SOCKET_BUFFER_SIZE);
            let _ = socket_v4.set_send_buffer_size(UDP_SOCKET_BUFFER_SIZE);
            #[cfg(unix)]
            let _ = socket_v4.set_tos_v4(0xB8);
            socket_v4.set_nonblocking(true)?;
            socket_v4.bind(&v4_addr.into())?;
            Ok(socket_v4.into())
        }
        Err(e) => Err(e),
    }
}

/// Creates a SO_REUSEPORT TCP listener socket bound to `addr`.
fn create_reuseport_tcp(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    let _ = socket.set_reuse_address(true);
    let _ = socket.set_reuse_port(true);
    let _ = socket.set_recv_buffer_size(UDP_SOCKET_BUFFER_SIZE);
    let _ = socket.set_send_buffer_size(UDP_SOCKET_BUFFER_SIZE);
    #[cfg(unix)]
    let _ = socket.set_tos_v4(0xB8);
    socket.set_nonblocking(true)?;
    socket.set_tcp_nodelay(true)?;
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    match socket.bind(&addr.into()) {
        Ok(_) => {
            socket.listen(4096)?;
            Ok(socket.into())
        }
        Err(_e) if addr.is_ipv6() => {
            let v4_addr = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), addr.port());
            let socket_v4 = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            let _ = socket_v4.set_reuse_address(true);
            let _ = socket_v4.set_reuse_port(true);
            let _ = socket_v4.set_recv_buffer_size(UDP_SOCKET_BUFFER_SIZE);
            let _ = socket_v4.set_send_buffer_size(UDP_SOCKET_BUFFER_SIZE);
            #[cfg(unix)]
            let _ = socket_v4.set_tos_v4(0xB8);
            socket_v4.set_nonblocking(true)?;
            socket_v4.set_tcp_nodelay(true)?;
            socket_v4.bind(&v4_addr.into())?;
            socket_v4.listen(4096)?;
            Ok(socket_v4.into())
        }
        Err(e) => Err(e),
    }
}

/// Starts a multi-worker plain DNS UDP listener pool on port 53.
pub async fn start_plain_udp(
    state: Arc<AppState>,
    host: &str,
    port: u16,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let addr = resolve_socket_addr(host, port);
    let num_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(4, 32);
    info!(
        "[plain53] Spawning {} UDP SO_REUSEPORT workers on {} (kernel multi-queue hardware acceleration)",
        num_workers, addr
    );

    let udp_concurrency = Arc::new(tokio::sync::Semaphore::new(4096));

    for worker_id in 0..num_workers {
        let std_sock = match create_reuseport_udp(addr) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "[plain53] Worker {} UDP bind on {} failed: {}. Skipping worker.",
                    worker_id, addr, e
                );
                return;
            }
        };

        let sock = match UdpSocket::from_std(std_sock) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!(
                    "[plain53] Worker {} failed to create async UDP socket: {}",
                    worker_id, e
                );
                return;
            }
        };

        let state_worker = state.clone();
        let mut shutdown_rx_worker = shutdown_rx.clone();
        let udp_concurrency_worker = udp_concurrency.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 4096]; // Pre-allocated reusable receive arena
            loop {
                tokio::select! {
                    _ = shutdown_rx_worker.changed() => {
                        if *shutdown_rx_worker.borrow() {
                            info!("[plain53] UDP worker {} shutting down", worker_id);
                            break;
                        }
                    }
                    result = sock.recv_from(&mut buf) => {
                        match result {
                            Ok((len, peer)) => {
                                if len < 12 { continue; }

                                let flags = u16::from_be_bytes([buf[2], buf[3]]);
                                // RFC 1035 §4.1.1 / RFC 6895: Silently drop incoming DNS responses to prevent reflection loops
                                if (flags & 0x8000) != 0 {
                                    continue;
                                }

                                let client_ip = peer.ip().to_canonical();

                                // Rate Limiting (RRL & Reflection / Amplification Mitigation)
                                if !state_worker.check_rate_limit(client_ip, None) {
                                    state_worker.metrics.burst_events.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    continue;
                                }

                                // Fast-Path Microsecond Negative, RFC 8482 ANY & Instant Blocker Absorber (<1µs zero-alloc drop)
                                if let Some(parsed) = crate::dns::parser::parse_dns_query_opts(&buf[..len], state_worker.config.rfc1035_8bit_labels) {
                                    if let Some(ref q) = parsed.question {
                                        // Fast-Path RFC 8482 Minimal ANY query absorber
                                        if q.qtype == 255 {
                                            if let Some(any_resp) = crate::dns::parser::build_any_minimal_response(&buf[..len]) {
                                                let _ = sock.send_to(&any_resp, peer).await;
                                                continue;
                                            }
                                        }

                                        let clean = q.name.trim_end_matches('.').to_ascii_lowercase();
                                        let is_bypassed = state_worker.is_bypassed(&clean);
                                        if !is_bypassed {
                                            // 1. Dedicated Instant Blocker check & isolated cache lookup
                                            if state_worker.is_instant_blocked(&clean) {
                                                state_worker.metrics.threat_blocks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                                state_worker.record_detected_block(&clean, "instant_shield_block");
                                                let blocked = if let Some(mut cached_resp) = state_worker.instant_cache.get_blocked_response(&clean, q.qtype, parsed.tx_id) {
                                                    if parsed.question_bytes_len > 0
                                                        && cached_resp.len() >= 12 + parsed.question_bytes_len
                                                        && len >= 12 + parsed.question_bytes_len
                                                    {
                                                        cached_resp[12..12 + parsed.question_bytes_len]
                                                            .copy_from_slice(&buf[12..12 + parsed.question_bytes_len]);
                                                    }
                                                    cached_resp
                                                } else {
                                                    let mut fresh = crate::dns::parser::build_sinkhole_response(&buf[..len]);
                                                    crate::dns::parser::append_ede_if_edns(&mut fresh, &buf[..len], 15, "INSTANT_BLOCK");
                                                    state_worker.instant_cache.insert_blocked_response(&clean, q.qtype, fresh.clone());
                                                    fresh
                                                };
                                                let _ = sock.send_to(&blocked, peer).await;
                                                continue;
                                            }

                                            // 2. Fast negative threat filter
                                            if let Some((reason, _is_nx)) = state_worker.fast_neg_filter.get(&clean) {
                                                state_worker.metrics.threat_blocks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                                state_worker.metrics.fast_neg_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                                state_worker.record_detected_block(&clean, reason);
                                                let mut blocked = crate::dns::parser::build_sinkhole_response(&buf[..len]);
                                                crate::dns::parser::append_ede_if_edns(&mut blocked, &buf[..len], 15, reason);
                                                let _ = sock.send_to(&blocked, peer).await;
                                                continue;
                                            }
                                        }
                                    }
                                }

                                let permit = match udp_concurrency_worker.clone().try_acquire_owned() {
                                    Ok(p) => p,
                                    Err(_) => {
                                        state_worker.metrics.burst_events.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        continue;
                                    }
                                };

                                let query = buf[..len].to_vec();
                                let state_c = state_worker.clone();
                                let sock_c = sock.clone();

                                tokio::spawn(async move {
                                    let _permit = permit;
                                    // RFC 7873: Parse incoming client cookie
                                    let cookie_opt = crate::dns::parser::parse_dns_cookie(&query);

                                    let mut resp = crate::server::doh::process_dns_wire_packet(
                                        state_c.clone(),
                                        &query,
                                        client_ip,
                                        None,
                                        "Plain53-UDP",
                                    ).await;

                                    // RFC 7873: Attach fresh server cookie to response
                                    if let Some((client_cookie, _)) = cookie_opt {
                                        let secret = state_c.config.dns_token_secret.as_bytes();
                                        let now_unix = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs() as u32;
                                        let server_cookie = crate::dns::parser::generate_server_cookie(
                                            secret,
                                            client_ip,
                                            &client_cookie,
                                            now_unix,
                                        );
                                        crate::dns::parser::append_cookie_to_response(
                                            &mut resp,
                                            &client_cookie,
                                            &server_cookie,
                                        );
                                    }

                                    // RFC 1035 / RFC 6891: Cleanly truncate UDP response preserving whole record boundaries
                                    let send_resp = crate::dns::parser::truncate_response_properly(&resp, 1232);
                                    let _ = sock_c.send_to(&send_resp, peer).await;
                                });
                            }
                            Err(e) => {
                                error!("[plain53] UDP worker {} recv error: {}", worker_id, e);
                            }
                        }
                    }
                }
            }
        });
    }
}

/// Starts a plain DNS TCP listener on port 53.
/// RFC 1035 Section 4.2.2 & RFC 7766: TCP DNS uses 2-byte length prefix framing and persistent connections.
pub async fn start_plain_tcp(
    state: Arc<AppState>,
    host: &str,
    port: u16,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let addr = resolve_socket_addr(host, port);

    let std_listener = match create_reuseport_tcp(addr) {
        Ok(l) => l,
        Err(e) => {
            warn!(
                "[plain53] TCP bind on {} failed: {}. Skipping plain DNS TCP.",
                addr, e
            );
            return;
        }
    };

    let listener = match TcpListener::from_std(std_listener) {
        Ok(l) => l,
        Err(e) => {
            error!("[plain53] Failed to create async TCP listener: {}", e);
            return;
        }
    };

    info!("[plain53] TCP DNS listener active on {}", addr);
    let conn_limiter = Arc::new(tokio::sync::Semaphore::new(1024));

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("[plain53] TCP listener shutting down");
                    break;
                }
            }
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        let permit = match conn_limiter.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                warn!("[plain53] Max concurrent TCP connections (1024) reached; shedding connection from {}", peer);
                                drop(stream);
                                continue;
                            }
                        };
                        let state2 = state.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            handle_plain_tcp_conn(state2, stream, peer).await;
                        });
                    }
                    Err(e) => {
                        error!("[plain53] TCP accept error: {}", e);
                    }
                }
            }
        }
    }
}

async fn handle_plain_tcp_conn(
    state: Arc<AppState>,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Connection-level rate limit check
    if !state.check_rate_limit(peer.ip(), None) {
        return;
    }

    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    let writer_task = tokio::spawn(async move {
        while let Some(resp) = rx.recv().await {
            let resp_len = (resp.len() as u16).to_be_bytes();
            if writer.write_all(&resp_len).await.is_err() || writer.write_all(&resp).await.is_err()
            {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    loop {
        let mut len_buf = [0u8; 2];
        let read_res =
            tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut len_buf)).await;
        match read_res {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 65535 {
            break;
        }
        let mut query = vec![0u8; msg_len];
        if tokio::time::timeout(Duration::from_secs(5), reader.read_exact(&mut query))
            .await
            .map_or(true, |r| r.is_err())
        {
            break;
        }

        // RFC 1035 §4.1.1: Drop unsolicited responses on TCP streams
        if query.len() >= 4 {
            let flags = u16::from_be_bytes([query[2], query[3]]);
            if (flags & 0x8000) != 0 {
                break;
            }
        }

        let client_ip = peer.ip().to_canonical();

        // Per-query rate limit check within persistent TCP connection
        if !state.check_rate_limit(client_ip, None) {
            let fail = crate::dns::parser::build_servfail_response(&query);
            let _ = tx.send(fail).await;
            break;
        }

        let state_c = state.clone();
        let tx_c = tx.clone();
        tokio::spawn(async move {
            let resp = crate::server::doh::process_dns_wire_packet(
                state_c,
                &query,
                client_ip,
                None,
                "Plain53-TCP",
            )
            .await;
            let _ = tx_c.send(resp).await;
        });
    }

    drop(tx);
    let _ = writer_task.await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_resolve_socket_addr_and_plain_dns_cookie_contract() {
        // 1. Dual-stack unspecified IPv6 wildcard
        let addr_v6_wildcard = resolve_socket_addr("::", 53);
        assert_eq!(
            addr_v6_wildcard,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53)
        );

        // 2. Standard IPv4 wildcard
        let addr_v4_wildcard = resolve_socket_addr("0.0.0.0", 53);
        assert_eq!(
            addr_v4_wildcard,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53)
        );

        // 3. Localhost IPv4
        let addr_v4_local = resolve_socket_addr("127.0.0.1", 5053);
        assert_eq!(
            addr_v4_local,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5053)
        );

        // 4. Localhost IPv6 bracketed
        let addr_v6_bracketed = resolve_socket_addr("[::1]", 5053);
        assert_eq!(
            addr_v6_bracketed,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5053)
        );

        // 5. Bare IPv6 address (without brackets)
        let addr_v6_bare = resolve_socket_addr("::1", 5053);
        assert_eq!(
            addr_v6_bare,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5053)
        );

        // 6. Unknown invalid string fallback
        let addr_invalid = resolve_socket_addr("invalid-host-string-xyz", 53);
        assert_eq!(
            addr_invalid,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53)
        );

        // 7. Verify RFC 7873 cookie generation and verification contract used by UDP worker
        let secret = b"super-secure-production-cookie-token-secret-64-characters-long!";
        let client_cookie = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42));
        let timestamp = 1700000000u32;

        let server_cookie = crate::dns::parser::generate_server_cookie(
            secret,
            client_ip,
            &client_cookie,
            timestamp,
        );

        assert!(crate::dns::parser::verify_server_cookie(
            secret,
            client_ip,
            &client_cookie,
            &server_cookie,
            timestamp + 60,
        ));

        // Mismatched client IP must fail verification
        assert!(!crate::dns::parser::verify_server_cookie(
            secret,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            &client_cookie,
            &server_cookie,
            timestamp + 60,
        ));
    }
}
