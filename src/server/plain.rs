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

const UDP_SOCKET_BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4MB socket buffer for traffic spikes
const NUM_UDP_WORKERS: usize = 4; // 4 parallel SO_REUSEPORT worker threads

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

/// Creates a high-performance SO_REUSEPORT UDP socket bound to `addr` with 4MB buffers.
fn create_reuseport_udp(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    let _ = socket.set_reuse_address(true);
    let _ = socket.set_reuse_port(true); // Kernel-level multi-worker distribution
    let _ = socket.set_recv_buffer_size(UDP_SOCKET_BUFFER_SIZE);
    let _ = socket.set_send_buffer_size(UDP_SOCKET_BUFFER_SIZE);
    socket.set_nonblocking(true)?;
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// Creates a SO_REUSEPORT TCP listener socket bound to `addr`.
fn create_reuseport_tcp(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    let _ = socket.set_reuse_address(true);
    let _ = socket.set_reuse_port(true);
    socket.set_nonblocking(true)?;
    socket.set_tcp_nodelay(true)?;
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    Ok(socket.into())
}

/// Starts a multi-worker plain DNS UDP listener pool on port 53.
pub async fn start_plain_udp(
    state: Arc<AppState>,
    host: &str,
    port: u16,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let addr = resolve_socket_addr(host, port);
    info!("[plain53] Spawning {} UDP SO_REUSEPORT workers on {}", NUM_UDP_WORKERS, addr);

    for worker_id in 0..NUM_UDP_WORKERS {
        let std_sock = match create_reuseport_udp(addr) {
            Ok(s) => s,
            Err(e) => {
                warn!("[plain53] Worker {} UDP bind on {} failed: {}. Skipping worker.", worker_id, addr, e);
                return;
            }
        };

        let sock = match UdpSocket::from_std(std_sock) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!("[plain53] Worker {} failed to create async UDP socket: {}", worker_id, e);
                return;
            }
        };

        let state_worker = state.clone();
        let mut shutdown_rx_worker = shutdown_rx.clone();

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
                                let query = buf[..len].to_vec();
                                let state_c = state_worker.clone();
                                let sock_c = sock.clone();

                                tokio::spawn(async move {
                                    // RFC 7873: Parse incoming client cookie
                                    let cookie_opt = crate::dns::parser::parse_dns_cookie(&query);

                                    let mut resp = crate::server::doh::process_dns_wire_packet(
                                        state_c.clone(),
                                        &query,
                                        peer.ip(),
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
                                            peer.ip(),
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
            warn!("[plain53] TCP bind on {} failed: {}. Skipping plain DNS TCP.", addr, e);
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
                        let state2 = state.clone();
                        tokio::spawn(handle_plain_tcp_conn(state2, stream, peer));
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
    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    let writer_task = tokio::spawn(async move {
        while let Some(resp) = rx.recv().await {
            let resp_len = (resp.len() as u16).to_be_bytes();
            if writer.write_all(&resp_len).await.is_err() || writer.write_all(&resp).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    loop {
        let mut len_buf = [0u8; 2];
        let read_res = tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut len_buf)).await;
        match read_res {
            Ok(Ok(_)) => {},
            _ => break,
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 65535 {
            break;
        }
        let mut query = vec![0u8; msg_len];
        if tokio::time::timeout(Duration::from_secs(5), reader.read_exact(&mut query)).await.map_or(true, |r| r.is_err()) {
            break;
        }
        let state_c = state.clone();
        let tx_c = tx.clone();
        tokio::spawn(async move {
            let resp = crate::server::doh::process_dns_wire_packet(
                state_c,
                &query,
                peer.ip(),
                None,
                "Plain53-TCP",
            ).await;
            let _ = tx_c.send(resp).await;
        });
    }

    drop(tx);
    let _ = writer_task.await;
}
