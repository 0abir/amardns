use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::dns::parser::build_servfail_response;
use crate::state::AppState;

// RFC 7858 Section 3.4: servers SHOULD allow idle connections to remain open.
// Increased from 15s to 120s so Android Private DNS and iOS DoT clients don't get
// their persistent connections severed between user queries, preventing Fly.io
// proxy Broken Pipe (OS error 32) errors.
const DOT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
// Allow 8s for slow upstream resolvers.
const DOT_READ_TIMEOUT: Duration = Duration::from_secs(8);
const DOT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// DNS-over-TLS (DoT, RFC 7858) internal backend listener.
///
/// NOTE ON TLS TERMINATION & ENCRYPTION:
/// In production on Fly.io, TLS 1.3/1.2 is terminated at Fly's Anycast Edge Proxy on public port 853
/// via `handlers = ["tls"]` in `fly.toml` using valid Let's Encrypt certificates.
/// Clients (e.g. Android Private DNS) establish an encrypted TLS tunnel with Fly's Edge.
/// Fly proxies the stream over its internal private WireGuard network to internal port 8853,
/// where this listener processes RFC 7858 length-prefixed DNS wire packets.
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wrapper that replays pre-read bytes before streaming from the underlying async socket.
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    prefix_pos: usize,
    stream: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, stream: S) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            stream,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.prefix_pos < self.prefix.len() {
            let available = self.prefix.len() - self.prefix_pos;
            let to_read = std::cmp::min(available, buf.remaining());
            buf.put_slice(&self.prefix[self.prefix_pos..self.prefix_pos + to_read]);
            self.prefix_pos += to_read;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Creates a dual-stack TCP listener that accepts both IPv4 and IPv6 connections when bound to an IPv6 address.
pub fn create_dual_stack_tcp_listener(addr: SocketAddr) -> Result<TcpListener, std::io::Error> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    let _ = socket.set_reuse_address(true);
    #[cfg(unix)]
    let _ = socket.set_reuse_port(true);
    let _ = socket.set_tcp_nodelay(true);
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(4096)?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

pub async fn start_dot_server(
    state: Arc<AppState>,
    host: &str,
    port: u16,
    tls_config: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), std::io::Error> {
    let host_ip: std::net::IpAddr = host
        .parse()
        .unwrap_or(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED));
    let addr = SocketAddr::new(host_ip, port);
    let listener = create_dual_stack_tcp_listener(addr)?;
    let tls_acceptor = tls_config.map(tokio_rustls::TlsAcceptor::from);
    let conn_limiter = Arc::new(tokio::sync::Semaphore::new(1024));

    if tls_acceptor.is_some() {
        info!(
            "[dot] AmarDNS DoT server listening on {} with native TLS termination (RFC 7858)",
            addr
        );
    } else {
        info!(
            "[dot] AmarDNS DoT server listening on {} (Edge TLS terminated via Fly proxy on 853)",
            addr
        );
    }

    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((mut socket, client_addr)) => {
                        let permit = match conn_limiter.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                warn!("[dot] Max concurrent DoT connections (1024) reached; shedding connection from {}", client_addr);
                                drop(socket);
                                continue;
                            }
                        };
                        let state_clone = state.clone();
                        let acceptor_clone = tls_acceptor.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            let _ = socket.set_nodelay(true);
                            {
                                use socket2::{SockRef, TcpKeepalive};
                                let sock_ref = SockRef::from(&socket);
                                let ka = TcpKeepalive::new()
                                    .with_time(std::time::Duration::from_secs(30))
                                    .with_interval(std::time::Duration::from_secs(10));
                                let _ = sock_ref.set_tcp_keepalive(&ka);
                            }

                            // 1. Extract real client IP via PROXY v2 (or retain direct peer socket)
                            let (real_client_addr, pre_read) = parse_proxy_v2_header(&mut socket, client_addr).await;
                            let stream = PrefixedStream::new(pre_read, socket);

                            // 2. Perform Native TLS termination if enabled, otherwise handle stream directly
                            if let Some(acceptor) = acceptor_clone {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        handle_dot_connection(tls_stream, real_client_addr, state_clone).await;
                                    }
                                    Err(e) => {
                                        let err_str = e.to_string().to_lowercase();
                                        if err_str.contains("eof")
                                            || err_str.contains("unexpected eof")
                                            || err_str.contains("connection reset")
                                        {
                                            debug!("[dot] TCP probe / handshake aborted from {}: {}", real_client_addr, e);
                                        } else {
                                            warn!("[dot] TLS handshake failed from {}: {}", real_client_addr, e);
                                        }
                                    }
                                }
                            } else {
                                handle_dot_connection(stream, real_client_addr, state_clone).await;
                            }
                        });
                    }
                    Err(e) => {
                        warn!("[dot] Accept error: {}", e);
                    }
                }
            }
            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    info!("[dot] Shutting down DoT listener gracefully...");
                    break;
                }
            }
        }
    }
    Ok(())
}

const PROXY_V2_MAGIC: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

/// Attempts to parse HAProxy PROXY protocol v2 header from the incoming stream.
/// If present, extracts the real client SocketAddr and returns any extra bytes read.
/// If absent (e.g. direct TCP / health check), returns the original SocketAddr and the buffered bytes.
pub async fn parse_proxy_v2_header<S>(
    socket: &mut S,
    fallback_addr: SocketAddr,
) -> (SocketAddr, Vec<u8>)
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut header_buf = [0u8; 16];
    let mut total_read = 0;

    // Read the first byte to see if stream is active
    let n = match tokio::time::timeout(DOT_IDLE_TIMEOUT, socket.read(&mut header_buf[0..1])).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return (fallback_addr, Vec::new()),
    };
    total_read += n;
    debug!(
        "[dot] Connection from {}, first byte: 0x{:02X}",
        fallback_addr, header_buf[0]
    );

    // If the first byte is '\r' (0x0D), it might be the start of PROXY_V2_MAGIC.
    // Let's read until we have 16 bytes or determine it's not PROXY_V2_MAGIC.
    if header_buf[0] == PROXY_V2_MAGIC[0] {
        while total_read < 16 {
            match tokio::time::timeout(
                DOT_READ_TIMEOUT,
                socket.read(&mut header_buf[total_read..16]),
            )
            .await
            {
                Ok(Ok(m)) if m > 0 => {
                    total_read += m;
                    let check_len = std::cmp::min(total_read, 12);
                    if header_buf[..check_len] != PROXY_V2_MAGIC[..check_len] {
                        break;
                    }
                }
                _ => break,
            }
        }
    }

    if total_read >= 12 && &header_buf[..12] == PROXY_V2_MAGIC {
        // Ensure all 16 fixed header bytes are read
        if total_read < 16
            && tokio::time::timeout(
                DOT_READ_TIMEOUT,
                socket.read_exact(&mut header_buf[total_read..16]),
            )
            .await
            .is_err()
        {
            return (fallback_addr, Vec::new());
        }

        let ver_cmd = header_buf[12];
        let fam_proto = header_buf[13];
        let addr_len = u16::from_be_bytes([header_buf[14], header_buf[15]]) as usize;

        if (ver_cmd & 0xF0) == 0x20 {
            let mut addr_buf = vec![0u8; addr_len];
            if addr_len > 0
                && tokio::time::timeout(DOT_READ_TIMEOUT, socket.read_exact(&mut addr_buf))
                    .await
                    .is_err()
            {
                return (fallback_addr, Vec::new());
            }

            let real_addr = match fam_proto {
                0x11 if addr_len >= 12 => {
                    // AF_INET (IPv4), STREAM (TCP)
                    let src_ip =
                        std::net::Ipv4Addr::new(addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]);
                    let src_port = u16::from_be_bytes([addr_buf[8], addr_buf[9]]);
                    Some(SocketAddr::new(std::net::IpAddr::V4(src_ip), src_port))
                }
                0x21 if addr_len >= 36 => {
                    // AF_INET6 (IPv6), STREAM (TCP)
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&addr_buf[0..16]);
                    let src_ip = std::net::Ipv6Addr::from(octets);
                    let src_port = u16::from_be_bytes([addr_buf[32], addr_buf[33]]);
                    Some(SocketAddr::new(std::net::IpAddr::V6(src_ip), src_port))
                }
                _ => None,
            };

            if let Some(addr) = real_addr {
                debug!(
                    "[dot] Extracted real client IP via PROXY v2: {} (proxy peer: {})",
                    addr, fallback_addr
                );
                return (addr, Vec::new());
            }
            return (fallback_addr, Vec::new());
        }
    } else {
        debug!(
            "[dot] Stream from {} is not PROXY v2 (first byte: 0x{:02X}, total_read: {})",
            fallback_addr, header_buf[0], total_read
        );
    }

    (fallback_addr, header_buf[..total_read].to_vec())
}

#[allow(dead_code)]
async fn read_exact_buffered<S>(
    socket: &mut S,
    pre_read: &mut Vec<u8>,
    out: &mut [u8],
) -> Result<usize, std::io::Error>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let needed = out.len();
    if needed == 0 {
        return Ok(0);
    }

    let from_pre = std::cmp::min(pre_read.len(), needed);
    if from_pre > 0 {
        out[..from_pre].copy_from_slice(&pre_read[..from_pre]);
        pre_read.drain(..from_pre);
    }

    if from_pre < needed {
        socket.read_exact(&mut out[from_pre..needed]).await?;
    }

    Ok(needed)
}

async fn handle_dot_connection<S>(socket: S, client_addr: SocketAddr, state: Arc<AppState>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let client_ip = client_addr.ip().to_canonical();

    // Check rate limiter (private/internal Fly.io proxy IPs are automatically exempt).
    if !state.check_rate_limit(client_ip, None) {
        let mut s = socket;
        let _ = s.shutdown().await;
        return;
    }

    let (mut reader, mut writer) = tokio::io::split(socket);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    let writer_task = tokio::spawn(async move {
        while let Some(resp) = rx.recv().await {
            if send_length_prefixed(&mut writer, &resp).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    loop {
        // Read 2-byte length prefix (RFC 7858 Section 3.4 idle timeout)
        let mut len_buf = [0u8; 2];
        let read_res =
            tokio::time::timeout(DOT_IDLE_TIMEOUT, reader.read_exact(&mut len_buf)).await;
        match read_res {
            Ok(Ok(2)) => {}
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                break;
            }
            Ok(_) => {
                break;
            }
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 4096 {
            break;
        }

        let mut query = vec![0u8; msg_len];
        let body_res = tokio::time::timeout(DOT_READ_TIMEOUT, reader.read_exact(&mut query)).await;
        if body_res.is_err() || body_res.unwrap().is_err() {
            break;
        }

        if !state.check_rate_limit(client_ip, None) {
            let fail = build_servfail_response(&query);
            let _ = tx.send(fail).await;
            break;
        }

        let state_c = state.clone();
        let tx_c = tx.clone();
        tokio::spawn(async move {
            let resp_bytes = crate::server::doh::process_dns_wire_packet(
                state_c, &query, client_ip, None, "DoT",
            )
            .await;
            let _ = tx_c.send(resp_bytes).await;
        });
    }

    drop(tx);
    let _ = writer_task.await;
}

/// Writes a RFC 7858 length-prefixed DNS response with a 5s write timeout.
/// Returns Ok(()) on success. Translates BrokenPipe and ConnectionReset to
/// debug-level events — these mean the client already closed the connection
/// (normal for Android Private DNS and iOS DoT clients).
async fn send_length_prefixed<S>(socket: &mut S, data: &[u8]) -> Result<(), std::io::Error>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let len = data.len() as u16;
    let write_fut = async {
        socket.write_all(&len.to_be_bytes()).await?;
        socket.write_all(data).await?;
        socket.flush().await?;
        Ok::<(), std::io::Error>(())
    };

    match tokio::time::timeout(DOT_WRITE_TIMEOUT, write_fut).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            match e.kind() {
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset => {
                    // Client closed connection before we could write — normal for DoT clients
                    debug!("[dot] Client closed connection before response: {}", e);
                }
                _ => {
                    debug!("[dot] Write error: {}", e);
                }
            }
            Err(e)
        }
        Err(_) => {
            // Write timed out — client is unresponsive
            debug!("[dot] Write timeout — client unresponsive");
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "write timeout",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn test_parse_proxy_v2_ipv4() {
        let fallback = "127.0.0.1:853".parse().unwrap();
        // PROXY v2 IPv4 TCP header: 12-byte magic + ver_cmd(0x21) + fam_proto(0x11) + len(12) + src_ip(1.2.3.4) + dst_ip(5.6.7.8) + src_port(1234) + dst_port(853)
        let mut data = Vec::new();
        data.extend_from_slice(PROXY_V2_MAGIC);
        data.push(0x21); // v2, PROXY command
        data.push(0x11); // AF_INET, STREAM (TCP)
        data.extend_from_slice(&12u16.to_be_bytes()); // length 12
        data.extend_from_slice(&[1, 2, 3, 4]); // src ip: 1.2.3.4
        data.extend_from_slice(&[5, 6, 7, 8]); // dst ip: 5.6.7.8
        data.extend_from_slice(&1234u16.to_be_bytes()); // src port: 1234
        data.extend_from_slice(&853u16.to_be_bytes()); // dst port: 853

        // Trailing DoT payload
        data.extend_from_slice(&[0x00, 0x05, b'h', b'e', b'l', b'l', b'o']);

        let mut cursor = Cursor::new(data);
        let (extracted_addr, pre_read) = parse_proxy_v2_header(&mut cursor, fallback).await;

        assert_eq!(extracted_addr.ip(), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(extracted_addr.port(), 1234);
        assert!(pre_read.is_empty());

        let mut len_buf = [0u8; 2];
        let mut pre = pre_read;
        let res = read_exact_buffered(&mut cursor, &mut pre, &mut len_buf).await;
        assert!(res.is_ok());
        assert_eq!(len_buf, [0x00, 0x05]);
    }

    #[tokio::test]
    async fn test_parse_proxy_v2_ipv6() {
        let fallback = "127.0.0.1:853".parse().unwrap();
        // PROXY v2 IPv6 TCP header: 12-byte magic + ver_cmd(0x21) + fam_proto(0x21) + len(36) + src_ip(2001:db8::1) + dst_ip + src_port(4321) + dst_port
        let mut data = Vec::new();
        data.extend_from_slice(PROXY_V2_MAGIC);
        data.push(0x21); // v2, PROXY command
        data.push(0x21); // AF_INET6, STREAM (TCP)
        data.extend_from_slice(&36u16.to_be_bytes()); // length 36
        let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst_v6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        data.extend_from_slice(&src_v6.octets());
        data.extend_from_slice(&dst_v6.octets());
        data.extend_from_slice(&4321u16.to_be_bytes()); // src port
        data.extend_from_slice(&853u16.to_be_bytes()); // dst port

        let mut cursor = Cursor::new(data);
        let (extracted_addr, pre_read) = parse_proxy_v2_header(&mut cursor, fallback).await;

        assert_eq!(extracted_addr.ip(), IpAddr::V6(src_v6));
        assert_eq!(extracted_addr.port(), 4321);
        assert!(pre_read.is_empty());
    }

    #[tokio::test]
    async fn test_parse_proxy_v2_fallback_on_direct_stream() {
        let fallback = "10.0.0.1:5555".parse().unwrap();
        // Direct RFC 7858 wire data without PROXY header (e.g. 2-byte length + payload)
        let data = vec![
            0x00, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        ];

        let mut cursor = Cursor::new(data.clone());
        let (extracted_addr, mut pre_read) = parse_proxy_v2_header(&mut cursor, fallback).await;

        assert_eq!(extracted_addr, fallback);
        assert!(!pre_read.is_empty());

        let mut out = vec![0u8; data.len()];
        let res = read_exact_buffered(&mut cursor, &mut pre_read, &mut out).await;
        assert!(res.is_ok());
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn test_prefixed_stream_tls_handshake() {
        use crate::server::tls::DynamicCertResolver;
        use tokio_rustls::rustls::pki_types::ServerName;

        let resolver =
            Arc::new(DynamicCertResolver::from_self_signed(&["localhost".to_string()]).unwrap());
        let server_cfg = crate::server::tls::create_dynamic_dot_server_config(resolver).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);

        // Build root cert store for client using server's cert
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        // Generate self-signed cert for client trust
        let self_signed =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der =
            tokio_rustls::rustls::pki_types::CertificateDer::from(self_signed.cert.der().to_vec());
        let _ = root_store.add(cert_der);

        // Client config with dangerous cert verifier (for self-signed test)
        let mut client_cfg = tokio_rustls::rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerification))
            .with_no_client_auth();
        client_cfg.alpn_protocols = vec![b"dot".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));

        let (client_io, mut server_io) = tokio::io::duplex(1024);

        let server_task = tokio::spawn(async move {
            let fallback: SocketAddr = "127.0.0.1:12345".parse().unwrap();
            let (real_addr, pre_read) = parse_proxy_v2_header(&mut server_io, fallback).await;
            let stream = PrefixedStream::new(pre_read, server_io);
            let mut tls_stream = acceptor.accept(stream).await.unwrap();
            let mut buf = [0u8; 4];
            tls_stream.read_exact(&mut buf).await.unwrap();
            tls_stream.write_all(b"PONG").await.unwrap();
            (real_addr, buf)
        });

        let client_task = tokio::spawn(async move {
            let server_name: ServerName<'static> = "localhost".try_into().unwrap();
            let mut tls_stream = connector.connect(server_name, client_io).await.unwrap();
            tls_stream.write_all(b"PING").await.unwrap();
            let mut buf = [0u8; 4];
            tls_stream.read_exact(&mut buf).await.unwrap();
            buf
        });

        let (server_res, client_res) = tokio::join!(server_task, client_task);
        let (server_addr, req_buf) = server_res.unwrap();
        let resp_buf = client_res.unwrap();

        assert_eq!(&req_buf, b"PING");
        assert_eq!(&resp_buf, b"PONG");
        assert_eq!(server_addr.to_string(), "127.0.0.1:12345");
    }

    #[derive(Debug)]
    struct NoCertVerification;
    impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoCertVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
            _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: tokio_rustls::rustls::pki_types::UnixTime,
        ) -> Result<
            tokio_rustls::rustls::client::danger::ServerCertVerified,
            tokio_rustls::rustls::Error,
        > {
            Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
            _dss: &tokio_rustls::rustls::DigitallySignedStruct,
        ) -> Result<
            tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
            tokio_rustls::rustls::Error,
        > {
            Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
            _dss: &tokio_rustls::rustls::DigitallySignedStruct,
        ) -> Result<
            tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
            tokio_rustls::rustls::Error,
        > {
            Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
            vec![
                tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                tokio_rustls::rustls::SignatureScheme::ED25519,
                tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }

    #[tokio::test]
    async fn test_create_dual_stack_tcp_listener() {
        // Test IPv4 bind (e.g. 127.0.0.1:0)
        let addr_v4: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener_v4 = create_dual_stack_tcp_listener(addr_v4).unwrap();
        let local_addr_v4 = listener_v4.local_addr().unwrap();
        assert!(local_addr_v4.is_ipv4());

        // Test IPv6 dual-stack bind (e.g. [::1]:0 or [::]:0)
        let addr_v6: SocketAddr = "[::1]:0".parse().unwrap();
        let listener_v6 = create_dual_stack_tcp_listener(addr_v6).unwrap();
        let local_addr_v6 = listener_v6.local_addr().unwrap();
        assert!(local_addr_v6.is_ipv6());
    }
}
