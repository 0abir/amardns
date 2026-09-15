// tests/test_quic_live.rs
// Live end-to-end integration tests for RFC 9250 DoQ (DNS-over-QUIC) and RFC 9114 DoH3 (DNS-over-HTTP/3)

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;

use amardns::config::Config;
use amardns::dns::parser::parse_dns_query;
use amardns::server::doq::{read_varint, start_doq_server};
use amardns::server::tls::{DynamicCertResolver, create_dynamic_quic_server_config};
use amardns::state::AppState;

/// Dummy TLS verification that trusts our test server cert
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn create_test_quinn_client(alpn: Vec<Vec<u8>>) -> quinn::Endpoint {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    crypto.alpn_protocols = alpn;

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
    ));

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}

#[tokio::test]
async fn test_doq_rfc9250_live_end_to_end() {
    let mut config = Config::from_env();
    config.dns_access_mode = "public".to_string();
    let state = Arc::new(AppState::new(config));

    let cert_resolver = Arc::new(
        DynamicCertResolver::from_self_signed(&["127.0.0.1".to_string(), "localhost".to_string()])
            .expect("self signed cert"),
    );
    let quic_tls_cfg = create_dynamic_quic_server_config(
        cert_resolver,
        vec![b"doq".to_vec(), b"doq-i00".to_vec(), b"doq-i02".to_vec()],
    )
    .expect("quic tls server config");

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let doq_state = state.clone();

    // Start DoQ server on ephemeral port
    let doq_port = 19853;
    tokio::spawn(async move {
        let _ = start_doq_server(
            doq_state,
            "127.0.0.1",
            doq_port,
            Some(quic_tls_cfg),
            shutdown_rx,
            "DoQ",
        )
        .await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect with Quinn DoQ client
    let client = create_test_quinn_client(vec![b"doq".to_vec()]);
    let server_addr: SocketAddr = format!("127.0.0.1:{}", doq_port).parse().unwrap();
    let conn = client
        .connect(server_addr, "localhost")
        .expect("start connect")
        .await
        .expect("QUIC handshake for DoQ");

    // Open bidirectional stream
    let (mut send, mut recv) = conn.open_bi().await.expect("open bi stream");

    // Build RFC 1035 query wire: google.com A (with 2-byte prefix length for RFC 9250)
    let query_wire = amardns::dns::parser::build_query_wire("google.com", 1);
    let len = (query_wire.len() as u16).to_be_bytes();
    send.write_all(&len).await.expect("write len");
    send.write_all(&query_wire).await.expect("write wire");
    send.finish().expect("finish send stream");

    // Read response
    let mut resp_buf = vec![0u8; 1024];
    let n = recv.read(&mut resp_buf).await.expect("read response").expect("non empty");
    assert!(n >= 14, "DoQ response must be at least 14 bytes (2 len + 12 header)");

    let resp_len = u16::from_be_bytes([resp_buf[0], resp_buf[1]]) as usize;
    assert_eq!(n - 2, resp_len);

    let parsed = parse_dns_query(&resp_buf[2..2 + resp_len]).expect("valid dns message");
    assert_eq!(parsed.question.unwrap().name, "google.com");
}

#[tokio::test]
async fn test_doh3_rfc9114_live_end_to_end() {
    let mut config = Config::from_env();
    config.dns_access_mode = "public".to_string();
    let state = Arc::new(AppState::new(config));

    let cert_resolver = Arc::new(
        DynamicCertResolver::from_self_signed(&["127.0.0.1".to_string(), "localhost".to_string()])
            .expect("self signed cert"),
    );
    let quic_tls_cfg = create_dynamic_quic_server_config(cert_resolver, vec![b"h3".to_vec()])
        .expect("quic tls server config");

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let doh3_state = state.clone();

    // Start DoH3 server on ephemeral port
    let doh3_port = 19443;
    tokio::spawn(async move {
        let _ = start_doq_server(
            doh3_state,
            "127.0.0.1",
            doh3_port,
            Some(quic_tls_cfg),
            shutdown_rx,
            "DoH3",
        )
        .await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect with Quinn DoH3 client (ALPN h3)
    let client = create_test_quinn_client(vec![b"h3".to_vec()]);
    let server_addr: SocketAddr = format!("127.0.0.1:{}", doh3_port).parse().unwrap();
    let conn = client
        .connect(server_addr, "localhost")
        .expect("start connect")
        .await
        .expect("QUIC handshake for DoH3");

    // Open bidirectional stream
    let (mut send, mut recv) = conn.open_bi().await.expect("open bi stream");

    // Build HTTP/3 HEADERS frame with GET /dns-query?dns=<base64url>
    let query_wire = amardns::dns::parser::build_query_wire("cloudflare.com", 1);
    let b64 = amardns::server::acme::b64url(&query_wire);
    let pseudo_header = format!(":method=GET :path=/dns-query?dns={}&client=test :scheme=https", b64);
    let mut headers_frame = Vec::new();
    amardns::server::doq::write_varint(0x01, &mut headers_frame); // HEADERS frame
    amardns::server::doq::write_varint(pseudo_header.len() as u64, &mut headers_frame);
    headers_frame.extend_from_slice(pseudo_header.as_bytes());

    send.write_all(&headers_frame).await.expect("write headers frame");
    send.finish().expect("finish send stream");

    // Read HTTP/3 response (HEADERS frame 0x01 + DATA frame 0x00)
    let mut resp_buf = vec![0u8; 2048];
    let n = recv.read(&mut resp_buf).await.expect("read response").expect("non empty");
    assert!(n >= 10, "DoH3 HTTP/3 response must contain frames");

    // Decode HEADERS frame
    let (frame1_type, f1_len) = read_varint(&resp_buf).expect("varint frame1");
    assert_eq!(frame1_type, 0x01, "First frame must be HTTP/3 HEADERS frame");
    let (h_len, h_len_len) = read_varint(&resp_buf[f1_len..]).expect("headers length");
    let headers_end = f1_len + h_len_len + h_len as usize;

    // Decode DATA frame
    let (frame2_type, f2_len) = read_varint(&resp_buf[headers_end..]).expect("varint frame2");
    assert_eq!(frame2_type, 0x00, "Second frame must be HTTP/3 DATA frame");
    let (d_len, d_len_len) = read_varint(&resp_buf[headers_end + f2_len..]).expect("data length");
    let data_start = headers_end + f2_len + d_len_len;
    let data_end = data_start + d_len as usize;

    let wire_dns = &resp_buf[data_start..data_end];
    let parsed = parse_dns_query(wire_dns).expect("valid dns message inside HTTP/3 DATA frame");
    assert_eq!(parsed.question.unwrap().name, "cloudflare.com");
}
