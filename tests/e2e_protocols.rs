use amardns::config::Config;
use amardns::dns::parser::build_query_wire;
use amardns::server::doh::create_doh_router;
use amardns::server::doh3::start_doh3_server;
use amardns::server::doq::start_doq_server;
use amardns::server::dot::start_dot_server;
use amardns::server::plain::{start_plain_tcp, start_plain_udp};
use amardns::server::tls::{
    DynamicCertResolver, create_dynamic_doh3_server_config, create_dynamic_doq_server_config,
    create_dynamic_dot_server_config,
};
use amardns::state::{AppState, BlockEntry};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
struct NoCertVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertVerification {
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
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

fn get_free_ports(count: usize) -> Vec<u16> {
    let mut listeners = Vec::with_capacity(count);
    let mut ports = Vec::with_capacity(count);
    for _ in 0..count {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        ports.push(listener.local_addr().unwrap().port());
        listeners.push(listener);
    }
    drop(listeners);
    ports
}

#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_all_protocols_suite() {
    let ports = get_free_ports(6);
    let udp_port = ports[0];
    let tcp_port = ports[1];
    let doh_port = ports[2];
    let dot_port = ports[3];
    let doq_port = ports[4];
    let doh3_port = ports[5];

    let cert_resolver = Arc::new(
        DynamicCertResolver::from_self_signed(&["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("Failed to create self-signed cert resolver"),
    );

    let dot_tls = create_dynamic_dot_server_config(cert_resolver.clone())
        .expect("Failed to create DoT TLS config");
    let doq_tls = create_dynamic_doq_server_config(cert_resolver.clone())
        .expect("Failed to create DoQ TLS config");
    let doh3_tls = create_dynamic_doh3_server_config(cert_resolver.clone())
        .expect("Failed to create DoH3 TLS config");

    let mut config = Config::from_env();
    config.host = "127.0.0.1".to_string();
    config.udp_host = "127.0.0.1".to_string();
    config.plain53_host = "127.0.0.1".to_string();
    config.plain53_udp_host = "127.0.0.1".to_string();
    config.port = doh_port;
    config.dot_port = dot_port;
    config.doq_port = doq_port;
    config.doh3_port = doh3_port;
    config.dns_master_key = "test-master-key".to_string();
    config.db_path = ":memory:".to_string();

    let state = Arc::new(AppState::new(config));
    state.custom_blocklist.write().insert(
        "e2e-blocked.test".to_string(),
        BlockEntry {
            domain: "e2e-blocked.test".to_string(),
            reason: "custom_block".to_string(),
            source: "manual".to_string(),
            tag: "CUSTOM".to_string(),
            auto: false,
            created_at: 0,
        },
    );

    // 1. Spawn Plain UDP listener
    let state_udp = state.clone();
    let rx_udp = state.shutdown_rx.clone();
    tokio::spawn(async move {
        start_plain_udp(state_udp, "127.0.0.1", udp_port, rx_udp).await;
    });

    // 2. Spawn Plain TCP listener
    let state_tcp = state.clone();
    let rx_tcp = state.shutdown_rx.clone();
    tokio::spawn(async move {
        start_plain_tcp(state_tcp, "127.0.0.1", tcp_port, rx_tcp).await;
    });

    // 3. Spawn DoT listener
    let state_dot = state.clone();
    let rx_dot = state.shutdown_rx.clone();
    tokio::spawn(async move {
        let _ = start_dot_server(state_dot, "127.0.0.1", dot_port, Some(dot_tls), rx_dot).await;
    });

    // 4. Spawn DoH listener
    let doh_app = create_doh_router(state.clone());
    let doh_listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", doh_port))
        .await
        .expect("Failed to bind DoH listener");
    let mut rx_doh = state.shutdown_rx.clone();
    tokio::spawn(async move {
        let _ = axum::serve(
            doh_listener,
            doh_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            while rx_doh.changed().await.is_ok() {
                if *rx_doh.borrow() {
                    break;
                }
            }
        })
        .await;
    });

    // 5. Spawn DoQ listener
    let state_doq = state.clone();
    let rx_doq = state.shutdown_rx.clone();
    tokio::spawn(async move {
        let _ = start_doq_server(state_doq, "127.0.0.1", doq_port, doq_tls, rx_doq).await;
    });

    // 6. Spawn DoH3 listener
    let state_doh3 = state.clone();
    let rx_doh3 = state.shutdown_rx.clone();
    tokio::spawn(async move {
        let _ = start_doh3_server(state_doh3, "127.0.0.1", doh3_port, doh3_tls, rx_doh3).await;
    });

    // Allow all socket listeners to complete startup
    tokio::time::sleep(Duration::from_millis(150)).await;

    let query_wire = build_query_wire("e2e-blocked.test", 1);
    let prefix = (query_wire.len() as u16).to_be_bytes();

    // ─── Test 1: Plain UDP (RFC 1035) ──────────────────────────────────────────
    {
        let udp_client = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("Client UDP bind failed");
        udp_client
            .send_to(&query_wire, format!("127.0.0.1:{}", udp_port))
            .await
            .expect("UDP send failed");
        let mut buf = [0u8; 1024];
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), udp_client.recv_from(&mut buf))
            .await
            .expect("UDP timeout")
            .expect("UDP recv failed");
        assert!(len >= 12, "UDP response packet too short: {} bytes", len);
        assert_eq!(&buf[0..2], &query_wire[0..2], "UDP Transaction ID mismatch");
        assert_ne!(buf[2] & 0x80, 0, "UDP QR bit not set to response");
    }

    // ─── Test 2: Plain TCP (RFC 1035 / RFC 7766) ───────────────────────────────
    {
        let mut tcp_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", tcp_port))
            .await
            .expect("TCP connect failed");
        tcp_stream
            .write_all(&prefix)
            .await
            .expect("TCP write prefix failed");
        tcp_stream
            .write_all(&query_wire)
            .await
            .expect("TCP write query failed");

        let mut len_buf = [0u8; 2];
        tcp_stream
            .read_exact(&mut len_buf)
            .await
            .expect("TCP read len prefix failed");
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        tcp_stream
            .read_exact(&mut resp_buf)
            .await
            .expect("TCP read response payload failed");
        assert_eq!(
            &resp_buf[0..2],
            &query_wire[0..2],
            "TCP Transaction ID mismatch"
        );
        assert_ne!(resp_buf[2] & 0x80, 0, "TCP QR bit not set to response");
    }

    // ─── Test 3: DoT (DNS-over-TLS, RFC 7858) ──────────────────────────────────
    {
        let mut client_tls_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerification))
            .with_no_client_auth();
        client_tls_cfg.alpn_protocols = vec![b"dot".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls_cfg));
        let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", dot_port))
            .await
            .expect("DoT TCP connect failed");
        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let mut tls_stream = connector
            .connect(server_name, tcp)
            .await
            .expect("DoT TLS handshake failed");

        tls_stream
            .write_all(&prefix)
            .await
            .expect("DoT write prefix failed");
        tls_stream
            .write_all(&query_wire)
            .await
            .expect("DoT write query failed");

        let mut dot_len_buf = [0u8; 2];
        tls_stream
            .read_exact(&mut dot_len_buf)
            .await
            .expect("DoT read length prefix failed");
        let dot_resp_len = u16::from_be_bytes(dot_len_buf) as usize;
        let mut dot_resp_buf = vec![0u8; dot_resp_len];
        tls_stream
            .read_exact(&mut dot_resp_buf)
            .await
            .expect("DoT read response payload failed");
        assert_eq!(
            &dot_resp_buf[0..2],
            &query_wire[0..2],
            "DoT Transaction ID mismatch"
        );
        assert_ne!(dot_resp_buf[2] & 0x80, 0, "DoT QR bit not set to response");
    }

    // ─── Test 4: DoH (DNS-over-HTTPS / RFC 8484 wire & RFC 8427 JSON) ──────────
    {
        let req_client = reqwest::Client::builder().build().unwrap();

        // 4a. Binary Wire POST /dns-query
        let doh_post_resp = req_client
            .post(format!("http://127.0.0.1:{}/dns-query", doh_port))
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(query_wire.clone())
            .send()
            .await
            .expect("DoH POST request failed");
        assert_eq!(doh_post_resp.status(), reqwest::StatusCode::OK);
        assert_eq!(
            doh_post_resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/dns-message")
        );
        let doh_bytes = doh_post_resp.bytes().await.unwrap();
        assert_eq!(
            &doh_bytes[0..2],
            &query_wire[0..2],
            "DoH Transaction ID mismatch"
        );

        // 4b. REST JSON GET /resolve?name=...
        let doh_json_resp = req_client
            .get(format!(
                "http://127.0.0.1:{}/resolve?name=e2e-blocked.test&type=A",
                doh_port
            ))
            .send()
            .await
            .expect("DoH JSON GET request failed");
        assert_eq!(doh_json_resp.status(), reqwest::StatusCode::OK);
        let json_val: serde_json::Value = doh_json_resp.json().await.unwrap();
        assert!(json_val.get("Status").is_some());

        // 4c. Telemetry endpoints (/health & /metrics)
        let health_resp = req_client
            .get(format!("http://127.0.0.1:{}/health", doh_port))
            .send()
            .await
            .expect("Health GET failed");
        assert_eq!(health_resp.status(), reqwest::StatusCode::OK);

        let metrics_resp = req_client
            .get(format!("http://127.0.0.1:{}/metrics", doh_port))
            .header("Authorization", "Bearer test-master-key")
            .send()
            .await
            .expect("Metrics GET failed");
        assert_eq!(metrics_resp.status(), reqwest::StatusCode::OK);
    }

    // ─── Test 5: DoQ (DNS-over-QUIC, RFC 9250) ─────────────────────────────────
    {
        let mut doq_client_tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerification))
            .with_no_client_auth();
        doq_client_tls.alpn_protocols = vec![b"doq".to_vec()];
        let doq_quic_client_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(doq_client_tls)
            .expect("Failed to build DoQ QuicClientConfig");
        let mut doq_client_cfg = quinn::ClientConfig::new(Arc::new(doq_quic_client_cfg));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(quinn::VarInt::from_u32(10_000).into()));
        doq_client_cfg.transport_config(Arc::new(transport));

        let mut doq_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())
            .expect("Failed to create DoQ client endpoint");
        doq_endpoint.set_default_client_config(doq_client_cfg);

        let doq_conn = doq_endpoint
            .connect(
                format!("127.0.0.1:{}", doq_port).parse().unwrap(),
                "localhost",
            )
            .expect("DoQ connect initiation failed")
            .await
            .expect("DoQ QUIC handshake failed");

        let (mut doq_send, mut doq_recv) = doq_conn
            .open_bi()
            .await
            .expect("Failed to open DoQ bidi stream");
        doq_send
            .write_all(&prefix)
            .await
            .expect("DoQ write prefix failed");
        doq_send
            .write_all(&query_wire)
            .await
            .expect("DoQ write query failed");
        doq_send.finish().expect("DoQ finish write failed");

        let mut doq_len_buf = [0u8; 2];
        doq_recv
            .read_exact(&mut doq_len_buf)
            .await
            .expect("DoQ read length prefix failed");
        let doq_resp_len = u16::from_be_bytes(doq_len_buf) as usize;
        let mut doq_resp_wire = vec![0u8; doq_resp_len];
        doq_recv
            .read_exact(&mut doq_resp_wire)
            .await
            .expect("DoQ read response wire failed");
        assert_eq!(
            &doq_resp_wire[0..2],
            &query_wire[0..2],
            "DoQ Transaction ID mismatch"
        );
        assert_ne!(doq_resp_wire[2] & 0x80, 0, "DoQ QR bit not set to response");
    }

    // ─── Test 6: DoH3 (DNS-over-HTTP/3, RFC 9114 / RFC 8484) ───────────────────
    {
        let mut doh3_client_tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerification))
            .with_no_client_auth();
        doh3_client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let doh3_quic_client_cfg =
            quinn::crypto::rustls::QuicClientConfig::try_from(doh3_client_tls)
                .expect("Failed to build DoH3 QuicClientConfig");
        let doh3_client_cfg = quinn::ClientConfig::new(Arc::new(doh3_quic_client_cfg));

        let mut doh3_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())
            .expect("Failed to create DoH3 client endpoint");
        doh3_endpoint.set_default_client_config(doh3_client_cfg);

        let doh3_conn = doh3_endpoint
            .connect(
                format!("127.0.0.1:{}", doh3_port).parse().unwrap(),
                "localhost",
            )
            .expect("DoH3 connect initiation failed")
            .await
            .expect("DoH3 QUIC handshake failed");

        let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(doh3_conn))
            .await
            .expect("H3 client handshake failed");
        tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });

        let doh3_req = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("https://localhost:{}/dns-query", doh3_port))
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(())
            .unwrap();
        let mut req_stream = send_request
            .send_request(doh3_req)
            .await
            .expect("H3 send_request failed");
        req_stream
            .send_data(bytes::Bytes::from(query_wire.clone()))
            .await
            .expect("H3 send_data failed");
        req_stream.finish().await.expect("H3 finish stream failed");

        let doh3_resp = req_stream
            .recv_response()
            .await
            .expect("H3 recv_response failed");
        assert_eq!(doh3_resp.status(), http::StatusCode::OK);

        let mut doh3_body = Vec::new();
        while let Ok(Some(mut chunk)) = req_stream.recv_data().await {
            use bytes::Buf;
            doh3_body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        assert!(
            !doh3_body.is_empty(),
            "DoH3 response body wire format was empty"
        );
        assert_eq!(
            &doh3_body[0..2],
            &query_wire[0..2],
            "DoH3 Transaction ID mismatch"
        );
        assert_ne!(doh3_body[2] & 0x80, 0, "DoH3 QR bit not set to response");
    }

    // Clean teardown across all servers
    state.trigger_shutdown();
}
