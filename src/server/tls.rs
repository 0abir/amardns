use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use axum::extract::ConnectInfo;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio_rustls::rustls;
use tokio_rustls::TlsAcceptor;
use tower_service::Service;

/// Loads certificates and private key from PEM files and creates a rustls::ServerConfig.
pub fn load_tls_config(
    cert_path: &str,
    key_path: &str,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    // 1. Read PEM certificate chain
    let cert_file = File::open(cert_path)
        .map_err(|e| format!("Failed to open TLS certificate file '{}': {}", cert_path, e))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse TLS certificates from '{}': {}", cert_path, e))?;

    if certs.is_empty() {
        return Err(format!("No valid PEM certificates found in '{}'", cert_path).into());
    }

    // 2. Read PEM private key (supports PKCS8, RSA PKCS1, and SEC1 EC keys)
    let key_file = File::open(key_path)
        .map_err(|e| format!("Failed to open TLS private key file '{}': {}", key_path, e))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("Failed to parse TLS private key from '{}': {}", key_path, e))?
        .ok_or_else(|| format!("No private key found in '{}'", key_path))?;

    // 3. Build rustls ServerConfig
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS server configuration error: {}", e))?;

    if !alpn_protocols.is_empty() {
        config.alpn_protocols = alpn_protocols;
    }

    Ok(Arc::new(config))
}

/// Creates TLS configuration optimized for DoH (HTTP/2 + HTTP/1.1 ALPN).
pub fn create_doh_tls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    load_tls_config(
        cert_path,
        key_path,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    )
}

/// Creates TLS configuration optimized for DoT (RFC 7858 "dot" ALPN).
pub fn create_dot_tls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    load_tls_config(
        cert_path,
        key_path,
        vec![b"dot".to_vec()],
    )
}

/// Serves Axum Router over native TLS using tokio-rustls and hyper-util with graceful shutdown.
pub async fn serve_axum_tls<F>(
    listener: TcpListener,
    app: axum::Router,
    tls_config: Arc<rustls::ServerConfig>,
    shutdown: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let acceptor = TlsAcceptor::from(tls_config);
    let auto_builder = Builder::new(TokioExecutor::new());
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                let (tcp_stream, remote_addr) = match accept_res {
                    Ok(conn) => conn,
                    Err(err) => {
                        tracing::warn!("[tls] TCP accept error: {}", err);
                        continue;
                    }
                };

                let acceptor = acceptor.clone();
                let auto_builder = auto_builder.clone();
                let app = app.clone();

                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(tcp_stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!("[tls] Handshake error: {}", e);
                            return;
                        }
                    };

                    let io = TokioIo::new(tls_stream);
                    let service = hyper::service::service_fn(move |mut req: axum::http::Request<hyper::body::Incoming>| {
                        let mut app_clone = app.clone();
                        req.extensions_mut().insert(ConnectInfo(remote_addr));
                        let req = req.map(axum::body::Body::new);
                        app_clone.call(req)
                    });

                    if let Err(err) = auto_builder.serve_connection_with_upgrades(io, service).await {
                        tracing::debug!("[tls] Connection error: {}", err);
                    }
                });
            }
            _ = &mut shutdown => {
                tracing::info!("[tls] Graceful shutdown signal received");
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_tls_config_missing_files() {
        let res = load_tls_config("/nonexistent/cert.pem", "/nonexistent/key.pem", vec![]);
        assert!(res.is_err());
    }

    #[test]
    fn test_create_doh_tls_config_missing_files() {
        let res = create_doh_tls_config("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(res.is_err());
    }

    #[test]
    fn test_create_dot_tls_config_missing_files() {
        let res = create_dot_tls_config("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(res.is_err());
    }
}

