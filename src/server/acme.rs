// src/server/acme.rs
// Automated ACME DNS-01 provisioning and auto-renewal engine for AmarDNS.
// Supports ZeroSSL (with EAB credentials & ApiKey auth) and Let's Encrypt fallback.
// Manages genuine TLS certificates for DNS-over-QUIC (DoQ), DoH3, and DoT.

use chrono::{DateTime, Utc};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

const ZEROSSL_ACME_DIR: &str = "https://acme.zerossl.com/v2/DV90";
const LETSENCRYPT_DIR: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// URL-safe Base64 encoder without padding (RFC 7515 / RFC 8555)
pub fn b64url(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() {
            input[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < input.len() {
            input[i + 2] as u32
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < input.len() {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        }
        if i + 2 < input.len() {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        }
        i += 3;
    }
    out
}

/// URL-safe Base64 decoder supporting both padded and unpadded input
pub fn b64url_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in input.chars() {
        if c == '=' || c.is_whitespace() {
            continue;
        }
        let val = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '-' | '+' => 62,
            '_' | '/' => 63,
            _ => return Err(format!("Invalid base64 character: {}", c)),
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

#[derive(Deserialize, Debug)]
struct Directory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
}

struct AcmeClient {
    http: reqwest::Client,
    dir: Directory,
    key_pair: Arc<EcdsaKeyPair>,
    jwk_thumbprint: String,
    jwk_json: serde_json::Value,
    account_url: Option<String>,
    next_nonce: Mutex<Option<String>>,
}

impl AcmeClient {
    async fn new(
        http: reqwest::Client,
        dir_url: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let dir: Directory = http.get(dir_url).send().await?.json().await?;

        let account_key_path = if Path::new("/data").exists() {
            "/data/acme_account.pk8"
        } else {
            "acme_account.pk8"
        };

        let rng = SystemRandom::new();
        let key_pair = if let Ok(bytes) = fs::read(account_key_path) {
            if let Ok(kp) = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &bytes, &rng) {
                kp
            } else {
                let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                    .map_err(|e| format!("generate_pkcs8 error: {:?}", e))?;
                let _ = fs::write(account_key_path, pkcs8_bytes.as_ref());
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes.as_ref(), &rng)
                    .map_err(|e| format!("from_pkcs8 error: {:?}", e))?
            }
        } else {
            let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .map_err(|e| format!("generate_pkcs8 error: {:?}", e))?;
            let _ = fs::write(account_key_path, pkcs8_bytes.as_ref());
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes.as_ref(), &rng)
                .map_err(|e| format!("from_pkcs8 error: {:?}", e))?
        };

        let pub_key_bytes = key_pair.public_key().as_ref(); // 65 bytes (0x04 + x + y)

        let x = b64url(&pub_key_bytes[1..33]);
        let y = b64url(&pub_key_bytes[33..65]);

        let jwk_json = serde_json::json!({
            "crv": "P-256",
            "kty": "EC",
            "x": x,
            "y": y,
        });

        // RFC 7638 canonical JWK ordering: crv, kty, x, y
        let jwk_canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#, x, y);
        let thumb_hash = ring::digest::digest(&ring::digest::SHA256, jwk_canonical.as_bytes());
        let jwk_thumbprint = b64url(thumb_hash.as_ref());

        Ok(Self {
            http,
            dir,
            key_pair: Arc::new(key_pair),
            jwk_thumbprint,
            jwk_json,
            account_url: None,
            next_nonce: Mutex::new(None),
        })
    }

    async fn get_nonce(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let cached = {
            let mut lock = self.next_nonce.lock().await;
            lock.take()
        };
        if let Some(nonce) = cached {
            return Ok(nonce);
        }
        let resp = self.http.head(&self.dir.new_nonce).send().await?;
        let nonce = resp
            .headers()
            .get("replay-nonce")
            .ok_or("No replay-nonce header")?
            .to_str()?
            .to_string();
        Ok(nonce)
    }

    async fn post_jws(
        &self,
        url: &str,
        payload_json: &serde_json::Value,
    ) -> Result<reqwest::Response, Box<dyn std::error::Error + Send + Sync>> {
        self.post_jws_internal(url, payload_json, false).await
    }

    async fn post_jws_internal(
        &self,
        url: &str,
        payload_json: &serde_json::Value,
        is_retry: bool,
    ) -> Result<reqwest::Response, Box<dyn std::error::Error + Send + Sync>> {
        let nonce = self.get_nonce().await?;

        let mut protected = serde_json::json!({
            "alg": "ES256",
            "nonce": nonce,
            "url": url,
        });

        if let Some(ref kid) = self.account_url {
            protected["kid"] = serde_json::Value::String(kid.clone());
        } else {
            protected["jwk"] = self.jwk_json.clone();
        }

        let protected_b64 = b64url(protected.to_string().as_bytes());
        let payload_b64 = if payload_json.is_null() {
            String::new()
        } else {
            b64url(payload_json.to_string().as_bytes())
        };

        let signing_input = format!("{}.{}", protected_b64, payload_b64);
        let rng = SystemRandom::new();
        let sig = self
            .key_pair
            .sign(&rng, signing_input.as_bytes())
            .map_err(|e| format!("sign error: {:?}", e))?;
        let sig_b64 = b64url(sig.as_ref());

        let body = serde_json::json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": sig_b64,
        });

        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/jose+json"),
        );

        let resp = self
            .http
            .post(url)
            .headers(headers)
            .body(body.to_string())
            .send()
            .await?;

        // Cache new nonce if returned in response headers
        if let Some(new_nonce) = resp.headers().get("replay-nonce").and_then(|h| h.to_str().ok()) {
            let mut lock = self.next_nonce.lock().await;
            *lock = Some(new_nonce.to_string());
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            if let Ok(err_json) = serde_json::from_str::<serde_json::Value>(&body_text) {
                let err_type = err_json["type"].as_str().unwrap_or("unknown");
                let detail = err_json["detail"].as_str().unwrap_or(&body_text);

                // Auto-retry once on badNonce error
                if !is_retry && err_type.contains("badNonce") {
                    let mut lock = self.next_nonce.lock().await;
                    *lock = None;
                    return Box::pin(self.post_jws_internal(url, payload_json, true)).await;
                }

                return Err(format!("ACME API error ({} - {}): {}", status, err_type, detail).into());
            } else {
                return Err(format!("ACME API error (status {}): {}", status, body_text).into());
            }
        }

        Ok(resp)
    }
}

// ── DNS-01 Challenge Handlers ───────────────────────────────────────────────

async fn set_duckdns_txt(
    http: &reqwest::Client,
    token: &str,
    txt_val: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("[acme/duckdns] Publishing TXT record for amardns.duckdns.org...");
    let url = format!(
        "https://www.duckdns.org/update?domains=amardns&token={}&txt={}",
        token, txt_val
    );
    let resp = http.get(&url).send().await?.text().await?;
    if resp.trim() == "OK" {
        info!("[acme/duckdns] TXT record published successfully");
        Ok(())
    } else {
        Err(format!("DuckDNS error: {}", resp).into())
    }
}

async fn clear_duckdns_txt(
    http: &reqwest::Client,
    token: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = format!(
        "https://www.duckdns.org/update?domains=amardns&token={}&txt=",
        token
    );
    let _ = http.get(&url).send().await;
    Ok(())
}

async fn set_desec_txt(
    http: &reqwest::Client,
    token: &str,
    domain: &str,
    txt_val: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("[acme/desec] Publishing TXT record for {}...", domain);

    let put_url = format!(
        "https://desec.io/api/v1/domains/{}/rrsets/_acme-challenge/TXT/",
        domain
    );
    let body = serde_json::json!({
        "subname": "_acme-challenge",
        "type": "TXT",
        "records": [format!("\"{}\"", txt_val)],
        "ttl": 900
    });
    let resp = http
        .put(&put_url)
        .header("Authorization", format!("Token {}", token))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() {
        info!(
            "[acme/desec] TXT record published successfully for {}",
            domain
        );
        Ok(())
    } else {
        // Fallback to POST if PUT returned 404 (first creation on some endpoints)
        let post_url = format!("https://desec.io/api/v1/domains/{}/rrsets/", domain);
        let resp2 = http
            .post(&post_url)
            .header("Authorization", format!("Token {}", token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;
        if resp2.status().is_success() {
            info!(
                "[acme/desec] TXT record published successfully (via POST) for {}",
                domain
            );
            Ok(())
        } else {
            let err = resp2.text().await?;
            Err(format!("deSEC API error: {}", err).into())
        }
    }
}

async fn clear_desec_txt(
    http: &reqwest::Client,
    token: &str,
    domain: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let delete_url = format!(
        "https://desec.io/api/v1/domains/{}/rrsets/_acme-challenge/TXT/",
        domain
    );
    let _ = http
        .delete(&delete_url)
        .header("Authorization", format!("Token {}", token))
        .send()
        .await;
    Ok(())
}

pub fn is_dynu_domain(domain: &str) -> bool {
    let d = domain.to_ascii_lowercase();
    d.ends_with(".dynu.net")
        || d.ends_with(".dynu.com")
        || d.ends_with(".freeddns.org")
        || d.ends_with(".ddnsfree.com")
        || d.ends_with(".mywire.org")
        || d.ends_with(".accesscam.org")
        || d.ends_with(".camdvr.org")
        || d.ends_with(".kozow.com")
        || d.ends_with(".webhop.me")
        || d.ends_with(".dns-cloud.net")
        || d.ends_with(".blogdns.com")
        || d.ends_with(".dynu.email")
}

fn compute_dynu_node_name(full_domain: &str, root_domain: &str) -> String {
    let full = full_domain.trim_end_matches('.');
    let root = root_domain.trim_end_matches('.');
    if full.eq_ignore_ascii_case(root) {
        "_acme-challenge".to_string()
    } else if let Some(sub) = full.strip_suffix(root) {
        let sub_trimmed = sub.trim_end_matches('.');
        format!("_acme-challenge.{}", sub_trimmed)
    } else {
        "_acme-challenge".to_string()
    }
}

async fn get_dynu_domain_info(
    http: &reqwest::Client,
    api_key: &str,
    domain: &str,
) -> Result<(u64, String), Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://api.dynu.com/v2/dns/getroot/{}", domain);
    if let Ok(resp) = http
        .get(&url)
        .header("API-Key", api_key)
        .header("Accept", "application/json")
        .send()
        .await
    {
        if resp.status().is_success() {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let (Some(id), Some(name)) = (json["id"].as_u64(), json["domainName"].as_str()) {
                    return Ok((id, name.to_string()));
                }
            }
        }
    }

    // Fallback: list all domains
    let list_url = "https://api.dynu.com/v2/dns";
    let list_resp = http
        .get(list_url)
        .header("API-Key", api_key)
        .header("Accept", "application/json")
        .send()
        .await?;

    if list_resp.status().is_success() {
        let json: serde_json::Value = list_resp.json().await?;
        let domains = json["domains"].as_array().or_else(|| json.as_array());
        if let Some(arr) = domains {
            for d in arr {
                if let (Some(name), Some(id)) = (d["name"].as_str(), d["id"].as_u64()) {
                    if domain.eq_ignore_ascii_case(name)
                        || domain
                            .to_ascii_lowercase()
                            .ends_with(&format!(".{}", name.to_ascii_lowercase()))
                    {
                        return Ok((id, name.to_string()));
                    }
                }
            }
        }
    }

    Err(format!("Could not locate Dynu domain ID for '{}'", domain).into())
}

async fn set_dynu_txt(
    http: &reqwest::Client,
    api_key: &str,
    domain: &str,
    txt_val: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("[acme/dynu] Publishing TXT record for {}...", domain);
    let (domain_id, root_name) = get_dynu_domain_info(http, api_key, domain).await?;
    let node_name = compute_dynu_node_name(domain, &root_name);

    let records_url = format!("https://api.dynu.com/v2/dns/{}/record", domain_id);
    let rec_resp = http
        .get(&records_url)
        .header("API-Key", api_key)
        .header("Accept", "application/json")
        .send()
        .await?;

    let mut existing_record_id: Option<u64> = None;
    if rec_resp.status().is_success() {
        if let Ok(rec_json) = rec_resp.json::<serde_json::Value>().await {
            let records = rec_json["dnsRecords"].as_array().or_else(|| rec_json.as_array());
            if let Some(arr) = records {
                for r in arr {
                    let rec_type = r["recordType"].as_str().unwrap_or("");
                    let n_name = r["nodeName"].as_str().unwrap_or("");
                    if rec_type.eq_ignore_ascii_case("TXT")
                        && n_name.eq_ignore_ascii_case(&node_name)
                    {
                        if let Some(id) = r["id"].as_u64() {
                            existing_record_id = Some(id);
                            break;
                        }
                    }
                }
            }
        }
    }

    let payload = serde_json::json!({
        "nodeName": node_name,
        "recordType": "TXT",
        "textData": txt_val,
        "ttl": 120,
        "state": true
    });

    let resp = if let Some(rec_id) = existing_record_id {
        let update_url = format!(
            "https://api.dynu.com/v2/dns/{}/record/{}",
            domain_id, rec_id
        );
        http.post(&update_url)
            .header("API-Key", api_key)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?
    } else {
        http.post(&records_url)
            .header("API-Key", api_key)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?
    };

    if resp.status().is_success() {
        info!("[acme/dynu] TXT record published successfully for {}", domain);
        Ok(())
    } else {
        let err_text = resp.text().await.unwrap_or_default();
        Err(format!("Dynu API error: {}", err_text).into())
    }
}

async fn clear_dynu_txt(
    http: &reqwest::Client,
    api_key: &str,
    domain: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Ok((domain_id, root_name)) = get_dynu_domain_info(http, api_key, domain).await {
        let node_name = compute_dynu_node_name(domain, &root_name);
        let records_url = format!("https://api.dynu.com/v2/dns/{}/record", domain_id);
        if let Ok(rec_resp) = http
            .get(&records_url)
            .header("API-Key", api_key)
            .header("Accept", "application/json")
            .send()
            .await
        {
            if rec_resp.status().is_success() {
                if let Ok(rec_json) = rec_resp.json::<serde_json::Value>().await {
                    let records = rec_json["dnsRecords"].as_array().or_else(|| rec_json.as_array());
                    if let Some(arr) = records {
                        for r in arr {
                            let rec_type = r["recordType"].as_str().unwrap_or("");
                            let n_name = r["nodeName"].as_str().unwrap_or("");
                            if rec_type.eq_ignore_ascii_case("TXT")
                                && n_name.eq_ignore_ascii_case(&node_name)
                            {
                                if let Some(rec_id) = r["id"].as_u64() {
                                    let del_url = format!(
                                        "https://api.dynu.com/v2/dns/{}/record/{}",
                                        domain_id, rec_id
                                    );
                                    let _ = http.delete(&del_url).header("API-Key", api_key).send().await;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

// ── Certificate Expiry Parser ───────────────────────────────────────────────

/// Parses ASN.1 UTCTime (tag 0x17) or GeneralizedTime (tag 0x18) from DER bytes.
fn parse_der_time(bytes: &[u8]) -> Option<DateTime<Utc>> {
    let s = std::str::from_utf8(bytes).ok()?;
    if s.len() == 13 && s.ends_with('Z') {
        // YYMMDDHHMMSSZ (UTCTime)
        let year_prefix = if &s[0..2] >= "50" { "19" } else { "20" };
        let full_s = format!("{}{}", year_prefix, s);
        chrono::NaiveDateTime::parse_from_str(&full_s, "%Y%m%d%H%M%SZ")
            .ok()
            .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc))
    } else if s.len() == 15 && s.ends_with('Z') {
        // YYYYMMDDHHMMSSZ (GeneralizedTime)
        chrono::NaiveDateTime::parse_from_str(s, "%Y%m%d%H%M%SZ")
            .ok()
            .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc))
    } else {
        None
    }
}

/// Inspects a DER certificate and extracts the `notAfter` expiration timestamp.
pub fn extract_cert_expiry_der(der_bytes: &[u8]) -> Option<DateTime<Utc>> {
    let mut i = 0;
    let mut times = Vec::new();
    while i < der_bytes.len() {
        let tag = der_bytes[i];
        if (tag == 0x17 || tag == 0x18) && i + 1 < der_bytes.len() {
            let len = der_bytes[i + 1] as usize;
            let start = i + 2;
            let end = start + len;
            if end <= der_bytes.len() {
                if let Some(dt) = parse_der_time(&der_bytes[start..end]) {
                    times.push(dt);
                    if times.len() == 2 {
                        // First time is notBefore, second time is notAfter
                        return Some(times[1]);
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// Checks the days remaining before expiration for a PEM certificate file.
pub fn get_cert_days_remaining(cert_path: &str) -> Option<i64> {
    let cert_data = fs::read_to_string(cert_path).ok()?;
    let mut reader = std::io::BufReader::new(cert_data.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let first_cert = certs.first()?;
    let expiry = extract_cert_expiry_der(first_cert.as_ref())?;
    let now = Utc::now();
    let duration = expiry.signed_duration_since(now);
    Some(duration.num_days())
}

/// Validates an existing certificate and private key pair on disk.
/// Checks that the files exist, parse cleanly into valid DER, have valid signing keys,
/// and have at least `min_days_remaining` days remaining before expiration.
pub fn validate_existing_cert_and_key(
    cert_path: &str,
    key_path: &str,
    min_days_remaining: i64,
) -> Option<i64> {
    let days = get_cert_days_remaining(cert_path)?;
    if days < min_days_remaining {
        return None;
    }

    // Verify key exists and is a valid supported private key
    let key_data = fs::read_to_string(key_path).ok()?;
    let mut key_reader = std::io::BufReader::new(key_data.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader).ok()??;
    let _signing_key = tokio_rustls::rustls::crypto::ring::sign::any_supported_type(&key).ok()?;

    Some(days)
}

// ── ACME Provisioning Flow ──────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct AcmeConfig {
    pub zerossl_api_key: Option<String>,
    pub desec_token: Option<String>,
    pub duckdns_token: Option<String>,
    pub dynu_api_key: Option<String>,
    pub desec_domains: Vec<String>,
    pub duckdns_domains: Vec<String>,
    pub dynu_domains: Vec<String>,
    pub domains: Vec<String>,
    pub cert_path: String,
    pub key_path: String,
    pub cert_resolver: Option<Arc<crate::server::tls::DynamicCertResolver>>,
}

/// Executes full ACME DNS-01 certificate provisioning against ZeroSSL or Let's Encrypt.
pub async fn provision_acme_certificate(
    config: &AcmeConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if config.domains.is_empty() {
        return Err("No domains specified for ACME certificate provisioning".into());
    }

    let is_zerossl = config.zerossl_api_key.is_some();
    let ca_name = if is_zerossl { "ZeroSSL" } else { "Let's Encrypt" };
    let dir_url = if is_zerossl {
        ZEROSSL_ACME_DIR
    } else {
        LETSENCRYPT_DIR
    };

    info!("============================================================");
    info!("[acme] Starting Automated {} DNS-01 Provisioning", ca_name);
    info!("[acme] Domains: {:?}", config.domains);
    info!("============================================================");

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut client = AcmeClient::new(http.clone(), dir_url).await?;

    // 1. Create / Register Account
    info!("[acme] [1/5] Registering ACME account with {}...", ca_name);
    let account_payload = if let Some(ref api_key) = config.zerossl_api_key {
        // Fetch EAB credentials via header-based auth
        info!("[acme] Fetching ZeroSSL EAB credentials via API...");
        let eab_resp: serde_json::Value = http
            .post("https://api.zerossl.com/acme/eab-credentials")
            .header("Authorization", format!("ApiKey {}", api_key))
            .send()
            .await?
            .json()
            .await?;

        let eab_kid = eab_resp["eab_kid"]
            .as_str()
            .ok_or("Missing eab_kid in ZeroSSL EAB response")?;
        let eab_hmac_key = eab_resp["eab_hmac_key"]
            .as_str()
            .ok_or("Missing eab_hmac_key in ZeroSSL EAB response")?;

        let eab_protected = serde_json::json!({
            "alg": "HS256",
            "kid": eab_kid,
            "url": client.dir.new_account.clone(),
        });
        let eab_protected_b64 = b64url(eab_protected.to_string().as_bytes());
        let eab_payload_b64 = b64url(client.jwk_json.to_string().as_bytes());
        let eab_signing_input = format!("{}.{}", eab_protected_b64, eab_payload_b64);

        let hmac_key_bytes = b64url_decode(eab_hmac_key)
            .map_err(|e| format!("Failed to decode eab_hmac_key: {}", e))?;
        let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &hmac_key_bytes);
        let eab_sig = ring::hmac::sign(&hmac_key, eab_signing_input.as_bytes());
        let eab_sig_b64 = b64url(eab_sig.as_ref());

        serde_json::json!({
            "termsOfServiceAgreed": true,
            "contact": [format!("mailto:admin@{}", config.domains[0])],
            "externalAccountBinding": {
                "protected": eab_protected_b64,
                "payload": eab_payload_b64,
                "signature": eab_sig_b64,
            }
        })
    } else {
        serde_json::json!({ "termsOfServiceAgreed": true })
    };

    let acc_resp = client
        .post_jws(&client.dir.new_account.clone(), &account_payload)
        .await?;
    let account_url = acc_resp
        .headers()
        .get("location")
        .ok_or_else(|| {
            format!(
                "Missing ACME account Location header, status: {}",
                acc_resp.status()
            )
        })?
        .to_str()?
        .to_string();
    client.account_url = Some(account_url.clone());
    info!("[acme] ACME account registered: {}", account_url);

    // 2. Submit New Order
    info!("[acme] [2/5] Submitting certificate order for domains...");
    let identifiers: Vec<_> = config
        .domains
        .iter()
        .map(|d| serde_json::json!({"type": "dns", "value": d}))
        .collect();
    let order_payload = serde_json::json!({ "identifiers": identifiers });
    let order_resp: serde_json::Value = client
        .post_jws(&client.dir.new_order.clone(), &order_payload)
        .await?
        .json()
        .await?;

    let authz_urls = order_resp["authorizations"]
        .as_array()
        .ok_or("No authorizations in order")?;
    let finalize_url = order_resp["finalize"]
        .as_str()
        .ok_or("No finalize URL")?
        .to_string();
    info!(
        "[acme] Order submitted with {} authorization(s)",
        authz_urls.len()
    );

    // 3. Solve DNS-01 Challenges
    info!("[acme] [3/5] Publishing DNS-01 challenges to authoritative nameservers...");
    let mut expected_challenges: Vec<(String, String)> = Vec::new();
    let mut challenge_triggers: Vec<(String, String)> = Vec::new();

    for authz_val in authz_urls {
        let authz_url = authz_val.as_str().unwrap();
        let authz_data: serde_json::Value = client
            .post_jws(authz_url, &serde_json::Value::Null)
            .await?
            .json()
            .await?;
        let domain = authz_data["identifier"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        let authz_status = authz_data["status"].as_str().unwrap_or("pending");

        if authz_status == "valid" {
            info!("[acme] Domain '{}' is already valid (cached authorization)", domain);
            continue;
        }

        let challenges = authz_data["challenges"]
            .as_array()
            .ok_or("No challenges array")?;
        let dns_challenge = challenges
            .iter()
            .find(|c| c["type"] == "dns-01")
            .ok_or("No dns-01 challenge found")?;
        let token = dns_challenge["token"].as_str().unwrap();
        let challenge_url = dns_challenge["url"].as_str().unwrap().to_string();

        let key_auth = format!("{}.{}", token, client.jwk_thumbprint);
        let digest_hash = ring::digest::digest(&ring::digest::SHA256, key_auth.as_bytes());
        let digest_b64 = b64url(digest_hash.as_ref());

        expected_challenges.push((domain.clone(), digest_b64.clone()));
        challenge_triggers.push((domain.clone(), challenge_url));

        if config.desec_domains.contains(&domain) || domain.ends_with(".dedyn.io") {
            if let Some(ref dtoken) = config.desec_token {
                set_desec_txt(&http, dtoken, &domain, &digest_b64).await?;
            } else {
                warn!("[acme] DESEC_TOKEN not configured for domain '{}'", domain);
            }
        } else if config.duckdns_domains.contains(&domain) || domain.ends_with(".duckdns.org") {
            if let Some(ref dtoken) = config.duckdns_token {
                set_duckdns_txt(&http, dtoken, &digest_b64).await?;
            } else {
                warn!(
                    "[acme] DUCKDNS_TOKEN not configured for domain '{}'",
                    domain
                );
            }
        } else if config.dynu_domains.contains(&domain) || is_dynu_domain(&domain) || config.dynu_api_key.is_some() {
            if let Some(ref dkey) = config.dynu_api_key {
                set_dynu_txt(&http, dkey, &domain, &digest_b64).await?;
            } else {
                warn!(
                    "[acme] DYNU_API_KEY not configured for domain '{}'",
                    domain
                );
            }
        }
    }

    if !challenge_triggers.is_empty() {
        // Replication sleep for authoritative anycast nameservers
        info!(
            "[acme] Waiting 35 seconds for DNS TXT records to replicate across authoritative nameservers..."
        );
        tokio::time::sleep(Duration::from_secs(35)).await;

        // Check propagation via DoH
        for (domain, expected_val) in &expected_challenges {
            let mut propagated = false;
            for _attempt in 1..=6 {
                if check_txt_propagation(&http, domain, expected_val).await {
                    info!(
                        "[acme] Confirmed TXT propagation for '{}' (verified via DoH)",
                        domain
                    );
                    propagated = true;
                    break;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            if !propagated {
                info!(
                    "[acme] Direct DoH propagation check pending for '{}'; proceeding after grace period.",
                    domain
                );
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
        info!("[acme] Replication delay complete");

        // 4. Trigger validation and poll
        info!("[acme] [4/5] Triggering {} challenge verification...", ca_name);
        for (domain, challenge_url) in &challenge_triggers {
            info!("[acme] Notifying ACME server for challenge on '{}'...", domain);
            let _ = client
                .post_jws(challenge_url, &serde_json::json!({}))
                .await?;
        }
    }

    // Poll order status until ready or all authorizations valid
    let order_url = finalize_url.replace("/finalize", "");
    let mut order_ready = false;
    for attempt in 1..=60 {
        tokio::time::sleep(Duration::from_secs(5)).await;

        let mut all_valid = true;
        for authz_val in authz_urls {
            let authz_url = authz_val.as_str().unwrap();
            let authz_data: serde_json::Value = client
                .post_jws(authz_url, &serde_json::Value::Null)
                .await?
                .json()
                .await?;
            let domain = authz_data["identifier"]["value"].as_str().unwrap_or("unknown");
            let status = authz_data["status"].as_str().unwrap_or("unknown");
            info!(
                "[acme] Verification status for '{}': {} (attempt {})",
                domain, status, attempt
            );
            if status == "invalid" {
                return Err(format!("Domain '{}' validation failed: {:?}", domain, authz_data).into());
            }
            if status != "valid" {
                all_valid = false;
                // If still pending, re-notify the specific challenge every 4 attempts (every ~20s)
                if attempt % 4 == 0 {
                    if let Some(chals) = authz_data["challenges"].as_array() {
                        if let Some(dns_chal) = chals.iter().find(|c| c["type"] == "dns-01") {
                            if let Some(chal_url) = dns_chal["url"].as_str() {
                                info!("[acme] Re-triggering verification for '{}'...", domain);
                                let _ = client.post_jws(chal_url, &serde_json::json!({})).await;
                            }
                        }
                    }
                }
            }
        }

        let order_check: serde_json::Value = client
            .post_jws(&order_url, &serde_json::Value::Null)
            .await?
            .json()
            .await?;
        let order_status = order_check["status"].as_str().unwrap_or("unknown");
        info!("[acme] Certificate order status: {} (attempt {})", order_status, attempt);

        if order_status == "ready" || all_valid {
            order_ready = true;
            break;
        } else if order_status == "invalid" {
            return Err(format!("ACME order invalid: {:?}", order_check).into());
        }
    }

    if !order_ready {
        return Err("Timeout waiting for ACME order to become ready".into());
    }

    // 5. Generate CSR and Finalize
    info!("[acme] [5/5] Generating ECDSA private key and CSR...");
    let mut params = rcgen::CertificateParams::new(config.domains.clone())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, &config.domains[0]);
    let key_pair_cert = rcgen::KeyPair::generate()?;
    let csr = params.serialize_request(&key_pair_cert)?;
    let csr_der = csr.der();
    let csr_b64 = b64url(csr_der);

    let finalize_payload = serde_json::json!({ "csr": csr_b64 });
    let finalize_resp: serde_json::Value = client
        .post_jws(&finalize_url, &finalize_payload)
        .await?
        .json()
        .await?;

    let mut cert_url = finalize_resp["certificate"].as_str().map(|s| s.to_string());
    if cert_url.is_none() {
        for _ in 0..15 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let order_status: serde_json::Value = client
                .post_jws(&order_url, &serde_json::Value::Null)
                .await?
                .json()
                .await?;
            if let Some(c) = order_status["certificate"].as_str() {
                cert_url = Some(c.to_string());
                break;
            }
        }
    }

    let cert_url = cert_url.ok_or_else(|| format!("No certificate URL issued by {}", ca_name))?;
    info!("[acme] Certificate issued! Downloading certificate chain...");

    let cert_resp = client.post_jws(&cert_url, &serde_json::Value::Null).await?;
    let cert_pem = cert_resp.text().await?;
    let key_pem = key_pair_cert.serialize_pem();

    // Ensure destination directory exists
    if let Some(parent) = Path::new(&config.cert_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Some(parent) = Path::new(&config.key_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    fs::write(&config.cert_path, &cert_pem)?;
    if let Ok(f) = std::fs::File::open(&config.cert_path) {
        let _ = f.sync_all();
    }

    fs::write(&config.key_path, &key_pem)?;
    if let Ok(f) = std::fs::File::open(&config.key_path) {
        let _ = f.sync_all();
    }

    info!(
        "[acme] Certificate chain saved to '{}' ({} bytes)",
        config.cert_path,
        cert_pem.len()
    );
    info!(
        "[acme] Private key saved to '{}' ({} bytes)",
        config.key_path,
        key_pem.len()
    );

    // Also mirror to local fallback paths if saving in /data
    if config.cert_path.starts_with("/data/") {
        let _ = fs::write("cert.pem", &cert_pem);
        let _ = fs::write("key.pem", &key_pem);
    }

    // Immediately update live QUIC / TLS in-memory certificate resolver
    if let Some(ref resolver) = config.cert_resolver {
        if let Err(e) = resolver.update_from_pem(&config.cert_path, &config.key_path) {
            warn!("[acme] Failed to hot-reload live TLS resolver: {}", e);
        } else {
            info!(
                "[acme] Live TLS certificate resolver updated in-memory. Zero restart needed."
            );
        }
    }

    // Clean up TXT challenge records
    for domain in &config.domains {
        if config.desec_domains.contains(domain) || domain.ends_with(".dedyn.io") {
            if let Some(ref dtoken) = config.desec_token {
                let _ = clear_desec_txt(&http, dtoken, domain).await;
            }
        } else if config.duckdns_domains.contains(domain) || domain.ends_with(".duckdns.org") {
            if let Some(ref dtoken) = config.duckdns_token {
                let _ = clear_duckdns_txt(&http, dtoken).await;
            }
        } else if config.dynu_domains.contains(domain) || is_dynu_domain(domain) || config.dynu_api_key.is_some() {
            if let Some(ref dkey) = config.dynu_api_key {
                let _ = clear_dynu_txt(&http, dkey, domain).await;
            }
        }
    }

    info!("============================================================");
    info!("[acme] {} CERTIFICATE PROVISIONED SUCCESSFULLY!", ca_name.to_uppercase());
    info!("============================================================");

    Ok(())
}

async fn check_txt_propagation(http: &reqwest::Client, domain: &str, expected_val: &str) -> bool {
    let check_name = format!("_acme-challenge.{}", domain);

    // Google DoH
    let google_url = format!("https://dns.google/resolve?name={}&type=TXT", check_name);
    if let Ok(resp) = http.get(&google_url).send().await {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            if let Some(answers) = json["Answer"].as_array() {
                for ans in answers {
                    if let Some(data) = ans["data"].as_str() {
                        let clean = data.trim_matches('"');
                        if clean == expected_val {
                            return true;
                        }
                    }
                }
            }
        }
    }

    // Cloudflare DoH
    let cf_url = format!(
        "https://cloudflare-dns.com/dns-query?name={}&type=TXT",
        check_name
    );
    if let Ok(resp) = http
        .get(&cf_url)
        .header("Accept", "application/dns-json")
        .send()
        .await
    {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            if let Some(answers) = json["Answer"].as_array() {
                for ans in answers {
                    if let Some(data) = ans["data"].as_str() {
                        let clean = data.trim_matches('"');
                        if clean == expected_val {
                            return true;
                        }
                    }
                }
            }
        }
    }

    // Quad9 DoH
    let q9_url = format!(
        "https://dns.quad9.net:5053/dns-query?name={}&type=TXT",
        check_name
    );
    if let Ok(resp) = http
        .get(&q9_url)
        .header("Accept", "application/dns-json")
        .send()
        .await
    {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            if let Some(answers) = json["Answer"].as_array() {
                for ans in answers {
                    if let Some(data) = ans["data"].as_str() {
                        let clean = data.trim_matches('"');
                        if clean == expected_val {
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}

async fn try_sync_from_peer(config: &AcmeConfig, master_key: Option<&str>) -> bool {
    let key = match master_key {
        Some(k) if !k.is_empty() => k,
        _ => return false,
    };

    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    let primary_region = std::env::var("PRIMARY_REGION")
        .or_else(|_| std::env::var("FLY_PRIMARY_REGION"))
        .unwrap_or_else(|_| "sin".to_string());

    let peer_urls = [
        format!("http://{}.amardns.internal:443/internal/tls/bundle/{}", primary_region, key),
        format!("http://{}.amardns.internal:443/internal/tls/bundle", primary_region),
        format!("http://amardns.internal:443/internal/tls/bundle/{}", key),
        "http://amardns.internal:443/internal/tls/bundle".to_string(),
        format!("http://_apps.internal:443/internal/tls/bundle/{}", key),
        format!("http://top1.nearest.of.amardns.internal:443/internal/tls/bundle/{}", key),
    ];

    for url in &peer_urls {
        if let Ok(resp) = http
            .get(url)
            .header("x-master-key", key)
            .header("x-auth-key", key)
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if json["ok"].as_bool().unwrap_or(false) {
                        if let (Some(cert_pem), Some(key_pem)) =
                            (json["cert_pem"].as_str(), json["key_pem"].as_str())
                        {
                            if let Some(days) = json["days_remaining"].as_i64() {
                                if days >= 30 {
                                    if let Some(parent) = Path::new(&config.cert_path).parent() {
                                        let _ = fs::create_dir_all(parent);
                                    }
                                    if let Some(parent) = Path::new(&config.key_path).parent() {
                                        let _ = fs::create_dir_all(parent);
                                    }
                                    let _ = fs::write(&config.cert_path, cert_pem);
                                    let _ = fs::write(&config.key_path, key_pem);
                                    if config.cert_path.starts_with("/data/") {
                                        let _ = fs::write("cert.pem", cert_pem);
                                        let _ = fs::write("key.pem", key_pem);
                                    }
                                    if let Some(ref resolver) = config.cert_resolver {
                                        if let Err(e) = resolver.update_from_pem(&config.cert_path, &config.key_path) {
                                            warn!("[acme-peer-sync] Failed to hot-reload live TLS resolver: {}", e);
                                        } else {
                                            info!("[acme-peer-sync] Live TLS certificate resolver updated in-memory after peer sync.");
                                        }
                                    }
                                    info!("[acme-peer-sync] Successfully synced and applied TLS certificate bundle ({} days remaining) from peer ({})", days, url);
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

/// Starts the background ACME Auto-Renewal Supervisor.
pub fn spawn_acme_supervisor(config: AcmeConfig, master_key: Option<String>) {
    tokio::spawn(async move {
        let primary_region = std::env::var("PRIMARY_REGION")
            .or_else(|_| std::env::var("FLY_PRIMARY_REGION"))
            .unwrap_or_else(|_| "sin".to_string());
        let current_region = std::env::var("FLY_REGION").unwrap_or_default();
        let is_leader = current_region.is_empty() || current_region == primary_region;

        info!(
            "[acme-supervisor] Initializing ACME coordinator (Region: '{}', Leader: {}, Primary: '{}')",
            if current_region.is_empty() { "local" } else { &current_region },
            is_leader,
            primary_region
        );

        // Stagger startup slightly
        tokio::time::sleep(Duration::from_secs(3)).await;

        loop {
            let days_opt = validate_existing_cert_and_key(&config.cert_path, &config.key_path, 30);
            let needs_action = match days_opt {
                Some(days) => {
                    info!(
                        "[acme-supervisor] Active TLS certificate and key validated on disk ({} days remaining). Preserving existing certificate without issuing duplicate.",
                        days
                    );
                    // Ensure live in-memory resolver is updated with the validated cert on disk
                    if let Some(ref resolver) = config.cert_resolver {
                        let _ = resolver.update_from_pem(&config.cert_path, &config.key_path);
                    }
                    false
                }
                None => {
                    info!(
                        "[acme-supervisor] No valid TLS certificate/key pair found at '{}' and '{}' (or <30 days remaining)",
                        config.cert_path, config.key_path
                    );
                    true
                }
            };

            if needs_action {
                if is_leader {
                    // LEADER NODE FLOW (e.g. Singapore / primary region)
                    // First, check if peer already has a valid bundle (e.g. after container restart)
                    if try_sync_from_peer(&config, master_key.as_deref()).await {
                        info!("[acme-supervisor] Leader synced valid TLS certificate bundle from peer machine");
                        tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
                        continue;
                    }

                    // Otherwise, execute authoritative ACME DNS-01 certificate provisioning
                    let ca_name = if config.zerossl_api_key.is_some() {
                        "ZeroSSL"
                    } else {
                        "Let's Encrypt"
                    };
                    info!(
                        "[acme-supervisor] Leader node running automated {} DNS-01 provisioning...",
                        ca_name
                    );
                    match provision_acme_certificate(&config).await {
                        Ok(_) => {
                            info!("[acme-supervisor] {} provisioning succeeded. Next check in 24 hours.", ca_name);
                            tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("rateLimited") {
                                warn!(
                                    "[acme-supervisor] Rate limit encountered: {}. Backing off for 6 hours. (Edge TLS & dynamic fallback remain fully operational).",
                                    err_str
                                );
                                tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
                            } else {
                                error!(
                                    "[acme-supervisor] Certificate provisioning error: {}. Will retry in 15 minutes.",
                                    err_str
                                );
                                tokio::time::sleep(Duration::from_secs(900)).await;
                            }
                        }
                    }
                } else {
                    // REPLICA NODE FLOW (e.g. Frankfurt / secondary region)
                    info!(
                        "[acme-replica] Replica node in region '{}'. Waiting for leader in region '{}' to provision TLS certificate...",
                        current_region, primary_region
                    );

                    let mut synced = false;
                    // Poll leader every 10 seconds for up to 10 minutes (60 attempts)
                    for attempt in 1..=60 {
                        if try_sync_from_peer(&config, master_key.as_deref()).await {
                            info!(
                                "[acme-replica] Successfully synced TLS certificate bundle from leader on attempt {}",
                                attempt
                            );
                            synced = true;
                            break;
                        }
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }

                    if synced {
                        tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
                    } else {
                        warn!(
                            "[acme-replica] Leader sync timed out after 10 minutes. Attempting standalone ACME DNS-01 provisioning as fail-safe..."
                        );
                        match provision_acme_certificate(&config).await {
                            Ok(_) => {
                                info!("[acme-replica] Fail-safe ACME provisioning succeeded. Next check in 24 hours.");
                                tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
                            }
                            Err(e) => {
                                error!(
                                    "[acme-replica] Fail-safe ACME provisioning error: {}. Will retry peer sync in 5 minutes.",
                                    e
                                );
                                tokio::time::sleep(Duration::from_secs(300)).await;
                            }
                        }
                    }
                }
            } else {
                // Certificate is healthy (>= 30 days remaining)
                tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_b64url_encoding() {
        assert_eq!(b64url(b"hello world"), "aGVsbG8gd29ybGQ");
        assert_eq!(b64url(b"\x00\x01\x02"), "AAEC");
    }

    #[test]
    fn test_b64url_roundtrip() {
        let original = b"testing base64url roundtrip with arbitrary bytes \x00\xff\x12\x34";
        let encoded = b64url(original);
        let decoded = b64url_decode(&encoded).expect("decode failed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_der_time_parsing() {
        let utc_time = b"260912120000Z";
        let dt = parse_der_time(utc_time).expect("Failed to parse UTCTime");
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2026-09-12");

        let gen_time = b"20260912120000Z";
        let dt2 = parse_der_time(gen_time).expect("Failed to parse GeneralizedTime");
        assert_eq!(dt2.format("%Y-%m-%d").to_string(), "2026-09-12");
    }

    #[test]
    fn test_extract_cert_expiry_from_existing_cert() {
        if Path::new("cert.pem").exists() {
            let days = get_cert_days_remaining("cert.pem");
            assert!(days.is_some());
            let days_val = days.unwrap();
            println!("Local cert.pem days remaining: {}", days_val);
            assert!(days_val > 0);
        }
    }

    #[test]
    fn test_validate_existing_cert_and_key_nonexistent() {
        let res = validate_existing_cert_and_key("/nonexistent/cert.pem", "/nonexistent/key.pem", 30);
        assert!(res.is_none());
    }

    #[test]
    fn test_is_dynu_domain() {
        assert!(is_dynu_domain("amardns.dynu.net"));
        assert!(is_dynu_domain("sub.test.freeddns.org"));
        assert!(is_dynu_domain("myhost.ddnsfree.com"));
        assert!(!is_dynu_domain("amardns.dedyn.io"));
        assert!(!is_dynu_domain("amardns.duckdns.org"));
    }

    #[test]
    fn test_compute_dynu_node_name() {
        assert_eq!(compute_dynu_node_name("amardns.dynu.net", "amardns.dynu.net"), "_acme-challenge");
        assert_eq!(compute_dynu_node_name("sub.amardns.dynu.net", "amardns.dynu.net"), "_acme-challenge.sub");
    }
}
