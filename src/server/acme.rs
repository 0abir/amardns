// src/server/acme.rs
// Automated ACME DNS-01 provisioning and auto-renewal engine for AmarDNS.
// Supports ZeroSSL (with EAB credentials & ApiKey auth) and Let's Encrypt fallback.
// Manages genuine TLS certificates for DNS-over-TLS (DoT) and DoH.

use chrono::{DateTime, Utc};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

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
    public_x: String,
    public_y: String,
    account_url: Option<String>,
    next_nonce: Mutex<Option<String>>,
}

impl AcmeClient {
    pub fn public_jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "crv": "P-256",
            "kty": "EC",
            "x": &self.public_x,
            "y": &self.public_y,
        })
    }

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
            if let Ok(kp) = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &bytes, &rng)
            {
                kp
            } else {
                let pkcs8_bytes =
                    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                        .map_err(|e| format!("generate_pkcs8 error: {:?}", e))?;
                let _ = fs::write(account_key_path, pkcs8_bytes.as_ref());
                EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    pkcs8_bytes.as_ref(),
                    &rng,
                )
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

        // RFC 7638 canonical JWK ordering: crv, kty, x, y
        let jwk_canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#, x, y);
        let thumb_hash = ring::digest::digest(&ring::digest::SHA256, jwk_canonical.as_bytes());
        let jwk_thumbprint = b64url(thumb_hash.as_ref());

        Ok(Self {
            http,
            dir,
            key_pair: Arc::new(key_pair),
            jwk_thumbprint,
            public_x: x,
            public_y: y,
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
        for attempt in 0..5 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(1000 * attempt)).await;
            }
            for endpoint in &[&self.dir.new_nonce, &self.dir.new_account, &self.dir.new_order] {
                if let Ok(resp) = self.http.head(*endpoint).send().await {
                    if let Some(nonce) = resp
                        .headers()
                        .get("replay-nonce")
                        .and_then(|h| h.to_str().ok())
                    {
                        return Ok(nonce.to_string());
                    }
                }
                if let Ok(resp) = self.http.get(*endpoint).send().await {
                    if let Some(nonce) = resp
                        .headers()
                        .get("replay-nonce")
                        .and_then(|h| h.to_str().ok())
                    {
                        return Ok(nonce.to_string());
                    }
                }
            }
        }
        Err("No replay-nonce header available from ACME server".into())
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
        let parsed_url: reqwest::Url = url
            .parse()
            .map_err(|e| format!("Invalid ACME URL '{}': {}", url, e))?;
        if parsed_url.scheme() != "https" {
            return Err(format!("Insecure ACME URL '{}': HTTPS is strictly required by RFC 8555", url).into());
        }
        let host_port = match (parsed_url.host_str(), parsed_url.port()) {
            (Some(h), Some(p)) if p != 443 => format!("{}:{}", h, p),
            (Some(h), _) => h.to_string(),
            _ => return Err("Invalid host in ACME URL".into()),
        };
        let path_and_query = match parsed_url.query() {
            Some(q) => format!("{}?{}", parsed_url.path(), q),
            None => parsed_url.path().to_string(),
        };
        let https_url = format!("https://{}{}", host_port, path_and_query);

        let nonce = self.get_nonce().await?;

        let mut protected = serde_json::json!({
            "alg": "ES256",
            "nonce": nonce,
            "url": &https_url,
        });

        if let Some(ref kid) = self.account_url {
            protected["kid"] = serde_json::Value::String(kid.to_string());
        } else {
            protected["jwk"] = self.public_jwk();
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
            .post(&https_url)
            .headers(headers)
            .body(body.to_string())
            .send()
            .await?;

        // Cache new nonce if returned in response headers
        if let Some(new_nonce) = resp
            .headers()
            .get("replay-nonce")
            .and_then(|h| h.to_str().ok())
        {
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
                    return Box::pin(self.post_jws_internal(&https_url, payload_json, true)).await;
                }

                return Err(
                    format!("ACME API error ({} - {}): {}", status, err_type, detail).into(),
                );
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
    domain: &str,
    txt_val: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sub = domain.trim_end_matches(".duckdns.org");
    info!("[acme/duckdns] Publishing TXT record for {}...", domain);
    let url = format!(
        "https://www.duckdns.org/update?domains={}&token={}&txt={}",
        sub, token, txt_val
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
    domain: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sub = domain.trim_end_matches(".duckdns.org");
    let url = format!(
        "https://www.duckdns.org/update?domains={}&token={}&txt=",
        sub, token
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
            let records = rec_json["dnsRecords"]
                .as_array()
                .or_else(|| rec_json.as_array());
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
        info!(
            "[acme/dynu] TXT record published successfully for {}",
            domain
        );
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
                    let records = rec_json["dnsRecords"]
                        .as_array()
                        .or_else(|| rec_json.as_array());
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
                                    let _ = http
                                        .delete(&del_url)
                                        .header("API-Key", api_key)
                                        .send()
                                        .await;
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

/// Extracts all dNSName Subject Alternative Names (SANs) from a DER-encoded X.509 certificate.
pub fn extract_cert_sans_der(der_bytes: &[u8]) -> Vec<String> {
    let mut sans = Vec::new();
    // SubjectAltName extension OID: 2.5.29.17 -> 0x55, 0x1D, 0x11 (DER: 0x06, 0x03, 0x55, 0x1D, 0x11)
    let san_oid = [0x06, 0x03, 0x55, 0x1D, 0x11];

    if let Some(pos) = der_bytes.windows(san_oid.len()).position(|w| w == san_oid) {
        let mut i = pos + san_oid.len();
        // Look for OCTET STRING (tag 0x04) containing the GeneralNames sequence
        while i + 2 < der_bytes.len() && i < pos + 60 {
            if der_bytes[i] == 0x04 {
                let mut octet_len = der_bytes[i + 1] as usize;
                let mut start = i + 2;
                if octet_len & 0x80 != 0 {
                    let num_bytes = octet_len & 0x7F;
                    if i + 2 + num_bytes <= der_bytes.len() {
                        octet_len = 0;
                        for b in &der_bytes[i + 2..i + 2 + num_bytes] {
                            octet_len = (octet_len << 8) | (*b as usize);
                        }
                        start = i + 2 + num_bytes;
                    }
                }
                let end = (start + octet_len).min(der_bytes.len());
                let mut san_slice = &der_bytes[start..end];

                // Unwrap outer SEQUENCE (tag 0x30) if present
                if !san_slice.is_empty() && san_slice[0] == 0x30 && san_slice.len() > 2 {
                    let mut seq_len = san_slice[1] as usize;
                    let mut seq_start = 2;
                    if seq_len & 0x80 != 0 {
                        let num_bytes = seq_len & 0x7F;
                        if 2 + num_bytes <= san_slice.len() {
                            seq_len = 0;
                            for b in &san_slice[2..2 + num_bytes] {
                                seq_len = (seq_len << 8) | (*b as usize);
                            }
                            seq_start = 2 + num_bytes;
                        }
                    }
                    let seq_end = (seq_start + seq_len).min(san_slice.len());
                    san_slice = &san_slice[seq_start..seq_end];
                }

                let mut p = 0;
                while p + 1 < san_slice.len() {
                    let tag = san_slice[p];
                    let mut len = san_slice[p + 1] as usize;
                    let mut val_start = p + 2;
                    if len & 0x80 != 0 {
                        let num_bytes = len & 0x7F;
                        if p + 2 + num_bytes <= san_slice.len() {
                            len = 0;
                            for b in &san_slice[p + 2..p + 2 + num_bytes] {
                                len = (len << 8) | (*b as usize);
                            }
                            val_start = p + 2 + num_bytes;
                        }
                    }
                    if tag == 0x82 && val_start + len <= san_slice.len() {
                        if let Ok(name) =
                            std::str::from_utf8(&san_slice[val_start..val_start + len])
                        {
                            let n = name.trim().to_ascii_lowercase();
                            if !sans.contains(&n) {
                                sans.push(n);
                            }
                        }
                    }
                    p = val_start + len;
                }
                break;
            }
            i += 1;
        }
    }
    sans
}

/// Extracts all domain names (SANs) from a PEM certificate file.
pub fn extract_cert_domains(cert_path: &str) -> Vec<String> {
    let cert_data = match fs::read_to_string(cert_path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let mut reader = std::io::BufReader::new(cert_data.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default();
    let first_cert = match certs.first() {
        Some(c) => c,
        None => return Vec::new(),
    };
    extract_cert_sans_der(first_cert.as_ref())
}

/// Validates an individual certificate and private key file pair.
pub fn validate_cert_key_pair(
    cert_path: &str,
    key_path: &str,
    expected_domains: &[String],
    min_days_remaining: i64,
) -> Option<i64> {
    let days = get_cert_days_remaining(cert_path)?;
    if days < min_days_remaining {
        return None;
    }

    if !expected_domains.is_empty() {
        let cert_domains = extract_cert_domains(cert_path);
        for d in expected_domains {
            let dl = d.trim().to_ascii_lowercase();
            if !cert_domains.iter().any(|cd| cd == &dl) {
                return None;
            }
        }
    }

    // Verify key exists and is a valid supported private key
    let key_data = fs::read_to_string(key_path).ok()?;
    let mut key_reader = std::io::BufReader::new(key_data.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader).ok()??;
    let _signing_key = tokio_rustls::rustls::crypto::ring::sign::any_supported_type(&key).ok()?;

    Some(days)
}

/// Validates an existing certificate and private key pair on disk.
/// Checks that the files exist, parse cleanly into valid DER, have valid signing keys,
/// have at least `min_days_remaining` days remaining before expiration,
/// and that ALL `expected_domains` are covered by the certificate's SANs.
/// Checks specified paths and fallback candidate paths on disk.
pub fn validate_existing_cert_and_key(
    cert_path: &str,
    key_path: &str,
    expected_domains: &[String],
    min_days_remaining: i64,
) -> Option<i64> {
    // 1. Check primary specified paths
    if let Some(days) = validate_cert_key_pair(cert_path, key_path, expected_domains, min_days_remaining) {
        return Some(days);
    }

    // 2. Check candidate fallback locations on disk
    let candidates = [
        ("/data/cert.pem", "/data/key.pem"),
        ("cert.pem", "key.pem"),
    ];
    for (c_path, k_path) in &candidates {
        if *c_path == cert_path && *k_path == key_path {
            continue;
        }
        if let Some(days) = validate_cert_key_pair(c_path, k_path, expected_domains, min_days_remaining) {
            if let (Ok(cert_content), Ok(key_content)) = (fs::read_to_string(c_path), fs::read_to_string(k_path)) {
                if let Some(parent) = Path::new(cert_path).parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if let Some(parent) = Path::new(key_path).parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let _ = fs::write(cert_path, &cert_content);
                let _ = fs::write(key_path, &key_content);
                info!(
                    "[acme-supervisor] Restored valid certificate and key from candidate '{}' -> '{}' ({} days remaining)",
                    c_path, cert_path, days
                );
                return Some(days);
            }
        }
    }

    None
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

/// Executes full ACME DNS-01 certificate provisioning against ZeroSSL or Let's Encrypt with automated fallback.
pub async fn provision_acme_certificate(
    config: &AcmeConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if config.domains.is_empty() {
        return Err("No domains specified for ACME certificate provisioning".into());
    }

    if config.zerossl_api_key.is_some() {
        match provision_acme_certificate_ca(config, true).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                warn!(
                    "[acme] ZeroSSL DNS-01 provisioning encountered error: {}. Falling back to Let's Encrypt DNS-01...",
                    e
                );
            }
        }
    }

    provision_acme_certificate_ca(config, false).await
}

async fn provision_acme_certificate_ca(
    config: &AcmeConfig,
    use_zerossl: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let is_zerossl = use_zerossl && config.zerossl_api_key.is_some();
    let ca_name = if is_zerossl {
        "ZeroSSL"
    } else {
        "Let's Encrypt"
    };
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
        .timeout(Duration::from_secs(60))
        .build()?;
    let mut client = AcmeClient::new(http.clone(), dir_url).await?;

    // 1. Create / Register Account
    info!("[acme] [1/5] Registering ACME account with {}...", ca_name);
    let account_payload = if is_zerossl {
        if let Some(ref api_key) = config.zerossl_api_key {
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
            let eab_payload_b64 = b64url(client.public_jwk().to_string().as_bytes());
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
            serde_json::json!({
                "termsOfServiceAgreed": true,
                "contact": [format!("mailto:admin@{}", config.domains[0])],
            })
        }
    } else {
        serde_json::json!({
            "termsOfServiceAgreed": true,
            "contact": [format!("mailto:admin@{}", config.domains[0])],
        })
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
            info!(
                "[acme] Domain '{}' is already valid (cached authorization)",
                domain
            );
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
                set_duckdns_txt(&http, dtoken, &domain, &digest_b64).await?;
            } else {
                warn!(
                    "[acme] DUCKDNS_TOKEN not configured for domain '{}'",
                    domain
                );
            }
        } else if config.dynu_domains.contains(&domain)
            || is_dynu_domain(&domain)
            || config.dynu_api_key.is_some()
        {
            if let Some(ref dkey) = config.dynu_api_key {
                set_dynu_txt(&http, dkey, &domain, &digest_b64).await?;
            } else {
                warn!("[acme] DYNU_API_KEY not configured for domain '{}'", domain);
            }
        }
    }

    if !challenge_triggers.is_empty() {
        // Replication sleep for authoritative anycast nameservers
        info!(
            "[acme] Waiting 40 seconds for DNS TXT records to replicate across authoritative nameservers..."
        );
        tokio::time::sleep(Duration::from_secs(40)).await;

        // Check propagation via DoH (spaced checks, max 6 attempts)
        for (domain, expected_val) in &expected_challenges {
            let mut propagated = false;
            for attempt in 1..=6 {
                if check_txt_propagation(&http, domain, expected_val).await {
                    info!(
                        "[acme] Confirmed TXT propagation for '{}' (verified via DoH on attempt {})",
                        domain, attempt
                    );
                    propagated = true;
                    break;
                }
                tokio::time::sleep(Duration::from_secs(8)).await;
            }
            if !propagated {
                warn!(
                    "[acme] Direct DoH propagation check pending for '{}'; proceeding with CA challenge.",
                    domain
                );
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
        info!("[acme] Replication delay complete");

        // 4. Trigger validation and poll
        info!(
            "[acme] [4/5] Triggering {} challenge verification...",
            ca_name
        );
        for (domain, challenge_url) in &challenge_triggers {
            info!(
                "[acme] Notifying ACME server for challenge on '{}'...",
                domain
            );
            let _ = client
                .post_jws(challenge_url, &serde_json::json!({}))
                .await?;
        }
    }

    // Poll order status until ready or all authorizations valid (non-hammering with progressive backoff)
    let order_url = finalize_url.replace("/finalize", "");
    let mut order_ready = false;
    let mut verified_authz: std::collections::HashSet<String> = std::collections::HashSet::new();
    let max_attempts = if is_zerossl { 10 } else { 12 };

    for attempt in 1..=max_attempts {
        let sleep_secs = if attempt <= 2 { 10 } else { 15 };
        tokio::time::sleep(Duration::from_secs(sleep_secs)).await;

        // 1. Check overall order status first
        let mut order_status_str = None;
        if let Ok(order_resp) = client.post_jws(&order_url, &serde_json::Value::Null).await {
            if let Ok(order_check) = order_resp.json::<serde_json::Value>().await {
                let status = order_check["status"].as_str().unwrap_or("unknown").to_string();
                info!(
                    "[acme] Certificate order status: {} (attempt {}/{})",
                    status, attempt, max_attempts
                );
                if status == "ready" {
                    order_ready = true;
                    break;
                } else if status == "invalid" {
                    return Err(format!("ACME order invalid: {:?}", order_check).into());
                }
                order_status_str = Some(status);
            }
        }

        // 2. Only poll pending authorizations that have not yet verified
        let mut all_valid = true;
        for authz_val in authz_urls {
            let authz_url = match authz_val.as_str() {
                Some(u) => u,
                None => continue,
            };
            if verified_authz.contains(authz_url) {
                continue;
            }

            let authz_resp = match client.post_jws(authz_url, &serde_json::Value::Null).await {
                Ok(r) => r,
                Err(e) => {
                    warn!(
                        "[acme] Transient network error polling authz: {}. Continuing next tick...",
                        e
                    );
                    all_valid = false;
                    continue;
                }
            };
            let authz_data: serde_json::Value = match authz_resp.json().await {
                Ok(j) => j,
                Err(e) => {
                    warn!(
                        "[acme] Error decoding authz response: {}. Continuing next tick...",
                        e
                    );
                    all_valid = false;
                    continue;
                }
            };
            let domain = authz_data["identifier"]["value"]
                .as_str()
                .unwrap_or("unknown");
            let status = authz_data["status"].as_str().unwrap_or("unknown");
            info!(
                "[acme] Verification status for '{}': {} (attempt {}/{})",
                domain, status, attempt, max_attempts
            );
            if status == "invalid" {
                return Err(
                    format!("Domain '{}' validation failed: {:?}", domain, authz_data).into(),
                );
            }
            if status == "valid" {
                verified_authz.insert(authz_url.to_string());
            } else {
                all_valid = false;
                // Only re-notify challenge on attempt 3 to avoid hammering
                if attempt == 3 {
                    if let Some(chals) = authz_data["challenges"].as_array() {
                        if let Some(dns_chal) = chals.iter().find(|c| c["type"] == "dns-01") {
                            if let Some(chal_url) = dns_chal["url"].as_str() {
                                info!("[acme] Re-notifying ACME challenge for '{}'...", domain);
                                let _ = client.post_jws(chal_url, &serde_json::json!({})).await;
                            }
                        }
                    }
                }
            }
        }

        if (all_valid && verified_authz.len() == authz_urls.len()) || order_status_str.as_deref() == Some("ready") {
            order_ready = true;
            break;
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
            info!("[acme] Live TLS certificate resolver updated in-memory. Zero restart needed.");
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
                let _ = clear_duckdns_txt(&http, dtoken, domain).await;
            }
        } else if config.dynu_domains.contains(domain)
            || is_dynu_domain(domain)
            || config.dynu_api_key.is_some()
        {
            if let Some(ref dkey) = config.dynu_api_key {
                let _ = clear_dynu_txt(&http, dkey, domain).await;
            }
        }
    }

    // Automatically import newly provisioned multi-domain certificate into Fly Edge if token present
    try_import_to_fly_edge(&http, &config.domains, &cert_pem, &key_pem).await;

    info!("============================================================");
    info!(
        "[acme] {} CERTIFICATE PROVISIONED SUCCESSFULLY!",
        ca_name.to_uppercase()
    );
    info!("============================================================");

    Ok(())
}

async fn auto_sync_desec_ownership(
    http: &reqwest::Client,
    desec_token: &str,
    domain: &str,
    target: &str,
) {
    if desec_token.is_empty() || domain.is_empty() || target.is_empty() {
        return;
    }
    let target_clean = target.trim().trim_end_matches('.');
    // Extract app ID token from target (e.g., myapp.dedyn.io.d62jozd.flydns.net -> d62jozd)
    let parts: Vec<&str> = target_clean.split('.').collect();
    let app_id_token = if parts.len() >= 3 && parts[parts.len() - 2] == "flydns" {
        parts[parts.len() - 3]
    } else {
        ""
    };

    // 1. Update _acme-challenge CNAME on deSEC
    let cname_url = format!(
        "https://desec.io/api/v1/domains/{}/rrsets/_acme-challenge/CNAME/",
        domain
    );
    let cname_payload = serde_json::json!({
        "subname": "_acme-challenge",
        "type": "CNAME",
        "records": [format!("{}.", target_clean)],
        "ttl": 900
    });
    let _ = http
        .put(&cname_url)
        .header("Authorization", format!("Token {}", desec_token))
        .header("Content-Type", "application/json")
        .json(&cname_payload)
        .send()
        .await;

    // 2. Update _fly-ownership TXT on deSEC if token extracted
    if !app_id_token.is_empty() {
        let txt_url = format!(
            "https://desec.io/api/v1/domains/{}/rrsets/_fly-ownership/TXT/",
            domain
        );
        let txt_payload = serde_json::json!({
            "subname": "_fly-ownership",
            "type": "TXT",
            "records": [format!("\"app-{}\"", app_id_token)],
            "ttl": 900
        });
        let _ = http
            .put(&txt_url)
            .header("Authorization", format!("Token {}", desec_token))
            .header("Content-Type", "application/json")
            .json(&txt_payload)
            .send()
            .await;
        debug!(
            "[acme/fly-edge] Synchronized deSEC verification records (_fly-ownership: app-{}, _acme-challenge: {})",
            app_id_token, target_clean
        );
    }
}

pub async fn try_import_to_fly_edge(
    http: &reqwest::Client,
    domains: &[String],
    cert_pem: &str,
    key_pem: &str,
) {
    let fly_token = std::env::var("FLY_API_TOKEN")
        .or_else(|_| std::env::var("FLY_AUTH_TOKEN"))
        .ok();
    let token = match fly_token {
        Some(t) if !t.is_empty() => t,
        _ => return,
    };
    let app_name = std::env::var("FLY_APP_NAME").unwrap_or_else(|_| "amardns".to_string());
    let desec_token = std::env::var("DESEC_TOKEN")
        .or_else(|_| std::env::var("DEDYN_TOKEN"))
        .unwrap_or_default();

    for domain in domains {
        // 1. Add certificate registration on Fly edge
        let add_query = serde_json::json!({
            "query": "mutation($appId: ID!, $hostname: String!) { addCertificate(appId: $appId, hostname: $hostname) { certificate { id hostname clientStatus dnsValidationHostname dnsValidationTarget } } }",
            "variables": {
                "appId": app_name,
                "hostname": domain
            }
        });

        let mut validation_target = String::new();

        if let Ok(resp) = http
            .post("https://api.fly.io/graphql")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(15))
            .json(&add_query)
            .send()
            .await
        {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(cert) = json
                    .get("data")
                    .and_then(|d| d.get("addCertificate"))
                    .and_then(|c| c.get("certificate"))
                {
                    info!(
                        "[acme/fly-edge] Successfully registered custom domain '{}' on Fly edge",
                        domain
                    );
                    if let Some(target) = cert.get("dnsValidationTarget").and_then(|t| t.as_str()) {
                        validation_target = target.to_string();
                    }
                } else if let Some(errors) = json.get("errors").and_then(|e| e.as_array()) {
                    let msg = errors
                        .first()
                        .and_then(|e| e.get("message"))
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown");
                    if msg.contains("already exists") {
                        debug!("[acme/fly-edge] Domain '{}' already active on Fly edge", domain);
                    } else {
                        warn!(
                            "[acme/fly-edge] Fly edge registration note for '{}': {}",
                            domain, msg
                        );
                    }
                }
            }
        }

        // 2. Query certificate details if target wasn't in add response
        if validation_target.is_empty() {
            let check_query = serde_json::json!({
                "query": "query($appId: String!, $hostname: String!) { app(name: $appId) { certificate(hostname: $hostname) { clientStatus dnsValidationTarget } } }",
                "variables": {
                    "appId": app_name,
                    "hostname": domain
                }
            });
            if let Ok(resp) = http
                .post("https://api.fly.io/graphql")
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .timeout(Duration::from_secs(15))
                .json(&check_query)
                .send()
                .await
            {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(target) = json
                        .get("data")
                        .and_then(|d| d.get("app"))
                        .and_then(|a| a.get("certificate"))
                        .and_then(|c| c.get("dnsValidationTarget"))
                        .and_then(|t| t.as_str())
                    {
                        validation_target = target.to_string();
                    }
                }
            }
        }

        // 3. Auto-sync deSEC records if domain belongs to deSEC
        if domain.contains("dedyn.io") || domain.contains("desec") {
            if !validation_target.is_empty() && !desec_token.is_empty() {
                auto_sync_desec_ownership(http, &desec_token, domain, &validation_target).await;
            }
        }

        // 4. Upload custom certificate directly to Fly edge proxy
        if !cert_pem.is_empty() && !key_pem.is_empty() {
            let custom_cert_payload = serde_json::json!({
                "hostname": domain,
                "fullchain": cert_pem,
                "private_key": key_pem,
            });
            let custom_url = format!("https://api.machines.dev/v1/apps/{}/certificates/custom", app_name);
            match http
                .post(&custom_url)
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .timeout(Duration::from_secs(15))
                .json(&custom_cert_payload)
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        info!(
                            "[acme/fly-edge] Successfully imported custom TLS certificate for '{}' to Fly edge proxy ({})",
                            domain, status
                        );
                    } else {
                        let body = resp.text().await.unwrap_or_default();
                        warn!(
                            "[acme/fly-edge] Fly edge custom certificate import for '{}' returned {}: {}",
                            domain, status, body
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "[acme/fly-edge] Network error importing custom TLS certificate for '{}' to Fly edge: {}",
                        domain, e
                    );
                }
            }
        }

        // 5. Trigger validation check on Fly edge
        let trigger_check = serde_json::json!({
            "query": "mutation($appId: ID!, $hostname: String!) { checkCertificate(appId: $appId, hostname: $hostname) { certificate { clientStatus } } }",
            "variables": {
                "appId": app_name,
                "hostname": domain
            }
        });
        let _ = http
            .post("https://api.fly.io/graphql")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(15))
            .json(&trigger_check)
            .send()
            .await;
    }
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

pub async fn try_sync_from_peer(config: &AcmeConfig, master_key: Option<&str>) -> bool {
    let key = match master_key {
        Some(k) if !k.is_empty() => k,
        _ => return false,
    };

    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    let app_name = std::env::var("FLY_APP_NAME").unwrap_or_else(|_| "amardns".to_string());
    let primary_region = std::env::var("PRIMARY_REGION")
        .or_else(|_| std::env::var("FLY_PRIMARY_REGION"))
        .unwrap_or_else(|_| "sin".to_string());

    let mut peer_urls = vec![
        format!(
            "http://{}.{}.internal:443/internal/tls/bundle/{}",
            primary_region, app_name, key
        ),
        format!(
            "http://{}.internal:443/internal/tls/bundle/{}",
            app_name, key
        ),
        format!(
            "http://{}.{}.internal:443/internal/tls/bundle",
            primary_region, app_name
        ),
        format!("http://{}.internal:443/internal/tls/bundle/{}", app_name, key),
        format!("http://{}.internal:443/internal/tls/bundle", app_name),
        format!("http://_apps.internal:443/internal/tls/bundle/{}", key),
        format!(
            "http://top1.nearest.of.{}.internal:443/internal/tls/bundle/{}",
            app_name, key
        ),
        format!(
            "http://top1.nearest.of.{}.internal:443/internal/tls/bundle",
            app_name
        ),
    ];

    // Direct IPv6 resolution across all Fly mesh instances in cluster
    for lookup in &[
        format!("{}.{}.internal:443", primary_region, app_name),
        format!("{}.internal:443", app_name),
        format!("global.{}.internal:443", app_name),
    ] {
        if let Ok(addrs) = tokio::net::lookup_host(lookup).await {
            for addr in addrs {
                peer_urls.push(format!(
                    "http://[{}]:443/internal/tls/bundle/{}",
                    addr.ip(),
                    key
                ));
                peer_urls.push(format!(
                    "http://[{}]:443/internal/tls/bundle",
                    addr.ip()
                ));
            }
        }
    }

    // Deduplicate peer URLs
    let mut seen = std::collections::HashSet::new();
    peer_urls.retain(|u| seen.insert(u.clone()));

    for url in &peer_urls {
        if let Ok(resp) = http
            .get(url)
            .header("x-master-key", key)
            .header("x-auth-key", key)
            .header("Authorization", format!("Bearer {}", key))
            .header("x-peer-sync", "1")
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
                                        if let Err(e) = resolver
                                            .update_from_pem(&config.cert_path, &config.key_path)
                                        {
                                            warn!(
                                                "[acme-peer-sync] Failed to hot-reload live TLS resolver: {}",
                                                e
                                            );
                                        } else {
                                            info!(
                                                "[acme-peer-sync] Live TLS certificate resolver updated in-memory after peer sync."
                                            );
                                        }
                                    }
                                    info!(
                                        "[acme-peer-sync] Successfully synced and applied TLS certificate bundle ({} days remaining) from peer ({})",
                                        days, url
                                    );
                                    try_import_to_fly_edge(&http, &config.domains, cert_pem, key_pem).await;
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

async fn try_acquire_cluster_lock(
    http: &reqwest::Client,
    app_state: Option<&Arc<crate::state::AppState>>,
    machine_id: &str,
    master_key: Option<&str>,
) -> bool {
    let key = master_key.unwrap_or_default();
    let app_name = std::env::var("FLY_APP_NAME").unwrap_or_else(|_| "amardns".to_string());
    let primary_region = std::env::var("PRIMARY_REGION")
        .or_else(|_| std::env::var("FLY_PRIMARY_REGION"))
        .unwrap_or_else(|_| "sin".to_string());

    // 1. Check local AppState lock
    if let Some(state) = app_state {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut lock = state.acme_lock.lock();
        if let Some((ref holder, expiry)) = *lock {
            if expiry > now && holder != machine_id && holder < &machine_id.to_string() {
                return false;
            }
        }
        *lock = Some((machine_id.to_string(), now + 600));
    }

    // 2. Query peer nodes across Fly 6PN to acquire lock
    let mut lock_urls = vec![
        format!(
            "https://{}.{}.internal:443/internal/acme/lock/{}",
            primary_region, app_name, key
        ),
        format!(
            "https://{}.internal:443/internal/acme/lock/{}",
            app_name, key
        ),
        format!(
            "http://{}.{}.internal:443/internal/acme/lock/{}",
            primary_region, app_name, key
        ),
        format!("http://{}.internal:443/internal/acme/lock/{}", app_name, key),
        format!(
            "http://top1.nearest.of.{}.internal:443/internal/acme/lock/{}",
            app_name, key
        ),
    ];

    for lookup in &[
        format!("{}.{}.internal:443", primary_region, app_name),
        format!("{}.internal:443", app_name),
    ] {
        if let Ok(addrs) = tokio::net::lookup_host(lookup).await {
            for addr in addrs {
                lock_urls.push(format!(
                    "http://[{}]:443/internal/acme/lock/{}",
                    addr.ip(),
                    key
                ));
            }
        }
    }

    let mut seen = std::collections::HashSet::new();
    lock_urls.retain(|u| seen.insert(u.clone()));

    let mut acquired = true;
    for url in &lock_urls {
        let body = serde_json::json!({
            "machine_id": machine_id,
            "ttl_secs": 600
        });
        if let Ok(resp) = http
            .post(url)
            .header("x-master-key", key)
            .header("x-auth-key", key)
            .header("Authorization", format!("Bearer {}", key))
            .header("x-peer-sync", "1")
            .json(&body)
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if json["granted"].as_bool() == Some(false) {
                        acquired = false;
                        break;
                    }
                }
            }
        }
    }

    if !acquired {
        if let Some(state) = app_state {
            let mut lock = state.acme_lock.lock();
            if let Some((ref holder, _)) = *lock {
                if holder == machine_id {
                    *lock = None;
                }
            }
        }
        return false;
    }

    true
}

async fn try_release_cluster_lock(
    http: &reqwest::Client,
    app_state: Option<&Arc<crate::state::AppState>>,
    machine_id: &str,
    master_key: Option<&str>,
) {
    let key = master_key.unwrap_or_default();
    let app_name = std::env::var("FLY_APP_NAME").unwrap_or_else(|_| "amardns".to_string());
    let primary_region = std::env::var("PRIMARY_REGION")
        .or_else(|_| std::env::var("FLY_PRIMARY_REGION"))
        .unwrap_or_else(|_| "sin".to_string());

    if let Some(state) = app_state {
        let mut lock = state.acme_lock.lock();
        if let Some((ref holder, _)) = *lock {
            if holder == machine_id {
                *lock = None;
            }
        }
    }

    let mut unlock_urls = vec![
        format!(
            "https://{}.{}.internal:443/internal/acme/unlock/{}",
            primary_region, app_name, key
        ),
        format!(
            "https://{}.internal:443/internal/acme/unlock/{}",
            app_name, key
        ),
        format!(
            "http://{}.{}.internal:443/internal/acme/unlock/{}",
            primary_region, app_name, key
        ),
        format!(
            "http://{}.internal:443/internal/acme/unlock/{}",
            app_name, key
        ),
    ];

    for lookup in &[
        format!("{}.{}.internal:443", primary_region, app_name),
        format!("{}.internal:443", app_name),
    ] {
        if let Ok(addrs) = tokio::net::lookup_host(lookup).await {
            for addr in addrs {
                unlock_urls.push(format!(
                    "http://[{}]:443/internal/acme/unlock/{}",
                    addr.ip(),
                    key
                ));
            }
        }
    }

    let mut seen = std::collections::HashSet::new();
    unlock_urls.retain(|u| seen.insert(u.clone()));

    for url in &unlock_urls {
        let body = serde_json::json!({ "machine_id": machine_id });
        let _ = http
            .post(url)
            .header("x-master-key", key)
            .header("x-auth-key", key)
            .header("Authorization", format!("Bearer {}", key))
            .header("x-peer-sync", "1")
            .json(&body)
            .send()
            .await;
    }
}

/// Starts the background ACME Auto-Renewal Supervisor with cluster-wide leader coordination.
pub fn spawn_acme_supervisor(
    config: AcmeConfig,
    master_key: Option<String>,
    app_state: Option<Arc<crate::state::AppState>>,
) {
    tokio::spawn(async move {
        let primary_region = std::env::var("PRIMARY_REGION")
            .or_else(|_| std::env::var("FLY_PRIMARY_REGION"))
            .unwrap_or_else(|_| "sin".to_string());
        let current_region = std::env::var("FLY_REGION").unwrap_or_default();
        let machine_id = std::env::var("FLY_MACHINE_ID")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "local".to_string());
        let is_leader_region = current_region.is_empty() || current_region == primary_region;

        info!(
            "[acme-supervisor] Initializing ACME coordinator (Machine: '{}', Region: '{}', LeaderRegion: {}, Primary: '{}')",
            machine_id,
            if current_region.is_empty() {
                "local"
            } else {
                &current_region
            },
            is_leader_region,
            primary_region
        );

        // Stagger startup slightly based on machine id to prevent dual-boot races
        let stagger_secs = {
            let mut h = 0u64;
            for b in machine_id.bytes() {
                h = h.wrapping_mul(31).wrapping_add(b as u64);
            }
            (h % 5) + 2
        };
        tokio::time::sleep(Duration::from_secs(stagger_secs)).await;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        loop {
            let days_opt = validate_existing_cert_and_key(
                &config.cert_path,
                &config.key_path,
                &config.domains,
                30,
            );
            let needs_action = match days_opt {
                Some(days) => {
                    info!(
                        "[acme-supervisor] Active TLS certificate and key validated on disk ({} days remaining, covers all {} domains: {:?}). Preserving existing certificate without issuing duplicate.",
                        days,
                        config.domains.len(),
                        config.domains
                    );
                    // Ensure live in-memory resolver is updated with the validated cert on disk
                    if let Some(ref resolver) = config.cert_resolver {
                        let _ = resolver.update_from_pem(&config.cert_path, &config.key_path);
                    }
                    if let (Ok(cert_pem), Ok(key_pem)) = (
                        fs::read_to_string(&config.cert_path),
                        fs::read_to_string(&config.key_path),
                    ) {
                        try_import_to_fly_edge(&http, &config.domains, &cert_pem, &key_pem).await;
                    }
                    false
                }
                None => {
                    info!(
                        "[acme-supervisor] No valid TLS certificate/key pair found at '{}' and '{}' covering all domains {:?} (or <30 days remaining)",
                        config.cert_path, config.key_path, config.domains
                    );
                    true
                }
            };

            if needs_action {
                // First, check if peer already has a valid bundle (e.g. after container restart / peer finished)
                if try_sync_from_peer(&config, master_key.as_deref()).await {
                    info!(
                        "[acme-supervisor] Successfully synced valid TLS certificate bundle from peer machine"
                    );
                    tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
                    continue;
                }

                if is_leader_region {
                    // Stagger startup slightly based on machine_id hash to eliminate simultaneous lock collision
                    let stagger_ms = (machine_id.bytes().map(|b| b as u64).sum::<u64>() % 7 + 1) * 800;
                    tokio::time::sleep(Duration::from_millis(stagger_ms)).await;

                    // Re-check peer sync after stagger
                    if try_sync_from_peer(&config, master_key.as_deref()).await {
                        info!(
                            "[acme-supervisor] Successfully synced valid TLS certificate bundle from peer machine"
                        );
                        tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
                        continue;
                    }

                    // Try to acquire the cluster ACME provisioning lock
                    let has_lock = try_acquire_cluster_lock(
                        &http,
                        app_state.as_ref(),
                        &machine_id,
                        master_key.as_deref(),
                    )
                    .await;

                    if has_lock {
                        let ca_name = if config.zerossl_api_key.is_some() {
                            "ZeroSSL"
                        } else {
                            "Let's Encrypt"
                        };
                        info!(
                            "[acme-supervisor] Acquired ACME leader lock for machine '{}'. Running automated {} DNS-01 provisioning...",
                            machine_id, ca_name
                        );
                        let prov_res = provision_acme_certificate(&config).await;
                        try_release_cluster_lock(
                            &http,
                            app_state.as_ref(),
                            &machine_id,
                            master_key.as_deref(),
                        )
                        .await;

                        match prov_res {
                            Ok(_) => {
                                info!(
                                    "[acme-supervisor] {} provisioning succeeded. Next check in 24 hours.",
                                    ca_name
                                );
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
                                        "[acme-supervisor] Certificate provisioning error: {}. Will retry in 45 seconds.",
                                        err_str
                                    );
                                    tokio::time::sleep(Duration::from_secs(45)).await;
                                }
                            }
                        }
                    } else {
                        // Another machine in the cluster is actively provisioning. Wait as replica.
                        info!(
                            "[acme-supervisor] ACME lock is held by a peer node. Waiting for peer to complete certificate provisioning..."
                        );
                        let mut synced = false;
                        for _ in 1..=120 {
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            if try_sync_from_peer(&config, master_key.as_deref()).await {
                                info!(
                                    "[acme-supervisor] Successfully synced certificate bundle from peer."
                                );
                                synced = true;
                                break;
                            }
                        }
                        if synced {
                            tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
                        } else {
                            tokio::time::sleep(Duration::from_secs(60)).await;
                        }
                    }
                } else {
                    // REPLICA NODE IN SECONDARY REGION
                    info!(
                        "[acme-replica] Replica node in region '{}'. Waiting for leader in region '{}' to provision TLS certificate...",
                        current_region, primary_region
                    );

                    let mut synced = false;
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
                                info!(
                                    "[acme-replica] Fail-safe ACME provisioning succeeded. Next check in 24 hours."
                                );
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
            assert!(days_val > 0);
        }
    }

    #[test]
    fn test_validate_existing_cert_and_key_nonexistent() {
        let res = validate_existing_cert_and_key(
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
            &[],
            30,
        );
        assert!(res.is_none());
    }

    #[test]
    fn test_is_dynu_domain() {
        assert!(is_dynu_domain("example.dynu.net"));
        assert!(is_dynu_domain("sub.test.freeddns.org"));
        assert!(is_dynu_domain("myhost.ddnsfree.com"));
        assert!(!is_dynu_domain("example.dedyn.io"));
        assert!(!is_dynu_domain("example.duckdns.org"));
    }

    #[test]
    fn test_compute_dynu_node_name() {
        assert_eq!(
            compute_dynu_node_name("example.dynu.net", "example.dynu.net"),
            "_acme-challenge"
        );
        assert_eq!(
            compute_dynu_node_name("sub.example.dynu.net", "example.dynu.net"),
            "_acme-challenge.sub"
        );
    }

    #[test]
    fn test_extract_cert_domains_live() {
        if Path::new("live_cert.pem").exists() {
            let domains = extract_cert_domains("live_cert.pem");
            assert!(!domains.is_empty());
        }
    }
}
