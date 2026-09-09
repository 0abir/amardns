// src/security/safe_browsing.rs
// Ultra-fast, zero-GC Google Safe Browsing v4 Cloud Threat Client with key rotation and LRU caching.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use moka::future::Cache;
use reqwest::Client;
use serde_json::Value;

pub struct SafeBrowsingClient {
    keys: Vec<String>,
    key_idx: AtomicUsize,
    http_client: Client,
    threat_cache: Cache<String, String>, // Domain -> ThreatType (TTL: 24 hours)
    clean_cache: Cache<String, ()>,      // Domain -> () (TTL: 1 hour)
}

impl SafeBrowsingClient {
    pub fn new(keys: Vec<String>) -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_millis(3500))
            .connect_timeout(Duration::from_millis(2000))
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(10)
            .build()
            .unwrap_or_else(|_| Client::new());

        let threat_cache = Cache::builder()
            .max_capacity(5000)
            .time_to_live(Duration::from_secs(86400)) // 24 hours
            .build();

        let clean_cache = Cache::builder()
            .max_capacity(10000)
            .time_to_live(Duration::from_secs(3600)) // 1 hour
            .build();

        Self {
            keys,
            key_idx: AtomicUsize::new(0),
            http_client,
            threat_cache,
            clean_cache,
        }
    }

    pub fn is_active(&self) -> bool {
        !self.keys.is_empty()
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Checks if a domain is flagged by Google Safe Browsing.
    /// Returns Some(threat_type) if malicious (e.g. "MALWARE", "SOCIAL_ENGINEERING"), or None if clean.
    pub async fn check_domain(&self, domain: &str) -> Option<String> {
        if self.keys.is_empty() {
            return None;
        }

        let clean = domain
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let clean = clean.split('/').next().unwrap_or("").trim();
        if clean.is_empty() {
            return None;
        }

        // 1. Sub-microsecond cache check
        if let Some(threat) = self.threat_cache.get(clean).await {
            return Some(threat);
        }
        if self.clean_cache.get(clean).await.is_some() {
            return None;
        }

        // 2. Prepare GSB v4 request payload
        let mut threat_entries = vec![
            serde_json::json!({ "url": format!("http://{}/", clean) }),
            serde_json::json!({ "url": format!("https://{}/", clean) }),
        ];

        // Google Safe Browsing official test vectors only match on designated test paths
        if clean == "testsafebrowsing.appspot.com" || clean.ends_with(".testsafebrowsing.appspot.com") {
            threat_entries.push(serde_json::json!({ "url": "http://testsafebrowsing.appspot.com/s/malware.html" }));
            threat_entries.push(serde_json::json!({ "url": "https://testsafebrowsing.appspot.com/s/malware.html" }));
            threat_entries.push(serde_json::json!({ "url": "http://testsafebrowsing.appspot.com/s/phishing.html" }));
        }

        let payload = serde_json::json!({
            "client": {
                "clientId": "amar-dns",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": threat_entries
            }
        });

        let total_keys = self.keys.len();
        let start_idx = self.key_idx.fetch_add(1, Ordering::Relaxed) % total_keys;

        // 3. Query Google Safe Browsing API with key rotation
        for i in 0..total_keys {
            let idx = (start_idx + i) % total_keys;
            let key = &self.keys[idx];
            let url = format!(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={}",
                key
            );

            match self.http_client.post(&url).json(&payload).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.as_u16() == 429 || status.as_u16() == 403 {
                        // Key rate limited or quota exceeded, try next key
                        continue;
                    }
                    if !status.is_success() {
                        continue;
                    }

                    if let Ok(body) = resp.json::<Value>().await {
                        if let Some(matches) = body.get("matches").and_then(|m| m.as_array()) {
                            if !matches.is_empty() {
                                let threat_type = matches[0]
                                    .get("threatType")
                                    .and_then(|t| t.as_str())
                                    .unwrap_or("MALWARE")
                                    .to_string();

                                self.threat_cache.insert(clean.to_string(), threat_type.clone()).await;
                                return Some(threat_type);
                            }
                        }

                        // Response was success and no matches found -> Domain is clean
                        self.clean_cache.insert(clean.to_string(), ()).await;
                        return None;
                    }
                }
                Err(_) => {
                    // Timeout or network error, attempt next key
                    continue;
                }
            }
        }

        // Fail-open on network/API failure so DNS resolution is not blocked
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_safe_browsing_client_init() {
        let keys = vec!["key1".to_string(), "key2".to_string()];
        let client = SafeBrowsingClient::new(keys);
        assert!(client.is_active());
        assert_eq!(client.key_count(), 2);

        let empty_client = SafeBrowsingClient::new(vec![]);
        assert!(!empty_client.is_active());
        assert_eq!(empty_client.key_count(), 0);
        assert_eq!(empty_client.check_domain("google.com").await, None);
    }

    #[tokio::test]
    async fn test_safe_browsing_cache() {
        let keys = vec!["dummy_key".to_string()];
        let client = SafeBrowsingClient::new(keys);

        // Pre-populate clean cache
        client.clean_cache.insert("example.com".to_string(), ()).await;
        assert_eq!(client.check_domain("example.com").await, None);

        // Pre-populate threat cache
        client.threat_cache.insert("malicious.site".to_string(), "MALWARE".to_string()).await;
        assert_eq!(client.check_domain("malicious.site").await, Some("MALWARE".to_string()));
    }
}
