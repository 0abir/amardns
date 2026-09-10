use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum FeedFormat {
    Hosts,      // 0.0.0.0 domain.com
    Domains,    // one domain per line
    AdblockPlus // ||domain.com^
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeedSubscription {
    pub id: u64,
    pub name: String,
    pub url: String,
    pub format: FeedFormat,
    pub enabled: bool,
    pub last_synced: u64,
    pub domain_count: u64,
    pub description: String,
}

pub struct FeedManager {
    feeds: RwLock<Vec<FeedSubscription>>,
    #[allow(dead_code)]
    next_id: AtomicU64,
    pub total_synced_domains: AtomicU64,
}

impl FeedManager {
    pub fn new() -> Self {
        let default_feeds = vec![
            FeedSubscription {
                id: 1,
                name: "HaGeZi Multi PRO".to_string(),
                url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt".to_string(),
                format: FeedFormat::Domains,
                enabled: true,
                last_synced: 0,
                domain_count: 0,
                description: "HaGeZi Multi PRO — aggressive ad, tracker, and malware blocking".to_string(),
            },
            FeedSubscription {
                id: 2,
                name: "OISD Big".to_string(),
                url: "https://big.oisd.nl/domains".to_string(),
                format: FeedFormat::Domains,
                enabled: false,
                last_synced: 0,
                domain_count: 0,
                description: "OISD Big — large all-purpose blocklist".to_string(),
            },
            FeedSubscription {
                id: 3,
                name: "Steven Black Unified".to_string(),
                url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".to_string(),
                format: FeedFormat::Hosts,
                enabled: false,
                last_synced: 0,
                domain_count: 0,
                description: "Steven Black hosts — ads and malware".to_string(),
            },
            FeedSubscription {
                id: 4,
                name: "HaGeZi Gambling".to_string(),
                url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/gambling.txt".to_string(),
                format: FeedFormat::Domains,
                enabled: false,
                last_synced: 0,
                domain_count: 0,
                description: "HaGeZi Gambling — gambling site blocker".to_string(),
            },
            FeedSubscription {
                id: 5,
                name: "HaGeZi Porn".to_string(),
                url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/porn.txt".to_string(),
                format: FeedFormat::Domains,
                enabled: false,
                last_synced: 0,
                domain_count: 0,
                description: "HaGeZi Porn — adult content blocker".to_string(),
            },
        ];

        Self {
            feeds: RwLock::new(default_feeds),
            next_id: AtomicU64::new(6),
            total_synced_domains: AtomicU64::new(0),
        }
    }

    /// Parses domains from raw feed content based on format.
    pub fn parse_domains(content: &str, format: &FeedFormat) -> Vec<String> {
        let mut domains = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }
            match format {
                FeedFormat::Hosts => {
                    // "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let domain = parts[1].trim().to_ascii_lowercase();
                        if is_valid_domain(&domain) && domain != "localhost" {
                            domains.push(domain);
                        }
                    }
                }
                FeedFormat::Domains => {
                    let domain = line.trim_start_matches("0.0.0.0").trim().to_ascii_lowercase();
                    let domain = domain.trim_start_matches("127.0.0.1").trim();
                    let domain = domain.trim_end_matches('.');
                    if is_valid_domain(domain) {
                        domains.push(domain.to_string());
                    }
                }
                FeedFormat::AdblockPlus => {
                    // "||domain.com^" or "||domain.com^$important"
                    if let Some(inner) = line.strip_prefix("||") {
                        let domain = inner.split('^').next().unwrap_or("").trim();
                        let domain = domain.to_ascii_lowercase();
                        if is_valid_domain(&domain) {
                            domains.push(domain);
                        }
                    }
                }
            }
        }
        domains
    }

    pub fn list_feeds(&self) -> Vec<FeedSubscription> {
        self.feeds.read().clone()
    }

    pub fn toggle_feed(&self, id: u64) -> bool {
        let mut feeds = self.feeds.write();
        if let Some(feed) = feeds.iter_mut().find(|f| f.id == id) {
            feed.enabled = !feed.enabled;
            true
        } else {
            false
        }
    }

    pub fn update_sync_stats(&self, id: u64, domain_count: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut feeds = self.feeds.write();
        if let Some(feed) = feeds.iter_mut().find(|f| f.id == id) {
            feed.last_synced = now;
            feed.domain_count = domain_count;
        }
        self.total_synced_domains.fetch_add(domain_count, Ordering::Relaxed);
    }

    /// Returns enabled feed URLs and their formats for syncing.
    pub fn enabled_feeds(&self) -> Vec<(u64, String, FeedFormat)> {
        self.feeds
            .read()
            .iter()
            .filter(|f| f.enabled)
            .map(|f| (f.id, f.url.clone(), f.format.clone()))
            .collect()
    }

    #[allow(dead_code)]
    pub fn add_feed(&self, name: String, url: String, format: FeedFormat, description: String) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.feeds.write().push(FeedSubscription {
            id,
            name,
            url,
            format,
            enabled: true,
            last_synced: 0,
            domain_count: 0,
            description,
        });
        id
    }

    #[allow(dead_code)]
    pub fn remove_feed(&self, id: u64) -> bool {
        // Don't allow removing built-in feeds (id <= 5)
        if id <= 5 {
            return false;
        }
        let mut feeds = self.feeds.write();
        let before = feeds.len();
        feeds.retain(|f| f.id != id);
        feeds.len() < before
    }
}

fn is_valid_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.contains('.') && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

impl Default for FeedManager {
    fn default() -> Self {
        Self::new()
    }
}
