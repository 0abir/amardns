use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use parking_lot::RwLock;

/// Shannon entropy calculation to detect High-Entropy DGA (Domain Generation Algorithm) malware domains
pub fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }
    let len_f = s.len() as f64;
    let mut entropy = 0.0;
    for &c in &freq {
        if c > 0 {
            let p = c as f64 / len_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Known high-value brands vulnerable to typosquatting and homoglyphs
const HIGH_VALUE_BRANDS: &[&str] = &[
    "paypal", "google", "apple", "microsoft", "amazon",
    "facebook", "netflix", "binance", "coinbase", "whatsapp",
    "instagram", "chase", "bankofamerica", "wellsfargo"
];

/// Immutable whitelist domains that enjoy 100% immunity from AI and lookalike blocks
const IMMUNE_TLD_OR_DOMAINS: &[&str] = &[
    "google.com", "cloudflare.com", "apple.com", "microsoft.com",
    "github.com", "wikipedia.org", "jsdelivr.net", "fly.dev",
    "ubuntu.com", "debian.org", "mozilla.org", "nist.gov"
];

pub fn is_known_immune(domain: &str) -> bool {
    let clean = domain.trim_end_matches('.').to_ascii_lowercase();
    for immune in IMMUNE_TLD_OR_DOMAINS {
        if clean == *immune || clean.ends_with(&format!(".{}", immune)) {
            return true;
        }
    }
    false
}

/// Detects lookalikes, Punycode homoglyphs, and substitution attacks
pub fn is_lookalike_threat(domain: &str) -> bool {
    let clean = domain.trim_end_matches('.').to_ascii_lowercase();
    if is_known_immune(&clean) {
        return false;
    }

    // Punycode check: internationalized domains mimicking latin
    if clean.starts_with("xn--") || clean.contains(".xn--") {
        return true;
    }

    // Strip TLD for brand impersonation checks
    let parts: Vec<&str> = clean.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let sld = parts[parts.len() - 2];

    // Normalized substitutions: '1' -> 'l', '0' -> 'o', '5' -> 's', 'vv' -> 'w'
    let normalized = sld
        .replace('0', "o")
        .replace('1', "l")
        .replace('5', "s")
        .replace("vv", "w");

    for brand in HIGH_VALUE_BRANDS {
        if sld == *brand {
            continue; // Exact match on real brand is handled by whitelist
        }
        // If normalized matches brand or has Levenshtein distance of 1
        if normalized == *brand {
            return true;
        }
        if levenshtein_dist(sld, brand) == 1 && sld.len() >= 5 {
            return true;
        }
    }

    false
}

/// DGA threat detection using length, Shannon entropy, and consonant clusters
pub fn is_dga_threat(domain: &str) -> bool {
    let clean = domain.trim_end_matches('.').to_ascii_lowercase();
    if is_known_immune(&clean) {
        return false;
    }
    let parts: Vec<&str> = clean.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let sld = parts[parts.len() - 2];
    if sld.len() >= 12 && calculate_entropy(sld) > 3.65 {
        return true;
    }
    false
}

/// Fast Levenshtein distance calculation
fn levenshtein_dist(a: &str, b: &str) -> usize {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut costs: Vec<usize> = (0..=b_bytes.len()).collect();

    for (i, &ca) in a_bytes.iter().enumerate() {
        let mut last_val = i;
        costs[0] = i + 1;
        for (j, &cb) in b_bytes.iter().enumerate() {
            let mut new_val = last_val;
            if ca != cb {
                new_val = (new_val.min(costs[j])).min(costs[j + 1]) + 1;
            }
            last_val = costs[j + 1];
            costs[j + 1] = new_val;
        }
    }
    costs[b_bytes.len()]
}

const FP_WINDOW_MS: u64 = 60_000;
const FP_SCAN_UNIQ: usize = 60;
const FP_FLOOD_COUNT: u32 = 150;
const FP_TUNNEL_PAYLOAD_LEN: usize = 28;
const FP_TUNNEL_ENTROPY: f64 = 3.9;
const NX_WINDOW_MS: u64 = 120_000;
const FLAG_EXPIRY_MS: u64 = 3_600_000; // Retain suspicious status for 1 hour

#[derive(Debug, Clone)]
struct ClientFp {
    uniq_domains: HashSet<String>,
    queries: u32,
    tunnel_hits: u32,
    window_start: Instant,
    flagged: Option<&'static str>,
    flagged_at: Option<Instant>,
}

#[derive(Debug, Clone)]
struct ClientNx {
    nx_count: u32,
    total_count: u32,
    window_start: Instant,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SuspiciousEvent {
    pub ip: IpAddr,
    pub flag: &'static str,
    pub query: String,
    pub timestamp: u128,
}

#[derive(Debug)]
pub struct ClientFingerprintTracker {
    fp_map: RwLock<HashMap<IpAddr, ClientFp>>,
    nx_map: RwLock<HashMap<IpAddr, ClientNx>>,
    suspicious_history: RwLock<std::collections::VecDeque<SuspiciousEvent>>,
    total_fp_events: AtomicU64,
}

impl ClientFingerprintTracker {
    pub fn new() -> Self {
        Self {
            fp_map: RwLock::new(HashMap::new()),
            nx_map: RwLock::new(HashMap::new()),
            suspicious_history: RwLock::new(std::collections::VecDeque::with_capacity(64)),
            total_fp_events: AtomicU64::new(0),
        }
    }

    pub fn total_events(&self) -> u64 {
        self.total_fp_events.load(Ordering::Relaxed)
    }

    pub fn flag_client(&self, client_ip: IpAddr, flag_type: &'static str, query: &str) {
        let now = Instant::now();
        let mut map = self.fp_map.write();
        let fp = map.entry(client_ip).or_insert_with(|| ClientFp {
            uniq_domains: HashSet::new(),
            queries: 0,
            tunnel_hits: 0,
            window_start: now,
            flagged: None,
            flagged_at: None,
        });
        fp.queries += 1;
        fp.flagged = Some(flag_type);
        fp.flagged_at = Some(now);
        self.total_fp_events.fetch_add(1, Ordering::Relaxed);

        let mut hist = self.suspicious_history.write();
        if hist.len() >= 50 {
            hist.pop_back();
        }
        hist.push_front(SuspiciousEvent {
            ip: client_ip,
            flag: flag_type,
            query: query.to_string(),
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis(),
        });
    }

    pub fn record_query(&self, client_ip: IpAddr, domain: &str) -> Option<&'static str> {
        let now = Instant::now();
        let mut map = self.fp_map.write();

        // Prevent unbounded memory growth
        if map.len() > 5000 {
            map.retain(|_, v| {
                v.flagged.is_some() && v.flagged_at.map_or(false, |t| now.duration_since(t).as_millis() < FLAG_EXPIRY_MS as u128)
            });
        }

        let fp = map.entry(client_ip).or_insert_with(|| ClientFp {
            uniq_domains: HashSet::new(),
            queries: 0,
            tunnel_hits: 0,
            window_start: now,
            flagged: None,
            flagged_at: None,
        });

        // Check sliding window reset (60s)
        if now.duration_since(fp.window_start).as_millis() > FP_WINDOW_MS as u128 {
            fp.uniq_domains.clear();
            fp.queries = 0;
            fp.tunnel_hits = 0;
            fp.window_start = now;
        }

        // Check flag expiration (1 hour)
        if let Some(flagged_at) = fp.flagged_at {
            if now.duration_since(flagged_at).as_millis() > FLAG_EXPIRY_MS as u128 {
                fp.flagged = None;
                fp.flagged_at = None;
                fp.tunnel_hits = 0;
            }
        }

        fp.queries += 1;
        let clean = domain.trim_end_matches('.').to_ascii_lowercase();
        let is_legit = is_known_immune(&clean);
        if !clean.is_empty() && !is_legit {
            fp.uniq_domains.insert(clean.clone());
        }

        let mut newly_flagged = None;

        // 1. DNS Scan check (>= 20 unique domains in 60s)
        if fp.uniq_domains.len() > FP_SCAN_UNIQ && fp.flagged.is_none() {
            fp.flagged = Some("DNS_SCAN");
            fp.flagged_at = Some(now);
            self.total_fp_events.fetch_add(1, Ordering::Relaxed);
            newly_flagged = Some("DNS_SCAN");
        } else if fp.queries > FP_FLOOD_COUNT && fp.flagged.is_none() {
            // 2. Query Stress / Flooding check (>= 80 queries in 60s)
            fp.flagged = Some("QUERY_STRESS");
            fp.flagged_at = Some(now);
            self.total_fp_events.fetch_add(1, Ordering::Relaxed);
            newly_flagged = Some("QUERY_STRESS");
        }

        // 3. DNS Tunneling check (Payload len >= 28, Shannon entropy >= 3.9)
        if !is_legit && clean.len() >= 35 && fp.flagged.is_none() {
            if let Some(first_label) = clean.split('.').next() {
                if first_label.len() >= FP_TUNNEL_PAYLOAD_LEN {
                    let ent = calculate_entropy(first_label);
                    if ent >= FP_TUNNEL_ENTROPY {
                        fp.tunnel_hits += 1;
                        if ent >= 4.2 || fp.tunnel_hits >= 2 {
                            fp.flagged = Some("DNS_TUNNEL_SUSPECT");
                            fp.flagged_at = Some(now);
                            self.total_fp_events.fetch_add(1, Ordering::Relaxed);
                            newly_flagged = Some("DNS_TUNNEL_SUSPECT");
                        }
                    }
                }
            }
        }

        newly_flagged
    }

    pub fn record_response(&self, client_ip: IpAddr, rcode: u16) -> Option<&'static str> {
        let now = Instant::now();
        let mut nx_map = self.nx_map.write();

        if nx_map.len() > 3000 {
            nx_map.retain(|_, v| now.duration_since(v.window_start).as_millis() < NX_WINDOW_MS as u128);
        }

        let rec = nx_map.entry(client_ip).or_insert_with(|| ClientNx {
            nx_count: 0,
            total_count: 0,
            window_start: now,
        });

        if now.duration_since(rec.window_start).as_millis() > NX_WINDOW_MS as u128 {
            rec.nx_count = 0;
            rec.total_count = 0;
            rec.window_start = now;
        }

        rec.total_count += 1;
        if rcode == 3 {
            rec.nx_count += 1;
        }

        let rate = if rec.total_count >= 10 {
            rec.nx_count as f64 / rec.total_count as f64
        } else {
            0.0
        };

        if rate >= 0.60 {
            let mut fp_map = self.fp_map.write();
            let fp = fp_map.entry(client_ip).or_insert_with(|| ClientFp {
                uniq_domains: HashSet::new(),
                queries: rec.total_count,
                tunnel_hits: 0,
                window_start: now,
                flagged: None,
                flagged_at: None,
            });

            if fp.flagged.is_none() {
                fp.flagged = Some("NX_SCANNER");
                fp.flagged_at = Some(now);
                self.total_fp_events.fetch_add(1, Ordering::Relaxed);
                return Some("NX_SCANNER");
            }
        }

        None
    }

    pub fn get_suspicious(&self) -> Vec<serde_json::Value> {
        let now = Instant::now();
        let map = self.fp_map.read();
        let mut seen = HashSet::new();
        let mut res = Vec::new();

        for (ip, fp) in map.iter() {
            if let (Some(flag), Some(flagged_at)) = (fp.flagged, fp.flagged_at) {
                if now.duration_since(flagged_at).as_millis() <= FLAG_EXPIRY_MS as u128 {
                    seen.insert(*ip);
                    res.push(serde_json::json!({
                        "ip": ip.to_string(),
                        "type": flag,
                        "queries": fp.queries.max(1)
                    }));
                }
            }
            if res.len() >= 20 {
                break;
            }
        }

        if res.len() < 20 {
            let hist = self.suspicious_history.read();
            for ev in hist.iter() {
                if !seen.contains(&ev.ip) {
                    seen.insert(ev.ip);
                    res.push(serde_json::json!({
                        "ip": ev.ip.to_string(),
                        "type": ev.flag,
                        "queries": 1
                    }));
                }
                if res.len() >= 20 {
                    break;
                }
            }
        }

        res
    }

    #[allow(dead_code)]
    pub fn memory_bytes(&self) -> usize {
        let fp_len = self.fp_map.read().len() * 128;
        let nx_len = self.nx_map.read().len() * 64;
        let hist_len = self.suspicious_history.read().len() * 128;
        fp_len + nx_len + hist_len + 4096
    }

    pub fn clear(&self) {
        self.fp_map.write().clear();
        self.nx_map.write().clear();
        self.suspicious_history.write().clear();
        self.total_fp_events.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookalike_detection() {
        assert!(is_lookalike_threat("paypa1.com"));
        assert!(is_lookalike_threat("g00gle.com"));
        assert!(!is_lookalike_threat("paypal.com"));
        assert!(!is_lookalike_threat("google.com"));
        assert!(!is_lookalike_threat("github.com"));
    }

    #[test]
    fn test_dga_detection() {
        assert!(is_dga_threat("xkj8a7f9q2lmnz8.biz"));
        assert!(!is_dga_threat("example.com"));
        assert!(!is_dga_threat("wikipedia.org"));
    }

    #[test]
    fn test_client_fingerprint_scan() {
        let tracker = ClientFingerprintTracker::new();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        for i in 0..60 {
            tracker.record_query(ip, &format!("domain-{}.test", i));
        }
        assert!(tracker.get_suspicious().is_empty());

        let flagged = tracker.record_query(ip, "domain-61.test");
        assert_eq!(flagged, Some("DNS_SCAN"));
        let suspicious = tracker.get_suspicious();
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0]["type"], "DNS_SCAN");
        assert_eq!(suspicious[0]["ip"], "192.168.1.100");
    }

    #[test]
    fn test_client_fingerprint_flood() {
        let tracker = ClientFingerprintTracker::new();
        let ip: IpAddr = "192.168.1.101".parse().unwrap();

        for _ in 0..150 {
            tracker.record_query(ip, "same-domain.com");
        }
        assert!(tracker.get_suspicious().is_empty());

        let flagged = tracker.record_query(ip, "same-domain.com");
        assert_eq!(flagged, Some("QUERY_STRESS"));
        let suspicious = tracker.get_suspicious();
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0]["type"], "QUERY_STRESS");
    }

    #[test]
    fn test_client_fingerprint_nx_scanner() {
        let tracker = ClientFingerprintTracker::new();
        let ip: IpAddr = "192.168.1.102".parse().unwrap();

        for _ in 0..9 {
            tracker.record_response(ip, 3); // NXDOMAIN
        }
        assert!(tracker.get_suspicious().is_empty());

        let flagged = tracker.record_response(ip, 3); // 10th query, 100% NXDOMAIN
        assert_eq!(flagged, Some("NX_SCANNER"));
        let suspicious = tracker.get_suspicious();
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0]["type"], "NX_SCANNER");
    }
}
