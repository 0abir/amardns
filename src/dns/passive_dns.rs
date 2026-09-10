use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

const MAX_ENTRIES_PER_DOMAIN: usize = 50;
const MAX_AGE_SECS: u64 = 7 * 24 * 3600; // 7 days
const MAX_TRACKED_DOMAINS: usize = 10_000; // Cap to prevent memory leaks in passive DNS store

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PassiveDnsEntry {
    pub ip: String,
    pub seen_at: u64,
}

#[derive(Default)]
struct DomainRecord {
    entries: VecDeque<PassiveDnsEntry>,
    last_ip_set: Vec<String>,
}

pub struct PassiveDnsStore {
    inner: RwLock<HashMap<String, DomainRecord>>,
    pub drift_events: AtomicU64,
    pub total_observations: AtomicU64,
}

impl PassiveDnsStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            drift_events: AtomicU64::new(0),
            total_observations: AtomicU64::new(0),
        }
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Records IPs observed for a domain. Returns Some(old_ips) if IP set changed (drift detected).
    pub fn record(&self, domain: &str, ips: &[IpAddr]) -> Option<Vec<String>> {
        if ips.is_empty() {
            return None;
        }
        let now = Self::now_secs();
        let clean = domain.trim_end_matches('.').to_ascii_lowercase();
        let new_ip_strs: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();

        let mut map = self.inner.write();
        if map.len() >= MAX_TRACKED_DOMAINS && !map.contains_key(&clean) {
            if let Some(oldest_key) = map.keys().next().cloned() {
                map.remove(&oldest_key);
            }
        }
        let rec = map.entry(clean).or_default();

        // Evict stale entries
        let cutoff = now.saturating_sub(MAX_AGE_SECS);
        while rec.entries.front().map(|e| e.seen_at < cutoff).unwrap_or(false) {
            rec.entries.pop_front();
        }

        // Detect drift: new IP set differs from last observed set
        let mut drift_old: Option<Vec<String>> = None;
        if !rec.last_ip_set.is_empty() {
            let mut old_sorted = rec.last_ip_set.clone();
            let mut new_sorted = new_ip_strs.clone();
            old_sorted.sort();
            new_sorted.sort();
            if old_sorted != new_sorted {
                drift_old = Some(rec.last_ip_set.clone());
                self.drift_events.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Insert entries
        for ip_str in &new_ip_strs {
            if rec.entries.len() >= MAX_ENTRIES_PER_DOMAIN {
                rec.entries.pop_front();
            }
            rec.entries.push_back(PassiveDnsEntry {
                ip: ip_str.clone(),
                seen_at: now,
            });
        }
        rec.last_ip_set = new_ip_strs;
        self.total_observations.fetch_add(1, Ordering::Relaxed);

        drift_old
    }

    /// Returns the timeline (most recent first) for a domain.
    pub fn get_timeline(&self, domain: &str) -> Vec<PassiveDnsEntry> {
        let clean = domain.trim_end_matches('.').to_ascii_lowercase();
        let map = self.inner.read();
        if let Some(rec) = map.get(&clean) {
            let mut entries: Vec<PassiveDnsEntry> = rec.entries.iter().cloned().collect();
            entries.reverse();
            entries
        } else {
            Vec::new()
        }
    }

    /// Returns the total number of tracked domains.
    pub fn domain_count(&self) -> usize {
        self.inner.read().len()
    }

    /// Returns recent drift events (IP changes) across all domains.
    pub fn get_recent_drifts(&self, limit: usize) -> Vec<serde_json::Value> {
        let now = Self::now_secs();
        let map = self.inner.read();
        let cutoff = now.saturating_sub(3600);
        let mut out = Vec::new();
        for (domain, rec) in map.iter() {
            let entries: Vec<&PassiveDnsEntry> = rec.entries.iter()
                .filter(|e| e.seen_at >= cutoff)
                .collect();
            if entries.len() >= 2 {
                let first = entries.last().unwrap();
                let last = entries.first().unwrap();
                if first.ip != last.ip {
                    out.push(serde_json::json!({
                        "domain": domain,
                        "newIp": last.ip,
                        "oldIp": first.ip,
                        "seenAt": last.seen_at
                    }));
                    if out.len() >= limit {
                        break;
                    }
                }
            }
        }
        out
    }
}

impl Default for PassiveDnsStore {
    fn default() -> Self {
        Self::new()
    }
}
