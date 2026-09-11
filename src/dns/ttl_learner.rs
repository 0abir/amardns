use std::collections::{HashMap, VecDeque};
use parking_lot::RwLock;

const MAX_SAMPLES: usize = 20;
const EMA_ALPHA: f64 = 0.3; // weight for new observations
const MIN_SMART_TTL: u32 = 10;
const MAX_SMART_TTL: u32 = 3600;
const MAX_LEARNED_DOMAINS: usize = 5_000; // 5k domains × ~200 bytes = ~1 MB max

struct TtlStats {
    samples: VecDeque<u32>,
    ema: f64,
}

impl TtlStats {
    fn new(first: u32) -> Self {
        let mut samples = VecDeque::with_capacity(MAX_SAMPLES);
        samples.push_back(first);
        Self {
            samples,
            ema: first as f64,
        }
    }

    fn observe(&mut self, ttl: u32) {
        if self.samples.len() >= MAX_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(ttl);
        // EMA update: new = alpha*ttl + (1-alpha)*old
        self.ema = EMA_ALPHA * ttl as f64 + (1.0 - EMA_ALPHA) * self.ema;
    }

    fn smart_ttl(&self) -> u32 {
        (self.ema.round() as u32).clamp(MIN_SMART_TTL, MAX_SMART_TTL)
    }
}

pub struct TtlLearner {
    inner: RwLock<HashMap<String, TtlStats>>,
}

impl TtlLearner {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Records an observed upstream TTL for a domain and updates the EMA.
    pub fn observe(&self, domain: &str, ttl: u32) {
        if ttl == 0 || ttl > 86400 {
            return; // ignore bogus values
        }
        let clean = domain.trim_end_matches('.').to_ascii_lowercase();
        let mut map = self.inner.write();
        if map.len() >= MAX_LEARNED_DOMAINS && !map.contains_key(&clean) {
            if let Some(k) = map.keys().next().cloned() {
                map.remove(&k);
            }
        }
        if let Some(stats) = map.get_mut(&clean) {
            stats.observe(ttl);
        } else {
            map.insert(clean, TtlStats::new(ttl));
        }
    }

    /// Returns the learned smart TTL for a domain.
    /// Falls back to `default_ttl` if no observations yet.
    pub fn smart_ttl(&self, domain: &str, default_ttl: u32) -> u32 {
        let clean = domain.trim_end_matches('.').to_ascii_lowercase();
        let map = self.inner.read();
        if let Some(stats) = map.get(&clean) {
            stats.smart_ttl()
        } else {
            default_ttl.clamp(MIN_SMART_TTL, MAX_SMART_TTL)
        }
    }

    /// Returns number of domains being tracked.
    pub fn domain_count(&self) -> usize {
        self.inner.read().len()
    }

    /// Returns top N most volatile domains (shortest learned TTL).
    pub fn volatile_domains(&self, limit: usize) -> Vec<serde_json::Value> {
        let map = self.inner.read();
        let mut list: Vec<(&String, u32)> = map
            .iter()
            .map(|(k, v)| (k, v.smart_ttl()))
            .collect();
        list.sort_by_key(|(_, ttl)| *ttl);
        list.into_iter()
            .take(limit)
            .map(|(domain, ttl)| serde_json::json!({ "domain": domain, "smartTtl": ttl }))
            .collect()
    }
}

impl Default for TtlLearner {
    fn default() -> Self {
        Self::new()
    }
}
