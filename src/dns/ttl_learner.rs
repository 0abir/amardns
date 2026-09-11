use std::collections::{HashMap, VecDeque};
use parking_lot::RwLock;

const MAX_SAMPLES: usize = 20;
const EMA_ALPHA: f64 = 0.3; // weight for new observations
const MIN_SMART_TTL: u32 = 10;
const MAX_SMART_TTL: u32 = 86400; // allow up to 24h for ultra-frequent domains
const MAX_LEARNED_DOMAINS: usize = 5_000; // 5k domains × ~200 bytes = ~1 MB max

struct TtlStats {
    samples: VecDeque<u32>,
    ema: f64,
    hit_count: u64,
}

impl TtlStats {
    fn new(first: u32) -> Self {
        let mut samples = VecDeque::with_capacity(MAX_SAMPLES);
        samples.push_back(first);
        Self {
            samples,
            ema: first as f64,
            hit_count: 1,
        }
    }

    fn record_hit(&mut self) {
        self.hit_count = self.hit_count.saturating_add(1);
    }

    fn observe(&mut self, ttl: u32) {
        self.hit_count = self.hit_count.saturating_add(1);
        if self.samples.len() >= MAX_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(ttl);
        // EMA update: new = alpha*ttl + (1-alpha)*old
        self.ema = EMA_ALPHA * ttl as f64 + (1.0 - EMA_ALPHA) * self.ema;
    }

    /// Frequency-boosted smart TTL and SWR grace calculation:
    /// - Normal / infrequent domains (< 5 hits): Base authoritative TTL (clamped 10s - 3600s), 300s grace
    /// - Moderately frequent (5 - 19 hits): 2x multiplier (min 600s, max 7200s), 600s grace
    /// - Highly frequent (20 - 99 hits): 4x multiplier (min 1800s, max 28800s), 1800s grace
    /// - Ultra frequent (>= 100 hits): 8x multiplier (min 3600s, max 86400s), 3600s grace
    fn smart_ttl_and_grace(&self) -> (u32, u32) {
        let base = (self.ema.round() as u32).clamp(MIN_SMART_TTL, 3600);
        if self.hit_count < 5 {
            (base, 300)
        } else if self.hit_count < 20 {
            let boosted = (base.saturating_mul(2)).clamp(600, 7200);
            (boosted, 600)
        } else if self.hit_count < 100 {
            let boosted = (base.saturating_mul(4)).clamp(1800, 28800);
            (boosted, 1800)
        } else {
            let boosted = (base.saturating_mul(8)).clamp(3600, MAX_SMART_TTL);
            (boosted, 3600)
        }
    }

    fn smart_ttl(&self) -> u32 {
        self.smart_ttl_and_grace().0
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

    /// Increments the access frequency counter for a domain upon cache hit
    pub fn record_hit(&self, domain: &str) {
        let clean = domain.trim_end_matches('.').to_ascii_lowercase();
        let mut map = self.inner.write();
        if let Some(stats) = map.get_mut(&clean) {
            stats.record_hit();
        } else if map.len() < MAX_LEARNED_DOMAINS {
            let mut stats = TtlStats::new(300);
            stats.hit_count = 1;
            map.insert(clean, stats);
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
        self.smart_ttl_and_grace(domain, default_ttl).0
    }

    /// Returns (smart_ttl, smart_grace) accounting for query frequency.
    pub fn smart_ttl_and_grace(&self, domain: &str, default_ttl: u32) -> (u32, u32) {
        let clean = domain.trim_end_matches('.').to_ascii_lowercase();
        let map = self.inner.read();
        if let Some(stats) = map.get(&clean) {
            stats.smart_ttl_and_grace()
        } else {
            (default_ttl.clamp(MIN_SMART_TTL, 3600), 300)
        }
    }

    /// Returns the tracked hit frequency for a domain.
    #[allow(dead_code)]
    pub fn hit_count(&self, domain: &str) -> u64 {
        let clean = domain.trim_end_matches('.').to_ascii_lowercase();
        let map = self.inner.read();
        map.get(&clean).map(|s| s.hit_count).unwrap_or(0)
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

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_frequency_ttl_boosting() {
        let learner = TtlLearner::new();
        // Initial observation with 60s TTL
        learner.observe("example.com", 60);
        let (ttl1, grace1) = learner.smart_ttl_and_grace("example.com", 60);
        assert_eq!(ttl1, 60);
        assert_eq!(grace1, 300);

        // Simulate 6 hits
        for _ in 0..5 {
            learner.record_hit("example.com");
        }
        let (ttl2, grace2) = learner.smart_ttl_and_grace("example.com", 60);
        assert_eq!(ttl2, 600); // boosted to 600s
        assert_eq!(grace2, 600);

        // Simulate 25 hits
        for _ in 0..20 {
            learner.record_hit("example.com");
        }
        let (ttl3, grace3) = learner.smart_ttl_and_grace("example.com", 60);
        assert_eq!(ttl3, 1800); // boosted to 1800s
        assert_eq!(grace3, 1800);

        // Simulate 100 hits
        for _ in 0..80 {
            learner.record_hit("example.com");
        }
        let (ttl4, grace4) = learner.smart_ttl_and_grace("example.com", 60);
        assert_eq!(ttl4, 3600); // boosted to 3600s
        assert_eq!(grace4, 3600);
    }
}
