use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use moka::future::Cache;

#[derive(Clone)]
pub struct CachedResponse {
    pub raw_response: Vec<u8>,
    pub created_at: Instant,
    pub original_ttl: u32,
}

pub struct DnsCache {
    cache: Cache<String, CachedResponse>,
    neg_cache: Cache<String, (Instant, u32)>,
    neg_hits: AtomicU64,
    max_capacity: u64,
}

impl DnsCache {
    pub fn new(max_capacity: u64) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(max_capacity)
                .time_to_idle(Duration::from_secs(3600))
                .build(),
            neg_cache: Cache::builder()
                .max_capacity(50_000)
                .time_to_idle(Duration::from_secs(600))
                .build(),
            neg_hits: AtomicU64::new(0),
            max_capacity,
        }
    }

    #[inline(always)]
    fn make_key(qname: &str, qtype: u16) -> String {
        let clean = qname.trim_end_matches('.');
        let mut key = String::with_capacity(clean.len() + 6);
        for b in clean.bytes() {
            key.push(b.to_ascii_lowercase() as char);
        }
        key.push(':');
        use std::fmt::Write;
        let _ = write!(key, "{}", qtype);
        key
    }

    pub async fn get(&self, qname: &str, qtype: u16, client_tx_id: u16) -> Option<Vec<u8>> {
        let key = Self::make_key(qname, qtype);
        if let Some(entry) = self.cache.get(&key).await {
            let elapsed_secs = entry.created_at.elapsed().as_secs() as u32;
            if elapsed_secs >= entry.original_ttl {
                self.cache.invalidate(&key).await;
                return None;
            }

            let mut out = entry.raw_response.clone();
            // Rewrite transaction ID to match the client's query
            if out.len() >= 2 {
                out[0..2].copy_from_slice(&client_tx_id.to_be_bytes());
            }
            return Some(out);
        }
        None
    }

    pub async fn insert(&self, qname: &str, qtype: u16, raw_response: Vec<u8>, ttl: u32) {
        let key = Self::make_key(qname, qtype);
        let safe_ttl = ttl.clamp(10, 86400);
        let entry = CachedResponse {
            raw_response,
            created_at: Instant::now(),
            original_ttl: safe_ttl,
        };
        self.cache.insert(key, entry).await;
    }

    pub async fn get_negative(&self, qname: &str) -> bool {
        let clean = qname.trim_end_matches('.').to_ascii_lowercase();
        if let Some((created, ttl)) = self.neg_cache.get(&clean).await {
            if created.elapsed().as_secs() as u32 <= ttl {
                self.neg_hits.fetch_add(1, Ordering::Relaxed);
                return true;
            } else {
                self.neg_cache.invalidate(&clean).await;
            }
        }
        false
    }

    pub async fn insert_negative(&self, qname: &str, ttl: u32) {
        let clean = qname.trim_end_matches('.').to_ascii_lowercase();
        let safe_ttl = ttl.clamp(5, 300);
        self.neg_cache.insert(clean, (Instant::now(), safe_ttl)).await;
    }

    pub fn get_neg_stats(&self) -> (usize, u64) {
        (self.neg_cache.entry_count() as usize, self.neg_hits.load(Ordering::Relaxed))
    }

    pub async fn invalidate_negative(&self, qname: &str) {
        let clean = qname.trim_end_matches('.').to_ascii_lowercase();
        self.neg_cache.invalidate(&clean).await;
    }

    pub async fn clear(&self) {
        self.cache.invalidate_all();
        self.neg_cache.invalidate_all();
        self.neg_hits.store(0, Ordering::Relaxed);
    }

    pub fn get_stats(&self) -> (usize, u64, f64, u64) {
        let count = self.cache.entry_count() as usize;
        let bytes = (count as u64) * 256;
        let mb = (bytes as f64 / (1024.0 * 1024.0) * 100.0).round() / 100.0;
        (count, bytes, mb, self.max_capacity)
    }

    #[allow(dead_code)]
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.cache.entry_count() as usize
    }
}
