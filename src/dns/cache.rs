use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use moka::future::Cache;

#[derive(Clone)]
pub struct CachedResponse {
    pub raw_response: Vec<u8>,
    pub created_at: Instant,
    pub original_ttl: u32,
    pub stale_grace_secs: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CacheLookupResult {
    Fresh(Vec<u8>),
    Stale(Vec<u8>),
    Miss,
}

pub struct DnsCache {
    cache: Cache<String, CachedResponse>,
    neg_cache: Cache<String, (Instant, u32)>,
    neg_hits: AtomicU64,
    swr_hits: AtomicU64,
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
            swr_hits: AtomicU64::new(0),
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

    /// Fast lookup supporting RFC 8767 Stale-While-Revalidate (Serve-Stale).
    /// Returns:
    /// - Fresh: within original TTL (no upstream query needed)
    /// - Stale: expired but within grace period (sub-0.1ms immediate return with 5s downstream TTL; triggers background revalidation)
    /// - Miss: completely expired or not in cache
    pub async fn get_with_swr(&self, qname: &str, qtype: u16, client_tx_id: u16) -> CacheLookupResult {
        let key = Self::make_key(qname, qtype);
        if let Some(entry) = self.cache.get(&key).await {
            let elapsed_secs = entry.created_at.elapsed().as_secs() as u32;
            if elapsed_secs < entry.original_ttl {
                let mut out = entry.raw_response.clone();
                if out.len() >= 2 {
                    out[0..2].copy_from_slice(&client_tx_id.to_be_bytes());
                }
                return CacheLookupResult::Fresh(out);
            } else if elapsed_secs < entry.original_ttl.saturating_add(entry.stale_grace_secs) {
                self.swr_hits.fetch_add(1, Ordering::Relaxed);
                let mut out = entry.raw_response.clone();
                if out.len() >= 2 {
                    out[0..2].copy_from_slice(&client_tx_id.to_be_bytes());
                }
                Self::cap_response_ttl(&mut out, 5);
                return CacheLookupResult::Stale(out);
            } else {
                self.cache.invalidate(&key).await;
                return CacheLookupResult::Miss;
            }
        }
        CacheLookupResult::Miss
    }

    pub async fn get(&self, qname: &str, qtype: u16, client_tx_id: u16) -> Option<Vec<u8>> {
        match self.get_with_swr(qname, qtype, client_tx_id).await {
            CacheLookupResult::Fresh(out) | CacheLookupResult::Stale(out) => Some(out),
            CacheLookupResult::Miss => None,
        }
    }

    pub async fn insert(&self, qname: &str, qtype: u16, raw_response: Vec<u8>, ttl: u32) {
        self.insert_with_grace(qname, qtype, raw_response, ttl, 300).await;
    }

    pub async fn insert_with_grace(&self, qname: &str, qtype: u16, raw_response: Vec<u8>, ttl: u32, grace_secs: u32) {
        let key = Self::make_key(qname, qtype);
        let safe_ttl = ttl.clamp(10, 86400);
        let safe_grace = grace_secs.clamp(30, 3600);
        let entry = CachedResponse {
            raw_response,
            created_at: Instant::now(),
            original_ttl: safe_ttl,
            stale_grace_secs: safe_grace,
        };
        self.cache.insert(key, entry).await;
    }

    /// Rewrites answer record TTLs to a capped ceiling in DNS wire format
    pub fn cap_response_ttl(wire: &mut [u8], max_ttl: u32) {
        if wire.len() < 12 {
            return;
        }
        let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
        let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;
        if ancount == 0 {
            return;
        }

        let mut pos = 12;
        // Skip Question records
        for _ in 0..qdcount {
            while pos < wire.len() {
                let len = wire[pos] as usize;
                if len == 0 {
                    pos += 1;
                    break;
                }
                if len & 0xc0 == 0xc0 {
                    pos += 2;
                    break;
                }
                pos += 1 + len;
            }
            pos += 4; // QTYPE (2) + QCLASS (2)
            if pos > wire.len() {
                return;
            }
        }

        // Walk Answer records and cap TTL
        let max_ttl_bytes = max_ttl.to_be_bytes();
        for _ in 0..ancount {
            if pos >= wire.len() {
                break;
            }
            // Skip NAME
            while pos < wire.len() {
                let len = wire[pos] as usize;
                if len == 0 {
                    pos += 1;
                    break;
                }
                if len & 0xc0 == 0xc0 {
                    pos += 2;
                    break;
                }
                pos += 1 + len;
            }
            if pos + 10 > wire.len() {
                break;
            }
            let ttl_offset = pos + 4; // TYPE(2) + CLASS(2)
            let curr_ttl = u32::from_be_bytes([
                wire[ttl_offset],
                wire[ttl_offset + 1],
                wire[ttl_offset + 2],
                wire[ttl_offset + 3],
            ]);
            if curr_ttl > max_ttl {
                wire[ttl_offset..ttl_offset + 4].copy_from_slice(&max_ttl_bytes);
            }
            let rdlen = u16::from_be_bytes([wire[pos + 8], wire[pos + 9]]) as usize;
            pos += 10 + rdlen;
        }
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

    pub fn get_swr_hits(&self) -> u64 {
        self.swr_hits.load(Ordering::Relaxed)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_swr_fresh_stale_and_miss() {
        let cache = DnsCache::new(100);
        let dummy_resp = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];

        // Insert with TTL 10 (minimum safe clamp) and grace 60s
        cache.insert_with_grace("example.com", 1, dummy_resp.clone(), 10, 60).await;

        // Immediately look up: Fresh
        let res1 = cache.get_with_swr("example.com", 1, 0xabcd).await;
        match res1 {
            CacheLookupResult::Fresh(wire) => {
                assert_eq!(wire[0..2], [0xab, 0xcd]);
            }
            _ => panic!("Expected Fresh lookup"),
        }

        // Test missing domain
        let res_miss = cache.get_with_swr("unknown.org", 1, 0x1111).await;
        assert_eq!(res_miss, CacheLookupResult::Miss);
    }
}
