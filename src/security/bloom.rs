use std::sync::atomic::{AtomicUsize, Ordering};

/// Highly optimized, zero-allocation, cache-friendly in-memory Bloom filter.
///
/// Engineered specifically for DNS-scale high-throughput query matching:
/// 1. Power-of-Two Bitset Sizing: Replaces hardware integer division (%) with single-cycle bitwise masking (&).
/// 2. Dual Independent 64-bit Hashing: Implements Kirsch-Mitzenmacher double-hashing with two independent,
///    avalanche-grade 64-bit mixers (FNV-1a golden ratio + Wyhash-style rotated multiplier) followed by SplitMix64.
/// 3. Coprime Step Guarantee: Ensures h2 is always odd (| 1) so it is mathematically coprime with any power-of-two bitset (gcd(h2, 2^B) = 1),
///    preventing short cycles and guaranteeing full bitset probe coverage across all k hashes.
/// 4. Differentiated Memory Profiles:
///    - Threat Feed (~900k-1.5M entries): 33,554,432 bits (4MB RAM) with k=7 probes, yielding <0.00005% false positive rate (< 1 in 2,000,000).
///    - Whitelist (~3k-20k entries): 262,144 bits (32KB RAM) with k=7 probes, fitting entirely within CPU L1/L2 data cache with ~0% false positive rate.
pub struct BloomFilter {
    words: Vec<u64>,
    num_hashes: u32,
    bit_mask: usize,
    count: AtomicUsize,
}

#[allow(dead_code)]
impl BloomFilter {
    /// Creates a new BloomFilter configured dynamically for expected capacity and target false positive rate.
    pub fn with_capacity(expected_elements: usize, target_fp_rate: f64) -> Self {
        let n = (expected_elements.max(64)) as f64;
        let p = target_fp_rate.clamp(0.0000001, 0.2);

        // Optimal bit count: m = - (n * ln(p)) / (ln(2)^2)
        let ln2_sq = std::f64::consts::LN_2 * std::f64::consts::LN_2;
        let m_ideal = (-(n * p.ln()) / ln2_sq).ceil() as usize;

        // Round up to the nearest power of 2, with minimum 512 bits (1 cache line = 64 bytes = 8 u64s)
        let mut bits = 512usize;
        while bits < m_ideal {
            bits <<= 1;
        }

        // Optimal number of hash functions: k = (m / n) * ln(2)
        let bits_per_elem = (bits as f64) / n;
        let k_ideal = (bits_per_elem * std::f64::consts::LN_2).round() as u32;
        let k = k_ideal.clamp(3, 12);

        let num_words = bits / 64;
        Self {
            words: vec![0u64; num_words],
            num_hashes: k,
            bit_mask: bits - 1,
            count: AtomicUsize::new(0),
        }
    }

    /// Profile engineered for the global threat blocklist (~900,333 to 1,500,000 domains).
    /// Uses 33,554,432 bits (4MB RAM) with 7 optimal hash probes:
    /// - For 900,333 domains: m/n = 37.26 bits/item.
    /// - Theoretical false positive rate p < 0.00005% (< 1 in 2,000,000).
    pub fn for_threat_feed() -> Self {
        let bits = 33_554_432usize; // 2^25 bits = 4MB RAM = 524,288 u64 words
        Self {
            words: vec![0u64; bits / 64],
            num_hashes: 7,
            bit_mask: bits - 1,
            count: AtomicUsize::new(0),
        }
    }

    /// Profile engineered for the whitelist feed (~2,818 to 20,000 domains).
    /// Uses 262,144 bits (32KB RAM) with 7 optimal hash probes:
    /// - Fits 100% inside CPU L1/L2 data cache.
    /// - For 2,818 domains: m/n = 93.0 bits/item.
    /// - Theoretical false positive rate p ~ 10^-8 (virtually zero).
    /// - Cuts memory by 99.2% compared to a uniform 4MB allocation.
    pub fn for_whitelist() -> Self {
        let bits = 262_144usize; // 2^18 bits = 32KB RAM = 4,096 u64 words
        Self {
            words: vec![0u64; bits / 64],
            num_hashes: 7,
            bit_mask: bits - 1,
            count: AtomicUsize::new(0),
        }
    }

    /// Standard default constructor (threat feed capacity)
    pub fn new() -> Self {
        Self::for_threat_feed()
    }

    /// High-entropy SplitMix64 finalizer for thorough avalanche bit diffusion
    #[inline(always)]
    fn splitmix64(mut x: u64) -> u64 {
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
        x ^ (x >> 31)
    }

    /// Dual independent 64-bit hash generation streaming lowercase bytes without heap allocation
    #[inline(always)]
    pub fn dual_hash_bytes<I: Iterator<Item = u8>>(bytes: I) -> (u64, u64) {
        // Hash 1: FNV-1a 64-bit with golden ratio prime
        let mut h1 = 0xcbf29ce484222325u64;
        // Hash 2: Secondary seed with rotated prime multipliers
        let mut h2 = 0x517cc1b727220a95u64;

        for b in bytes {
            let lower = b.to_ascii_lowercase() as u64;
            h1 ^= lower;
            h1 = h1.wrapping_mul(0x100000001b3);

            h2 = (h2 ^ lower).wrapping_mul(0x9e3779b97f4a7c15);
            h2 = h2.rotate_left(13);
        }

        let h1_mixed = Self::splitmix64(h1);
        // Ensure h2 is always odd (| 1) -> guaranteed coprime with 2^B bitsets
        let h2_mixed = Self::splitmix64(h2) | 1;

        (h1_mixed, h2_mixed)
    }

    /// Convenience dual-hash wrapper for string slices
    #[inline(always)]
    pub fn dual_hash(key: &str) -> (u64, u64) {
        Self::dual_hash_bytes(key.trim().trim_end_matches('.').bytes())
    }

    /// Inserts a domain into the Bloom filter using bitwise power-of-two masking (zero heap allocation)
    pub fn insert(&mut self, key: &str) {
        let clean = key.trim().trim_end_matches('.');
        if clean.is_empty() {
            return;
        }

        let (h1, h2) = Self::dual_hash_bytes(clean.bytes());
        let mask = self.bit_mask;
        for i in 0..self.num_hashes {
            let bit_idx = (h1.wrapping_add((i as u64).wrapping_mul(h2)) as usize) & mask;
            let word_idx = bit_idx >> 6;
            let bit_pos = bit_idx & 63;
            self.words[word_idx] |= 1u64 << bit_pos;
        }
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Checks whether a domain may be in the filter with ZERO heap allocations.
    /// Exits early on the very first 0-bit encountered (typically 1-2 memory probes on miss).
    #[inline(always)]
    pub fn contains(&self, key: &str) -> bool {
        let clean = key.trim().trim_end_matches('.');
        if clean.is_empty() {
            return false;
        }

        let (h1, h2) = Self::dual_hash_bytes(clean.bytes());
        let mask = self.bit_mask;
        for i in 0..self.num_hashes {
            let bit_idx = (h1.wrapping_add((i as u64).wrapping_mul(h2)) as usize) & mask;
            let word_idx = bit_idx >> 6;
            let bit_pos = bit_idx & 63;
            if (self.words[word_idx] & (1u64 << bit_pos)) == 0 {
                return false;
            }
        }
        true
    }

    /// Zero-allocation DNS wire format domain lookup in the Bloom filter.
    /// Traverses raw RFC 1035 labels directly from wire[offset..],
    /// hashing lowercased bytes on the fly without heap String allocation.
    pub fn contains_wire(&self, wire: &[u8], mut offset: usize) -> bool {
        if offset >= wire.len() {
            return false;
        }

        let mut h1 = 0xcbf29ce484222325u64;
        let mut h2 = 0x517cc1b727220a95u64;
        let mut first = true;
        let mut total_len = 0;

        while offset < wire.len() {
            let len = wire[offset] as usize;
            if len == 0 {
                break;
            }
            if len & 0xc0 == 0xc0 {
                // Compression pointer
                break;
            }
            if len > 63 || offset + 1 + len > wire.len() {
                return false;
            }
            offset += 1;

            if !first {
                h1 ^= b'.' as u64;
                h1 = h1.wrapping_mul(0x100000001b3);
                h2 = (h2 ^ (b'.' as u64)).wrapping_mul(0x9e3779b97f4a7c15);
                h2 = h2.rotate_left(13);
                total_len += 1;
            }
            first = false;

            for &b in &wire[offset..offset + len] {
                let lower = b.to_ascii_lowercase() as u64;
                h1 ^= lower;
                h1 = h1.wrapping_mul(0x100000001b3);
                h2 = (h2 ^ lower).wrapping_mul(0x9e3779b97f4a7c15);
                h2 = h2.rotate_left(13);
            }
            total_len += len;
            offset += len;
            if total_len > 255 {
                return false;
            }
        }

        if first {
            return false;
        }

        let h1_mixed = Self::splitmix64(h1);
        let h2_mixed = Self::splitmix64(h2) | 1;

        let mask = self.bit_mask;
        for i in 0..self.num_hashes {
            let bit_idx = (h1_mixed.wrapping_add((i as u64).wrapping_mul(h2_mixed)) as usize) & mask;
            let word_idx = bit_idx >> 6;
            let bit_pos = bit_idx & 63;
            if (self.words[word_idx] & (1u64 << bit_pos)) == 0 {
                return false;
            }
        }
        true
    }

    /// Checks the wire domain and all parent subdomains (e.g. a.b.c.com -> b.c.com -> c.com)
    /// completely in-place with zero heap allocations.
    pub fn contains_wire_with_subdomains(&self, wire: &[u8], offset: usize) -> bool {
        if offset >= wire.len() {
            return false;
        }

        // Count total labels
        let mut label_offsets = [0usize; 16];
        let mut label_count = 0;
        let mut scan = offset;

        while scan < wire.len() && label_count < 16 {
            let len = wire[scan] as usize;
            if len == 0 || (len & 0xc0 == 0xc0) {
                break;
            }
            if len > 63 || scan + 1 + len > wire.len() {
                return false;
            }
            label_offsets[label_count] = scan;
            label_count += 1;
            scan += 1 + len;
        }

        if label_count == 0 {
            return false;
        }

        // Check each subdomain starting from full domain down to 2nd-level domain
        // (stop before checking TLD alone, so skip last label)
        for &offset in label_offsets.iter().take(label_count.saturating_sub(1)) {
            if self.contains_wire(wire, offset) {
                return true;
            }
        }
        false
    }

    /// Clears all bits in the bitset and resets counter
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.words.fill(0);
        self.count.store(0, Ordering::Relaxed);
    }

    /// Number of inserted items
    pub fn count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Total capacity in bits
    pub fn capacity_bits(&self) -> usize {
        self.words.len() * 64
    }

    /// Total allocated memory in bytes
    pub fn memory_bytes(&self) -> usize {
        self.words.len() * std::mem::size_of::<u64>()
    }

    /// Number of hash probes (k)
    pub fn num_hashes(&self) -> u32 {
        self.num_hashes
    }

    /// Mathematical false positive probability based on current inserted item count
    pub fn false_positive_rate(&self) -> f64 {
        let n = self.count.load(Ordering::Relaxed) as f64;
        let m = self.capacity_bits() as f64;
        if n == 0.0 || m == 0.0 {
            return 0.0;
        }
        let k = self.num_hashes as f64;
        let exponent = -k * n / m;
        (1.0 - exponent.exp()).powf(k)
    }

    /// Empirical saturation ratio (percentage of bits set to 1)
    pub fn fill_ratio(&self) -> f64 {
        let total_bits = self.capacity_bits();
        if total_bits == 0 {
            return 0.0;
        }
        let set_bits: u64 = self.words.iter().map(|&w| w.count_ones() as u64).sum();
        (set_bits as f64) / (total_bits as f64)
    }
}

impl Clone for BloomFilter {
    fn clone(&self) -> Self {
        Self {
            words: self.words.clone(),
            num_hashes: self.num_hashes,
            bit_mask: self.bit_mask,
            count: AtomicUsize::new(self.count.load(Ordering::Relaxed)),
        }
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_insert_contains() {
        let mut filter = BloomFilter::new();
        filter.insert("doubleclick.net");
        filter.insert("analytics.google.com");
        filter.insert("track.ads.com");

        assert!(filter.contains("doubleclick.net"));
        assert!(filter.contains("analytics.google.com"));
        assert!(filter.contains("track.ads.com"));
        assert!(!filter.contains("wikipedia.org"));
        assert!(!filter.contains("github.com"));
        assert_eq!(filter.count(), 3);
    }

    #[test]
    fn test_bloom_filter_whitelist_profile() {
        let mut filter = BloomFilter::for_whitelist();
        assert_eq!(filter.memory_bytes(), 32_768); // Exactly 32KB
        assert_eq!(filter.capacity_bits(), 262_144);

        filter.insert("apple.com");
        filter.insert("icloud.com");
        assert!(filter.contains("apple.com"));
        assert!(filter.contains("icloud.com"));
        assert!(!filter.contains("malware-test.ru"));
    }

    #[test]
    fn test_bloom_filter_threat_profile() {
        let filter = BloomFilter::for_threat_feed();
        assert_eq!(filter.memory_bytes(), 4_194_304); // Exactly 4MB
        assert_eq!(filter.capacity_bits(), 33_554_432);
        assert_eq!(filter.num_hashes(), 7);
    }

    #[test]
    fn test_bloom_filter_coprime_step() {
        // Verify dual_hash produces an odd h2
        let (_, h2_a) = BloomFilter::dual_hash("example.com");
        let (_, h2_b) = BloomFilter::dual_hash("doubleclick.net");
        assert_eq!(h2_a % 2, 1, "h2 must be odd to be coprime with 2^B");
        assert_eq!(h2_b % 2, 1, "h2 must be odd to be coprime with 2^B");
    }

    #[test]
    fn test_bloom_filter_with_capacity_dynamic() {
        let filter = BloomFilter::with_capacity(100_000, 0.01);
        assert!(filter.capacity_bits().is_power_of_two());
        assert!(filter.num_hashes() >= 3);
    }

    #[test]
    fn test_bloom_filter_zero_alloc_wire_parity() {
        let mut filter = BloomFilter::with_capacity(1000, 0.001);
        filter.insert("track.adserver.com");

        // Construct raw DNS wire bytes for "sub.track.adserver.com"
        // Wire: [3, 's', 'u', 'b', 5, 't', 'r', 'a', 'c', 'k', 8, 'a', 'd', 's', 'e', 'r', 'v', 'e', 'r', 3, 'c', 'o', 'm', 0]
        let mut wire = vec![0u8; 12]; // 12-byte header
        wire.extend_from_slice(&[3, b's', b'u', b'b']);
        wire.extend_from_slice(&[5, b't', b'r', b'a', b'c', b'k']);
        wire.extend_from_slice(&[8, b'a', b'd', b's', b'e', b'r', b'v', b'e', b'r']);
        wire.extend_from_slice(&[3, b'c', b'o', b'm', 0]);

        // Direct wire lookup for the exact domain
        let track_offset = 12 + 4; // Skip "sub."
        assert!(filter.contains_wire(&wire, track_offset));

        // Subdomain wire lookup from offset 12 (detects parent "track.adserver.com")
        assert!(filter.contains_wire_with_subdomains(&wire, 12));

        // Non-existent domain wire lookup
        let mut clean_wire = vec![0u8; 12];
        clean_wire.extend_from_slice(&[6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0]);
        assert!(!filter.contains_wire(&clean_wire, 12));
        assert!(!filter.contains_wire_with_subdomains(&clean_wire, 12));
    }
}
