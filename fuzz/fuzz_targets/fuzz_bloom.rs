// Fuzz target: Bloom filter
//
// Exercises the Bloom filter's `contains_bytes` and `contains_wire` methods
// with arbitrary byte sequences. The wire-native path (`contains_wire`) traverses
// DNS wire labels and compression pointers without heap allocation, so this
// surface is important for catching any pointer arithmetic issues.
//
// Run with:
//   cargo +nightly fuzz run fuzz_bloom -- -max_total_time=86400

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Build a small Bloom filter (128 KB, k=9 probes — same as whitelist profile)
    let filter = amardns::security::bloom::BloomFilter::for_whitelist();

    // 1. Arbitrary byte-slice lookup (zero-copy hashing path)
    let _ = filter.contains_bytes(data);

    // 2. Wire-format name lookup (label-walking + compression pointer path)
    //    Pass the whole buffer as a fake DNS wire packet starting at offset 0
    let _ = filter.contains_wire(data, 0);

    // 3. Insert a random domain name derived from input and re-query
    if !data.is_empty() {
        // Convert bytes to a printable pseudo-domain so the insert path exercises
        // the label encoder without triggering encoding panics
        let label: String = data
            .iter()
            .take(63)
            .map(|&b| char::from(b.clamp(b'a', b'z')))
            .collect();
        if !label.is_empty() {
            let domain = format!("{}.example.com", label);
            let mut filter2 = amardns::security::bloom::BloomFilter::for_whitelist();
            filter2.insert(&domain);
            let _ = filter2.contains(&domain);
            filter2.insert_bytes(data);
            let _ = filter2.contains_bytes(data);
        }
    }
});
