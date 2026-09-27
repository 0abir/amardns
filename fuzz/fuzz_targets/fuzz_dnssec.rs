// Fuzz target: DNSSEC record extraction and validation
//
// Exercises the DNSSEC wire parsing pipeline with arbitrary byte sequences,
// including the newly fixed RFC 4034 §3.1.8.1 RRset canonicalization path.
// Key surfaces:
//   - extract_dnssec_records  (parses RRSIG, DNSKEY, DS, NSEC, NSEC3 from wire)
//   - validate_dnssec         (calls extract_covered_rrset + build_rrsig_signed_data)
//   - Individual RDATA parsers: parse_rrsig_rdata, parse_dnskey_rdata, parse_ds_rdata
//   - NSEC3 hashing via hash_nsec3_name
//
// Run with:
//   cargo +nightly fuzz run fuzz_dnssec -- -max_total_time=86400

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Full DNSSEC extraction pipeline (RRSIG/DNSKEY/DS/NSEC/NSEC3)
    let extracted = amardns::dns::dnssec::extract_dnssec_records(data);

    // 2. Full validation pipeline (time-window check + signature verification + chain)
    let _ = amardns::dns::dnssec::validate_dnssec(data, Some(1_700_000_000));

    // 3. Individual RDATA parsers
    let _ = amardns::dns::dnssec::parse_rrsig_rdata(data, "example.com.".to_string());
    let _ = amardns::dns::dnssec::parse_dnskey_rdata(data, "example.com.".to_string());
    let _ = amardns::dns::dnssec::parse_ds_rdata(data, "example.com.".to_string());

    // 4. NSEC3 hash function with extracted parameters
    if !extracted.nsec3s.is_empty() {
        let n = &extracted.nsec3s[0];
        let _ = amardns::dns::dnssec::hash_nsec3_name(
            "fuzz.example.com",
            n.hash_algorithm,
            n.iterations.min(50), // cap iterations to avoid extreme CPU in fuzzing
            &n.salt,
        );
    } else {
        // Default: SHA-1 with empty salt
        let _ = amardns::dns::dnssec::hash_nsec3_name("fuzz.example.com", 1, 0, &[]);
    }

    // 5. DS digest calculation
    if let Some(dnskey) = amardns::dns::dnssec::parse_dnskey_rdata(data, ".".to_string()) {
        let _ = amardns::dns::dnssec::calculate_ds_digest(".", &dnskey, 2);
        let _ = amardns::dns::dnssec::calculate_ds_digest(".", &dnskey, 4);
    }
});
