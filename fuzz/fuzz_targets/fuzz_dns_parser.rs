// Fuzz target: DNS wire-format parser
//
// Exercises the full DNS wire parsing pipeline with arbitrary byte sequences.
// The parser is the first thing that touches untrusted network data in AmarDNS,
// so this is the highest-priority fuzz surface.
//
// Run with:
//   cargo +nightly fuzz run fuzz_dns_parser -- -max_total_time=86400
//
// Seed corpus (from tests/fixtures/ and real captured packets) significantly
// improves coverage speed.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. DNS query parser (question section, name decompression, EDNS0)
    let _ = amardns::dns::parser::parse_dns_query(data);

    // 2. Bare name label parser with arbitrary offsets
    for start in [0usize, 1, 2, 4, 12] {
        if start <= data.len() {
            let _ = amardns::dns::parser::parse_name_with_offset(data, start);
        }
    }

    // 3. Name skipper (used in RRSIG extraction and extraction loops)
    let _ = amardns::dns::parser::skip_dns_name(data, 0);

    // 4. End-to-end: build a blocked response from arbitrary input
    //    (exercises the response builder path)
    if data.len() >= 12 {
        let _ = amardns::dns::parser::build_blocked_response(data, false);
        let _ = amardns::dns::parser::build_blocked_response(data, true);
    }
});
