use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ParsedDnsQuery {
    pub tx_id: u16,
    pub flags: u16,
    pub question: Option<DnsQuestion>,
    pub question_bytes_len: usize,
}

/// Safely parses a domain name from a DNS buffer starting at `pos`, following compression pointers.
/// Returns `Some((domain_name, next_stream_pos))` where `next_stream_pos` is the position
/// in the original packet stream immediately following the domain name (or the first pointer).
pub fn parse_name_with_offset(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::with_capacity(64);
    let mut jumps = 0;
    let mut next_pos = None;
    let mut label_count = 0;

    while pos < buf.len() {
        label_count += 1;
        if label_count > 128 || jumps > 16 {
            return None; // Loop or excessive depth detected
        }
        let len = buf[pos] as usize;
        if len == 0 {
            if next_pos.is_none() {
                next_pos = Some(pos + 1);
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= buf.len() {
                return None;
            }
            let ptr = ((len & 0x3f) << 8) | (buf[pos + 1] as usize);
            if next_pos.is_none() {
                next_pos = Some(pos + 2);
            }
            if ptr >= buf.len() {
                return None; // Invalid pointer offset
            }
            pos = ptr;
            jumps += 1;
            continue;
        }
        if len > 63 {
            return None; // RFC 1035 max label length is 63 octets
        }
        pos += 1;
        if pos + len > buf.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        if name.len() + len > 253 {
            return None; // RFC 1035 max domain length
        }
        for &b in &buf[pos..pos + len] {
            name.push((b as char).to_ascii_lowercase());
        }
        pos += len;
    }

    let end_pos = next_pos.unwrap_or(pos);
    Some((name, end_pos))
}

/// Skips over a DNS name in the buffer starting at `pos` without allocating or decoding.
/// Returns the offset immediately after the name in the stream.
pub fn skip_dns_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    let mut count = 0;
    while pos < buf.len() && count < 128 {
        count += 1;
        let len = buf[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            if pos + 2 > buf.len() {
                return None;
            }
            return Some(pos + 2);
        }
        if len > 63 || pos + 1 + len > buf.len() {
            return None;
        }
        pos += 1 + len;
    }
    None
}

/// Parses a DNS packet header and question section with zero unnecessary allocations.
pub fn parse_dns_query(buf: &[u8]) -> Option<ParsedDnsQuery> {
    if buf.len() < 12 {
        return None;
    }

    let tx_id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);

    if qdcount == 0 {
        return Some(ParsedDnsQuery {
            tx_id,
            flags,
            question: None,
            question_bytes_len: 0,
        });
    }

    let (name, pos) = parse_name_with_offset(buf, 12)?;

    if pos + 4 > buf.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
    let question_bytes_len = pos + 4 - 12;

    Some(ParsedDnsQuery {
        tx_id,
        flags,
        question: Some(DnsQuestion {
            name,
            qtype,
            qclass,
        }),
        question_bytes_len,
    })
}

/// Synthesizes an authoritative blocked DNS response (NXDOMAIN or NODATA) matching RFC 1035 + RFC 6891.
/// Preserves Question and Additional Records (EDNS0 OPT RR) from the query buffer verbatim.
pub fn build_blocked_response(query_buf: &[u8], is_nxdomain: bool) -> Vec<u8> {
    if query_buf.len() < 12 {
        return vec![0; 12];
    }
    let mut resp = query_buf.to_vec();
    let orig_flags = u16::from_be_bytes([query_buf[2], query_buf[3]]);
    let rcode = if is_nxdomain { 0x0003 } else { 0x0000 };
    // Preserve RD, CD, Opcode from original query while setting QR=1, AA=1, RA=1 and RCODE
    let new_flags = (orig_flags & 0x7900) | 0x8180 | rcode;
    resp[2..4].copy_from_slice(&new_flags.to_be_bytes());

    // ANCOUNT = 0 (no answer records), NSCOUNT = 0 (no authority records)
    resp[6..8].copy_from_slice(&0u16.to_be_bytes());
    resp[8..10].copy_from_slice(&0u16.to_be_bytes());
    // Leave QDCOUNT, ARCOUNT and all trailing bytes (including EDNS0 OPT RR) intact!
    resp
}

/// Synthesizes a SERVFAIL (RCODE = 2) response preserving EDNS0 OPT RR.
pub fn build_servfail_response(query_buf: &[u8]) -> Vec<u8> {
    if query_buf.len() < 12 {
        return vec![0; 12];
    }
    let mut resp = query_buf.to_vec();
    let orig_flags = u16::from_be_bytes([query_buf[2], query_buf[3]]);
    let new_flags = (orig_flags & 0x7900) | 0x8182; // QR=1, RA=1, RCODE=2
    resp[2..4].copy_from_slice(&new_flags.to_be_bytes());
    resp[6..8].copy_from_slice(&0u16.to_be_bytes());
    resp[8..10].copy_from_slice(&0u16.to_be_bytes());
    resp
}

/// Builds an RFC 9462 Discovery of Designated Resolvers (DDR) SVCB / HTTPS response.
/// Announces multi-protocol support for DoH3 (h3), DoH (h2), DoQ (doq), and DoT (dot)
/// on ports 443 & 853 with path /dns-query{?dns}.
pub fn build_ddr_response(query_buf: &[u8]) -> Option<Vec<u8>> {
    let parsed = parse_dns_query(query_buf)?;
    let q = parsed.question?;
    let q_clean = q.name.trim_end_matches('.').to_ascii_lowercase();
    if q_clean != "_dns.resolver.arpa" {
        return None;
    }

    if q.qtype != 64 && q.qtype != 65 && q.qtype != 255 {
        return None;
    }

    let mut resp = Vec::with_capacity(query_buf.len() + 64);
    resp.extend_from_slice(&query_buf[0..2]);
    let orig_flags = u16::from_be_bytes([query_buf[2], query_buf[3]]);
    let flags = (orig_flags & 0x0100) | 0x8580; // QR=1, AA=1, RA=1, NOERROR
    resp.extend_from_slice(&flags.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    let q_end = 12 + parsed.question_bytes_len;
    if q_end > query_buf.len() {
        return None;
    }
    resp.extend_from_slice(&query_buf[12..q_end]);

    // Answer Record (pointer 0xC00C -> _dns.resolver.arpa)
    resp.extend_from_slice(&[0xC0, 0x0C]);
    let ans_type = if q.qtype == 65 { 65u16 } else { 64u16 };
    resp.extend_from_slice(&ans_type.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // Class IN
    resp.extend_from_slice(&3600u32.to_be_bytes()); // TTL 3600s

    // SvcBinding RDATA
    let mut rdata = Vec::with_capacity(48);
    rdata.extend_from_slice(&1u16.to_be_bytes()); // Priority = 1
    rdata.push(0x00); // Target = "." (root / in-bailiwick)

    // Key 1: ALPN (h3, h2, doq, dot)
    rdata.extend_from_slice(&1u16.to_be_bytes());
    let alpn_val = b"\x02h3\x02h2\x03doq\x03dot";
    rdata.extend_from_slice(&(alpn_val.len() as u16).to_be_bytes());
    rdata.extend_from_slice(alpn_val);

    // Key 3: Port (443)
    rdata.extend_from_slice(&3u16.to_be_bytes());
    rdata.extend_from_slice(&2u16.to_be_bytes());
    rdata.extend_from_slice(&443u16.to_be_bytes());

    // Key 7: dohpath ("/dns-query{?dns}")
    rdata.extend_from_slice(&7u16.to_be_bytes());
    let dohpath_val = b"/dns-query{?dns}";
    rdata.extend_from_slice(&(dohpath_val.len() as u16).to_be_bytes());
    rdata.extend_from_slice(dohpath_val);

    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&rdata);

    Some(resp)
}

/// Ensures that a DNS query buffer includes an EDNS0 OPT record (RFC 6891) with the
/// DO (DNSSEC OK) bit set (RFC 3225).
///
/// If an OPT record already exists in the Additional section, its DO bit is set.
/// If no OPT record is present, an 11-byte standard EDNS0 OPT RR (UDP size 1232, DO=1)
/// is appended and the ARCOUNT header is incremented.
pub fn ensure_edns0_do_bit(query_buf: &[u8]) -> Vec<u8> {
    if query_buf.len() < 12 {
        return query_buf.to_vec();
    }

    let qdcount = u16::from_be_bytes([query_buf[4], query_buf[5]]) as usize;
    let ancount = u16::from_be_bytes([query_buf[6], query_buf[7]]) as usize;
    let nscount = u16::from_be_bytes([query_buf[8], query_buf[9]]) as usize;
    let arcount = u16::from_be_bytes([query_buf[10], query_buf[11]]) as usize;

    let mut pos = 12;

    // Skip question section
    for _ in 0..qdcount {
        pos = match skip_dns_name(query_buf, pos) {
            Some(p) => p + 4,
            None => return query_buf.to_vec(),
        };
        if pos > query_buf.len() {
            return query_buf.to_vec();
        }
    }

    // Skip answer and authority sections
    for _ in 0..(ancount + nscount) {
        pos = match skip_dns_name(query_buf, pos) {
            Some(p) => p,
            None => return query_buf.to_vec(),
        };
        if pos + 10 > query_buf.len() {
            return query_buf.to_vec();
        }
        let rdlen = u16::from_be_bytes([query_buf[pos + 8], query_buf[pos + 9]]) as usize;
        pos += 10 + rdlen;
        if pos > query_buf.len() {
            return query_buf.to_vec();
        }
    }

    // Check existing additional records for an OPT RR (TYPE 41)
    let mut cur_pos = pos;
    for _ in 0..arcount {
        if cur_pos >= query_buf.len() {
            break;
        }
        let (_rr_name, next_p) = match parse_name_with_offset(query_buf, cur_pos) {
            Some(res) => res,
            None => break,
        };
        cur_pos = next_p;
        if cur_pos + 10 > query_buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([query_buf[cur_pos], query_buf[cur_pos + 1]]);
        let rdlen = u16::from_be_bytes([query_buf[cur_pos + 8], query_buf[cur_pos + 9]]) as usize;

        if rtype == 41 {
            // Found existing OPT RR!
            // TTL field starts at cur_pos + 4 (4 bytes: Ext-RCODE, Version, Flags with DO bit, Z)
            // DO bit is bit 0 of flags (in big-endian, high byte at cur_pos + 6)
            let mut modified = query_buf.to_vec();
            modified[cur_pos + 6] |= 0x80; // Set DO bit
            return modified;
        }

        cur_pos += 10 + rdlen;
    }

    // No OPT record found; safely append a standard RFC 6891 EDNS0 OPT RR with DO=1
    let mut modified = query_buf.to_vec();
    let new_arcount = (arcount as u16).saturating_add(1);
    modified[10..12].copy_from_slice(&new_arcount.to_be_bytes());

    // Standard EDNS0 OPT RR:
    // NAME: 0x00 (root)
    // TYPE: 0x0029 (41 = OPT)
    // CLASS: 0x04D0 (1232 bytes UDP payload size per DNS Flag Day)
    // TTL: [0x00, 0x00, 0x80, 0x00] (Ext-RCODE=0, Version=0, DO=1, Z=0)
    // RDLEN: 0x0000 (0 bytes)
    const EDNS0_OPT_DO: [u8; 11] = [
        0x00, 0x00, 0x29, 0x04, 0xD0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    ];
    modified.extend_from_slice(&EDNS0_OPT_DO);

    modified
}

/// Checks if an IPv4 address is in a private, loopback, link-local, multicast, or reserved range.
pub fn is_rebind_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 0.0.0.0/8 (Current network / "This host on this network", RFC 1122)
    if octets[0] == 0 {
        return true;
    }
    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918 Private LAN)
    if ip.is_private() {
        return true;
    }
    // 100.64.0.0/10 (Shared Address Space / CGNAT, RFC 6598)
    if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
        return true;
    }
    // 127.0.0.0/8 (Loopback / Localhost, RFC 1122)
    if ip.is_loopback() {
        return true;
    }
    // 169.254.0.0/16 (Link-local & AWS/GCP/Azure Cloud Metadata e.g. 169.254.169.254, RFC 3927)
    if ip.is_link_local() {
        return true;
    }
    // 192.0.0.0/24 (IETF Protocol Assignments, RFC 6890)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return true;
    }
    // 192.0.2.0/24 (TEST-NET-1, RFC 5737)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }
    // 192.88.99.0/24 (6to4 Relay Anycast, RFC 7526)
    if octets[0] == 192 && octets[1] == 88 && octets[2] == 99 {
        return true;
    }
    // 198.18.0.0/15 (Network Interconnect Device Benchmark, RFC 2544)
    if octets[0] == 198 && (octets[1] & 0xFE) == 18 {
        return true;
    }
    // 198.51.100.0/24 (TEST-NET-2, RFC 5737)
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }
    // 203.0.113.0/24 (TEST-NET-3, RFC 5737)
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }
    // 224.0.0.0/4 (Multicast, RFC 5771)
    if ip.is_multicast() {
        return true;
    }
    // 240.0.0.0/4 (Reserved for future use / Class E, RFC 1112)
    if octets[0] >= 240 {
        return true;
    }
    // 255.255.255.255 (Broadcast, RFC 919)
    if ip.is_broadcast() {
        return true;
    }
    false
}

/// Checks if an IPv6 address is in a private, loopback, link-local, multicast, or reserved range.
pub fn is_rebind_ipv6(ip: &Ipv6Addr) -> bool {
    let seg = ip.segments();
    // ::1 (Loopback, RFC 4291)
    if ip.is_loopback() {
        return true;
    }
    // :: (Unspecified, RFC 4291)
    if ip.is_unspecified() {
        return true;
    }
    // Unique Local (fc00::/7) - RFC 4193
    if (seg[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // Link-Local (fe80::/10) - RFC 4291
    if (seg[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // Multicast (ff00::/8) - RFC 4291
    if ip.is_multicast() {
        return true;
    }
    // Discard prefix (100::/64, RFC 6666)
    if seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 {
        return true;
    }
    // Documentation prefix (2001:db8::/32, RFC 3849)
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return true;
    }
    // Benchmarking (2001:2::/48, RFC 5180)
    if seg[0] == 0x2001 && seg[1] == 0x0002 && seg[2] == 0 {
        return true;
    }
    // ORCHIDv2 (2001:10::/28, RFC 7343)
    if seg[0] == 0x2001 && (seg[1] & 0xfff0) == 0x0010 {
        return true;
    }
    // IPv4-mapped IPv6 (::ffff:0:0/96 or ::ffff:0:0:0/96)
    let octets = ip.octets();
    if (octets[0..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff)
        || (octets[0..12] == [0; 12])
    {
        let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
        if is_rebind_ipv4(&v4) {
            return true;
        }
    }
    // NAT64 / Well-Known IPv4-IPv6 Translation Prefix (64:ff9b::/96, RFC 6052)
    if seg[0] == 0x0064
        && seg[1] == 0xff9b
        && seg[2] == 0
        && seg[3] == 0
        && seg[4] == 0
        && seg[5] == 0
    {
        let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
        if is_rebind_ipv4(&v4) {
            return true;
        }
    }
    // NAT64 Local Translation Prefix (64:ff9b:1::/48, RFC 8215)
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001 {
        return true;
    }
    false
}

/// Checks if a domain is explicitly intended for local / internal private resolution.
pub fn is_rebind_exempt_domain(domain: &str) -> bool {
    let clean = domain.trim_end_matches('.').to_ascii_lowercase();
    clean == "localhost"
        || clean.ends_with(".localhost")
        || clean.ends_with(".local")
        || clean.ends_with(".lan")
        || clean.ends_with(".home.arpa")
        || clean.ends_with(".internal")
        || clean.ends_with(".corp")
}

/// Inspects the Answer section of a DNS response packet for DNS rebinding threats.
/// Returns Some(IpAddr) if an answer record points to a private, loopback, or link-local address.
pub fn extract_rebind_ip(buf: &[u8]) -> Option<IpAddr> {
    if buf.len() < 12 {
        return None;
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    let mut pos = 12;
    // Skip Question records
    for _ in 0..qdcount {
        pos = skip_dns_name(buf, pos)?;
        pos += 4; // QTYPE + QCLASS
        if pos > buf.len() {
            return None;
        }
    }

    // Inspect Answer records
    for _ in 0..ancount {
        if pos >= buf.len() {
            break;
        }
        // Skip NAME
        pos = match skip_dns_name(buf, pos) {
            Some(p) => p,
            None => break,
        };
        if pos + 10 > buf.len() {
            break;
        }

        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            break;
        }

        if rtype == 1 && rdlen == 4 {
            let ip = Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]);
            if is_rebind_ipv4(&ip) {
                return Some(IpAddr::V4(ip));
            }
        } else if rtype == 28 && rdlen == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[pos..pos + 16]);
            let ip = Ipv6Addr::from(octets);
            if is_rebind_ipv6(&ip) {
                return Some(IpAddr::V6(ip));
            }
        }
        pos += rdlen;
    }

    None
}

/// Converts a DNS Query Type (u16) to its standard mnemonic representation.
pub fn qtype_to_str(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        64 => "SVCB",
        65 => "HTTPS",
        255 => "ANY",
        257 => "CAA",
        _ => "OTHER",
    }
}

/// Converts a DNS Response Code (u16) to its standard RFC name.
#[allow(dead_code)]
pub fn rcode_to_str(rcode: u16) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => "UNKNOWN",
    }
}

// ── RFC 8914 Extended DNS Errors (EDE) ────────────────────────────────────────

/// Appends an RFC 8914 Extended DNS Error (EDE) EDNS0 option to a DNS wire response.
/// If an OPT RR exists, the EDE option is appended to its RDATA.
/// If no OPT RR exists, a minimal one is created containing only the EDE option.
/// EDE option layout: OPTION-CODE=15(2B) + OPTION-LENGTH(2B) + INFO-CODE(2B) + EXTRA-TEXT
pub fn append_ede_to_response(wire: &mut Vec<u8>, ede_code: u16, extra_text: &str) {
    if wire.len() < 12 {
        return;
    }
    let raw_text = extra_text.as_bytes();
    let text_bytes = if raw_text.len() > 256 {
        &raw_text[..256]
    } else {
        raw_text
    };
    let opt_data_len = 2u16 + text_bytes.len() as u16;
    let mut ede_option: Vec<u8> = Vec::with_capacity(4 + text_bytes.len());
    ede_option.extend_from_slice(&15u16.to_be_bytes()); // OPTION-CODE = 15
    ede_option.extend_from_slice(&opt_data_len.to_be_bytes()); // OPTION-LENGTH
    ede_option.extend_from_slice(&ede_code.to_be_bytes()); // INFO-CODE
    ede_option.extend_from_slice(text_bytes); // EXTRA-TEXT

    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;
    let nscount = u16::from_be_bytes([wire[8], wire[9]]) as usize;
    let arcount = u16::from_be_bytes([wire[10], wire[11]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        match skip_dns_name(wire, pos) {
            Some(p) => {
                pos = p + 4;
            }
            None => {
                ede_append_new_opt(wire, &ede_option);
                return;
            }
        }
        if pos > wire.len() {
            ede_append_new_opt(wire, &ede_option);
            return;
        }
    }
    for _ in 0..(ancount + nscount) {
        match skip_dns_name(wire, pos) {
            Some(p) => {
                pos = p;
            }
            None => {
                ede_append_new_opt(wire, &ede_option);
                return;
            }
        }
        if pos + 10 > wire.len() {
            ede_append_new_opt(wire, &ede_option);
            return;
        }
        let rdlen = u16::from_be_bytes([wire[pos + 8], wire[pos + 9]]) as usize;
        pos += 10 + rdlen;
        if pos > wire.len() {
            ede_append_new_opt(wire, &ede_option);
            return;
        }
    }

    let mut ar_pos = pos;
    for _ in 0..arcount {
        if ar_pos >= wire.len() {
            break;
        }
        let name_end = match skip_dns_name(wire, ar_pos) {
            Some(p) => p,
            None => break,
        };
        if name_end + 10 > wire.len() {
            break;
        }
        let rtype = u16::from_be_bytes([wire[name_end], wire[name_end + 1]]);
        let rdlen = u16::from_be_bytes([wire[name_end + 8], wire[name_end + 9]]) as usize;
        let rdata_end = name_end + 10 + rdlen;
        if rtype == 41 {
            if rdata_end > wire.len() {
                return;
            }
            let new_rdlen = rdlen.saturating_add(ede_option.len());
            if new_rdlen > 65535 {
                return;
            }
            wire[name_end + 8..name_end + 10].copy_from_slice(&(new_rdlen as u16).to_be_bytes());
            for (i, &b) in ede_option.iter().enumerate() {
                wire.insert(rdata_end + i, b);
            }
            return;
        }
        ar_pos = rdata_end;
        if ar_pos > wire.len() {
            break;
        }
    }

    ede_append_new_opt(wire, &ede_option);
}

fn ede_append_new_opt(wire: &mut Vec<u8>, ede_option: &[u8]) {
    if wire.len() < 12 {
        return;
    }
    let arcount = u16::from_be_bytes([wire[10], wire[11]]);
    wire[10..12].copy_from_slice(&arcount.saturating_add(1).to_be_bytes());
    let rdlen = ede_option.len() as u16;
    wire.push(0x00); // NAME = root
    wire.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT (41)
    wire.extend_from_slice(&4096u16.to_be_bytes()); // CLASS = UDP payload 4096
    wire.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // TTL = ext-rcode=0, ver=0
    wire.extend_from_slice(&rdlen.to_be_bytes()); // RDLEN
    wire.extend_from_slice(ede_option);
}

// ── DNS 0x20 Case Randomization (draft-vixie-dnsext-dns0x20) ─────────────────

/// Randomizes ASCII letter casing in the outbound QNAME using a per-query LCG PRNG
/// seeded from the transaction ID. Hardens against cache poisoning — spoofed answers
/// that fail to echo the exact casing are trivially detectable.
/// Reference: draft-vixie-dnsext-dns0x20-00
pub fn apply_dns0x20_randomization(wire: &[u8]) -> Vec<u8> {
    if wire.len() < 12 {
        return wire.to_vec();
    }
    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    if qdcount == 0 {
        return wire.to_vec();
    }
    let tx_id = u16::from_be_bytes([wire[0], wire[1]]);
    let mut out = wire.to_vec();
    let mut pos = 12;
    let mut rng = (tx_id as u64)
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    loop {
        if pos >= out.len() {
            break;
        }
        let len = out[pos] as usize;
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 {
            break;
        }
        if len > 63 || pos + 1 + len > out.len() {
            break;
        }
        pos += 1;
        for i in 0..len {
            let b = out[pos + i];
            rng = rng
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let flip = (rng >> 33) & 1;
            if b.is_ascii_alphabetic() && flip == 1 {
                out[pos + i] = b ^ 0x20;
            }
        }
        pos += len;
        if pos >= out.len() {
            break;
        }
    }
    out
}

// ── RFC 8482 ANY Query Minimal Answer ─────────────────────────────────────────

/// RFC 8482: Synthesizes a minimal HINFO record for QTYPE=ANY (255) queries
/// to prevent DNS amplification attacks. Returns None for non-ANY queries.
pub fn build_any_minimal_response(query_buf: &[u8]) -> Option<Vec<u8>> {
    let parsed = parse_dns_query(query_buf)?;
    let q = parsed.question.as_ref()?;
    if q.qtype != 255 {
        return None;
    }
    let mut resp = Vec::with_capacity(query_buf.len() + 32);
    resp.extend_from_slice(&query_buf[0..2]);
    let orig_flags = u16::from_be_bytes([query_buf[2], query_buf[3]]);
    let flags = (orig_flags & 0x0100) | 0x8180; // QR=1, RD=copy, RA=1, NOERROR
    resp.extend_from_slice(&flags.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    let q_end = 12 + parsed.question_bytes_len;
    if q_end > query_buf.len() {
        return None;
    }
    resp.extend_from_slice(&query_buf[12..q_end]);
    resp.extend_from_slice(&[0xC0, 0x0C]); // Pointer to QNAME at offset 12
    resp.extend_from_slice(&13u16.to_be_bytes()); // TYPE = HINFO (13)
    resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    resp.extend_from_slice(&3600u32.to_be_bytes()); // TTL = 3600
    let cpu = b"RFC8482";
    let rdlen = (1 + cpu.len() + 1) as u16;
    resp.extend_from_slice(&rdlen.to_be_bytes());
    resp.push(cpu.len() as u8);
    resp.extend_from_slice(cpu);
    resp.push(0u8); // OS length = 0
    Some(resp)
}

/// Truncates a DNS wire response to fit within max_bytes preserving clean record boundaries (RFC 1035 / RFC 6891).
/// Sets the TC (Truncated) bit in the header without cutting arbitrary bytes inside RDATA.
pub fn truncate_response_properly(wire: &[u8], max_bytes: usize) -> Vec<u8> {
    if wire.len() <= max_bytes || wire.len() < 12 {
        return wire.to_vec();
    }

    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;

    let mut pos = 12;
    // Skip Question section
    for _ in 0..qdcount {
        pos = match skip_dns_name(wire, pos) {
            Some(p) => p + 4,
            None => {
                let mut fallback = wire[..12.min(wire.len())].to_vec();
                if fallback.len() >= 3 {
                    fallback[2] |= 0x02;
                }
                return fallback;
            }
        };
        if pos > wire.len() {
            let mut fallback = wire[..12.min(wire.len())].to_vec();
            if fallback.len() >= 3 {
                fallback[2] |= 0x02;
            }
            return fallback;
        }
    }
    let q_end = pos;

    let mut out = Vec::with_capacity(max_bytes);
    out.extend_from_slice(&wire[..q_end]);
    // Set TC bit (bit 9 of 16-bit flags -> byte 2 bit 1: 0x02)
    out[2] |= 0x02;
    out[6..8].copy_from_slice(&0u16.to_be_bytes()); // Reset ANCOUNT
    out[8..10].copy_from_slice(&0u16.to_be_bytes()); // Reset NSCOUNT
    out[10..12].copy_from_slice(&0u16.to_be_bytes()); // Reset ARCOUNT

    let mut included_ancount = 0u16;
    for _ in 0..ancount {
        let name_end = match skip_dns_name(wire, pos) {
            Some(p) => p,
            None => break,
        };
        if name_end + 10 > wire.len() {
            break;
        }
        let rdlen = u16::from_be_bytes([wire[name_end + 8], wire[name_end + 9]]) as usize;
        let rr_end = name_end + 10 + rdlen;
        if rr_end > wire.len() {
            break;
        }
        let rr_len = rr_end - pos;
        if out.len() + rr_len <= max_bytes {
            out.extend_from_slice(&wire[pos..rr_end]);
            included_ancount += 1;
            pos = rr_end;
        } else {
            break;
        }
    }
    out[6..8].copy_from_slice(&included_ancount.to_be_bytes());
    out
}

// ── RFC 7871 EDNS0 Client Subnet (ECS) Privacy Scrubbing ────────────────────

/// RFC 7871: EDNS0 Client Subnet option code.
const ECS_OPTION_CODE: u16 = 8;

/// RFC 7871 ECS Privacy Mode:
/// - Strip: completely removes ECS option from EDNS0 OPT RR
/// - Anonymize: truncates client subnet to /16 (IPv4) or /48 (IPv6)
/// - Passthrough: returns the wire unchanged
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum EcsMode {
    Strip,
    Anonymize,
    Passthrough,
}

/// Processes EDNS0 Client Subnet options in an outbound DNS query.
/// In Strip mode: removes the ECS option entirely from the OPT RR RDATA.
/// In Anonymize mode: truncates the prefix length to /16 (IPv4) or /48 (IPv6).
/// In Passthrough mode: returns the wire unchanged.
pub fn process_ecs_option(wire: &[u8], mode: EcsMode) -> Vec<u8> {
    if mode == EcsMode::Passthrough {
        return wire.to_vec();
    }
    if wire.len() < 12 {
        return wire.to_vec();
    }

    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;
    let nscount = u16::from_be_bytes([wire[8], wire[9]]) as usize;
    let arcount = u16::from_be_bytes([wire[10], wire[11]]) as usize;

    let mut pos = 12;
    // Skip question
    for _ in 0..qdcount {
        pos = match skip_dns_name(wire, pos) {
            Some(p) => p + 4,
            None => return wire.to_vec(),
        };
        if pos > wire.len() {
            return wire.to_vec();
        }
    }
    // Skip answer + authority
    for _ in 0..(ancount + nscount) {
        pos = match skip_dns_name(wire, pos) {
            Some(p) => p,
            None => return wire.to_vec(),
        };
        if pos + 10 > wire.len() {
            return wire.to_vec();
        }
        let rdlen = u16::from_be_bytes([wire[pos + 8], wire[pos + 9]]) as usize;
        pos += 10 + rdlen;
    }

    // Walk additional section
    let mut out = wire.to_vec();
    let mut ar_pos = pos;
    for _ in 0..arcount {
        if ar_pos >= out.len() {
            break;
        }
        let name_end = match skip_dns_name(&out, ar_pos) {
            Some(p) => p,
            None => break,
        };
        if name_end + 10 > out.len() {
            break;
        }
        let rtype = u16::from_be_bytes([out[name_end], out[name_end + 1]]);
        let rdlen = u16::from_be_bytes([out[name_end + 8], out[name_end + 9]]) as usize;
        let rdata_start = name_end + 10;
        let rdata_end = rdata_start + rdlen;

        if rtype == 41 && rdata_end <= out.len() {
            // Found OPT RR - process its RDATA options
            match mode {
                EcsMode::Strip => {
                    // Remove ECS option(s) from RDATA, rebuild RDATA without ECS
                    let new_rdata = strip_ecs_from_rdata(&out[rdata_start..rdata_end]);
                    let new_rdlen = new_rdata.len();
                    // Replace RDATA
                    let mut new_out = Vec::with_capacity(out.len());
                    new_out.extend_from_slice(&out[..rdata_start]);
                    new_out.extend_from_slice(&new_rdata);
                    new_out.extend_from_slice(&out[rdata_end..]);
                    // Update RDLEN at name_end+8
                    new_out[name_end + 8..name_end + 10]
                        .copy_from_slice(&(new_rdlen as u16).to_be_bytes());
                    return new_out;
                }
                EcsMode::Anonymize => {
                    // Truncate ECS prefix length
                    anonymize_ecs_in_rdata(&mut out[rdata_start..rdata_end]);
                    return out;
                }
                EcsMode::Passthrough => unreachable!(),
            }
        }
        ar_pos = rdata_end;
        if ar_pos > out.len() {
            break;
        }
    }
    out
}

fn strip_ecs_from_rdata(rdata: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rdata.len());
    let mut pos = 0;
    while pos + 4 <= rdata.len() {
        let opt_code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let opt_len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        let opt_end = pos + 4 + opt_len;
        if opt_end > rdata.len() {
            break;
        }
        if opt_code != ECS_OPTION_CODE {
            out.extend_from_slice(&rdata[pos..opt_end]);
        }
        // Skip ECS option
        pos = opt_end;
    }
    out
}

fn anonymize_ecs_in_rdata(rdata: &mut [u8]) {
    let mut pos = 0;
    while pos + 4 <= rdata.len() {
        let opt_code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let opt_len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        let opt_end = pos + 4 + opt_len;
        if opt_end > rdata.len() {
            break;
        }
        if opt_code == ECS_OPTION_CODE && opt_len >= 4 {
            // ECS RDATA: FAMILY(2) + SOURCE PREFIX-LEN(1) + SCOPE PREFIX-LEN(1) + ADDRESS
            let family = u16::from_be_bytes([rdata[pos + 4], rdata[pos + 5]]);
            let max_prefix = if family == 1 { 16u8 } else { 48u8 }; // IPv4=/16, IPv6=/48
            if rdata[pos + 6] > max_prefix {
                rdata[pos + 6] = max_prefix;
                // Zero out address bits beyond the prefix
                let addr_start = pos + 8;
                let prefix_bytes = (max_prefix as usize).div_ceil(8);
                let addr_end = opt_end.min(addr_start + if family == 1 { 4 } else { 16 });
                if addr_start + prefix_bytes < addr_end {
                    for b in &mut rdata[addr_start + prefix_bytes..addr_end] {
                        *b = 0;
                    }
                }
            }
        }
        pos = opt_end;
    }
}

// ── RFC 7873 / RFC 8162 DNS Server Cookies Engine ───────────────────────────

/// RFC 7873: EDNS0 COOKIE option code.
pub const COOKIE_OPTION_CODE: u16 = 10;

/// Parses client and optional server cookies from an EDNS0 OPT RR in a DNS query wire packet.
/// Returns (client_cookie_8_bytes, Option<server_cookie_8_to_32_bytes>) if COOKIE option is present.
pub fn parse_dns_cookie(wire: &[u8]) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    if wire.len() < 12 {
        return None;
    }

    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;
    let nscount = u16::from_be_bytes([wire[8], wire[9]]) as usize;
    let arcount = u16::from_be_bytes([wire[10], wire[11]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_dns_name(wire, pos)? + 4;
        if pos > wire.len() {
            return None;
        }
    }
    for _ in 0..(ancount + nscount) {
        pos = skip_dns_name(wire, pos)?;
        if pos + 10 > wire.len() {
            return None;
        }
        let rdlen = u16::from_be_bytes([wire[pos + 8], wire[pos + 9]]) as usize;
        pos += 10 + rdlen;
        if pos > wire.len() {
            return None;
        }
    }

    for _ in 0..arcount {
        if pos >= wire.len() {
            break;
        }
        let name_end = skip_dns_name(wire, pos)?;
        if name_end + 10 > wire.len() {
            break;
        }
        let rtype = u16::from_be_bytes([wire[name_end], wire[name_end + 1]]);
        let rdlen = u16::from_be_bytes([wire[name_end + 8], wire[name_end + 9]]) as usize;
        let rdata_start = name_end + 10;
        let rdata_end = rdata_start + rdlen;

        if rtype == 41 && rdata_end <= wire.len() {
            let mut opt_pos = rdata_start;
            while opt_pos + 4 <= rdata_end {
                let opt_code = u16::from_be_bytes([wire[opt_pos], wire[opt_pos + 1]]);
                let opt_len = u16::from_be_bytes([wire[opt_pos + 2], wire[opt_pos + 3]]) as usize;
                let opt_data_end = opt_pos + 4 + opt_len;
                if opt_data_end > rdata_end {
                    break;
                }

                if opt_code == COOKIE_OPTION_CODE && opt_len >= 8 {
                    let client_cookie = wire[opt_pos + 4..opt_pos + 12].to_vec();
                    let server_cookie = if opt_len >= 16 {
                        Some(wire[opt_pos + 12..opt_data_end].to_vec())
                    } else {
                        None
                    };
                    return Some((client_cookie, server_cookie));
                }
                opt_pos = opt_data_end;
            }
        }
        pos = rdata_end;
    }
    None
}

/// Generates an RFC 7873 / RFC 8162 standard 16-byte server cookie:
/// Version (1B: 0x01) + Reserved (3B: 0x000000) + Timestamp (4B) + Truncated HMAC-SHA256 (8B).
pub fn generate_server_cookie(
    secret: &[u8],
    client_ip: std::net::IpAddr,
    client_cookie: &[u8],
    timestamp: u32,
) -> Vec<u8> {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let mut msg = Vec::with_capacity(36);
    match client_ip {
        std::net::IpAddr::V4(v4) => msg.extend_from_slice(&v4.octets()),
        std::net::IpAddr::V6(v6) => msg.extend_from_slice(&v6.octets()),
    }
    msg.extend_from_slice(client_cookie);
    msg.push(0x01); // Version 1
    msg.extend_from_slice(&[0x00, 0x00, 0x00]); // Reserved
    msg.extend_from_slice(&timestamp.to_be_bytes());

    let tag = ring::hmac::sign(&key, &msg);
    let hmac_8b = &tag.as_ref()[..8];

    let mut server_cookie = Vec::with_capacity(16);
    server_cookie.push(0x01);
    server_cookie.extend_from_slice(&[0x00, 0x00, 0x00]);
    server_cookie.extend_from_slice(&timestamp.to_be_bytes());
    server_cookie.extend_from_slice(hmac_8b);
    server_cookie
}

/// Verifies an incoming server cookie against client IP, client cookie, and timestamp.
/// Accepts valid server cookies within a 3600-second window.
#[allow(dead_code)]
pub fn verify_server_cookie(
    secret: &[u8],
    client_ip: std::net::IpAddr,
    client_cookie: &[u8],
    server_cookie: &[u8],
    now_unix: u32,
) -> bool {
    if server_cookie.len() != 16 || server_cookie[0] != 0x01 || client_cookie.len() != 8 {
        return false;
    }
    let cookie_time = u32::from_be_bytes([
        server_cookie[4],
        server_cookie[5],
        server_cookie[6],
        server_cookie[7],
    ]);
    if now_unix.abs_diff(cookie_time) > 3600 {
        return false;
    }
    let expected = generate_server_cookie(secret, client_ip, client_cookie, cookie_time);
    if expected.len() != server_cookie.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(server_cookie.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Appends or updates the EDNS0 COOKIE option in a response wire packet.
pub fn append_cookie_to_response(wire: &mut Vec<u8>, client_cookie: &[u8], server_cookie: &[u8]) {
    if wire.len() < 12 || client_cookie.is_empty() || server_cookie.is_empty() {
        return;
    }
    let opt_len = (client_cookie.len() + server_cookie.len()) as u16;
    let mut cookie_opt = Vec::with_capacity(4 + opt_len as usize);
    cookie_opt.extend_from_slice(&COOKIE_OPTION_CODE.to_be_bytes());
    cookie_opt.extend_from_slice(&opt_len.to_be_bytes());
    cookie_opt.extend_from_slice(client_cookie);
    cookie_opt.extend_from_slice(server_cookie);

    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;
    let nscount = u16::from_be_bytes([wire[8], wire[9]]) as usize;
    let arcount = u16::from_be_bytes([wire[10], wire[11]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        match skip_dns_name(wire, pos) {
            Some(p) => {
                pos = p + 4;
            }
            None => {
                ede_append_new_opt(wire, &cookie_opt);
                return;
            }
        }
        if pos > wire.len() {
            ede_append_new_opt(wire, &cookie_opt);
            return;
        }
    }
    for _ in 0..(ancount + nscount) {
        match skip_dns_name(wire, pos) {
            Some(p) => {
                pos = p;
            }
            None => {
                ede_append_new_opt(wire, &cookie_opt);
                return;
            }
        }
        if pos + 10 > wire.len() {
            ede_append_new_opt(wire, &cookie_opt);
            return;
        }
        let rdlen = u16::from_be_bytes([wire[pos + 8], wire[pos + 9]]) as usize;
        pos += 10 + rdlen;
        if pos > wire.len() {
            ede_append_new_opt(wire, &cookie_opt);
            return;
        }
    }

    let mut ar_pos = pos;
    for _ in 0..arcount {
        if ar_pos >= wire.len() {
            break;
        }
        let name_end = match skip_dns_name(wire, ar_pos) {
            Some(p) => p,
            None => break,
        };
        if name_end + 10 > wire.len() {
            break;
        }
        let rtype = u16::from_be_bytes([wire[name_end], wire[name_end + 1]]);
        let rdlen = u16::from_be_bytes([wire[name_end + 8], wire[name_end + 9]]) as usize;
        let rdata_end = name_end + 10 + rdlen;
        if rtype == 41 {
            if rdata_end > wire.len() {
                return;
            }
            let new_rdlen = rdlen.saturating_add(cookie_opt.len());
            if new_rdlen > 65535 {
                return;
            }
            wire[name_end + 8..name_end + 10].copy_from_slice(&(new_rdlen as u16).to_be_bytes());
            for (i, &b) in cookie_opt.iter().enumerate() {
                wire.insert(rdata_end + i, b);
            }
            return;
        }
        ar_pos = rdata_end;
        if ar_pos > wire.len() {
            break;
        }
    }

    ede_append_new_opt(wire, &cookie_opt);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_query_wire(name: &str, qtype: u16) -> Vec<u8> {
        let mut wire = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            wire.push(label.len() as u8);
            wire.extend_from_slice(label.as_bytes());
        }
        wire.push(0);
        wire.extend_from_slice(&qtype.to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes()); // IN
        wire
    }

    #[test]
    fn test_parse_dns_query() {
        // Simple A query for "example.com" with TXID 0x1234
        let query = [
            0x12, 0x34, // TXID
            0x01, 0x00, // Flags (Standard query, RD=1)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // Terminating zero
            0x00, 0x01, // QTYPE = A (1)
            0x00, 0x01, // QCLASS = IN (1)
        ];

        let parsed = parse_dns_query(&query).expect("valid query");
        assert_eq!(parsed.tx_id, 0x1234);
        let q = parsed.question.expect("question exists");
        assert_eq!(q.name, "example.com");
        assert_eq!(q.qtype, 1);
        assert_eq!(q.qclass, 1);
    }

    #[test]
    fn test_build_blocked_response_nxdomain() {
        let query = [0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let resp = build_blocked_response(&query, true);
        assert_eq!(resp[0..2], [0xAB, 0xCD]); // Match TXID
        assert_eq!(resp[3] & 0x0F, 3); // RCODE = NXDOMAIN
    }

    #[test]
    fn test_build_blocked_response_edns0_preserved() {
        let query = [
            0x12, 0x34, 0x01, 0x00, // TXID, Flags (RD=1)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x01, // ARCOUNT = 1
            0x03, b'f', b'o', b'o', 0x00, // "foo."
            0x00, 0x01, 0x00, 0x01, // A IN
            0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // OPT RR
        ];
        let resp = build_blocked_response(&query, true);
        assert_eq!(resp.len(), query.len());
        assert_eq!(resp[0..2], [0x12, 0x34]);
        assert_eq!(resp[3] & 0x0F, 3); // NXDOMAIN
        assert_eq!(resp[6..8], [0x00, 0x00]); // ANCOUNT = 0
        assert_eq!(resp[10..12], [0x00, 0x01]); // ARCOUNT preserved = 1!
        assert_eq!(&resp[resp.len() - 11..], &query[query.len() - 11..]); // OPT RR preserved!
    }

    #[test]
    fn test_ensure_edns0_do_bit_appends_when_missing() {
        let plain_query = [
            0x12, 0x34, 0x01, 0x00, // TXID, Flags
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01, // A IN
        ];
        let with_do = ensure_edns0_do_bit(&plain_query);
        assert_eq!(with_do.len(), plain_query.len() + 11);
        assert_eq!(with_do[10..12], [0x00, 0x01]); // ARCOUNT = 1
        // Check OPT record: root name 0, type 41, DO bit set (0x80)
        let opt_slice = &with_do[plain_query.len()..];
        assert_eq!(opt_slice[0], 0x00); // Root name
        assert_eq!(&opt_slice[1..3], &[0x00, 0x29]); // Type OPT (41)
        assert_eq!(&opt_slice[3..5], &[0x04, 0xD0]); // UDP size 1232
        assert_eq!(opt_slice[7], 0x80); // DO bit = 1
    }

    #[test]
    fn test_ensure_edns0_do_bit_sets_flag_when_existing() {
        let existing_opt = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, // ARCOUNT = 1
            0x03, b'f', b'o', b'o', 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DO = 0
        ];
        let with_do = ensure_edns0_do_bit(&existing_opt);
        assert_eq!(with_do.len(), existing_opt.len());
        assert_eq!(with_do[10..12], [0x00, 0x01]); // ARCOUNT remains 1
        let opt_idx = existing_opt.len() - 11;
        assert_eq!(with_do[opt_idx + 7], 0x80); // DO bit set!
    }

    #[test]
    fn test_extract_rebind_ip_detects_private_and_loopback() {
        // DNS response packet with 1 question and 1 answer pointing to 127.0.0.1
        let mut resp = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags (QR=1, RD=1, RA=1)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, 0x00, 0x00, // NSCOUNT, ARCOUNT
            // Question: "rebind.evil"
            0x06, b'r', b'e', b'b', b'i', b'n', b'd', 0x04, b'e', b'v', b'i', b'l', 0x00, 0x00,
            0x01, 0x00, 0x01, // A IN
            // Answer: compression pointer 0xc00c
            0xc0, 0x0c, 0x00, 0x01, // TYPE = A
            0x00, 0x01, // CLASS = IN
            0x00, 0x00, 0x00, 0x3c, // TTL = 60
            0x00, 0x04, // RDLENGTH = 4
            127, 0, 0, 1, // RDATA = 127.0.0.1
        ];

        let detected = extract_rebind_ip(&resp);
        assert_eq!(detected, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));

        // Change answer to 192.168.1.1 (RFC 1918)
        let last_idx = resp.len() - 4;
        resp[last_idx..].copy_from_slice(&[192, 168, 1, 1]);
        assert_eq!(
            extract_rebind_ip(&resp),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );

        // Change answer to 169.254.169.254 (Cloud metadata)
        resp[last_idx..].copy_from_slice(&[169, 254, 169, 254]);
        assert_eq!(
            extract_rebind_ip(&resp),
            Some(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)))
        );

        // Change answer to CGNAT 100.64.0.1
        resp[last_idx..].copy_from_slice(&[100, 64, 0, 1]);
        assert_eq!(
            extract_rebind_ip(&resp),
            Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)))
        );

        // Change answer to Multicast 224.0.0.251
        resp[last_idx..].copy_from_slice(&[224, 0, 0, 251]);
        assert_eq!(
            extract_rebind_ip(&resp),
            Some(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)))
        );

        // Change answer to Reserved 240.0.0.1
        resp[last_idx..].copy_from_slice(&[240, 0, 0, 1]);
        assert_eq!(
            extract_rebind_ip(&resp),
            Some(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1)))
        );

        // Change answer to public IP 8.8.8.8 -> Should NOT be detected
        resp[last_idx..].copy_from_slice(&[8, 8, 8, 8]);
        assert_eq!(extract_rebind_ip(&resp), None);

        // Test IPv6 Rebinding helpers
        assert!(is_rebind_ipv6(&"fe80::1".parse().unwrap()));
        assert!(is_rebind_ipv6(&"fc00::1".parse().unwrap()));
        assert!(is_rebind_ipv6(&"::1".parse().unwrap()));
        assert!(is_rebind_ipv6(&"::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_rebind_ipv6(&"::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_rebind_ipv6(&"64:ff9b::169.254.169.254".parse().unwrap()));
        assert!(!is_rebind_ipv6(&"2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn test_build_query_wire_and_parse_doh_json() {
        let wire = build_query_wire("example.com", 1);
        let parsed = parse_dns_query(&wire).expect("valid generated wire query");
        let q = parsed.question.expect("question exists");
        assert_eq!(q.name, "example.com");
        assert_eq!(q.qtype, 1);

        // Synthetic response wire for example.com -> 93.184.216.34
        let mut resp = wire.clone();
        resp[2] = (resp[2] | 0x80) & 0xFB; // QR = 1
        resp[3] = (resp[3] | 0x80) & 0xF0; // RA = 1
        resp[6] = 0x00;
        resp[7] = 0x01; // ANCOUNT = 1
        // Answer record: pointer 0xC00C, type A (1), class IN (1), TTL 300, len 4, IP 93.184.216.34
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
        resp.extend_from_slice(&[0x00, 0x04, 93, 184, 216, 34]);

        let (rcode, answers) = parse_answers_for_doh_json(&resp, "example.com");
        assert_eq!(rcode, 0);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].data, "93.184.216.34");
        assert_eq!(answers[0].ttl, 300);
        assert_eq!(answers[0].r#type, 1);
    }

    #[test]
    fn test_parse_dns_query_compression_pointer() {
        let mut pkt = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        pkt.extend_from_slice(&[0x03, b's', b'u', b'b', 0xC0, 22]);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=1, QCLASS=1
        pkt.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ]);

        let parsed = parse_dns_query(&pkt).expect("compressed query should parse");
        let q = parsed.question.expect("question exists");
        assert_eq!(q.name, "sub.example.com");
        assert_eq!(q.qtype, 1);
        assert_eq!(parsed.question_bytes_len, 10);
    }

    #[test]
    fn test_parse_dns_query_pointer_loop_safe() {
        let pkt = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0,
            0x0C, // points to offset 12 (itself)
            0x00, 0x01, 0x00, 0x01,
        ];
        assert!(
            parse_dns_query(&pkt).is_none(),
            "pointer loop must return None safely"
        );
    }

    #[test]
    fn test_parse_dns_query_malformed_packets() {
        // Buffer too short
        assert!(parse_dns_query(&[0x12, 0x34]).is_none());

        // Label length > 63
        let mut pkt = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 64,
        ];
        pkt.extend_from_slice(&[b'a'; 64]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        assert!(parse_dns_query(&pkt).is_none());

        // Truncated packet before QTYPE/QCLASS
        let pkt_trunc = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'f',
            b'o', b'o', 0x00, 0x00, 0x01,
        ];
        assert!(parse_dns_query(&pkt_trunc).is_none());
    }

    #[test]
    fn test_parse_dns_query_root_domain() {
        let pkt = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // Root label
            0x00, 0x02, // QTYPE = NS
            0x00, 0x01, // QCLASS = IN
        ];
        let parsed = parse_dns_query(&pkt).expect("root domain query is valid");
        let q = parsed.question.expect("question exists");
        assert_eq!(q.name, "");
        assert_eq!(q.qtype, 2);
    }

    #[test]
    fn test_build_ddr_response() {
        // Query for _dns.resolver.arpa SVCB (64)
        let mut pkt = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for l in ["_dns", "resolver", "arpa"] {
            pkt.push(l.len() as u8);
            pkt.extend_from_slice(l.as_bytes());
        }
        pkt.push(0x00);
        pkt.extend_from_slice(&64u16.to_be_bytes()); // SVCB
        pkt.extend_from_slice(&1u16.to_be_bytes()); // IN

        let resp = build_ddr_response(&pkt).expect("DDR response generated");
        assert_eq!(&resp[0..2], &[0xAB, 0xCD]);
        assert_eq!(resp[3] & 0x0F, 0); // NOERROR
        assert_eq!(resp[6..8], [0x00, 0x01]); // ANCOUNT = 1
        assert!(resp.len() > pkt.len());
    }
}

/// Extracts all IPv4 addresses from the Answer section of a DNS response wire packet.
/// Used by the passive DNS timeline to record domain→IP history.
pub fn extract_a_records(buf: &[u8]) -> Vec<std::net::IpAddr> {
    let mut ips = Vec::new();
    if buf.len() < 12 {
        return ips;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 {
        return ips;
    }

    let mut pos = 12;
    // Skip question section
    for _ in 0..qdcount {
        pos = match skip_dns_name(buf, pos) {
            Some(p) => p,
            None => return ips,
        };
        pos += 4;
        if pos > buf.len() {
            return ips;
        }
    }
    // Walk answers
    for _ in 0..ancount {
        if pos >= buf.len() {
            break;
        }
        pos = match skip_dns_name(buf, pos) {
            Some(p) => p,
            None => break,
        };
        if pos + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            break;
        }
        if rtype == 1 && rdlen == 4 {
            ips.push(std::net::IpAddr::V4(Ipv4Addr::new(
                buf[pos],
                buf[pos + 1],
                buf[pos + 2],
                buf[pos + 3],
            )));
        } else if rtype == 28 && rdlen == 16 {
            let mut b = [0u8; 16];
            b.copy_from_slice(&buf[pos..pos + 16]);
            ips.push(std::net::IpAddr::V6(Ipv6Addr::from(b)));
        }
        pos += rdlen;
    }
    ips
}

/// Extracts the minimum TTL from all answer records. Used by the TTL Manipulation Guard.
/// Returns None if no answer records found.
pub fn extract_min_ttl(buf: &[u8]) -> Option<u32> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_dns_name(buf, pos)?;
        pos += 4;
        if pos > buf.len() {
            return None;
        }
    }

    let mut min_ttl: Option<u32> = None;
    for _ in 0..ancount {
        if pos >= buf.len() {
            break;
        }
        pos = match skip_dns_name(buf, pos) {
            Some(p) => p,
            None => break,
        };
        if pos + 10 > buf.len() {
            break;
        }
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10 + rdlen;
        min_ttl = Some(min_ttl.map(|m: u32| m.min(ttl)).unwrap_or(ttl));
    }
    min_ttl
}

/// RFC 2308: Extract the SOA MINIMUM TTL from the Authority section of an NXDOMAIN/NODATA response.
/// Used for dynamic negative caching TTL instead of a hardcoded fallback.
/// Returns a TTL clamped to [5, 3600], or None if no SOA record is found.
pub fn extract_soa_minimum_ttl(wire: &[u8]) -> Option<u32> {
    if wire.len() < 12 {
        return None;
    }
    let rcode = wire[3] & 0x0F;
    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;
    let nscount = u16::from_be_bytes([wire[8], wire[9]]) as usize;
    // Only relevant for NXDOMAIN (3) or NODATA (NOERROR with no answers)
    if rcode != 3 && !(rcode == 0 && ancount == 0) {
        return None;
    }
    if nscount == 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let mut pos = 12;
    // Skip question section
    for _ in 0..qdcount {
        pos = skip_dns_name(wire, pos)?;
        pos += 4;
        if pos > wire.len() {
            return None;
        }
    }
    // Skip answer section
    for _ in 0..ancount {
        pos = skip_dns_name(wire, pos)?;
        if pos + 10 > wire.len() {
            return None;
        }
        let rdlen = u16::from_be_bytes([wire[pos + 8], wire[pos + 9]]) as usize;
        pos += 10 + rdlen;
        if pos > wire.len() {
            return None;
        }
    }
    // Parse authority section looking for SOA (type 6)
    for _ in 0..nscount {
        if pos >= wire.len() {
            return None;
        }
        let name_end = skip_dns_name(wire, pos)?;
        if name_end + 10 > wire.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([wire[name_end], wire[name_end + 1]]);
        let rdlen = u16::from_be_bytes([wire[name_end + 8], wire[name_end + 9]]) as usize;
        let rdata_start = name_end + 10;
        if rtype == 6 {
            // SOA RDATA: MNAME + RNAME + SERIAL(4) + REFRESH(4) + RETRY(4) + EXPIRE(4) + MINIMUM(4)
            let after_mname = skip_dns_name(wire, rdata_start)?;
            let after_rname = skip_dns_name(wire, after_mname)?;
            // MINIMUM is at after_rname + 16 (skip SERIAL + REFRESH + RETRY + EXPIRE)
            let minimum_offset = after_rname + 16;
            if minimum_offset + 4 <= wire.len() && minimum_offset + 4 <= rdata_start + rdlen {
                let minimum = u32::from_be_bytes([
                    wire[minimum_offset],
                    wire[minimum_offset + 1],
                    wire[minimum_offset + 2],
                    wire[minimum_offset + 3],
                ]);
                return Some(minimum.clamp(5, 3600));
            }
        }
        pos = rdata_start + rdlen;
        if pos > wire.len() {
            return None;
        }
    }
    None
}

/// Extracts the TTL from the first answer record. Used by SmartTTL learner.
pub fn extract_answer_ttl(buf: &[u8]) -> Option<u32> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_dns_name(buf, pos)?;
        pos += 4;
        if pos > buf.len() {
            return None;
        }
    }
    // Skip name of first answer
    pos = skip_dns_name(buf, pos)?;
    if pos + 8 > buf.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        buf[pos + 4],
        buf[pos + 5],
        buf[pos + 6],
        buf[pos + 7],
    ]))
}

/// Builds a standard recursive DNS query wire packet for a domain and qtype.
pub fn build_query_wire(domain: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    // Transaction ID
    buf.extend_from_slice(&[0x12, 0x34]);
    // Flags: RD=1 (recursion desired), standard query (0x0100)
    buf.extend_from_slice(&[0x01, 0x00]);
    // QDCOUNT: 1
    buf.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // Question: domain labels
    for part in domain.trim_end_matches('.').split('.') {
        if !part.is_empty() {
            buf.push(part.len() as u8);
            buf.extend_from_slice(part.as_bytes());
        }
    }
    buf.push(0x00); // root label
    // QTYPE & QCLASS: IN (1)
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x01]);
    buf
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DohAnswerRecord {
    pub name: String,
    pub r#type: u16,
    #[serde(rename = "TTL")]
    pub ttl: u32,
    pub data: String,
}

/// Safely parse a DNS domain name from a packet starting at pos, following compression pointers.
pub fn parse_domain_name_at(buf: &[u8], pos: usize) -> Option<String> {
    parse_name_with_offset(buf, pos).map(|(name, _)| {
        if name.is_empty() {
            ".".to_string()
        } else {
            name
        }
    })
}

/// Parses the answers from a raw wire DNS response into RFC 8427 format.
/// Returns (rcode, answers).
pub fn parse_answers_for_doh_json(buf: &[u8], query_domain: &str) -> (u8, Vec<DohAnswerRecord>) {
    if buf.len() < 12 {
        return (2, Vec::new()); // SERVFAIL
    }
    let rcode = buf[3] & 0x0F;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 {
        return (rcode, Vec::new());
    }

    let mut pos = 12;
    // Skip question section
    for _ in 0..qdcount {
        pos = match skip_dns_name(buf, pos) {
            Some(p) => p,
            None => return (rcode, Vec::new()),
        };
        pos += 4;
        if pos > buf.len() {
            return (rcode, Vec::new());
        }
    }

    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        if pos >= buf.len() {
            break;
        }
        // Parse record name
        let rec_name = parse_domain_name_at(buf, pos).unwrap_or_else(|| query_domain.to_string());
        // Skip over the name in the record
        pos = match skip_dns_name(buf, pos) {
            Some(p) => p,
            None => break,
        };
        if pos + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            break;
        }

        let data = match rtype {
            1 if rdlen == 4 => {
                format!(
                    "{}.{}.{}.{}",
                    buf[pos],
                    buf[pos + 1],
                    buf[pos + 2],
                    buf[pos + 3]
                )
            }
            28 if rdlen == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[pos..pos + 16]);
                std::net::Ipv6Addr::from(octets).to_string()
            }
            5 => parse_domain_name_at(buf, pos).unwrap_or_else(|| "<unknown>".to_string()),
            16 => {
                if rdlen > 1 {
                    String::from_utf8_lossy(&buf[pos + 1..pos + rdlen]).to_string()
                } else {
                    String::new()
                }
            }
            _ => buf[pos..pos + rdlen]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
        };

        answers.push(DohAnswerRecord {
            name: if rec_name.ends_with('.') {
                rec_name
            } else {
                format!("{}.", rec_name)
            },
            r#type: rtype,
            ttl,
            data,
        });

        pos += rdlen;
    }

    (rcode, answers)
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_append_ede_to_response_no_opt() {
        // Simple response without OPT RR
        let mut wire = build_blocked_response(
            &[
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65,
                0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
                0x01,
            ],
            true,
        );
        let orig_len = wire.len();
        append_ede_to_response(&mut wire, 15, "Blocked");
        // Should be longer now (OPT RR added)
        assert!(wire.len() > orig_len);
        // ARCOUNT should be 1
        let arcount = u16::from_be_bytes([wire[10], wire[11]]);
        assert_eq!(arcount, 1);
    }

    #[test]
    fn test_dns0x20_randomization_alters_casing() {
        // Build a simple query for "example.com" A
        let wire = build_query_wire("example.com", 1);
        let randomized = apply_dns0x20_randomization(&wire);
        // The wire should have same length
        assert_eq!(wire.len(), randomized.len());
        // At least check it doesn't corrupt structure (parseable)
        let parsed = parse_dns_query(&randomized);
        assert!(parsed.is_some());
        let q = parsed.unwrap().question.unwrap();
        // Name should still be example.com (case-insensitive)
        assert_eq!(q.name.to_ascii_lowercase(), "example.com");
    }

    #[test]
    fn test_build_any_minimal_response() {
        let wire = build_query_wire("example.com", 255);
        let resp = build_any_minimal_response(&wire);
        assert!(resp.is_some());
        let r = resp.unwrap();
        assert!(r.len() > 12);
        // ANCOUNT = 1
        let ancount = u16::from_be_bytes([r[6], r[7]]);
        assert_eq!(ancount, 1);
        // RCODE = 0 (NOERROR)
        assert_eq!(r[3] & 0x0F, 0);

        // Returns None for non-ANY
        let wire_a = build_query_wire("example.com", 1);
        assert!(build_any_minimal_response(&wire_a).is_none());
    }

    #[test]
    fn test_process_ecs_option_strip_and_passthrough() {
        let wire = build_query_wire("example.com", 1);
        // Passthrough leaves wire untouched
        let pt = process_ecs_option(&wire, EcsMode::Passthrough);
        assert_eq!(pt, wire);
        // Strip on wire without OPT RR leaves wire untouched
        let st = process_ecs_option(&wire, EcsMode::Strip);
        assert_eq!(st, wire);
    }

    #[test]
    fn test_extract_soa_minimum_ttl_edge_cases() {
        let empty = vec![0u8; 6];
        assert_eq!(extract_soa_minimum_ttl(&empty), None);
        let noerror_no_soa = vec![0u8; 12];
        assert_eq!(extract_soa_minimum_ttl(&noerror_no_soa), None);
    }

    #[test]
    fn test_dns_cookie_generate_and_verify() {
        let secret = b"secret-token-key-for-test-32bytes";
        let client_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
        let client_cookie = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let now = 1_700_000_000;

        let server_cookie = generate_server_cookie(secret, client_ip, &client_cookie, now);
        assert_eq!(server_cookie.len(), 16);
        assert_eq!(server_cookie[0], 0x01);

        // Verification success with matching parameters
        assert!(verify_server_cookie(
            secret,
            client_ip,
            &client_cookie,
            &server_cookie,
            now + 60
        ));

        // Verification failure with different client IP
        let diff_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 99));
        assert!(!verify_server_cookie(
            secret,
            diff_ip,
            &client_cookie,
            &server_cookie,
            now + 60
        ));

        // Verification failure when expired (>3600s)
        assert!(!verify_server_cookie(
            secret,
            client_ip,
            &client_cookie,
            &server_cookie,
            now + 7200
        ));

        // Append cookie to wire test
        let mut wire = build_query_wire("example.com", 1);
        let orig_len = wire.len();
        append_cookie_to_response(&mut wire, &client_cookie, &server_cookie);
        assert!(wire.len() > orig_len);

        let parsed_cookie = parse_dns_cookie(&wire);
        assert!(parsed_cookie.is_some());
        let (cc, sc) = parsed_cookie.unwrap();
        assert_eq!(cc, client_cookie.to_vec());
        assert_eq!(sc, Some(server_cookie));
    }

    #[test]
    fn test_truncate_response_properly() {
        let wire = build_query_wire("example.com", 1);
        // Under limit: untouched
        let res_no_trunc = truncate_response_properly(&wire, 1232);
        assert_eq!(res_no_trunc, wire);

        // Exceeds limit: truncated cleanly with TC=1 and zero answer/auth/addl records
        let res_trunc = truncate_response_properly(&wire, 10);
        assert!(res_trunc.len() <= wire.len());
        // TC bit set (byte 2 bit 1)
        assert_ne!(res_trunc[2] & 0x02, 0);
    }
}
