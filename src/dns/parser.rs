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

    let mut pos = 12;
    let mut name = String::with_capacity(64);
    let mut label_count = 0;

    while pos < buf.len() {
        label_count += 1;
        if label_count > 128 {
            return None;
        }
        let len = buf[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // DNS compression pointer (handle safely)
        if len & 0xc0 == 0xc0 {
            pos += 2;
            break;
        }
        if len > 63 {
            return None;
        }
        pos += 1;
        if pos + len > buf.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        if name.len() + len > 255 {
            return None;
        }
        for &b in &buf[pos..pos + len] {
            name.push((b as char).to_ascii_lowercase());
        }
        pos += len;
    }

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

/// Checks if an IPv4 address is in a private, loopback, or link-local range.
pub fn is_rebind_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 127.0.0.0/8 (Loopback / Localhost)
    if ip.is_loopback() {
        return true;
    }
    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918 Private LAN)
    if ip.is_private() {
        return true;
    }
    // 169.254.0.0/16 (Link-local & AWS/GCP/Azure Cloud Metadata e.g. 169.254.169.254)
    if ip.is_link_local() {
        return true;
    }
    // 0.0.0.0/8 (Current network / wildcard)
    if octets[0] == 0 {
        return true;
    }
    // 100.64.0.0/10 (Shared Address Space / CGNAT)
    if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
        return true;
    }
    // 255.255.255.255 (Broadcast)
    if ip.is_broadcast() {
        return true;
    }
    false
}

/// Checks if an IPv6 address is in a private, loopback, or link-local range.
pub fn is_rebind_ipv6(ip: &Ipv6Addr) -> bool {
    let seg = ip.segments();
    // ::1 (Loopback)
    if ip.is_loopback() {
        return true;
    }
    // :: (Unspecified)
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
    // IPv4-mapped IPv6 (::ffff:a.b.c.d)
    let octets = ip.octets();
    if octets[0..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
        let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
        if is_rebind_ipv4(&v4) {
            return true;
        }
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
        while pos < buf.len() {
            let len = buf[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if (len & 0xc0) == 0xc0 {
                pos += 2;
                break;
            }
            pos += 1 + len;
        }
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
        while pos < buf.len() {
            let len = buf[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if (len & 0xc0) == 0xc0 {
                pos += 2;
                break;
            }
            pos += 1 + len;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

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
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,       // Terminating zero
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
        assert_eq!(resp[3] & 0x0F, 3);         // RCODE = NXDOMAIN
    }

    #[test]
    fn test_build_blocked_response_edns0_preserved() {
        let query = [
            0x12, 0x34, 0x01, 0x00, // TXID, Flags (RD=1)
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x00,             // ANCOUNT = 0
            0x00, 0x00,             // NSCOUNT = 0
            0x00, 0x01,             // ARCOUNT = 1
            0x03, b'f', b'o', b'o', 0x00, // "foo."
            0x00, 0x01, 0x00, 0x01,       // A IN
            0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // OPT RR
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
    fn test_extract_rebind_ip_detects_private_and_loopback() {
        // DNS response packet with 1 question and 1 answer pointing to 127.0.0.1
        let mut resp = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags (QR=1, RD=1, RA=1)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, 0x00, 0x00, // NSCOUNT, ARCOUNT
            // Question: "rebind.evil"
            0x06, b'r', b'e', b'b', b'i', b'n', b'd',
            0x04, b'e', b'v', b'i', b'l',
            0x00,
            0x00, 0x01, 0x00, 0x01, // A IN
            // Answer: compression pointer 0xc00c
            0xc0, 0x0c,
            0x00, 0x01, // TYPE = A
            0x00, 0x01, // CLASS = IN
            0x00, 0x00, 0x00, 0x3c, // TTL = 60
            0x00, 0x04, // RDLENGTH = 4
            127, 0, 0, 1 // RDATA = 127.0.0.1
        ];

        let detected = extract_rebind_ip(&resp);
        assert_eq!(detected, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));

        // Change answer to 192.168.1.1 (RFC 1918)
        let last_idx = resp.len() - 4;
        resp[last_idx..].copy_from_slice(&[192, 168, 1, 1]);
        assert_eq!(extract_rebind_ip(&resp), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        // Change answer to 169.254.169.254 (Cloud metadata)
        resp[last_idx..].copy_from_slice(&[169, 254, 169, 254]);
        assert_eq!(extract_rebind_ip(&resp), Some(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));

        // Change answer to public IP 8.8.8.8 -> Should NOT be detected
        resp[last_idx..].copy_from_slice(&[8, 8, 8, 8]);
        assert_eq!(extract_rebind_ip(&resp), None);
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
        resp[6] = 0x00; resp[7] = 0x01;     // ANCOUNT = 1
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
}

/// Extracts all IPv4 addresses from the Answer section of a DNS response wire packet.
/// Used by the passive DNS timeline to record domain→IP history.
pub fn extract_a_records(buf: &[u8]) -> Vec<std::net::IpAddr> {
    let mut ips = Vec::new();
    if buf.len() < 12 { return ips; }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 { return ips; }

    let mut pos = 12;
    // Skip question section
    for _ in 0..qdcount {
        while pos < buf.len() {
            let len = buf[pos] as usize;
            if len == 0 { pos += 1; break; }
            if (len & 0xc0) == 0xc0 { pos += 2; break; }
            pos += 1 + len;
        }
        pos += 4;
        if pos > buf.len() { return ips; }
    }
    // Walk answers
    for _ in 0..ancount {
        if pos >= buf.len() { break; }
        while pos < buf.len() {
            let len = buf[pos] as usize;
            if len == 0 { pos += 1; break; }
            if (len & 0xc0) == 0xc0 { pos += 2; break; }
            pos += 1 + len;
        }
        if pos + 10 > buf.len() { break; }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() { break; }
        if rtype == 1 && rdlen == 4 {
            ips.push(std::net::IpAddr::V4(Ipv4Addr::new(buf[pos], buf[pos+1], buf[pos+2], buf[pos+3])));
        } else if rtype == 28 && rdlen == 16 {
            let mut b = [0u8; 16];
            b.copy_from_slice(&buf[pos..pos+16]);
            ips.push(std::net::IpAddr::V6(Ipv6Addr::from(b)));
        }
        pos += rdlen;
    }
    ips
}

/// Extracts the minimum TTL from all answer records. Used by the TTL Manipulation Guard.
/// Returns None if no answer records found.
pub fn extract_min_ttl(buf: &[u8]) -> Option<u32> {
    if buf.len() < 12 { return None; }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 { return None; }

    let mut pos = 12;
    for _ in 0..qdcount {
        while pos < buf.len() {
            let len = buf[pos] as usize;
            if len == 0 { pos += 1; break; }
            if (len & 0xc0) == 0xc0 { pos += 2; break; }
            pos += 1 + len;
        }
        pos += 4;
        if pos > buf.len() { return None; }
    }

    let mut min_ttl: Option<u32> = None;
    for _ in 0..ancount {
        if pos >= buf.len() { break; }
        while pos < buf.len() {
            let len = buf[pos] as usize;
            if len == 0 { pos += 1; break; }
            if (len & 0xc0) == 0xc0 { pos += 2; break; }
            pos += 1 + len;
        }
        if pos + 10 > buf.len() { break; }
        let ttl = u32::from_be_bytes([buf[pos+4], buf[pos+5], buf[pos+6], buf[pos+7]]);
        let rdlen = u16::from_be_bytes([buf[pos+8], buf[pos+9]]) as usize;
        pos += 10 + rdlen;
        min_ttl = Some(min_ttl.map(|m: u32| m.min(ttl)).unwrap_or(ttl));
    }
    min_ttl
}

/// Extracts the TTL from the first answer record. Used by SmartTTL learner.
pub fn extract_answer_ttl(buf: &[u8]) -> Option<u32> {
    if buf.len() < 12 { return None; }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 { return None; }

    let mut pos = 12;
    for _ in 0..qdcount {
        while pos < buf.len() {
            let len = buf[pos] as usize;
            if len == 0 { pos += 1; break; }
            if (len & 0xc0) == 0xc0 { pos += 2; break; }
            pos += 1 + len;
        }
        pos += 4;
        if pos > buf.len() { return None; }
    }
    // Skip name of first answer
    while pos < buf.len() {
        let len = buf[pos] as usize;
        if len == 0 { pos += 1; break; }
        if (len & 0xc0) == 0xc0 { pos += 2; break; }
        pos += 1 + len;
    }
    if pos + 8 > buf.len() { return None; }
    Some(u32::from_be_bytes([buf[pos+4], buf[pos+5], buf[pos+6], buf[pos+7]]))
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
pub fn parse_domain_name_at(buf: &[u8], mut pos: usize) -> Option<String> {
    let mut name = String::new();
    let mut jumps = 0;
    while pos < buf.len() && jumps < 16 {
        let len = buf[pos] as usize;
        if len == 0 { break; }
        if (len & 0xc0) == 0xc0 {
            if pos + 1 >= buf.len() { return None; }
            pos = ((len & 0x3f) << 8) | (buf[pos + 1] as usize);
            jumps += 1;
            continue;
        }
        pos += 1;
        if pos + len > buf.len() { return None; }
        if !name.is_empty() { name.push('.'); }
        for &b in &buf[pos..pos + len] {
            name.push((b as char).to_ascii_lowercase());
        }
        pos += len;
    }
    if name.is_empty() { None } else { Some(name) }
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
        while pos < buf.len() {
            let len = buf[pos] as usize;
            if len == 0 { pos += 1; break; }
            if (len & 0xc0) == 0xc0 { pos += 2; break; }
            pos += 1 + len;
        }
        pos += 4;
        if pos > buf.len() { return (rcode, Vec::new()); }
    }

    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        if pos >= buf.len() { break; }
        // Parse record name
        let rec_name = parse_domain_name_at(buf, pos).unwrap_or_else(|| query_domain.to_string());
        // Skip over the name in the record
        while pos < buf.len() {
            let len = buf[pos] as usize;
            if len == 0 { pos += 1; break; }
            if (len & 0xc0) == 0xc0 { pos += 2; break; }
            pos += 1 + len;
        }
        if pos + 10 > buf.len() { break; }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() { break; }

        let data = match rtype {
            1 if rdlen == 4 => {
                format!("{}.{}.{}.{}", buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3])
            }
            28 if rdlen == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[pos..pos + 16]);
                std::net::Ipv6Addr::from(octets).to_string()
            }
            5 => {
                parse_domain_name_at(buf, pos).unwrap_or_else(|| "<unknown>".to_string())
            }
            16 => {
                if rdlen > 1 {
                    String::from_utf8_lossy(&buf[pos + 1..pos + rdlen]).to_string()
                } else {
                    String::new()
                }
            }
            _ => {
                buf[pos..pos + rdlen].iter().map(|b| format!("{:02x}", b)).collect::<String>()
            }
        };

        answers.push(DohAnswerRecord {
            name: if rec_name.ends_with('.') { rec_name } else { format!("{}.", rec_name) },
            r#type: rtype,
            ttl,
            data,
        });

        pos += rdlen;
    }

    (rcode, answers)
}
