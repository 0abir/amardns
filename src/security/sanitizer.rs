// src/security/sanitizer.rs
// Robust server-side validation and sanitization for all user-supplied inputs.

use std::net::IpAddr;

/// Strict domain name sanitizer and validator.
///
/// Strips schemes, credentials, ports, paths, queries, and trailing dots.
/// Validates RFC 1035 label lengths (<=63), total length (<=253), allowed characters,
/// and rejects control characters, path traversal, and injection attempts.
pub fn sanitize_domain(input: &str) -> Result<String, &'static str> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err("domain cannot be empty");
    }

    // 1. Strip URI scheme if present (e.g., http://, https://, doh://)
    let without_scheme = if let Some(idx) = raw.find("://") {
        &raw[idx + 3..]
    } else {
        raw
    };

    // 2. Strip userinfo (e.g., user:pass@)
    let without_userinfo = if let Some(idx) = without_scheme.find('@') {
        &without_scheme[idx + 1..]
    } else {
        without_scheme
    };

    // 3. Strip path, query string, and fragment
    let without_path = without_userinfo
        .split('/')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .split('#')
        .next()
        .unwrap_or("");

    // 4. Strip port (e.g., :8080 or :443) unless it is an IPv6 bracketed address
    let host_str = if without_path.starts_with('[') {
        if let Some(end_bracket) = without_path.find(']') {
            &without_path[1..end_bracket]
        } else {
            return Err("malformed IPv6 address");
        }
    } else if let Some(idx) = without_path.find(':') {
        &without_path[..idx]
    } else {
        without_path
    };

    // 5. Trim leading and trailing dots and convert to ASCII lowercase
    let cleaned = host_str.trim_matches('.').to_ascii_lowercase();
    if cleaned.is_empty() {
        return Err("domain cannot be empty");
    }

    if cleaned.len() > 253 {
        return Err("domain exceeds maximum length of 253 characters");
    }

    // Check if it's a valid IP address literal
    if cleaned.parse::<IpAddr>().is_ok() {
        return Ok(cleaned);
    }

    // Special case for localhost
    if cleaned == "localhost" {
        return Ok(cleaned);
    }

    // 6. Validate domain labels
    let is_wildcard = cleaned.starts_with("*.");
    let domain_to_check = if is_wildcard {
        &cleaned[2..]
    } else {
        &cleaned[..]
    };

    if domain_to_check.is_empty() {
        return Err("invalid wildcard domain");
    }

    let labels: Vec<&str> = domain_to_check.split('.').collect();
    if labels.is_empty() {
        return Err("domain must contain at least one label");
    }

    for label in &labels {
        if label.is_empty() {
            return Err("domain label cannot be empty (consecutive dots)");
        }
        if label.len() > 63 {
            return Err("domain label exceeds maximum length of 63 characters");
        }

        // Labels must not start or end with a hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return Err("domain label cannot start or end with a hyphen");
        }

        // Each character in the label must be ASCII alphanumeric or hyphen
        for b in label.bytes() {
            if !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                return Err("domain contains invalid characters");
            }
        }
    }

    Ok(cleaned)
}

/// Validates 24-hour time format (HH:MM).
#[allow(dead_code)]
pub fn sanitize_time(time_str: &str) -> Result<String, &'static str> {
    let s = time_str.trim();
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err("time must be in HH:MM format");
    }
    let hour: u32 = parts[0].parse().map_err(|_| "invalid hour")?;
    let min: u32 = parts[1].parse().map_err(|_| "invalid minute")?;
    if hour > 23 || min > 59 {
        return Err("hour must be 0-23 and minute must be 0-59");
    }
    Ok(format!("{:02}:{:02}", hour, min))
}

/// Validates DNS mode setting.
pub fn sanitize_mode(mode_str: &str) -> Result<String, &'static str> {
    let m = mode_str.trim().to_ascii_lowercase();
    match m.as_str() {
        "strict" | "balance" | "fast" | "stealth" | "off" => Ok(m),
        _ => Err("invalid DNS mode (must be strict, balance, fast, stealth, or off)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_domain_valid() {
        assert_eq!(sanitize_domain("example.com").unwrap(), "example.com");
        assert_eq!(sanitize_domain("HTTP://Example.COM/path?arg=1").unwrap(), "example.com");
        assert_eq!(sanitize_domain("https://sub.domain.co.uk:443/").unwrap(), "sub.domain.co.uk");
        assert_eq!(sanitize_domain("*.malware-cdn.top").unwrap(), "*.malware-cdn.top");
        assert_eq!(sanitize_domain("1.1.1.1").unwrap(), "1.1.1.1");
        assert_eq!(sanitize_domain("localhost").unwrap(), "localhost");
    }

    #[test]
    fn test_sanitize_domain_invalid() {
        assert!(sanitize_domain("").is_err());
        assert!(sanitize_domain("   ").is_err());
        assert!(sanitize_domain("example..com").is_err());
        assert!(sanitize_domain("-badlabel.com").is_err());
        assert!(sanitize_domain("badlabel-.com").is_err());
        assert!(sanitize_domain("bad<script>.com").is_err());
        assert!(sanitize_domain("domain with spaces.com").is_err());
    }

    #[test]
    fn test_sanitize_time() {
        assert_eq!(sanitize_time("08:30").unwrap(), "08:30");
        assert_eq!(sanitize_time("23:59").unwrap(), "23:59");
        assert_eq!(sanitize_time("0:0").unwrap(), "00:00");
        assert!(sanitize_time("24:00").is_err());
        assert!(sanitize_time("12:60").is_err());
        assert!(sanitize_time("abc").is_err());
    }

    #[test]
    fn test_sanitize_mode() {
        assert_eq!(sanitize_mode("strict").unwrap(), "strict");
        assert_eq!(sanitize_mode("BALANCE").unwrap(), "balance");
        assert!(sanitize_mode("invalid_mode").is_err());
    }
}
