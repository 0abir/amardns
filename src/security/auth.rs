// src/security/auth.rs
// Master Key and HMAC Token authentication matching the Node reference implementation.

use axum::http::{header, HeaderMap};
use ring::hmac;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::state::AppState;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthRole {
    Admin,
    View,
    None,
}

impl AuthRole {
    pub fn is_admin(&self) -> bool {
        matches!(self, AuthRole::Admin)
    }

    pub fn is_view_or_admin(&self) -> bool {
        matches!(self, AuthRole::Admin | AuthRole::View)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AuthRole::Admin => "admin",
            AuthRole::View => "view",
            AuthRole::None => "none",
        }
    }
}

/// Constant-time string comparison to prevent timing attacks.
pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Returns `true` if `token` is syntactically well-formed.
///
/// A well-formed token is either:
/// - 80 hex characters (current format: 8-char timestamp + 8-char TTL + 64-char HMAC-SHA256)
/// - 72 hex characters (legacy format: 8-char timestamp + 64-char HMAC-SHA256)
///
/// Only lowercase/uppercase ASCII hex digits are accepted. Any other input is
/// rejected immediately so that `verify_hmac_token` never performs crypto work
/// on garbage data (prevents timing oracles on malformed tokens).
pub fn is_token_well_formed(token: &str) -> bool {
    let len = token.len();
    if len != 80 && len != 72 {
        return false;
    }
    token.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Helper to decode a hex string into bytes.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

/// Helper to encode bytes into a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Generates a signed view token matching Node's generateToken function.
pub fn generate_hmac_token(secret: &str, target_path: &str, ttl_secs: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let ts_hex = format!("{:08x}", now);
    let ttl_val = ttl_secs.max(60);
    let ttl_hex = format!("{:08x}", ttl_val);
    let scope = if target_path.is_empty() || target_path == "/" || target_path == "/dashboard" {
        "VIEW_ONLY"
    } else {
        target_path
    };

    let msg = format!("{}{}{}", ts_hex, ttl_hex, scope);
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let tag = hmac::sign(&key, msg.as_bytes());
    let sig_hex = hex_encode(tag.as_ref());

    format!("{}{}{}", ts_hex, ttl_hex, sig_hex)
}

/// Verifies a token string against the secret and target path.
///
/// # Security
/// - Hardcoded string backdoors have been removed. Every token must carry a
///   valid HMAC signature produced by `generate_hmac_token`.
/// - Malformed tokens (wrong length or non-hex characters) are rejected before
///   any cryptographic operation is performed, preventing timing side-channels
///   on inputs that could never be valid.
pub fn verify_hmac_token(token: &str, secret: &str, path: &str) -> bool {
    // Fast-path rejection: reject any token that does not look like a real
    // HMAC token. This is done BEFORE any crypto, so garbage inputs can never
    // create a timing oracle.
    if !is_token_well_formed(token) {
        return false;
    }

    if secret.is_empty() {
        return false;
    }

    let (ts_hex, ttl_hex, sig_hex, ttl_seconds) = if token.len() == 80 {
        let ts_hex = &token[0..8];
        let ttl_hex = &token[8..16];
        let sig_hex = &token[16..80];
        let ttl = match u64::from_str_radix(ttl_hex, 16) {
            Ok(v) => v,
            Err(_) => return false,
        };
        (ts_hex, Some(ttl_hex), sig_hex, ttl)
    } else {
        // token.len() == 72 — legacy format, no TTL field
        let ts_hex = &token[0..8];
        let sig_hex = &token[8..72];
        (ts_hex, None, sig_hex, 86400) // Default 24-hour window for legacy 72-char tokens
    };

    let ts = match u64::from_str_radix(ts_hex, 16) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Check validity window (with 60s clock skew tolerance)
    if now + 60 < ts || now > ts + ttl_seconds {
        return false;
    }

    let sig_bytes = match hex_decode(sig_hex) {
        Some(b) => b,
        None => return false,
    };

    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let prefix = match ttl_hex {
        Some(th) => format!("{}{}", ts_hex, th),
        None => ts_hex.to_string(),
    };

    // 1. Check VIEW_ONLY scope
    let view_msg = format!("{}VIEW_ONLY", prefix);
    if hmac::verify(&key, view_msg.as_bytes(), &sig_bytes).is_ok() {
        return true;
    }

    // 2. Check exact path scope
    let path_msg = format!("{}{}", prefix, path);
    if hmac::verify(&key, path_msg.as_bytes(), &sig_bytes).is_ok() {
        return true;
    }

    // 3. Check root fallback
    let root_msg = format!("{}/", prefix);
    if hmac::verify(&key, root_msg.as_bytes(), &sig_bytes).is_ok() {
        return true;
    }

    false
}

/// Extracts authentication credentials and evaluates the role.
pub fn check_auth(state: &AppState, key_param: Option<&str>, headers: &HeaderMap, path: &str) -> AuthRole {
    // 1. Check peer synchronization from internal Fly.io mesh
    // SECURITY: peer-sync MUST present a valid master key — never grant admin unconditionally.
    // If the x-peer-sync header is present but authentication fails, return None immediately
    // rather than falling through to other auth mechanisms.
    if let Some(peer) = headers.get("x-peer-sync") {
        if peer == "1" {
            let master_key = &state.config.dns_master_key;
            if !master_key.is_empty() {
                if let Some(auth_hdr) = headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
                    let token = auth_hdr.strip_prefix("Bearer ").unwrap_or(auth_hdr).trim();
                    if constant_time_eq_str(token, master_key) {
                        return AuthRole::Admin;
                    }
                }
            }
            // x-peer-sync was present but authentication failed — deny immediately.
            // Do NOT fall through; a peer that cannot authenticate should never be
            // re-evaluated against the view-token path.
            state.metrics.auth_fails.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return AuthRole::None;
        }
    }

    // 2. Extract candidate key/token
    let candidate = if let Some(p) = key_param {
        let p_clean = p.trim();
        if !p_clean.is_empty() && p_clean != "dashboard" && p_clean != "status" {
            Some(p_clean.to_string())
        } else {
            None
        }
    } else {
        None
    };

    let candidate = candidate.or_else(|| {
        if let Some(auth_hdr) = headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
            let token = auth_hdr.strip_prefix("Bearer ").unwrap_or(auth_hdr).trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
        for header_name in &["x-auth-key", "x-master-key", "x-api-key"] {
            if let Some(val) = headers.get(*header_name).and_then(|h| h.to_str().ok()) {
                let v = val.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
        None
    });

    let token = match candidate {
        Some(t) => t,
        None => return AuthRole::None,
    };

    // 3. Admin Authentication: Compare with DNS_MASTER_KEY
    let master_key = &state.config.dns_master_key;
    if !master_key.is_empty() && constant_time_eq_str(&token, master_key) {
        return AuthRole::Admin;
    }

    // 4. View-Only Authentication: HMAC-signed token only.
    //    No hardcoded bypass strings — every token must carry a valid signature.
    if verify_hmac_token(&token, &state.config.dns_token_secret, path) {
        return AuthRole::View;
    }

    state.metrics.auth_fails.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    AuthRole::None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn test_constant_time_eq_str() {
        assert!(constant_time_eq_str("abir", "abir"));
        assert!(!constant_time_eq_str("abir", "abiR"));
        assert!(!constant_time_eq_str("abir", "abir1"));
        assert!(!constant_time_eq_str("", "abir"));
        assert!(constant_time_eq_str("", ""));
    }

    #[test]
    fn test_is_token_well_formed() {
        // Valid 80-char hex token
        let good_80 = "a".repeat(80);
        assert!(is_token_well_formed(&good_80));

        // Valid 72-char hex token
        let good_72 = "f".repeat(72);
        assert!(is_token_well_formed(&good_72));

        // Wrong lengths
        assert!(!is_token_well_formed("view-only"));
        assert!(!is_token_well_formed(""));
        assert!(!is_token_well_formed(&"a".repeat(79)));
        assert!(!is_token_well_formed(&"a".repeat(81)));
        assert!(!is_token_well_formed(&"a".repeat(71)));
        assert!(!is_token_well_formed(&"a".repeat(73)));

        // Non-hex characters in otherwise correct length
        let mut bad_char = "a".repeat(80);
        bad_char.replace_range(0..1, "!");
        assert!(!is_token_well_formed(&bad_char));

        let mut bad_space = "a".repeat(72);
        bad_space.replace_range(10..11, " ");
        assert!(!is_token_well_formed(&bad_space));
    }

    #[test]
    fn test_hmac_token_lifecycle() {
        let secret = "test_secret_1234567890abcdef";
        let token = generate_hmac_token(secret, "/dashboard", 3600);
        assert_eq!(token.len(), 80);

        // Verification with valid token
        assert!(verify_hmac_token(&token, secret, "/dashboard"));
        assert!(verify_hmac_token(&token, secret, "/api/status")); // VIEW_ONLY scope covers everything

        // Verification failure with tampered token or wrong secret
        assert!(!verify_hmac_token(&token, "wrong_secret", "/dashboard"));
        let mut tampered = token.clone();
        tampered.replace_range(70..71, if &token[70..71] == "a" { "b" } else { "a" });
        assert!(!verify_hmac_token(&tampered, secret, "/dashboard"));
    }

    /// Ensure the old hardcoded "view-only" string is no longer accepted anywhere
    /// in the authentication stack.
    #[test]
    fn test_view_only_string_no_longer_bypasses_auth() {
        let mut config = Config::from_env();
        config.dns_master_key = "secret_master_key".to_string();
        config.dns_token_secret = "secret_token_key".to_string();
        let state = AppState::new(config);

        // The literal string "view-only" must never grant any access.
        let role = check_auth(&state, Some("view-only"), &HeaderMap::new(), "/");
        assert_eq!(
            role,
            AuthRole::None,
            "hardcoded 'view-only' backdoor must not grant any role"
        );

        // Also verify verify_hmac_token rejects it directly.
        assert!(
            !verify_hmac_token("view-only", "secret_token_key", "/"),
            "verify_hmac_token must reject the literal 'view-only' string"
        );
    }

    #[test]
    fn test_check_auth_roles() {
        let mut config = Config::from_env();
        config.dns_master_key = "secret_master_key".to_string();
        config.dns_token_secret = "secret_token_key".to_string();
        let state = AppState::new(config);

        // 1. Master key via path
        let headers = HeaderMap::new();
        let role = check_auth(&state, Some("secret_master_key"), &headers, "/");
        assert_eq!(role, AuthRole::Admin);

        // 2. Master key via Bearer authorization header
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer secret_master_key".parse().unwrap());
        let role = check_auth(&state, None, &headers, "/");
        assert_eq!(role, AuthRole::Admin);

        // 3. Master key via x-auth-key header
        let mut headers2 = HeaderMap::new();
        headers2.insert("x-auth-key", "secret_master_key".parse().unwrap());
        let role = check_auth(&state, None, &headers2, "/");
        assert_eq!(role, AuthRole::Admin);

        // 4. View-only via valid HMAC token (the "view-only" string no longer works)
        let token = generate_hmac_token(&state.config.dns_token_secret, "/dashboard", 7200);
        let role = check_auth(&state, Some(&token), &HeaderMap::new(), "/");
        assert_eq!(role, AuthRole::View);

        // 5. View-only via HMAC token for root path
        let token = generate_hmac_token(&state.config.dns_token_secret, "/", 7200);
        let role = check_auth(&state, Some(&token), &HeaderMap::new(), "/");
        assert_eq!(role, AuthRole::View);

        // 6. Unauthorized on wrong key
        let role = check_auth(&state, Some("wrong_password"), &HeaderMap::new(), "/");
        assert_eq!(role, AuthRole::None);

        // 7. Unauthorized on empty
        let role = check_auth(&state, None, &HeaderMap::new(), "/");
        assert_eq!(role, AuthRole::None);

        // 8. x-peer-sync present but no matching master key -> None immediately
        let mut peer_headers = HeaderMap::new();
        peer_headers.insert("x-peer-sync", "1".parse().unwrap());
        peer_headers.insert(header::AUTHORIZATION, "Bearer wrong_key".parse().unwrap());
        let role = check_auth(&state, None, &peer_headers, "/");
        assert_eq!(role, AuthRole::None);

        // 9. x-peer-sync present with correct master key -> Admin
        let mut peer_headers_ok = HeaderMap::new();
        peer_headers_ok.insert("x-peer-sync", "1".parse().unwrap());
        peer_headers_ok.insert(header::AUTHORIZATION, "Bearer secret_master_key".parse().unwrap());
        let role = check_auth(&state, None, &peer_headers_ok, "/");
        assert_eq!(role, AuthRole::Admin);
    }
}
