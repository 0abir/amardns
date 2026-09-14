use std::env;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Config {
    pub port: u16,
    pub dot_port: u16,
    pub doq_port: u16,
    pub doh3_port: u16,
    pub host: String,
    pub udp_host: String,
    pub db_path: String,
    pub log_level: String,
    pub dns_master_key: String,
    pub dns_token_secret: String,
    pub dns_access_mode: String, // "public" or "private"
    pub upstream_cron: String,
    pub upstream_tz: String,
    pub safe_browsing_keys: Vec<String>,
    pub custom_domains: Vec<String>,
    pub shield_fly_dev: bool,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub tls_enabled: bool,
    pub desec_token: Option<String>,
    pub duckdns_token: Option<String>,
    pub zerossl_api_key: Option<String>,
    pub acme_enabled: bool,
    pub plain53_enabled: bool,
    pub plain53_host: String,
    pub plain53_udp_host: String,
}

/// Parse a port number from the named environment variable.  If the variable
/// is set but cannot be parsed as a valid, non-zero u16, a warning is printed
/// to stderr and `default` is returned.  If the variable is absent, `default`
/// is returned silently.
fn parse_port(var: &str, default: u16) -> u16 {
    match env::var(var) {
        Ok(val) => match val.trim().parse::<u16>() {
            Ok(p) if p >= 1 => p,
            Ok(_) => {
                eprintln!(
                    "WARNING: {} value '{}' is zero, which is not a usable port. \
                     Falling back to default {}.",
                    var, val, default
                );
                default
            }
            Err(_) => {
                eprintln!(
                    "WARNING: {} value '{}' is not a valid port number (1-65535). \
                     Falling back to default {}.",
                    var, val, default
                );
                default
            }
        },
        Err(_) => default,
    }
}

impl Config {
    pub fn from_env() -> Self {
        let sb_env = env::var("SAFE_BROWSING_KEYS")
            .or_else(|_| env::var("SAFE_BROWSING_KEY"))
            .unwrap_or_default();
        let safe_browsing_keys: Vec<String> = sb_env
            .split(',')
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .collect();

        let custom_domains_env = env::var("CUSTOM_DOMAINS")
            .or_else(|_| env::var("ALLOWED_DOMAINS"))
            .unwrap_or_default();
        let custom_domains: Vec<String> = custom_domains_env
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let shield_fly_dev = env::var("SHIELD_FLY_DEV")
            .or_else(|_| env::var("HIDE_FLY_DEV"))
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(!custom_domains.is_empty());

        let tls_cert_path = env::var("TLS_CERT_PATH")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let tls_key_path = env::var("TLS_KEY_PATH")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let tls_enabled = env::var("TLS_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        let desec_token = env::var("DESEC_TOKEN")
            .or_else(|_| env::var("DEDYN_TOKEN"))
            .ok()
            .filter(|s| !s.trim().is_empty());

        let duckdns_token = env::var("DUCKDNS_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty());

        let zerossl_api_key = env::var("ZEROSSL_API_KEY")
            .or_else(|_| env::var("ZEROSSL_KEY"))
            .ok()
            .filter(|s| !s.trim().is_empty());

        let acme_enabled = env::var("ACME_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(desec_token.is_some() || duckdns_token.is_some() || zerossl_api_key.is_some());

        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let udp_host = env::var("UDP_HOST").unwrap_or_else(|_| host.clone());
        let plain53_host = env::var("PLAIN53_HOST").unwrap_or_else(|_| host.clone());
        let plain53_udp_host = env::var("PLAIN53_UDP_HOST").unwrap_or_else(|_| udp_host.clone());

        Self {
            port: parse_port("PORT", 443),
            dot_port: parse_port("DOT_PORT", 853),
            doq_port: parse_port("DOQ_PORT", 853),
            doh3_port: parse_port("DOH3_PORT", 443),
            host,
            udp_host,
            db_path: env::var("DB_PATH").unwrap_or_else(|_| "/data/amardns.wal".to_string()),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            dns_master_key: env::var("DNS_MASTER_KEY").unwrap_or_default(),
            dns_token_secret: env::var("DNS_TOKEN_SECRET").unwrap_or_default(),
            dns_access_mode: env::var("DNS_ACCESS_MODE").unwrap_or_else(|_| "public".to_string()),
            upstream_cron: env::var("UPSTREAM_CRON").unwrap_or_else(|_| "0 0 * * *".to_string()),
            upstream_tz: env::var("UPSTREAM_TZ").unwrap_or_else(|_| "Asia/Dhaka".to_string()),
            safe_browsing_keys,
            custom_domains,
            shield_fly_dev,
            tls_cert_path,
            tls_key_path,
            tls_enabled,
            desec_token,
            duckdns_token,
            zerossl_api_key,
            acme_enabled,
            plain53_enabled: env::var("PLAIN53_ENABLED")
                .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
                .unwrap_or(false),
            plain53_host,
            plain53_udp_host,
        }
    }

    /// Validate the configuration and return a list of human-readable
    /// diagnostic strings.  Each string is prefixed with either `"ERROR:"` or
    /// `"WARNING:"` so callers can distinguish severity.
    pub fn validate(&self) -> Vec<String> {
        let mut issues: Vec<String> = Vec::new();

        // ── PORT ────────────────────────────────────────────────────────────
        if let Ok(raw) = env::var("PORT") {
            let trimmed = raw.trim();
            if trimmed.parse::<u16>().map_or(true, |p| p == 0) {
                issues.push(format!(
                    "ERROR: PORT value '{}' is not in the valid range 1-65535; using default 443.",
                    raw
                ));
            }
        }

        // ── DOT_PORT ────────────────────────────────────────────────────────
        if let Ok(raw) = env::var("DOT_PORT") {
            let trimmed = raw.trim();
            if trimmed.parse::<u16>().map_or(true, |p| p == 0) {
                issues.push(format!(
                    "ERROR: DOT_PORT value '{}' is not in the valid range 1-65535; using default 853.",
                    raw
                ));
            }
        }

        // ── DOQ_PORT ────────────────────────────────────────────────────────
        if let Ok(raw) = env::var("DOQ_PORT") {
            let trimmed = raw.trim();
            if trimmed.parse::<u16>().map_or(true, |p| p == 0) {
                issues.push(format!(
                    "ERROR: DOQ_PORT value '{}' is not in the valid range 1-65535; using default 853.",
                    raw
                ));
            }
        }

        // ── DOH3_PORT ───────────────────────────────────────────────────────
        if let Ok(raw) = env::var("DOH3_PORT") {
            let trimmed = raw.trim();
            if trimmed.parse::<u16>().map_or(true, |p| p == 0) {
                issues.push(format!(
                    "ERROR: DOH3_PORT value '{}' is not in the valid range 1-65535; using default 443.",
                    raw
                ));
            }
        }

        // ── DNS_MASTER_KEY ──────────────────────────────────────────────────
        if self.dns_master_key.is_empty() {
            issues.push(
                "ERROR: DNS_MASTER_KEY is not set. The server cannot authenticate administrative requests.".to_string(),
            );
        } else if self.dns_master_key.starts_with("CHANGE_ME") {
            issues.push(
                "ERROR: DNS_MASTER_KEY starts with 'CHANGE_ME'. Please set a strong, unique master key.".to_string(),
            );
        } else if self.dns_master_key.len() < 16 {
            issues.push(
                "WARNING: DNS_MASTER_KEY is shorter than 16 characters. Use a longer key for adequate security.".to_string(),
            );
        }

        // ── DNS_TOKEN_SECRET ────────────────────────────────────────────────
        if self.dns_token_secret.is_empty() {
            issues.push(
                "WARNING: DNS_TOKEN_SECRET is not set. View tokens (JWT signing) will not work."
                    .to_string(),
            );
        } else if self.dns_token_secret.starts_with("CHANGE_ME") {
            issues.push(
                "WARNING: DNS_TOKEN_SECRET starts with 'CHANGE_ME'. Please set a strong, unique token secret.".to_string(),
            );
        } else if self.dns_token_secret.len() < 32 {
            issues.push(
                "WARNING: DNS_TOKEN_SECRET is shorter than 32 characters. Secrets under 32 bytes provide insufficient HMAC-SHA256 security.".to_string(),
            );
        }

        // ── DNS_ACCESS_MODE ─────────────────────────────────────────────────
        let mode = self.dns_access_mode.as_str();
        if mode != "public" && mode != "private" {
            issues.push(format!(
                "WARNING: DNS_ACCESS_MODE value '{}' is not recognised. Expected 'public' or 'private'.",
                mode
            ));
        }

        // ── LOG_LEVEL ───────────────────────────────────────────────────────
        const VALID_LOG_LEVELS: &[&str] = &["error", "warn", "info", "debug", "trace"];
        if !VALID_LOG_LEVELS.contains(&self.log_level.to_lowercase().as_str()) {
            issues.push(format!(
                "WARNING: LOG_LEVEL value '{}' is not one of the recognised levels (error, warn, info, debug, trace).",
                self.log_level
            ));
        }

        // ── TLS ─────────────────────────────────────────────────────────────
        if self.tls_enabled {
            if self.tls_cert_path.is_none() {
                issues.push(
                    "ERROR: TLS_ENABLED is true but TLS_CERT_PATH is not set or is empty."
                        .to_string(),
                );
            }
            if self.tls_key_path.is_none() {
                issues.push(
                    "ERROR: TLS_ENABLED is true but TLS_KEY_PATH is not set or is empty."
                        .to_string(),
                );
            }
        }

        issues
    }

    /// Returns `true` when the server is configured for private (authenticated)
    /// access only.
    pub fn access_mode_is_private(&self) -> bool {
        self.dns_access_mode.trim().eq_ignore_ascii_case("private")
    }

    /// Verifies if an incoming HTTP Host header is allowed under custom domain & shield policies.
    pub fn is_host_allowed(&self, host_header: Option<&str>) -> bool {
        if self.custom_domains.is_empty() && !self.shield_fly_dev {
            return true;
        }
        let host = match host_header {
            Some(h) => h
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase(),
            None => return true,
        };
        // Allow internal health checks, loopback, and peer traffic
        if host.is_empty()
            || host == "localhost"
            || host == "127.0.0.1"
            || host == "::1"
            || host.ends_with(".internal")
            || host.parse::<std::net::IpAddr>().is_ok()
        {
            return true;
        }
        // Block .fly.dev when shield is active
        if self.shield_fly_dev && host.ends_with(".fly.dev") {
            return false;
        }
        // If specific custom domains are defined, enforce them
        if !self.custom_domains.is_empty() {
            return self.custom_domains.iter().any(|d| d == &host);
        }
        true
    }

    /// Returns `true` when native TLS termination is configured and enabled.
    pub fn is_tls_enabled(&self) -> bool {
        self.tls_enabled && self.tls_cert_path.is_some() && self.tls_key_path.is_some()
    }

    /// Returns the effective TLS certificate and private key file paths if available on disk.
    pub fn get_effective_tls_paths(&self) -> Option<(String, String)> {
        // 1. Check explicitly configured paths
        if let (Some(cert), Some(key)) = (&self.tls_cert_path, &self.tls_key_path) {
            if std::path::Path::new(cert).exists() && std::path::Path::new(key).exists() {
                return Some((cert.clone(), key.clone()));
            }
        }
        // 2. Check /data/ persistent mount
        if std::path::Path::new("/data/cert.pem").exists()
            && std::path::Path::new("/data/key.pem").exists()
        {
            return Some(("/data/cert.pem".to_string(), "/data/key.pem".to_string()));
        }
        // 3. Check local root directory
        if std::path::Path::new("cert.pem").exists() && std::path::Path::new("key.pem").exists() {
            return Some(("cert.pem".to_string(), "key.pem".to_string()));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_host_allowed_shield_fly_dev() {
        let mut cfg = Config::from_env();
        cfg.custom_domains = vec![
            "amardns.dedyn.io".to_string(),
            "amardns.duckdns.org".to_string(),
        ];
        cfg.shield_fly_dev = true;

        assert!(cfg.is_host_allowed(Some("amardns.dedyn.io")));
        assert!(cfg.is_host_allowed(Some("amardns.dedyn.io:443")));
        assert!(cfg.is_host_allowed(Some("amardns.duckdns.org")));
        assert!(cfg.is_host_allowed(Some("localhost:8443")));
        assert!(cfg.is_host_allowed(Some("127.0.0.1:8443")));
        assert!(cfg.is_host_allowed(Some("amardns.internal:8080")));

        // Block .fly.dev
        assert!(!cfg.is_host_allowed(Some("amardns.fly.dev")));
        assert!(!cfg.is_host_allowed(Some("random-scanner.fly.dev:443")));
        assert!(!cfg.is_host_allowed(Some("unauthorized-domain.com")));
    }

    #[test]
    fn test_config_tls_disabled_by_default() {
        let mut cfg = Config::from_env();
        cfg.tls_cert_path = None;
        cfg.tls_key_path = None;
        cfg.tls_enabled = false;
        assert!(!cfg.is_tls_enabled());
    }

    #[test]
    fn test_config_tls_enabled_with_paths() {
        let mut cfg = Config::from_env();
        cfg.tls_cert_path = Some("/etc/ssl/certs/amardns.pem".to_string());
        cfg.tls_key_path = Some("/etc/ssl/private/amardns.key".to_string());
        cfg.tls_enabled = true;
        assert!(cfg.is_tls_enabled());
    }

    #[test]
    fn test_config_tls_validation_missing_paths() {
        let mut cfg = Config::from_env();
        cfg.dns_master_key = "strong_test_master_key_12345".to_string();
        cfg.dns_token_secret = "strong_test_token_secret_0123456789_abcdef".to_string();
        cfg.tls_enabled = true;
        cfg.tls_cert_path = None;
        cfg.tls_key_path = None;

        let issues = cfg.validate();
        assert!(issues.iter().any(|i| i.contains("TLS_CERT_PATH")));
        assert!(issues.iter().any(|i| i.contains("TLS_KEY_PATH")));
    }

    #[test]
    fn test_config_ports_and_udp_host() {
        let cfg = Config::from_env();
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.dot_port, 853);
        assert_eq!(cfg.doq_port, 853);
        assert_eq!(cfg.doh3_port, 443);
        assert!(!cfg.udp_host.is_empty());
    }
}
