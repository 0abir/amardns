use std::env;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Config {
    pub port: u16,
    pub dot_port: u16,
    pub host: String,
    pub db_path: String,
    pub log_level: String,
    pub dns_master_key: String,
    pub dns_token_secret: String,
    pub dns_access_mode: String, // "public" or "private"
    pub upstream_cron: String,
    pub upstream_tz: String,
    pub safe_browsing_keys: Vec<String>,
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

        Self {
            port: parse_port("PORT", 8080),
            dot_port: parse_port("DOT_PORT", 8053),
            host: env::var("HOST").unwrap_or_else(|_| "::".to_string()),
            db_path: env::var("DB_PATH").unwrap_or_else(|_| "/data/amardns.wal".to_string()),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            dns_master_key: env::var("DNS_MASTER_KEY").unwrap_or_default(),
            dns_token_secret: env::var("DNS_TOKEN_SECRET").unwrap_or_default(),
            dns_access_mode: env::var("DNS_ACCESS_MODE")
                .unwrap_or_else(|_| "public".to_string()),
            upstream_cron: env::var("UPSTREAM_CRON")
                .unwrap_or_else(|_| "0 0 * * *".to_string()),
            upstream_tz: env::var("UPSTREAM_TZ")
                .unwrap_or_else(|_| "Asia/Dhaka".to_string()),
            safe_browsing_keys,
        }
    }

    /// Validate the configuration and return a list of human-readable
    /// diagnostic strings.  Each string is prefixed with either `"ERROR:"` or
    /// `"WARNING:"` so callers can distinguish severity.
    ///
    /// * **Errors** indicate values that will definitely cause the server to
    ///   malfunction.
    /// * **Warnings** indicate values that are insecure or likely
    ///   mis-configured but will not prevent startup.
    pub fn validate(&self) -> Vec<String> {
        let mut issues: Vec<String> = Vec::new();

        // ── PORT ────────────────────────────────────────────────────────────
        // parse_port() already falls back gracefully; we surface the raw env
        // value here so main.rs can log/display a structured error.
        if let Ok(raw) = env::var("PORT") {
            let trimmed = raw.trim();
            if trimmed.parse::<u16>().map_or(true, |p| p == 0) {
                issues.push(format!(
                    "ERROR: PORT value '{}' is not in the valid range 1-65535; \
                     using default 8080.",
                    raw
                ));
            }
        }

        // ── DOT_PORT ────────────────────────────────────────────────────────
        if let Ok(raw) = env::var("DOT_PORT") {
            let trimmed = raw.trim();
            if trimmed.parse::<u16>().map_or(true, |p| p == 0) {
                issues.push(format!(
                    "ERROR: DOT_PORT value '{}' is not in the valid range 1-65535; \
                     using default 8053.",
                    raw
                ));
            }
        }

        // ── DNS_MASTER_KEY ──────────────────────────────────────────────────
        if self.dns_master_key.is_empty() {
            issues.push(
                "ERROR: DNS_MASTER_KEY is not set. \
                 The server cannot authenticate administrative requests."
                    .to_string(),
            );
        } else if self.dns_master_key.starts_with("CHANGE_ME") {
            issues.push(
                "ERROR: DNS_MASTER_KEY starts with 'CHANGE_ME'. \
                 Please set a strong, unique master key."
                    .to_string(),
            );
        } else if self.dns_master_key.len() < 16 {
            issues.push(
                "WARNING: DNS_MASTER_KEY is shorter than 16 characters. \
                 Use a longer key for adequate security."
                    .to_string(),
            );
        }

        // ── DNS_TOKEN_SECRET ────────────────────────────────────────────────
        if self.dns_token_secret.is_empty() {
            issues.push(
                "WARNING: DNS_TOKEN_SECRET is not set. \
                 View tokens (JWT signing) will not work."
                    .to_string(),
            );
        } else if self.dns_token_secret.starts_with("CHANGE_ME") {
            issues.push(
                "WARNING: DNS_TOKEN_SECRET starts with 'CHANGE_ME'. \
                 Please set a strong, unique token secret."
                    .to_string(),
            );
        } else if self.dns_token_secret.len() < 32 {
            issues.push(
                "WARNING: DNS_TOKEN_SECRET is shorter than 32 characters. \
                 Secrets under 32 bytes provide insufficient HMAC-SHA256 security."
                    .to_string(),
            );
        }

        // ── DNS_ACCESS_MODE ─────────────────────────────────────────────────
        let mode = self.dns_access_mode.as_str();
        if mode != "public" && mode != "private" {
            issues.push(format!(
                "WARNING: DNS_ACCESS_MODE value '{}' is not recognised. \
                 Expected 'public' or 'private'.",
                mode
            ));
        }

        // ── LOG_LEVEL ───────────────────────────────────────────────────────
        const VALID_LOG_LEVELS: &[&str] = &["error", "warn", "info", "debug", "trace"];
        if !VALID_LOG_LEVELS.contains(&self.log_level.to_lowercase().as_str()) {
            issues.push(format!(
                "WARNING: LOG_LEVEL value '{}' is not one of the recognised levels \
                 (error, warn, info, debug, trace).",
                self.log_level
            ));
        }

        issues
    }

    /// Returns `true` when the server is configured for private (authenticated)
    /// access only.
    pub fn access_mode_is_private(&self) -> bool {
        self.dns_access_mode.trim().eq_ignore_ascii_case("private")
    }
}

