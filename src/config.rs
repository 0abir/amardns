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

impl Config {
    pub fn from_env() -> Self {
        let sb_env = env::var("SAFE_BROWSING_KEYS").unwrap_or_default();
        let safe_browsing_keys: Vec<String> = sb_env
            .split(',')
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .collect();

        Self {
            port: env::var("PORT").unwrap_or_else(|_| "8080".to_string()).parse().unwrap_or(8080),
            dot_port: env::var("DOT_PORT").unwrap_or_else(|_| "8053".to_string()).parse().unwrap_or(8053),
            host: env::var("HOST").unwrap_or_else(|_| "::".to_string()),
            db_path: env::var("DB_PATH").unwrap_or_else(|_| "/data/amardns.wal".to_string()),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            dns_master_key: env::var("DNS_MASTER_KEY").unwrap_or_default(),
            dns_token_secret: env::var("DNS_TOKEN_SECRET").unwrap_or_default(),
            dns_access_mode: env::var("DNS_ACCESS_MODE").unwrap_or_else(|_| "public".to_string()),
            upstream_cron: env::var("UPSTREAM_CRON").unwrap_or_else(|_| "0 0 * * *".to_string()),
            upstream_tz: env::var("UPSTREAM_TZ").unwrap_or_else(|_| "Asia/Dhaka".to_string()),
            safe_browsing_keys,
        }
    }
}
