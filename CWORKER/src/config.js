// CWORKER/src/config.js
// Centralized, zero-dependency hardcoded configuration for AmarDNS Edge Security Resolver.
// All application constants, master keys, quotas, and engine limits are hardcoded directly here.

export const CONFIG = {
  APP_NAME: 'AmarDNS Cloudflare Edge',
  DNS_MASTER_KEY: 'abir73890',
  DNS_ACCESS_MODE: 'public',
  BLOCK_ACTION: 'ZERO_IP', // 'ZERO_IP' (0.0.0.0 / ::) or 'NXDOMAIN'
  UPSTREAM_TIMEOUT_MS: 3500,
  DEFAULT_CACHE_TTL: 300,
  MAX_MEMORY_CACHE_ENTRIES: 5000,
  DAILY_KV_WRITE_CAP: 900,
  DAILY_KV_READ_CAP: 90000,
  DAILY_D1_WRITE_CAP: 90000,
  DAILY_D1_READ_CAP: 4500000,
  MAX_QUERY_LOGS: 100
};
