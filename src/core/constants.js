// src/core/constants.js
// System constants, limits, quotas, HTTP security headers, and regex patterns.

export const VERSION = "01.00.00";
export const OPEN_ACCESS = Symbol("OPEN_ACCESS");

export const DNS_CT = "application/dns-message";
export const SECURITY_H = Object.freeze({
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
});
export const DNS_H = Object.freeze({
  ...SECURITY_H,
  "cross-origin-resource-policy": "cross-origin",
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type, accept",
  "access-control-max-age": "86400",
  "content-type": DNS_CT,
});
export const CORS_H = Object.freeze({
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type, authorization, accept",
  "access-control-max-age": "3600",
  "vary": "Origin",
});
export const NO_CACHE_H = Object.freeze({
  "cache-control": "no-store, no-cache, must-revalidate, proxy-revalidate",
  "pragma": "no-cache",
  "expires": "0",
});
export const ADMIN_CORS_H = Object.freeze({
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, PUT, DELETE, OPTIONS",
  "access-control-allow-headers": "content-type, authorization, x-auth-key",
  "access-control-max-age": "3600",
  "vary": "Origin",
});
export const KV_WRITE_LIMIT = Infinity;
export const KV_READ_LIMIT = Infinity;
export const D1_WRITE_LIMIT = Infinity;
export const D1_READ_LIMIT = Infinity;
export const D1_SOFT_CAP = 1.0;
export const BRAIN_SYNC_INTERVAL = 2 * 60 * 1e3;
export const BRAIN_CHUNK_SIZE = 1e4;
export const MAX_BODY = 65535;
export const MAX_DNS_QUERY = 4096;
export const MAX_ADMIN_BODY = 1024 * 1024;
export const _BG_SET1 = new Set(
  "th he in er an re on en at nd st es to it is or te et ng hi".split(" "),
);
export const _BG_SET2 = new Set(
  "th he in er an re on en at nd st es to it is or te et ng hi as ou ea ha ed be ti ev of co al ie nt se lo pl ur".split(
    " ",
  ),
);
export const _RE_VOWELS = /[aeiou]/g;
export const _RE_DIGITS = /\d/g;
export const _RE_CONSONANT_RUN = /[^aeiou\d\-_]{4,}/g;
export const _RE_HYPHENS = /-/g;
export const FEAT_CACHE_MAX = 1e3;
export const GSB_CACHE_MAX = 5e3;

export const ABIR_FEED = "https://cdn.jsdelivr.net/gh/abir614/-@latest/blocklist.txt";
export const ABIR_TOTAL_URL =
  "https://cdn.jsdelivr.net/gh/abir614/-@latest/total_blocked.txt";
export const COMMON_FEED = "https://cdn.jsdelivr.net/gh/abir614/-@latest/whitelist.txt";
export const COMMON_TOTAL_URL =
  "https://cdn.jsdelivr.net/gh/abir614/-@latest/total_whitelisted.txt";
export const FEED_SYNC_INTERVAL = 30 * 60 * 1e3;
export const FEED_CACHE_TTL = 24 * 60 * 60 * 1e3;

export const FEED_RETRY_INTERVAL = 5 * 60 * 1e3;
export const FEED_CACHE_MAX = 5e3;
export const BG_CONCURRENCY = 6;
export const IMPORT_CHUNK_CHARS = 1e4;
export const MAX_CACHE_TTL = 3600;
export const MIN_CACHE_TTL = 5;
export const DEF_CACHE_TTL = 300;
export const HMAC_WINDOW_S = 7200;
export const MAX_PTR_HOPS = 16;
export const NEG_TTL_MS = 3e4;
export const NEG_SRVFAIL_MS = 1e4;
export const NEG_MAX = 5e3;
export const BURST_WINDOW_MS = 2e3;
export const BURST_THRESHOLD = 60;
export const CB_WINDOW = 60;
export const CB_THRESHOLD = 0.45;
export const EWMA_FAST = 0.35;
export const EWMA_SLOW = 0.04;
export const AUTO_BLOCK_TTL = 1800;
export const AUTO_BLOCK_MAX = 200;
export const DGA_FLAG_SCORE = 50;
export const DGA_BLOCK_SCORE = 90;
export const DGA_MIN_LEN = 5;
export const LEET_MAP = {
  0: "o",
  1: "i",
  3: "e",
  4: "a",
  5: "s",
  6: "g",
  7: "t",
  8: "b",
  "@": "a",
  $: "s",
  "!": "i",
};

export const XV_PENALTY = 180;
export const TTL_DEVIATE_RATIO = 3;
export const TTL_DEFLATE_RATIO = 0.25;
export const TTL_PENALTY = 120;
export const FS_STALE_RATIO = 1.2;
export const FS_MIN_ELAPSED_S = 8;
export const FS_PENALTY = 40;

export const REBIND_PRIVATE = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^::1$/,
  /^fc|^fd/,
];
export const DGA_SKIP_TLDS = new Set([
  "gov",
  "edu",
  "mil",
  "int",
  "arpa",
  "local",
  "internal",
  "lan",
  "home",
  "corp",
]);
export const PRIVATE_SUFFIXES = new Set([
  ".local",
  ".internal",
  ".lan",
  ".home",
  ".corp",
  ".localhost",
]);

export const KV_BUCKET_CAP = 10;
export const KV_REFILL_PER_MIN = 1;
export const DOMAIN_IQ_MAX = 2e3;
export const HEATMAP_MAX = 2e3;
export const LEDGER_MAX = 200;
export const _enc = new TextEncoder();
export const _decoder = new TextDecoder();

export const _SEC_H = SECURITY_H;
