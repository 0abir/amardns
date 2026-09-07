// src/env-shim.js
// Modern environment loader for AmarDNS.
// Initializes AeroCache (in-process zero-copy S3-FIFO) and PulseDB (SuffixTrie WAL persistence).
// Zero native C++ compilation dependencies (no better-sqlite3 or node-gyp).

import { AeroCache } from "./storage/aero-cache.js";
import { PulseDB } from "./storage/pulse-db.js";

let _sharedCache = null;
let _sharedDb = null;

export function buildEnv() {
  const rawPath = process.env.DB_PATH || "./data/amardns.wal";
  const dbFile = rawPath.endsWith(".sqlite")
    ? rawPath.replace(/\.sqlite$/, ".wal")
    : rawPath;

  if (!_sharedDb) {
    _sharedDb = new PulseDB(dbFile);
    _sharedDb.boot();
  }

  if (!_sharedCache) {
    _sharedCache = new AeroCache({
      maxEntries: Number(process.env.CACHE_MAX_ENTRIES) || 25000,
      maxBytes: Number(process.env.CACHE_MAX_BYTES) || 24 * 1024 * 1024,
    });
  }

  return {
    pulseDb: _sharedDb,
    aeroCache: _sharedCache,
    db: _sharedDb,
    cache: _sharedCache,

    // Secrets & config
    DNS_MASTER_KEY: process.env.DNS_MASTER_KEY,
    DNS_TOKEN_SECRET: process.env.DNS_TOKEN_SECRET,
    DNS_CACHE_SECRET: process.env.DNS_CACHE_SECRET,
    DNS_WORKER_NAME: process.env.DNS_WORKER_NAME || "amardns",
    SAFE_BROWSING_KEYS: process.env.SAFE_BROWSING_KEYS || "",
    BRANDS_LIST: process.env.BRANDS_LIST || "",
    UPSTREAM_BASES: process.env.UPSTREAM_BASES || "",
    EXPECTED_USERS: process.env.EXPECTED_USERS || "1",
    DNS_ACCESS_MODE: process.env.DNS_ACCESS_MODE || "private",

    // DoT configuration
    DOT_PORT: Number(process.env.DOT_PORT) || 853,
    DOT_ENABLED: process.env.DOT_ENABLED !== "false",
  };
}
