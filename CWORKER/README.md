# AmarDNS - Standalone Cloudflare Worker Edition

A high-performance, zero-maintenance, serverless DNS-over-HTTPS (DoH) security resolver and real-time dashboard engineered natively for the **Cloudflare Workers** edge runtime.

---

## Architecture & Features

- **Serverless Anycast Edge**: Runs on Cloudflare's global edge network in 300+ cities.
- **Zero TLS Management**: Cloudflare automatically provisions, terminates, and renews edge SSL/TLS certificates.
- **Dual-Tier Zero-Cost Caching**:
  - **Tier 1 (Cloudflare Edge Cache API)**: Completely free, unlimited global DNS response caching with configurable TTL.
  - **Tier 2 (In-Memory V8 LRU)**: Sub-millisecond in-memory cache within active Worker isolates.
- **Strict Free-Tier Quota Guardian**: Enforces daily caps on KV and D1 writes/reads to guarantee zero overages.
- **DoH Protocol Standards**:
  - RFC 8484 Binary Wireformat (`/dns-query` via GET and POST).
  - RFC 8427 JSON Resolution API (`/resolve?name=google.com&type=A`).
- **Interactive Glassmorphic Dashboard**: Real-time telemetry, query stream, upstream latency monitor, and rule manager served on `/` and `/dashboard`.
- **Tiered Threat Protection**: Exact whitelist, exact blocklist, wildcard blocklist, and custom user rules.

---

## Directory Layout

```
CWORKER/
├── package.json          # Node / Wrangler project manifest
├── wrangler.toml         # Cloudflare Worker configuration & bindings
├── README.md             # Architecture & deployment manual
├── src/
│   ├── index.js          # Fetch and Scheduled cron handlers
│   ├── api/
│   │   └── router.js     # DoH endpoints, REST APIs, and UI router
│   ├── dns/
│   │   ├── codec.js      # Pure JS RFC 1035 wireformat encoder/decoder
│   │   ├── cache.js      # Two-tier Edge Cache API + In-Memory LRU
│   │   ├── resolver.js   # Multi-upstream DoH resolver with latency ranking
│   │   └── rules.js      # Tiered rule evaluation (exact, wildcard, threats)
│   ├── storage/
│   │   ├── quota.js      # Daily KV / D1 operation cap guardian
│   │   └── store.js      # Unified persistence for R2, KV, D1, and in-memory
│   └── ui/
│       └── dashboard.js  # Glassmorphic HTML/CSS/JS dashboard generator
└── test/
    └── worker.test.js    # Automated unit test suite
```

---

## How to Deploy to Cloudflare

### 1. Prerequisites
Install Wrangler CLI:
```bash
npm install -g wrangler
```

Authenticate with your Cloudflare account:
```bash
wrangler login
```

### 2. Local Testing
```bash
cd CWORKER
node test/worker.test.js
```

### 3. Deploy
```bash
cd CWORKER
wrangler deploy
```

---

## Cloudflare Free Tier Bindings (Optional)

The worker functions immediately out-of-the-box in memory. To enable persistent rule storage across restarts, you can optionally enable R2, KV, or D1 bindings:

### 1. Cloudflare R2 (Object Storage for Rules)
```bash
wrangler r2 bucket create amardns-bucket
```
Add to `wrangler.toml`:
```toml
[[r2_buckets]]
binding = "R2"
bucket_name = "amardns-bucket"
```

### 2. Cloudflare KV (Fast Rule Store)
```bash
wrangler kv:namespace create AMARDNS_KV
```
Add to `wrangler.toml`:
```toml
[[kv_namespaces]]
binding = "KV"
id = "<YOUR_KV_NAMESPACE_ID>"
```

### 3. Cloudflare D1 (Query Logs)
```bash
wrangler d1 create amardns_db
```
Add to `wrangler.toml`:
```toml
[[d1_databases]]
binding = "DB"
database_name = "amardns_db"
database_id = "<YOUR_D1_DATABASE_ID>"
```

---

## Public Endpoints

| Protocol | Endpoint | Description |
| :--- | :--- | :--- |
| **DoH Wireformat** | `https://<worker-name>.<account>.workers.dev/dns-query` | RFC 8484 standard endpoint for browsers and DNS clients. |
| **DoH JSON API** | `https://<worker-name>.<account>.workers.dev/resolve?name=example.com&type=A` | JSON DNS query endpoint. |
| **Dashboard UI** | `https://<worker-name>.<account>.workers.dev/` | Real-time monitoring and rule management dashboard. |
| **Health Check** | `https://<worker-name>.<account>.workers.dev/health` | Edge status check. |
| **API Telemetry** | `https://<worker-name>.<account>.workers.dev/api/status` | Real-time operational metrics and quota usage. |
