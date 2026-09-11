<p align="center">
  <h1 align="center">⚡ AmarDNS v2.0</h1>
  <p align="center">
    <strong>Ultra-Fast, Zero-GC, Memory-Safe DNS-over-HTTPS & DNS-over-TLS Security Gateway in Rust</strong>
  </p>
  <p align="center">
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-2021_Edition-orange.svg" alt="Rust"></a>
    <a href="https://fly.io/"><img src="https://img.shields.io/badge/Platform-Fly.io-purple.svg" alt="Fly.io"></a>
    <img src="https://img.shields.io/badge/Memory-Zero_GC_~13MB-green.svg" alt="Zero GC Memory">
    <img src="https://img.shields.io/badge/Latency-P95_<6ms-brightgreen.svg" alt="Latency">
  </p>
</p>

---

## 📖 Overview

**AmarDNS v2.0** is an enterprise-grade, asynchronous recursive DNS security resolver written in pure **Rust**. It provides high-throughput **DNS-over-HTTPS (DoH, RFC 8484)** and **DNS-over-TLS (DoT, RFC 7858)** endpoints, shielding networks from advertisements, malware, phishing traps, command-and-control (C2) botnets, and zero-day algorithmic threats.

Engineered to operate with **zero garbage-collection pauses**, AmarDNS indexes over **900,000 malicious domains in just 4 MB of RAM** and delivers sub-millisecond in-memory cache resolutions with automatic upstream hedging.

> **⚠️ TLS Termination Architecture**: AmarDNS processes DNS-over-HTTPS on plain HTTP internally and DNS-over-TLS on raw TCP internally. **TLS encryption is terminated at the edge proxy** (Fly.io Anycast Edge on ports 443/853 via `handlers = ["tls"]` in `fly.toml`). If you deploy outside Fly.io, you **MUST** place a TLS-terminating reverse proxy (e.g. Nginx, Caddy, Traefik) in front. **Never expose port 443 or 853 directly to the internet without TLS.**

---

## 🚀 Key Architectural Features

```
Incoming Query (DoH / DoT)
       │
       ▼
 ┌───────────────┐
 │ 1. Exact WL   │── Match ──► ALLOW (Explicit domain whitelist overrides everything)
 └───────┬───────┘
         ▼ No Match
 ┌───────────────┐
 │ 2. Exact BLK  │── Match ──► BLOCK (Punches a hole right through wildcard whitelists!)
 └───────┬───────┘
         ▼ No Match
 ┌───────────────┐
 │ 3. Wildcard WL│── Match ──► ALLOW (Protects remaining subdomains under *.parent)
 └───────┬───────┘
         ▼ No Match
 ┌───────────────┐
 │ 4. Custom BLK │── Match ──► BLOCK (Custom wildcard blocklists)
 └───────┬───────┘
         ▼ No Match
 ┌───────────────┐
 │ 5. AI Engines │── Match ──► BLOCK (Shannon entropy DGA > 3.65 / Lookalike / Neural Brain)
 └───────┬───────┘
         ▼ No Match
 ┌───────────────┐
 │ 6. Feed Bloom │── Match ──► BLOCK (900k+ global threat feed suffix-walk)
 └───────┬───────┘
         ▼ No Match
 ┌─────────────────────────────────────────────────────────┐
 │ 7. Speculative Hedged Resolution (P95: 5ms, P99: 6ms)  │
 │ Stage 1: Primary Resolver (0ms)                         │
 │ Stage 2: 10ms Hedge Race (Secondary Resolver)           │
 │ Stage 3: 25ms Hedge Race (Tertiary Resolver)            │
 └─────────────────────────────────────────────────────────┘
```

### 1. Ultra-Compact Dual-Hash Bloom Filters
- **Threat Feed**: Indexes 900,000+ domains into a **33,554,432-bit (4 MB RAM)** bitset ($k=7$ probes). False-positive probability is mathematically guaranteed at $< 0.00005\%$ ($< 1 \text{ in } 2,000,000$).
- **Whitelist Feed**: Indexes 2,800+ authoritative domains into **262,144 bits (32 KB RAM)**, fitting **100% inside CPU L1/L2 data cache**.
- **Hardware Optimization**: Sized to powers of two ($2^B$), replacing CPU integer division (`%`) with single-cycle bitwise masking (`&`).
- **Kirsch-Mitzenmacher Double-Hashing**: Dual independent 64-bit mixers (FNV-1a golden ratio prime + Wyhash-style rotated multiplier) finished with SplitMix64 and odd coprime stepping (`h2 | 1`).

### 2. Specificity Hierarchy (Hole-Punching Rules)
- **Exact Whitelist (Priority 1)**: Explicit domain additions always take absolute priority.
- **Exact Block Hole-Punching (Priority 2)**: Specific subdomain blocks punch a hole through broad wildcard whitelists. (e.g. `*.apple.com` is whitelisted, but `analytics.apple.com` is blocked; while `apple.com` and `music.apple.com` remain allowed).
- **Wildcard Whitelist (Priority 3)**: Broad rules protect all remaining subdomains.

### 3. Multi-Resolver Hedged Racing Pool
- Tracks top-tier public resolvers (Cloudflare, Google, Quad9, AdGuard, CleanBrowsing, ControlD, Mullvad) with real-time EWMA latency and percentiles (P50, P95, P99).
- **Speculative Hedging**: Fires the fastest resolver immediately. If it does not answer within 10ms, races the secondary resolver in parallel. Eliminates tail latency.
- **Circuit Breakers with Self-Healing**: Isolates degraded resolvers and heals error counts on consecutive successful responses.

### 4. Autonomous AI Zero-Day Shields
- **DGA Malware Detection**: Computes Shannon entropy on domain labels in $O(N)$. Intercepts algorithmic botnet domains ($H > 3.65$, length $\ge 12$).
- **Lookalike & Homoglyph Defense**: Normalizes confusing characters and runs Levenshtein distance checks to stop brand impersonation traps.
- **Online Neural Brain**: 8-layer neural weights updated online via live traffic telemetry.

### 5. AeroCache & PulseDB WAL
- Concurrent **W-TinyLFU / S3-FIFO** in-memory cache (bounded to 250,000 entries) with automatic TTL invalidation.
- Persistent Write-Ahead Log (`PulseDB`) with automatic background compaction every 10 minutes.

### 6. Real-Time Telemetry Dashboard
- Embedded zero-dependency web interface served from `/dashboard`.
- Real-time RPS tracking, cache hit rates, upstream health aura metrics, client device activity, and interactive rule management.

---

## 🛠️ Getting Started

### Prerequisites
- [Rust 1.75+](https://www.rust-lang.org/tools/install) (Edition 2021)
- *Optional*: Docker for containerized deployment

### Build & Run Locally

```bash
# Clone the repository
git clone https://github.com/0abir/amardns.git
cd amardns

# Run test suite (all 33 unit tests)
cargo test --release

# Run AmarDNS in release mode
cargo run --release
```

Server will start on:
- **DoH**: `http://127.0.0.1:443/dns-query`
- **DoT**: `127.0.0.1:853`
- **Dashboard**: `http://127.0.0.1:443/dashboard`

---

## 🐳 Docker Deployment

The included multi-stage `Dockerfile` produces a **scratch container (< 12 MB)** with zero package managers, zero shells, and non-root execution (UID 65532).

```bash
# Build Docker image
docker build -t amardns:latest .

# Run container with persistent WAL storage
docker run -d \
  --name amardns \
  -p 443:443 \
  -p 853:853 \
  -v amardns_data:/data \
  amardns:latest
```

---

## ☁️ Deploy to Fly.io

1. Copy the example configuration template:
   ```bash
   cp fly.toml.example fly.toml
   ```
2. Configure your environment secrets in `fly.toml` or via Fly secrets:
   ```bash
   fly secrets set DNS_MASTER_KEY="your_admin_key" DNS_TOKEN_SECRET="your_64_char_secret"
   ```
3. Deploy to Fly.io:
   ```bash
   fly deploy --remote-only
   ```

---

## ⚙️ Configuration Reference

All settings are configured via environment variables:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `443` | Local HTTP & DoH listening port. |
| `DOT_PORT` | `853` | Local DoT listening port. |
| `HOST` | `::` | Network binding address (`::` for dual-stack IPv4/IPv6). |
| `DB_PATH` | `/data/amardns.wal` | Path to persistent Write-Ahead Log. |
| `LOG_LEVEL` | `info` | Tracing log level (`error`, `warn`, `info`, `debug`). |
| `DNS_MASTER_KEY` | *(empty)* | Master API key for administrative endpoints and token creation. |
| `DNS_TOKEN_SECRET`| *(empty)* | 64-character secret for HMAC signed view-only tokens. |
| `DNS_ACCESS_MODE` | `public` | `public` (open resolver) or `private` (requires key/device ID). |
| `SAFE_BROWSING_KEYS` | *(empty)* | Comma-separated Google Safe Browsing v4 API keys. |
| `UPSTREAM_CRON` | `0 0 * * *` | Cron schedule for threat feed sync & upstream ranking. |
| `UPSTREAM_TZ` | `Asia/Dhaka` | Timezone for scheduled maintenance tasks. |

---

## 📡 Router Setup (OpenWrt `https-dns-proxy`)

To use AmarDNS with OpenWrt's `https-dns-proxy` for full multi-threaded parallel resolution across two local listeners:

```uci
config https-dns-proxy 'amardns_1'
    option listen_addr '127.0.0.1'
    option listen_port '5053'
    option user 'nobody'
    option group 'nogroup'
    option bootstrap_dns '66.241.124.207'
    option resolver_url 'https://amardns.fly.dev/dns-query?client=router_primary'

config https-dns-proxy 'amardns_2'
    option listen_addr '127.0.0.1'
    option listen_port '5054'
    option user 'nobody'
    option group 'nogroup'
    option bootstrap_dns '2a09:8280:1::186:5faa:0,66.241.124.207'
    option resolver_url 'https://amardns.fly.dev/dns-query?client=router_secondary'
```

---

## 📄 License

AmarDNS is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for complete details.

```
Copyright 2026 Abir (https://github.com/0abir)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
