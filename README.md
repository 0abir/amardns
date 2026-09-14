# AmarDNS v2.0

**Autonomous Zero-GC Edge DNS Security Gateway & Threat Intelligence Engine in Rust**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2024_Edition-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Fly.io%20%7C%20Linux%20%7C%20Docker-purple.svg)](https://fly.io/)
[![Memory](https://img.shields.io/badge/Memory-Zero_GC_~13MB-green.svg)](#zero-allocation-memory-architecture)
[![Latency](https://img.shields.io/badge/Latency-P95_<5ms-brightgreen.svg)](#singleflight-coalescing--hedged-upstream-racing)
[![Tests](https://img.shields.io/badge/Tests-132%20Passed%20(100%25)-success.svg)](#testing--verification)

---

## Overview

**AmarDNS v2.0** is an enterprise-grade, asynchronous recursive DNS security resolver written in pure **Rust**. It provides high-throughput **DNS-over-HTTPS (DoH, RFC 8484)**, **DNS-over-TLS (DoT, RFC 7858)**, **DNS-over-HTTP/3 (DoH3, RFC 9114)**, **DNS-over-QUIC (DoQ, RFC 9250)**, and standard **UDP/TCP Port 53 (RFC 1035)** endpoints.

Engineered with a **zero garbage-collection architecture**, AmarDNS indexes over **900,000 malicious domains in just 4 MB of RAM** and delivers sub-millisecond in-memory cache resolutions with automatic upstream hedging, cryptographic DNSSEC validation, singleflight deduplication, and an 8D online neural threat engine.

---

## System Architecture

```
Incoming Query (DoH / DoT / DoH3 / DoQ / Plain 53)
       │
       ▼
 ┌───────────────────────────────────────────────────────────┐
 │ 1. Edge Shielding & Rate Limiter (Dual-Token Bucket)      │
 └─────────────────────────────┬─────────────────────────────┘
                               ▼
 ┌───────────────────────────────────────────────────────────┐
 │ 2. Exact Whitelist (Priority 1)                           │── Match ──► ALLOW (Bypasses all checks)
 └─────────────────────────────┬─────────────────────────────┘
                               ▼ No Match
 ┌───────────────────────────────────────────────────────────┐
 │ 3. Exact Block Hole-Punch (Priority 2)                    │── Match ──► BLOCK (Punches through wildcard whitelists)
 └─────────────────────────────┬─────────────────────────────┘
                               ▼ No Match
 ┌───────────────────────────────────────────────────────────┐
 │ 4. Wildcard Whitelist (Priority 3)                        │── Match ──► ALLOW (Protects remaining subdomains)
 └─────────────────────────────┬─────────────────────────────┘
                               ▼ No Match
 ┌───────────────────────────────────────────────────────────┐
 │ 5. Custom Wildcard Blocklist (Priority 4)                 │── Match ──► BLOCK (User-defined regex/wildcards)
 └─────────────────────────────┬─────────────────────────────┘
                               ▼ No Match
 ┌───────────────────────────────────────────────────────────┐
 │ 6. AI 8D Neural + Markov & Shannon DGA Engine (Priority 5)│── Match ──► BLOCK (Intercepts zero-day algorithmic threats)
 └─────────────────────────────┬─────────────────────────────┘
                               ▼ No Match
 ┌───────────────────────────────────────────────────────────┐
 │ 7. Global Threat Feed Bloom Filter (Priority 6)           │── Match ──► BLOCK (900,000+ threat domain suffix walk)
 └─────────────────────────────┬─────────────────────────────┘
                               ▼ No Match
 ┌───────────────────────────────────────────────────────────┐
 │ 8. AeroCache & Fast-Negative Filter                       │── Hit ────► Instant In-Memory Serve (Sub-ms)
 └─────────────────────────────┬─────────────────────────────┘
                               ▼ Cache Miss
 ┌───────────────────────────────────────────────────────────┐
 │ 9. Hedged Upstream Race with Singleflight Deduplication   │
 │    • Dynamic EWMA Latency Ranking                         │
 │    • Singleflight In-Flight Coalescing (Zero Duplication) │
 │    • Self-Healing Circuit Breakers                        │
 └─────────────────────────────┬─────────────────────────────┘
                               ▼ Upstream Response
 ┌───────────────────────────────────────────────────────────┐
 │ 10. DNSSEC Cryptographic Validation (RFC 4034/4035/5155)  │
 │     • Root Anchor Chain Verification (IANA PKCS#7)        │
 │     • Authenticated Denial of Existence (NSEC/NSEC3)      │
 └─────────────────────────────┬─────────────────────────────┘
                               ▼
 ┌───────────────────────────────────────────────────────────┐
 │ 11. DNS Rebinding Sanitizer (RFC 1918 / Loopback Filter)  │
 └─────────────────────────────┬─────────────────────────────┘
                               ▼
                        Client Response
```

---

## Core Subsystems

### 1. Multi-Protocol Edge Ingestion
- **DNS-over-HTTPS (DoH, RFC 8484)**: Binary wireformat queries over HTTP/2 and HTTP/1.1 via `POST /dns-query` and `GET /dns-query?dns=...`.
- **DoH JSON REST API (RFC 8427)**: Browser-testable JSON endpoint via `GET /resolve?name=example.com&type=A`.
- **DNS-over-TLS (DoT, RFC 7858)**: Strict TLS on port `853` with ALPN `dot` negotiation.
- **DNS-over-QUIC (DoQ, RFC 9250)** & **DNS-over-HTTP/3 (DoH3)**: Ultra-low-latency UDP multiplexing with 0-RTT connection resumption.
- **Plain UDP/TCP Port 53 (RFC 1035)**: Standard recursive forwarding with EDNS(0) Cookie (RFC 7873) spoof protection and seamless TCP fallback for oversized responses.

### 2. Zero-Allocation Memory Architecture
- **Custom Zero-Copy Wire Parser**: Direct bit-level RFC 1035 parsing and serialization in `src/dns/parser.rs` with zero allocations on query hot paths.
- **Dual-Hash Threat Bloom Filter**: Indexes **900,000+ domains** in **4 MB of RAM** ($2^{25}$ bits, $k=7$ probes). False-positive probability is mathematically capped at $< 0.00005\%$ ($< 1 \text{ in } 2,000,000$).
- **Dual-Hash Whitelist Bloom Filter**: Indexes **2,800+ authoritative domains** in **32 KB of RAM**, fitting entirely inside CPU L1/L2 data cache.
- **Kirsch-Mitzenmacher Double-Hashing**: Dual independent 64-bit mixers (FNV-1a prime mixer + Wyhash rotated multiplier) finished with SplitMix64 and odd coprime stepping (`h2 | 1`).
- **Power-of-Two Masking**: Bitset dimensions are constrained to $2^B$, replacing slow CPU division (`%`) with single-cycle bitwise masking (`&`).

### 3. Strict Hole-Punching Rule Hierarchy
1. **Exact Whitelist (Priority 1)**: Explicit domain approvals always take absolute precedence.
2. **Exact Block Hole-Punch (Priority 2)**: Explicit subdomain blocks punch directly through broad wildcard whitelists (e.g., `*.apple.com` is whitelisted, but `analytics.apple.com` is explicitly blocked, while `apple.com` and `icloud.com` remain allowed).
3. **Wildcard Whitelist (Priority 3)**: Approves all remaining subdomains under an authorized apex domain.
4. **Custom Wildcard Blocklist (Priority 4)**: User-defined blocking rules.
5. **AI Heuristics & Neural Brain (Priority 5)**: Real-time DGA Shannon entropy ($H > 3.65$), homoglyph Levenshtein distance, and 8-feature neural classification.
6. **Global Threat Feed Bloom Filter (Priority 6)**: Suffix-walking verification against 400k+ malicious domains.

### 4. Singleflight Coalescing & Hedged Upstream Racing
- **Singleflight Deduplication**: When multiple clients concurrently request the same cache-miss domain, AmarDNS coalesces the requests into a single in-flight upstream lookup. All waiting clients share the single response, preventing upstream stampedes.
- **Speculative Hedged Racing**: Resolves queries against top-ranked providers (Cloudflare, Google, Quad9, Mullvad, CleanBrowsing, ControlD). The primary resolver is fired at $0\text{ms}$; if unanswered by $10\text{ms}$, a secondary hedged race begins in parallel to eliminate tail latency.
- **Dynamic EWMA Ranking & Circuit Breakers**: Upstreams are ranked continuously by exponentially weighted moving average latency. Nodes exhibiting consecutive errors or timeouts are isolated automatically and self-healed upon recovery.

### 5. DNSSEC Cryptographic Validation
- **RFC 4034 / 4035 / 5155 Validation Engine**: Verifies cryptographic signatures (`RRSIG`), DNS public keys (`DNSKEY`), and Delegation Signer (`DS`) records from the domain up to the root.
- **Authenticated Denial of Existence**: Validates `NSEC` and `NSEC3` proofs to mathematically verify non-existence without trusting unsigned `NXDOMAIN` responses.
- **Automated Root Anchor Sync with PKCS#7 Verification**: Periodically syncs root trust anchors directly from IANA with S/MIME PKCS#7 cryptographic signature validation (`src/dns/pkcs7.rs`).
- **EDNS(0) Signaling**: Correctly negotiates the `DO` (DNSSEC OK) bit and emits the `AD` (Authenticated Data) flag.

### 6. Dynamic Operating & Load-Balancing Modes
- **FAST MODE** ($\text{Stress} < 0.3$): Direct single-path resolution to the lowest-latency upstream node, zero racing overhead, instant SWR cache delivery.
- **BALANCED MODE** ($0.3 \le \text{Stress} \le 0.8$): Dual hedged upstream racing with EWMA load spreading across multiple providers.
- **RELIABLE / STRESS MODE** ($\text{Stress} > 0.8$ or $\text{RPS} > 100$): Parallel fan-out racing with singleflight deduplication and aggressive circuit breaking.
- **Access Modes**: `PRIVATE` (Enforces Master Key or HMAC token validation) vs. `PUBLIC` (Open resolution with rate-limiting).
- **Filtering Modes**: `ACTIVE` (Enforces threat blocking) vs. `DEACTIVE` (Audit/telemetry mode only).

### 7. Glassmorphic Real-Time Dashboard & Error Diagnostics
- **Zero-Dependency Web UI**: Real-time telemetry dashboard rendered directly from edge memory at `/dashboard` (or `/:key`).
- **Live Metrics**: Real-time RPS and peak RPS, latency histogram distribution ($<1\text{ms}$, $1\text{--}5\text{ms}$, $5\text{--}15\text{ms}$, $15\text{--}50\text{ms}$, $>50\text{ms}$), active client devices, threat heatmap, upstream health metrics, dynamic RAM allocation, singleflight coalescing count, and AI neural weights.
- **Modern Cyberpunk Error Pages**: Dark glassmorphic error pages for `404 Not Found`, `401 Unauthorized`, `403 Forbidden`, `405 Method Not Allowed`, and `500 Internal Error` with live node diagnostics (Client IP, Edge Region, Node UID, Requested Path).
- **Zero Emojis**: Clean typography, vector status indicators, and SVG icons.

---

## Getting Started

### Prerequisites
- [Rust 1.98+](https://www.rust-lang.org/tools/install) (Edition 2024)
- *Optional*: Docker or Podman for containerized deployment

### Build & Run Locally

```bash
# Clone repository
git clone https://github.com/0abir/amardns.git
cd amardns

# Run full test suite (132 tests)
cargo test

# Run in release mode
cargo run --release
```

Local listener endpoints:
- **DoH Wire & JSON**: `http://127.0.0.1:8443/dns-query` and `http://127.0.0.1:8443/resolve`
- **DoT**: `127.0.0.1:8853`
- **Dashboard**: `http://127.0.0.1:8443/`

---

## Docker Deployment

The multi-stage `Dockerfile` compiles AmarDNS with full Link-Time Optimization (LTO) and outputs a minimal container based on `gcr.io/distroless/cc-debian12` (< 15 MB) executed as a non-privileged user.

```bash
# Build Docker image
docker build -t amardns:latest .

# Run container with persistent WAL storage volume
docker run -d \
  --name amardns \
  -p 8443:8443 \
  -p 853:8853 \
  -v amardns_data:/data \
  amardns:latest
```

---

## Deploy to Fly.io

AmarDNS is optimized for deployment on Fly.io Anycast edge hardware:

1. Create or verify `fly.toml`:
   ```bash
   cp fly.toml.example fly.toml
   ```
2. Configure runtime secrets:
   ```bash
   fly secrets set DNS_MASTER_KEY="your_secure_master_key" DNS_TOKEN_SECRET="your_64_char_hmac_secret"
   ```
3. Deploy to Fly.io:
   ```bash
   fly deploy --remote-only
   ```

---

## Configuration Reference

All settings are configured via environment variables:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `8443` | Local HTTP / DoH listening port. |
| `DOT_PORT` | `8853` | Local DoT listening port. |
| `DOQ_PORT` | `8853` | Local DoQ UDP listening port. |
| `PLAIN_DNS_PORT` | `53` | Local plain UDP/TCP DNS listening port. |
| `HOST` | `::` | Network binding interface (`::` for dual-stack IPv4/IPv6). |
| `DB_PATH` | `/data/amardns.wal` | Filesystem path to the persistent Write-Ahead Log. |
| `LOG_LEVEL` | `info` | Logging verbosity (`error`, `warn`, `info`, `debug`, `trace`). |
| `DNS_MASTER_KEY` | *(empty)* | Master administrative API key for authentication and management. |
| `DNS_TOKEN_SECRET` | *(empty)* | 64-character secret for HMAC signed view-only tokens. |
| `DNS_ACCESS_MODE` | `private` | Access policy: `private` (authentication enforced) or `public`. |
| `DNSSEC_ENABLED` | `true` | Enables RFC 4034/4035/5155 cryptographic DNSSEC validation. |
| `SAFE_BROWSING_KEYS` | *(empty)* | Optional comma-separated Google Safe Browsing v4 API keys. |
| `UPSTREAM_CRON` | `0 0 * * *` | Cron expression for background threat feed sync and ranking. |
| `UPSTREAM_TZ` | `Asia/Dhaka` | IANA timezone for scheduled maintenance tasks. |
| `TLS_CERT_PATH` | *(empty)* | Optional path to custom TLS certificate file (X.509 PEM). |
| `TLS_KEY_PATH` | *(empty)* | Optional path to custom TLS private key file (PKCS#8 PEM). |

---

## Router & Client Setup

### OpenWrt (`https-dns-proxy`)
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

### Android (Private DNS / DoT)
- Navigate to: **Settings** $\rightarrow$ **Network & internet** $\rightarrow$ **Private DNS**.
- Select **Private DNS provider hostname** and enter: `amardns.fly.dev` (or your custom domain).

### Apple iOS / macOS (DoH Profile)
- Configure Encrypted DNS via configuration profile targeting: `https://amardns.fly.dev/dns-query`.

---

## API Endpoints Reference

| Endpoint | Method | Role | Description |
| :--- | :--- | :--- | :--- |
| `/dns-query` | `GET`, `POST` | Public / Private | Standard DoH wireformat endpoint (RFC 8484). |
| `/resolve` | `GET` | Public / Private | RFC 8427 DoH JSON query endpoint. |
| `/health` | `GET` | Public | Zero-allocation edge health status payload. |
| `/metrics` | `GET` | Admin | Prometheus exposition metrics. |
| `/` or `/:key` | `GET` | Public / View / Admin | Glassmorphic dashboard and telemetry console. |
| `/api/status` | `GET` | View / Admin | Real-time system telemetry and node diagnostics. |
| `/api/intelligence` | `GET` | View / Admin | Threat feeds, Bloom filter metrics, and domain IQ. |
| `/api/rules` | `GET`, `POST` | Admin | Manage custom blocklists and whitelists. |
| `/api/settings/blocking` | `POST` | Admin | Toggle blocking mode (`active` / `deactive`). |
| `/api/settings/dns-mode` | `POST` | Admin | Toggle server access mode (`public` / `private`). |

---

## Testing & Verification

AmarDNS includes an exhaustive unit and integration test suite covering RFC 1035 wire parsing, S/MIME PKCS#7 verification, DNSSEC validation, rate limiting, and singleflight deduplication:

```bash
# Execute test suite
cargo test --all-targets

# Execute strict linter verification
cargo clippy --all-targets -- -D warnings
```

---

## License

AmarDNS is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for complete details.

```
Copyright 2026 Abir (https://github.com/0abir)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
