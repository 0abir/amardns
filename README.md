# AmarDNS 🛡️⚡

A high-performance, ultra-lightweight, and privacy-first DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) resolver designed for minimal footprint environments (e.g. 256MB VMs, edge servers, or personal homelabs).

---

## ✨ Features

- **Dual Protocol Support**:
  - **DNS-over-HTTPS (DoH)**: RFC 8484 compliant endpoint (`/dns-query`).
  - **DNS-over-TLS (DoT)**: RFC 7858 compliant resolver on port 853 for native Android Private DNS and secure client connections.
- **Neural Threat Detection & Heuristics**:
  - Built-in ML-powered classifier for domain scoring, entropy analysis, DGA detection, and suspicious TLD evaluation.
  - Dynamic threat intelligence feed synchronization and trie-based prefix matching.
- **Ultra-Fast In-Memory Caching & Storage**:
  - **AeroCache**: High-speed LRU/TTL caching layer.
  - **PulseDB**: Append-only Write-Ahead Logging (WAL) persistent storage for analytics, logs, and state across restarts.
  - **Bloom Filters**: Fast probabilistic filtering to prevent redundant queries and malicious lookups.
- **Web Dashboard & Gateway Portal**:
  - Built-in administrative dashboard to monitor traffic, inspect queries, configure access mode, and manage blocklists.
  - Gateway access protection via master key.
- **Flexible Access Modes**:
  - **Public Mode**: Open DNS resolution (ideal for personal Android Private DNS or open resolvers).
  - **Private Mode**: Protected resolution requiring client token or master key.
- **Production-Ready & Minimal**:
  - Multi-stage Docker build producing a minimal Distroless runtime image (~25MB).
  - Pre-configured `fly.toml` for seamless 1-command deployment to Fly.io.

---

## 🚀 Getting Started

### Prerequisites

- **Node.js**: `v22.0.0` or higher
- **npm**

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/0abir/amardns.git
   cd amardns
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` to configure your ports, secrets, master key, and upstream DNS providers.

---

## ⚙️ Configuration

Key environment options in `.env`:

| Variable | Description | Default |
|---|---|---|
| `PORT` | HTTP/DoH server port | `8080` (or `443`) |
| `DOT_PORT` | DNS-over-TLS server port | `8053` (or `853`) |
| `DB_PATH` | Path to persistent WAL file | `./data/amardns.wal` |
| `DNS_MASTER_KEY` | Master secret key for admin dashboard access | Required |
| `DNS_ACCESS_MODE` | Resolver mode: `public` or `private` | `private` |
| `UPSTREAM_BASES` | JSON list of upstream DoH resolvers | `["https://cloudflare-dns.com/dns-query","https://dns.google/dns-query"]` |
| `USE_TLS` | Enable TLS for native HTTPS/DoT (reads `certs/`) | `false` |
| `CRON_SCHEDULE` | Cron interval for feed updates & compaction | `*/5 * * * *` |

---

## 🧪 Testing

Run test suites:

```bash
npm test
```

Includes unit and integration tests for storage WAL, access modes, DoT/DoH protocol handling, neural threat scoring, upstream synchronization, and stress scenarios.

---

## 🚢 Deployment

### Docker

Build and run using Docker:

```bash
docker build -t amardns .
docker run -d \
  -p 8080:8080 \
  -p 8053:8053 \
  -v amardns_data:/data \
  --env-file .env \
  amardns
```

### Fly.io

Deploy directly using Fly CLI:

```bash
fly launch
fly deploy
```

---

## 📄 License

Private / Proprietary.
