// CWORKER/src/dns/resolver.js
// Autonomous Dynamic Upstream Resolver with real-time background latency probing,
// aura-weighted ranking, singleflight deduplication, and hedged resolution.

export const DEFAULT_UPSTREAM_URL = 'https://cdn.jsdelivr.net/gh/abir614/-@latest/dns-upstream.json';

const FALLBACK_UPSTREAM_URLS = [
  'https://cdn.jsdelivr.net/gh/abir614/-@latest/dns-upstream.json',
  'https://fastly.jsdelivr.net/gh/abir614/-@latest/dns-upstream.json',
  'https://raw.githubusercontent.com/abir614/-/main/dns-upstream.json'
];

// RFC 1035 probe packet: query cloudflare.com IN A
const PROBE_PACKET = new Uint8Array([
  0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0a, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72, 0x65,
  0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01
]);
const PROBE_B64 = 'EjQBAAABAAAAAAAACmNsb3VkZmxhcmUDY29tAAABAAE';

import { CONFIG } from '../config.js';

export class UpstreamResolver {
  constructor(customConfig = {}) {
    this.timeoutMs = parseInt(customConfig.UPSTREAM_TIMEOUT_MS || CONFIG.UPSTREAM_TIMEOUT_MS, 10);
    this.inFlight = new Map(); // singleflight key -> Promise
    this.lastRankTime = 0;
    this.isSyncing = false;

    // Baseline fallback pool while background ranking warms up
    this.upstreams = [
      {
        provider: 'Cloudflare',
        url: 'https://cloudflare-dns.com/dns-query',
        aura: 'high',
        latencyMs: 12,
        score: 100,
        errors: 0,
        hits: 0,
        healthy: true
      },
      {
        provider: 'Quad9',
        url: 'https://dns.quad9.net/dns-query',
        aura: 'high',
        latencyMs: 20,
        score: 98,
        errors: 0,
        hits: 0,
        healthy: true
      },
      {
        provider: 'AdGuard',
        url: 'https://dns.adguard-dns.com/dns-query',
        aura: 'high',
        latencyMs: 25,
        score: 95,
        errors: 0,
        hits: 0,
        healthy: true
      },
      {
        provider: 'Mullvad',
        url: 'https://doh.mullvad.net/dns-query',
        aura: 'high',
        latencyMs: 28,
        score: 94,
        errors: 0,
        hits: 0,
        healthy: true
      },
      {
        provider: 'NextDNS',
        url: 'https://dns.nextdns.io/dns-query',
        aura: 'medium',
        latencyMs: 18,
        score: 95,
        errors: 0,
        hits: 0,
        healthy: true
      },
      {
        provider: 'ControlD',
        url: 'https://freedns.controld.com/p0',
        aura: 'medium',
        latencyMs: 22,
        score: 92,
        errors: 0,
        hits: 0,
        healthy: true
      },
      {
        provider: 'Google',
        url: 'https://dns.google/dns-query',
        aura: 'low',
        latencyMs: 24,
        score: 90,
        errors: 0,
        hits: 0,
        healthy: true
      }
    ];
  }

  /**
   * Normalizes provider name into a clean, capitalized word.
   */
  static normalizeProviderName(raw) {
    if (!raw) return 'Upstream';
    const lower = raw.toLowerCase();
    if (lower.includes('mullvad')) return 'Mullvad';
    if (lower.includes('quad9')) return 'Quad9';
    if (lower.includes('adguard')) return 'AdGuard';
    if (lower.includes('cloudflare')) return 'Cloudflare';
    if (lower.includes('digitale')) return 'Digitale';
    if (lower.includes('nextdns')) return 'NextDNS';
    if (lower.includes('control')) return 'ControlD';
    if (lower.includes('sb') || lower.includes('dns.sb')) return 'DNSSB';
    if (lower.includes('google')) return 'Google';
    if (lower.includes('opendns')) return 'OpenDNS';
    if (lower.includes('rethink')) return 'Rethink';
    if (lower.includes('cleanbrowsing')) return 'CleanBrowsing';
    if (lower.includes('applied')) return 'AppliedPrivacy';
    if (lower.includes('dns0')) return 'dns0.eu';
    if (lower.includes('njalla')) return 'Njalla';

    const match = raw.match(/^[a-zA-Z0-9]+/);
    return match ? match[0] : 'Upstream';
  }

  /**
   * Fetches the upstream list and dynamically probes & ranks them by real latency.
   * @param {string} [customUrl]
   * @returns {Promise<{ totalProbed?: number, topCount?: number, bestProvider?: string, lowestLatencyMs?: number, inProgress?: boolean }>}
   */
  async syncAndRank(customUrl = null) {
    if (this.isSyncing) return { inProgress: true };
    this.isSyncing = true;

    try {
      const urlsToTry = customUrl ? [customUrl] : FALLBACK_UPSTREAM_URLS;
      let rawList = [];

      for (const feedUrl of urlsToTry) {
        try {
          const resp = await fetch(feedUrl, {
            headers: { 'User-Agent': 'AmarDNS-Cloudflare-Worker/1.0' },
            cf: { cacheTtl: 3600, cacheEverything: true }
          });
          if (resp.ok) {
            const json = await resp.json();
            const list = Array.isArray(json) ? json : (json.dns_over_https || []);
            if (Array.isArray(list) && list.length > 0) {
              rawList = list;
              break;
            }
          }
        } catch (e) {}
      }

      if (rawList.length === 0) {
        rawList = this.upstreams;
      }

      // Filter valid HTTPS DoH endpoints
      const candidates = rawList
        .filter(c => c && typeof c.url === 'string' && c.url.startsWith('https://'))
        .map(c => ({
          provider: UpstreamResolver.normalizeProviderName(c.provider),
          url: c.url,
          aura: (c.aura || 'medium').toLowerCase()
        }));

      // Parallel probing with timeout
      const probePromises = candidates.map(candidate => this._probeUpstream(candidate));
      const probedResults = await Promise.all(probePromises);

      // Filter successful and sort by performance & aura score
      const ranked = probedResults
        .filter(r => r.healthy && r.latencyMs < 2000)
        .sort((a, b) => {
          if (b.score !== a.score) return b.score - a.score;
          return a.latencyMs - b.latencyMs;
        });

      if (ranked.length >= 3) {
        this.upstreams = ranked;
        this.lastRankTime = Date.now();
      }

      const best = this.upstreams[0] || { provider: 'Cloudflare', latencyMs: 12 };

      return {
        totalProbed: candidates.length,
        topCount: this.upstreams.length,
        bestProvider: best.provider,
        lowestLatencyMs: best.latencyMs
      };
    } finally {
      this.isSyncing = false;
    }
  }

  /**
   * Probes an upstream endpoint using a live binary DNS query.
   * @private
   */
  async _probeUpstream(candidate) {
    const t0 = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2000);

    let ok = false;
    let latencyMs = 9999;

    try {
      // 1. Try POST with binary wire packet
      const resp = await fetch(candidate.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/dns-message',
          'Accept': 'application/dns-message',
          'User-Agent': 'AmarDNS-Prober/1.0'
        },
        body: PROBE_PACKET,
        signal: controller.signal
      });

      if (resp.ok && resp.headers.get('content-type')?.includes('dns-message')) {
        const buf = await resp.arrayBuffer();
        if (buf.byteLength >= 12) {
          ok = true;
          latencyMs = Math.max(1, Date.now() - t0);
        }
      }
    } catch (e) {
      // 2. Fallback to GET with ?dns=
      try {
        const getUrl = candidate.url.includes('?')
          ? `${candidate.url}&dns=${PROBE_B64}`
          : `${candidate.url}?dns=${PROBE_B64}`;

        const getResp = await fetch(getUrl, {
          method: 'GET',
          headers: {
            'Accept': 'application/dns-message',
            'User-Agent': 'AmarDNS-Prober/1.0'
          },
          signal: controller.signal
        });

        if (getResp.ok) {
          const buf = await getResp.arrayBuffer();
          if (buf.byteLength >= 12) {
            ok = true;
            latencyMs = Math.max(1, Date.now() - t0);
          }
        }
      } catch (e2) {}
    } finally {
      clearTimeout(timer);
    }

    const auraBonus = candidate.aura === 'high' ? 12 : (candidate.aura === 'medium' ? 6 : 0);
    const score = ok ? Math.max(10, Math.min(100, Math.round(100 - (latencyMs / 4)) + auraBonus)) : 0;

    return {
      provider: candidate.provider,
      url: candidate.url,
      aura: candidate.aura,
      latencyMs: ok ? latencyMs : 9999,
      score,
      errors: ok ? 0 : 1,
      hits: ok ? 1 : 0,
      healthy: ok
    };
  }

  /**
   * Returns upstream nodes sorted by performance.
   */
  getRankedUpstreams() {
    return [...this.upstreams].sort((a, b) => {
      if (a.healthy !== b.healthy) return a.healthy ? -1 : 1;
      if (b.score !== a.score) return b.score - a.score;
      return a.latencyMs - b.latencyMs;
    });
  }

  /**
   * Resolves a binary DNS query using singleflight coalescing and low-latency hedging across top resolvers.
   * @param {Uint8Array} wireQuery
   * @param {string} domain
   * @param {number} qtype
   * @returns {Promise<{ raw: Uint8Array, provider: string, latencyMs: number }>}
   */
  async resolveWire(wireQuery, domain, qtype) {
    const flightKey = `${domain}:${qtype}`;

    if (this.inFlight.has(flightKey)) {
      return await this.inFlight.get(flightKey);
    }

    const promise = this._executeResolveWire(wireQuery);
    this.inFlight.set(flightKey, promise);

    try {
      return await promise;
    } finally {
      this.inFlight.delete(flightKey);
    }
  }

  async _executeResolveWire(wireQuery) {
    const ranked = this.getRankedUpstreams();
    const primary = ranked[0] || this.upstreams[0];
    const secondary = ranked[1] || this.upstreams[1];
    const tertiary = ranked[2] || this.upstreams[2];

    // Stage 1: Query primary fastest resolver immediately
    try {
      return await this._queryUpstream(primary, wireQuery);
    } catch (err1) {
      // Stage 2: Fallback to secondary
      try {
        if (secondary) return await this._queryUpstream(secondary, wireQuery);
      } catch (err2) {
        // Stage 3: Fallback to tertiary
        if (tertiary) return await this._queryUpstream(tertiary, wireQuery);
      }
      throw err1;
    }
  }

  async _queryUpstream(upstream, wireQuery) {
    const t0 = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const resp = await fetch(upstream.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/dns-message',
          'Accept': 'application/dns-message',
          'User-Agent': 'AmarDNS-Cloudflare-Worker/1.0'
        },
        body: wireQuery,
        signal: controller.signal
      });

      clearTimeout(timer);

      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} from ${upstream.provider}`);
      }

      const ab = await resp.arrayBuffer();
      const latencyMs = Math.max(1, Date.now() - t0);

      upstream.latencyMs = Math.round((upstream.latencyMs * 0.7) + (latencyMs * 0.3));
      upstream.hits = (upstream.hits || 0) + 1;
      upstream.score = Math.min(100, (upstream.score || 90) + 1);
      upstream.healthy = true;

      return {
        raw: new Uint8Array(ab),
        provider: upstream.provider,
        latencyMs
      };
    } catch (err) {
      clearTimeout(timer);
      upstream.errors = (upstream.errors || 0) + 1;
      upstream.score = Math.max(0, (upstream.score || 90) - 20);
      if (upstream.score <= 30) upstream.healthy = false;
      throw err;
    }
  }

  getTelemetry() {
    return this.getRankedUpstreams().map(u => ({
      provider: u.provider,
      url: u.url,
      aura: u.aura || 'medium',
      latencyMs: u.latencyMs,
      score: u.score,
      errors: u.errors || 0,
      hits: u.hits || 0,
      healthy: u.healthy
    }));
  }
}
