import { CONFIG } from '../config.js';

export class EdgeCache {
  constructor(customConfig = {}) {
    this.maxEntries = parseInt(customConfig.MAX_MEMORY_CACHE_ENTRIES || CONFIG.MAX_MEMORY_CACHE_ENTRIES, 10);
    this.defaultTtl = parseInt(customConfig.DEFAULT_CACHE_TTL || CONFIG.DEFAULT_CACHE_TTL, 10);
    this.memoryMap = new Map();
    this.hits = 0;
    this.misses = 0;
    this.lastPrune = Date.now();
  }

  /**
   * Retrieves a cached DNS wireformat or JSON response.
   * @param {string} cacheKey
   * @param {Request} request
   * @returns {Promise<{ data: Uint8Array | object, ttl: number } | null>}
   */
  async get(cacheKey, request = null) {
    const now = Date.now();

    // 1. Tier 2: Check in-memory map
    if (this.memoryMap.has(cacheKey)) {
      const entry = this.memoryMap.get(cacheKey);
      if (entry.expiresAt > now) {
        this.hits++;
        return { data: entry.data, ttl: Math.max(1, Math.round((entry.expiresAt - now) / 1000)) };
      }
      this.memoryMap.delete(cacheKey);
    }

    // 2. Tier 1: Check Cloudflare Cache API (unlimited & zero-cost)
    if (typeof caches !== 'undefined' && caches.default && request) {
      try {
        const cacheUrl = new URL(request.url);
        cacheUrl.pathname = `/cf-cache-internal/${encodeURIComponent(cacheKey)}`;
        const syntheticReq = new Request(cacheUrl.toString(), { method: 'GET' });
        const match = await caches.default.match(syntheticReq);
        if (match) {
          const contentType = match.headers.get('content-type') || '';
          const age = parseInt(match.headers.get('age') || '0', 10);
          const maxAge = parseInt((match.headers.get('cache-control') || '').match(/max-age=(\d+)/)?.[1] || `${this.defaultTtl}`, 10);
          const remainingTtl = Math.max(1, maxAge - age);

          let data;
          if (contentType.includes('application/dns-message')) {
            const ab = await match.arrayBuffer();
            data = new Uint8Array(ab);
          } else {
            data = await match.json();
          }

          this.setMemory(cacheKey, data, remainingTtl);
          this.hits++;
          return { data, ttl: remainingTtl };
        }
      } catch (err) {
        // Cache API fallback
      }
    }

    this.misses++;
    return null;
  }

  /**
   * Stores response in both in-memory LRU and Cloudflare Edge Cache API.
   * @param {string} cacheKey
   * @param {Uint8Array | object} data
   * @param {number} ttl
   * @param {Request} request
   * @param {ExecutionContext} ctx
   */
  async put(cacheKey, data, ttl, request = null, ctx = null) {
    const safeTtl = Math.max(10, Math.min(ttl || this.defaultTtl, 86400));
    this.setMemory(cacheKey, data, safeTtl);

    if (typeof caches !== 'undefined' && caches.default && request) {
      const putPromise = (async () => {
        try {
          const cacheUrl = new URL(request.url);
          cacheUrl.pathname = `/cf-cache-internal/${encodeURIComponent(cacheKey)}`;
          const syntheticReq = new Request(cacheUrl.toString(), { method: 'GET' });

          const isWire = data instanceof Uint8Array;
          const headers = new Headers({
            'Content-Type': isWire ? 'application/dns-message' : 'application/dns-json',
            'Cache-Control': `public, max-age=${safeTtl}`,
            'Access-Control-Allow-Origin': '*'
          });

          const body = isWire ? data : JSON.stringify(data);
          const syntheticRes = new Response(body, { status: 200, headers });
          await caches.default.put(syntheticReq, syntheticRes);
        } catch (err) {
          // Non-fatal
        }
      })();

      if (ctx && typeof ctx.waitUntil === 'function') {
        ctx.waitUntil(putPromise);
      } else {
        await putPromise;
      }
    }
  }

  setMemory(key, data, ttl) {
    const now = Date.now();

    // Periodic sweep every 60s
    if (now - this.lastPrune > 60000) {
      this.pruneExpired(now);
    }

    if (this.memoryMap.size >= this.maxEntries) {
      const oldestKey = this.memoryMap.keys().next().value;
      if (oldestKey) this.memoryMap.delete(oldestKey);
    }

    this.memoryMap.set(key, {
      data,
      expiresAt: now + ttl * 1000
    });
  }

  pruneExpired(now = Date.now()) {
    this.lastPrune = now;
    for (const [k, v] of this.memoryMap.entries()) {
      if (v.expiresAt <= now) {
        this.memoryMap.delete(k);
      }
    }
  }

  flush() {
    this.memoryMap.clear();
  }

  getStats() {
    const total = this.hits + this.misses;
    const hitRate = total > 0 ? ((this.hits / total) * 100).toFixed(1) + '%' : '0.0%';
    return {
      entries: this.memoryMap.size,
      maxEntries: this.maxEntries,
      hits: this.hits,
      misses: this.misses,
      hitRate
    };
  }
}
