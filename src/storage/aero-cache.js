// src/storage/aero-cache.js
// Ultra-fast in-process DNS wire cache engine.
// Implements S3-FIFO (Simple, Scalable, Small FIFO) + 2-bit frequency clock.
// Eliminates Redis/Valkey IPC latency, socket overhead, and separate daemon footprint.
// Designed for strict 256MB memory environments.

export class AeroCache {
  /**
   * @param {Object} [options]
   * @param {number} [options.maxEntries=25000] Maximum cached DNS records
   * @param {number} [options.maxBytes=25165824] Maximum wire memory in bytes (default 24MB)
   * @param {number} [options.minTtl=5] Minimum TTL in seconds
   * @param {number} [options.maxTtl=86400] Maximum TTL in seconds
   */
  constructor(options = {}) {
    this.maxEntries = options.maxEntries || 25000;
    this.maxBytes = options.maxBytes || 24 * 1024 * 1024; // 24 MB
    this.minTtl = options.minTtl || 5;
    this.maxTtl = options.maxTtl || 86400;

    /** @type {Map<string, { wire: Uint8Array, exp: number, freq: number, inMain: boolean, bytes: number }>} */
    this.map = new Map();

    /** @type {string[]} Small FIFO queue (10% of capacity for one-hit wonder filter) */
    this.smallQueue = [];
    /** @type {string[]} Main FIFO queue (90% of capacity for frequently hit entries) */
    this.mainQueue = [];
    /** @type {Set<string>} Ghost queue remembering recently evicted keys */
    this.ghostQueue = new Set();
    this.maxGhost = Math.floor(this.maxEntries * 0.5);

    this.currentBytes = 0;
    this.stats = {
      hits: 0,
      misses: 0,
      puts: 0,
      evictions: 0,
      expiredPurges: 0,
    };
  }

  /**
   * Normalizes cache key from domain name and query type.
   * @param {string} name
   * @param {number|string} qtype
   * @returns {string}
   */
  _key(name, qtype) {
    let n = name.toLowerCase();
    if (n.endsWith(".")) n = n.slice(0, -1);
    return `${qtype}:${n}`;
  }

  /**
   * Fast O(1) lookup. Returns raw binary wire Buffer/Uint8Array or null.
   * @param {string} name
   * @param {number|string} qtype
   * @returns {Uint8Array|null}
   */
  get(name, qtype) {
    const key = this._key(name, qtype);
    const entry = this.map.get(key);
    if (!entry) {
      this.stats.misses++;
      return null;
    }

    const now = Date.now();
    if (now >= entry.exp) {
      // Lazy eviction on expired access (direct purge without duplicate key & map lookup)
      this.currentBytes -= entry.bytes;
      this.map.delete(key);
      this.stats.misses++;
      this.stats.expiredPurges++;
      return null;
    }

    // Hit: increment frequency counter (capped at 3 for 2-bit clock)
    if (entry.freq < 3) entry.freq++;
    this.stats.hits++;
    return entry.wire;
  }

  /**
   * Inserts or updates a DNS response packet into cache.
   * @param {string} name
   * @param {number|string} qtype
   * @param {Uint8Array|ArrayBuffer} wireBuf
   * @param {number} ttlSec
   */
  put(name, qtype, wireBuf, ttlSec) {
    const key = this._key(name, qtype);
    const clampedTtl = Math.max(this.minTtl, Math.min(this.maxTtl, ttlSec || 60));
    const exp = Date.now() + clampedTtl * 1000;

    const wire = wireBuf instanceof Uint8Array ? wireBuf : new Uint8Array(wireBuf);
    const bytes = wire.byteLength;

    // Reject single packets that exceed 1MB sanity limit
    if (bytes > 1024 * 1024) return;

    // If key exists, update in place
    const existing = this.map.get(key);
    if (existing) {
      this.currentBytes += bytes - existing.bytes;
      existing.wire = wire;
      existing.exp = exp;
      existing.bytes = bytes;
      if (existing.freq < 3) existing.freq++;
      return;
    }

    // Ensure memory headroom before inserting
    this._ensureCapacity(bytes);

    // S3-FIFO placement:
    // If the key was recently seen in the ghost queue, insert directly into Main queue.
    // Otherwise, insert into Small queue to filter out one-hit wonders.
    const inGhost = this.ghostQueue.delete(key);
    const inMain = inGhost;

    const entry = {
      wire,
      exp,
      freq: 0,
      inMain,
      bytes,
    };

    this.map.set(key, entry);
    this.currentBytes += bytes;
    this.stats.puts++;

    if (inMain) {
      this.mainQueue.push(key);
    } else {
      this.smallQueue.push(key);
    }
  }

  /**
   * Removes a record from the cache.
   * @param {string} name
   * @param {number|string} qtype
   * @returns {boolean}
   */
  delete(name, qtype) {
    const key = this._key(name, qtype);
    const entry = this.map.get(key);
    if (!entry) return false;

    this.currentBytes -= entry.bytes;
    this.map.delete(key);
    return true;
  }

  /**
   * Evicts entries until both maxBytes and maxEntries constraints are met.
   * @private
   */
  _ensureCapacity(incomingBytes) {
    const targetBytes = this.maxBytes - incomingBytes;
    const targetEntries = this.maxEntries - 1;

    while (
      this.map.size > targetEntries ||
      (this.currentBytes > targetBytes && this.map.size > 0)
    ) {
      this._evictOne();
    }
  }

  /**
   * Evicts one entry using S3-FIFO with lazy TTL checks.
   * @private
   */
  _evictOne() {
    const smallTarget = Math.max(1, Math.floor(this.map.size * 0.1));
    const now = Date.now();

    // 1. If small queue is larger than 10%, evict or promote from small queue
    if (this.smallQueue.length > smallTarget) {
      while (this.smallQueue.length > 0) {
        const key = this.smallQueue.shift();
        const entry = this.map.get(key);
        if (!entry || entry.inMain) continue;

        // Expired? Free it immediately
        if (now >= entry.exp) {
          this.currentBytes -= entry.bytes;
          this.map.delete(key);
          this.stats.expiredPurges++;
          this.stats.evictions++;
          return;
        }

        // If accessed while in small queue, promote to main queue
        if (entry.freq > 0) {
          entry.inMain = true;
          entry.freq = 0;
          this.mainQueue.push(key);
        } else {
          // Evict from small queue and record in ghost filter
          this.currentBytes -= entry.bytes;
          this.map.delete(key);
          this._addToGhost(key);
          this.stats.evictions++;
          return;
        }
      }
    }

    // 2. Otherwise, evict from main queue using second-chance clock
    while (this.mainQueue.length > 0) {
      const key = this.mainQueue.shift();
      const entry = this.map.get(key);
      if (!entry || !entry.inMain) continue;

      // Expired? Free it immediately
      if (now >= entry.exp) {
        this.currentBytes -= entry.bytes;
        this.map.delete(key);
        this.stats.expiredPurges++;
        this.stats.evictions++;
        return;
      }

      // Second chance: if freq > 0, decrement and reinsert at tail
      if (entry.freq > 0) {
        entry.freq--;
        this.mainQueue.push(key);
      } else {
        // Evict from main queue
        this.currentBytes -= entry.bytes;
        this.map.delete(key);
        this.stats.evictions++;
        return;
      }
    }

    // Fallback: evict any remaining entry if queues had stale ghost keys
    if (this.map.size > 0) {
      const firstKey = this.map.keys().next().value;
      const entry = this.map.get(firstKey);
      if (entry) this.currentBytes -= entry.bytes;
      this.map.delete(firstKey);
      this.stats.evictions++;
    }
  }

  /**
   * Adds an evicted key to the ghost queue (capped FIFO).
   * @private
   */
  _addToGhost(key) {
    if (this.ghostQueue.size >= this.maxGhost) {
      const first = this.ghostQueue.values().next().value;
      this.ghostQueue.delete(first);
    }
    this.ghostQueue.add(key);
  }

  /**
   * Active TTL Micro-Sweeper. Sweeps a slice of keys to reclaim expired memory without latency spikes.
   * Call periodically (e.g. every 30 seconds).
   * @param {number} [maxScan=500] Maximum entries to check in one slice
   * @returns {number} Count of expired items purged
   */
  sweep(maxScan = 500) {
    let purged = 0;
    const now = Date.now();
    let scanned = 0;

    for (const [key, entry] of this.map) {
      if (scanned++ >= maxScan) break;
      if (now >= entry.exp) {
        this.currentBytes -= entry.bytes;
        this.map.delete(key);
        purged++;
      }
    }

    this.stats.expiredPurges += purged;
    return purged;
  }

  /**
   * Empties the cache completely.
   */
  clear() {
    this.map.clear();
    this.smallQueue.length = 0;
    this.mainQueue.length = 0;
    this.ghostQueue.clear();
    this.currentBytes = 0;
    this.stats = {
      hits: 0,
      misses: 0,
      puts: 0,
      evictions: 0,
      expiredPurges: 0,
    };
  }

  /**
   * Total number of cached entries.
   * @returns {number}
   */
  get size() {
    return this.map.size;
  }

  /**
   * Diagnostic summary of cache performance and memory.
   */
  getStats() {
    const total = this.stats.hits + this.stats.misses;
    const hitRate = total > 0 ? ((this.stats.hits / total) * 100).toFixed(1) + "%" : "0%";
    return {
      size: this.map.size,
      maxEntries: this.maxEntries,
      bytes: this.currentBytes,
      maxBytes: this.maxBytes,
      memoryMB: +(this.currentBytes / (1024 * 1024)).toFixed(2),
      hits: this.stats.hits,
      misses: this.stats.misses,
      hitRate,
      evictions: this.stats.evictions,
      expiredPurges: this.stats.expiredPurges,
    };
  }
}
