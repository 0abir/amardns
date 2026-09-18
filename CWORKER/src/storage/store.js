// CWORKER/src/storage/store.js
// Autonomous, auto-detecting storage manager for Cloudflare Workers.
// Automatically discovers and leverages ANY attached KV namespace, D1 database, or R2 bucket
// regardless of binding name or identifier, falling back gracefully to in-memory mode.

import { QuotaGuardian } from './quota.js';
import { CONFIG } from '../config.js';

/**
 * Dynamically scans the Cloudflare environment object to discover bound storage primitives
 * by inspecting their capability interfaces.
 * @param {object} env - Cloudflare worker env object
 */
export function detectStorageBindings(env = {}) {
  let kv = null;
  let kvName = null;
  let d1 = null;
  let d1Name = null;
  let r2 = null;
  let r2Name = null;

  if (env && typeof env === 'object') {
    for (const [key, val] of Object.entries(env)) {
      if (!val || typeof val !== 'object') continue;

      // 1. Cloudflare KV Detection (Duck typing: .get, .put, .delete, .list)
      if (!kv && typeof val.get === 'function' && typeof val.put === 'function' && typeof val.delete === 'function' && typeof val.list === 'function') {
        kv = val;
        kvName = key;
        continue;
      }

      // 2. Cloudflare D1 SQL Detection (Duck typing: .prepare, .batch, .exec)
      if (!d1 && typeof val.prepare === 'function' && typeof val.batch === 'function' && typeof val.exec === 'function') {
        d1 = val;
        d1Name = key;
        continue;
      }

      // 3. Cloudflare R2 Bucket Detection (Duck typing: .get, .put, .head)
      if (!r2 && typeof val.get === 'function' && typeof val.put === 'function' && typeof val.head === 'function') {
        r2 = val;
        r2Name = key;
        continue;
      }
    }
  }

  return { kv, kvName, d1, d1Name, r2, r2Name };
}

export class StorageManager {
  constructor(env = {}) {
    this.updateEnv(env);
    this.quota = new QuotaGuardian();

    this.memRules = new Map();
    this.memLogs = []; // Ring buffer capped at maxLogs
    this.maxLogs = CONFIG.MAX_QUERY_LOGS || 100;
    this.logCounter = 0;
  }

  updateEnv(env = {}) {
    this.env = env;
    const detected = detectStorageBindings(env);
    this.kv = detected.kv;
    this.kvName = detected.kvName;
    this.d1 = detected.d1;
    this.d1Name = detected.d1Name;
    this.r2 = detected.r2;
    this.r2Name = detected.r2Name;
  }

  getStorageInfo() {
    return {
      kv: {
        bound: Boolean(this.kv),
        name: this.kvName || null,
        type: this.kv ? 'Cloudflare KV' : 'None'
      },
      d1: {
        bound: Boolean(this.d1),
        name: this.d1Name || null,
        type: this.d1 ? 'Cloudflare D1 SQL' : 'None'
      },
      r2: {
        bound: Boolean(this.r2),
        name: this.r2Name || null,
        type: this.r2 ? 'Cloudflare R2' : 'None'
      },
      mode: (this.kv || this.d1 || this.r2) ? 'Persistent Edge Store' : 'In-Memory V8 Isolate'
    };
  }

  async initDb() {
    if (!this.d1) return;
    try {
      if (this.quota.canD1Write()) {
        await this.d1.exec(`
          CREATE TABLE IF NOT EXISTS custom_rules (
            domain TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            is_wildcard INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
          );
        `);
        this.quota.recordD1Write();
      }
    } catch (err) {}
  }

  async loadCustomRules() {
    // 1. Try R2 if detected
    if (this.r2) {
      try {
        const obj = await this.r2.get('rules/custom_rules.json');
        if (obj) {
          const raw = await obj.json();
          if (Array.isArray(raw)) {
            for (const r of raw) this.memRules.set(r.domain, r);
            return raw;
          }
        }
      } catch (err) {}
    }

    // 2. Try KV if detected
    if (this.kv && this.quota.canKvRead()) {
      try {
        const raw = await this.kv.get('amardns:custom_rules', 'json');
        this.quota.recordKvRead();
        if (Array.isArray(raw)) {
          for (const r of raw) this.memRules.set(r.domain, r);
          return raw;
        }
      } catch (err) {}
    }

    // 3. Try D1 SQL if detected
    if (this.d1 && this.quota.canD1Read()) {
      try {
        const res = await this.d1.prepare('SELECT domain, type, is_wildcard as isWildcard, created_at as createdAt FROM custom_rules').all();
        this.quota.recordD1Read();
        if (res && Array.isArray(res.results)) {
          const rules = res.results.map(r => ({
            domain: r.domain,
            type: r.type,
            isWildcard: Boolean(r.isWildcard),
            createdAt: r.createdAt
          }));
          for (const r of rules) this.memRules.set(r.domain, r);
          return rules;
        }
      } catch (err) {}
    }

    return Array.from(this.memRules.values());
  }

  async saveRule(rule) {
    this.memRules.set(rule.domain, rule);
    const allRules = Array.from(this.memRules.values());

    if (this.r2) {
      try {
        await this.r2.put('rules/custom_rules.json', JSON.stringify(allRules));
      } catch (err) {}
    }

    if (this.kv && this.quota.canKvWrite()) {
      try {
        await this.kv.put('amardns:custom_rules', JSON.stringify(allRules));
        this.quota.recordKvWrite();
      } catch (err) {}
    }

    if (this.d1 && this.quota.canD1Write()) {
      try {
        await this.d1.prepare(
          'INSERT OR REPLACE INTO custom_rules (domain, type, is_wildcard, created_at) VALUES (?, ?, ?, ?)'
        ).bind(rule.domain, rule.type, rule.isWildcard ? 1 : 0, rule.createdAt || Date.now()).run();
        this.quota.recordD1Write();
      } catch (err) {}
    }
  }

  async deleteRule(domain) {
    this.memRules.delete(domain);
    const allRules = Array.from(this.memRules.values());

    if (this.r2) {
      try {
        await this.r2.put('rules/custom_rules.json', JSON.stringify(allRules));
      } catch (err) {}
    }

    if (this.kv && this.quota.canKvWrite()) {
      try {
        await this.kv.put('amardns:custom_rules', JSON.stringify(allRules));
        this.quota.recordKvWrite();
      } catch (err) {}
    }

    if (this.d1 && this.quota.canD1Write()) {
      try {
        await this.d1.prepare('DELETE FROM custom_rules WHERE domain = ?').bind(domain).run();
        this.quota.recordD1Write();
      } catch (err) {}
    }
  }

  recordQueryLog(entry, ctx = null) {
    this.logCounter++;
    const logItem = {
      id: this.logCounter,
      domain: entry.domain,
      qtype: entry.qtype,
      clientIp: entry.clientIp || 'anonymous',
      status: entry.status,
      reason: entry.reason,
      latencyMs: entry.latencyMs,
      timestamp: entry.timestamp || Date.now()
    };

    this.memLogs.unshift(logItem);
    if (this.memLogs.length > this.maxLogs) {
      this.memLogs.length = this.maxLogs; // Fast truncation
    }
  }

  getLogs(filter = {}) {
    let result = this.memLogs;
    if (filter.status && filter.status !== 'ALL') {
      result = result.filter(l => l.status === filter.status);
    }
    if (filter.qtype && filter.qtype !== 'ALL') {
      result = result.filter(l => l.qtype === filter.qtype);
    }
    if (filter.search) {
      const q = filter.search.toLowerCase();
      result = result.filter(l => l.domain.includes(q) || (l.reason && l.reason.toLowerCase().includes(q)));
    }
    return result;
  }

  clearLogs() {
    this.memLogs = [];
  }

  /**
   * Loads serialized Bloom filter bitset from persistent storage (R2 / KV).
   * @param {string} name
   * @returns {Promise<{ buffer: ArrayBuffer, count: number, lastSyncTime: number } | null>}
   */
  async loadBloomFilter(name = 'threat') {
    // 1. Try R2 if detected
    if (this.r2) {
      try {
        const obj = await this.r2.get(`bloom/${name}.bin`);
        if (obj) {
          const buffer = await obj.arrayBuffer();
          const metaObj = await this.r2.get(`bloom/${name}.meta.json`);
          const meta = metaObj ? await metaObj.json() : {};
          return { buffer, count: meta.count || 0, lastSyncTime: meta.lastSyncTime || Date.now() };
        }
      } catch (err) {}
    }

    // 2. Try KV if detected
    if (this.kv && this.quota.canKvRead()) {
      try {
        if (typeof this.kv.getWithMetadata === 'function') {
          const res = await this.kv.getWithMetadata(`amardns:bloom:${name}`, 'arrayBuffer');
          this.quota.recordKvRead();
          if (res && res.value && res.value.byteLength > 0) {
            const meta = res.metadata || {};
            return {
              buffer: res.value,
              count: meta.count || 0,
              lastSyncTime: meta.lastSyncTime || Date.now()
            };
          }
        }

        const buffer = await this.kv.get(`amardns:bloom:${name}`, 'arrayBuffer');
        this.quota.recordKvRead();
        if (buffer && buffer.byteLength > 0) {
          let count = 0;
          let lastSyncTime = Date.now();
          if (this.quota.canKvRead()) {
            try {
              const meta = await this.kv.get(`amardns:bloom:${name}:meta`, 'json');
              this.quota.recordKvRead();
              if (meta) {
                count = meta.count || 0;
                lastSyncTime = meta.lastSyncTime || lastSyncTime;
              }
            } catch (e) {}
          }
          return { buffer, count, lastSyncTime };
        }
      } catch (err) {}
    }

    return null;
  }

  /**
   * Persists serialized Bloom filter bitset into storage (R2 / KV).
   * @param {string} name
   * @param {ArrayBuffer} buffer
   * @param {number} count
   */
  async saveBloomFilter(name = 'threat', buffer, count = 0) {
    const meta = { count, lastSyncTime: Date.now() };

    if (this.r2) {
      try {
        await this.r2.put(`bloom/${name}.bin`, buffer);
        await this.r2.put(`bloom/${name}.meta.json`, JSON.stringify(meta));
      } catch (err) {}
    }

    if (this.kv && this.quota.canKvWrite()) {
      try {
        await this.kv.put(`amardns:bloom:${name}`, buffer, { metadata: meta });
        this.quota.recordKvWrite();
      } catch (err) {}
    }
  }
}
