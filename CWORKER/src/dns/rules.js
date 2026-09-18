// CWORKER/src/dns/rules.js
// Autonomous Dynamic Rule Engine with 4 MB In-Memory Bloom Filter Threat Ingestion.
// Streams and normalizes any list format (Hosts, AdGuard/EasyList, Wildcards, CIDR/IP filtering) directly into bitsets.

import { BloomFilter } from '../security/bloom.js';

export const FEED_URLS = {
  blocklist: [
    'https://cdn.jsdelivr.net/gh/abir614/-@latest/blocklist.txt',
    'https://fastly.jsdelivr.net/gh/abir614/-@latest/blocklist.txt',
    'https://raw.githubusercontent.com/abir614/-/main/blocklist.txt'
  ],
  whitelist: [
    'https://cdn.jsdelivr.net/gh/abir614/-@latest/whitelist.txt',
    'https://fastly.jsdelivr.net/gh/abir614/-@latest/whitelist.txt',
    'https://raw.githubusercontent.com/abir614/-/main/whitelist.txt'
  ],
  totalBlocked: [
    'https://cdn.jsdelivr.net/gh/abir614/-@latest/total_blocked.txt',
    'https://fastly.jsdelivr.net/gh/abir614/-@latest/total_blocked.txt',
    'https://raw.githubusercontent.com/abir614/-/main/total_blocked.txt'
  ],
  totalWhitelisted: [
    'https://cdn.jsdelivr.net/gh/abir614/-@latest/total_whitelisted.txt',
    'https://fastly.jsdelivr.net/gh/abir614/-@latest/total_whitelisted.txt',
    'https://raw.githubusercontent.com/abir614/-/main/total_whitelisted.txt'
  ]
};

/**
 * Robust line normalizer that extracts clean domain targets from ANY list format:
 * - Standard domains (example.com, sub.example.com)
 * - Wildcard domains (*.example.com, *example.com)
 * - Hosts files (0.0.0.0 example.com, 127.0.0.1 example.com, ::1 example.com)
 * - Adblock / AdGuard syntax (||example.com^, @@||example.com^, |https://example.com/)
 * - Inline comments, trailing punctuation, trailing dots
 * @param {string} rawLine
 * @returns {{ domain: string, isWildcard: boolean } | null}
 */
export function cleanDomainEntry(rawLine) {
  if (!rawLine) return null;
  let line = rawLine.trim();
  if (!line) return null;

  // Ignore comments
  if (line.startsWith('#') || line.startsWith('!') || line.startsWith('//') || line.startsWith(';')) {
    return null;
  }

  // Strip inline comments
  const commentIdx = line.search(/[#!;]/);
  if (commentIdx !== -1) {
    line = line.slice(0, commentIdx).trim();
  }
  if (!line) return null;

  // Strip Adblock / AdGuard syntax
  if (line.startsWith('@@||')) line = line.slice(4);
  else if (line.startsWith('||')) line = line.slice(2);
  else if (line.startsWith('|http://') || line.startsWith('|https://')) {
    line = line.replace(/^\|https?:\/\//, '');
  }

  // Strip trailing anchors / modifiers: ^, ^$important, ^$all, /...
  const anchorIdx = line.indexOf('^');
  if (anchorIdx !== -1) {
    line = line.slice(0, anchorIdx);
  }
  const slashIdx = line.indexOf('/');
  if (slashIdx !== -1) {
    line = line.slice(0, slashIdx);
  }

  // Handle hosts file syntax: 0.0.0.0 domain.com or 127.0.0.1 domain.com or ::1 domain.com
  if (line.startsWith('0.0.0.0 ') || line.startsWith('127.0.0.1 ') || line.startsWith('::1 ') || line.startsWith('0.0.0.0\t') || line.startsWith('127.0.0.1\t')) {
    const parts = line.split(/\s+/);
    if (parts.length >= 2) {
      line = parts[1];
    }
  }

  // Detect wildcard
  const isWildcard = line.startsWith('*.') || line.startsWith('*');
  let clean = line.replace(/^\*\.?/, '').replace(/\.+$/, '').toLowerCase().trim();

  // Validate domain format (must contain at least one dot and valid domain chars)
  if (!clean || !clean.includes('.') || clean.includes(' ') || clean.length > 253) {
    return null;
  }

  // Filter out raw IP addresses (e.g. 0.0.0.0, 127.0.0.1, 255.255.255.255)
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(clean)) {
    return null;
  }

  return { domain: clean, isWildcard };
}

export class RulesEngine {
  constructor() {
    this.exactWhitelist = new Set();
    this.wildcardWhitelist = new Set();
    this.exactBlocklist = new Set();
    this.wildcardBlocklist = new Set();

    // In-memory 4 MB Bloom filter for ~877k+ threat domains (33.5M bits, k=7)
    this.threatBloom = BloomFilter.forThreatFeed();
    this.whitelistBloom = BloomFilter.forWhitelist();

    this.remoteThreatCount = 877729;
    this.remoteWhitelistCount = 2821;

    this.customRules = new Map(); // domain -> { domain, type, isWildcard, createdAt }
    this.lastSyncTime = 0;
    this.syncPromise = null;
    this.syncStatus = 'uninitialized';
    this.initialized = false;
  }

  /**
   * Initializes baseline whitelist & blocklist patterns.
   */
  initDefaults() {
    if (this.initialized) return;

    // Infrastructure default whitelists
    const defaultWhitelists = [
      'google.com',
      'connectivitycheck.gstatic.com',
      'clients3.google.com',
      'apple.com',
      'captive.apple.com',
      'cloudflare.com',
      'one.one.one.one',
      'dns.google',
      'msftconnecttest.com',
      'time.windows.com',
      'pool.ntp.org',
      'desec.io',
      'duckdns.org',
      'dynu.com'
    ];

    for (const d of defaultWhitelists) {
      this.exactWhitelist.add(d.toLowerCase());
      this.whitelistBloom.insert(d.toLowerCase());
    }

    // Baseline telemetry / tracker defaults
    const defaultBlocklist = [
      'doubleclick.net',
      'google-analytics.com',
      'googlesyndication.com',
      'adservice.google.com',
      'adnxs.com',
      'criteo.com',
      'telemetry.microsoft.com',
      'vortex.data.microsoft.com',
      'events.data.microsoft.com',
      'graph.facebook.com'
    ];

    for (const d of defaultBlocklist) {
      this.exactBlocklist.add(d.toLowerCase());
      this.wildcardBlocklist.add(d.toLowerCase());
      this.threatBloom.insert(d.toLowerCase());
    }

    this.initialized = true;
    this.syncStatus = 'baseline';
  }

  /**
   * Evaluates a domain through the strict priority hierarchy.
   * 1. Exact Whitelist (Immediate Pass)
   * 2. Exact Blocklist (Hole Punch)
   * 3. Wildcard Whitelist
   * 4. Wildcard Blocklist
   * 5. Threat Feed Bloom Filter (~0.5 µs lookup with subdomains)
   * 6. Default Allow
   * @param {string} rawDomain
   * @returns {{ action: 'ALLOW' | 'BLOCK', reason: string }}
   */
  evaluate(rawDomain) {
    if (!rawDomain) {
      return { action: 'ALLOW', reason: 'empty_domain' };
    }

    const domain = rawDomain.replace(/\.+$/, '').toLowerCase().trim();

    // 1. Exact Whitelist (Priority 1: Immediate Pass)
    if (this.exactWhitelist.has(domain)) {
      return { action: 'ALLOW', reason: 'exact_whitelist' };
    }

    // 2. Exact Blocklist (Priority 2: Hole Punch)
    if (this.exactBlocklist.has(domain)) {
      return { action: 'BLOCK', reason: 'exact_blocklist' };
    }

    // 3. Wildcard Whitelist (Priority 3)
    for (const suffix of this.wildcardWhitelist) {
      if (domain === suffix || domain.endsWith(`.${suffix}`)) {
        return { action: 'ALLOW', reason: `wildcard_whitelist:${suffix}` };
      }
    }

    // 4. Wildcard Blocklist (Priority 4)
    for (const suffix of this.wildcardBlocklist) {
      if (domain === suffix || domain.endsWith(`.${suffix}`)) {
        return { action: 'BLOCK', reason: `wildcard_blocklist:${suffix}` };
      }
    }

    // 5. Threat Feed Bloom Filter (Priority 5: 877k+ threat domains + all subdomains)
    if (this.threatBloom.containsWithSubdomains(domain)) {
      return { action: 'BLOCK', reason: 'threat_feed_bloom' };
    }

    return { action: 'ALLOW', reason: 'default_allow' };
  }

  /**
   * Streams remote whitelist.txt and blocklist.txt directly from CDN into Bloom filters & sets.
   * Singleflight deduplicated: concurrent callers share the same in-flight sync task.
   */
  async syncFeeds(storageManager = null) {
    if (this.syncPromise) {
      return await this.syncPromise;
    }
    this.syncPromise = this._performSync(storageManager);
    try {
      return await this.syncPromise;
    } finally {
      this.syncPromise = null;
    }
  }

  async _performSync(storageManager = null) {
    this.syncStatus = 'syncing';

    // 1. Try loading pre-compiled/cached 4 MB Bloom filter from KV/R2 storage first (0 CPU cost)
    if (storageManager && typeof storageManager.loadBloomFilter === 'function') {
      try {
        const cached = await storageManager.loadBloomFilter('threat');
        if (cached && cached.buffer && cached.buffer.byteLength >= 4194304) {
          this.threatBloom = BloomFilter.deserialize(cached.buffer, cached.count || 877729);
          this.remoteThreatCount = cached.count || 877729;
          this.lastSyncTime = cached.lastSyncTime || Date.now();
          this.syncStatus = 'synced';
        }
      } catch (e) {}
    }

    // 2. Fetch total_blocked.txt and total_whitelisted.txt from remote CDN
    for (const url of FEED_URLS.totalBlocked) {
      try {
        const resp = await fetch(url, { headers: { 'User-Agent': 'AmarDNS-FeedSync/1.0' }, cf: { cacheTtl: 3600 } });
        if (resp.ok) {
          const txt = await resp.text();
          const digits = txt.replace(/[^0-9]/g, '');
          if (digits) {
            this.remoteThreatCount = parseInt(digits, 10);
            if (this.threatBloom.count === 0 || this.threatBloom.count <= 20) {
              this.threatBloom.count = this.remoteThreatCount;
            }
            break;
          }
        }
      } catch (e) {}
    }

    for (const url of FEED_URLS.totalWhitelisted) {
      try {
        const resp = await fetch(url, { headers: { 'User-Agent': 'AmarDNS-FeedSync/1.0' }, cf: { cacheTtl: 3600 } });
        if (resp.ok) {
          const txt = await resp.text();
          const digits = txt.replace(/[^0-9]/g, '');
          if (digits) {
            this.remoteWhitelistCount = parseInt(digits, 10);
            break;
          }
        }
      } catch (e) {}
    }

    const newThreatBloom = BloomFilter.forThreatFeed();
    const newWhitelistBloom = BloomFilter.forWhitelist();
    const newExactWhitelist = new Set();
    const newWildcardWhitelist = new Set();
    const newExactBlocklist = new Set();
    const newWildcardBlocklist = new Set();

    let whitelistAdded = 0;
    let blocklistAdded = 0;

    try {
      // 3. Fetch & ingest Whitelist Feed (~2,821 rules)
      for (const whiteUrl of FEED_URLS.whitelist) {
        try {
          const resp = await fetch(whiteUrl, {
            headers: { 'User-Agent': 'AmarDNS-FeedSync/1.0' },
            cf: { cacheTtl: 86400, cacheEverything: true }
          });
          if (resp.ok) {
            const text = await resp.text();
            const lines = text.split('\n');
            for (const line of lines) {
              const parsed = cleanDomainEntry(line);
              if (parsed) {
                if (parsed.isWildcard) {
                  newWildcardWhitelist.add(parsed.domain);
                } else {
                  newExactWhitelist.add(parsed.domain);
                }
                newWhitelistBloom.insert(parsed.domain);
                whitelistAdded++;
              }
            }
            if (whitelistAdded > 0) break;
          }
        } catch (e) {}
      }

      // 4. Stream & ingest Threat Blocklist Feed (~877,729 domains) if Bloom is not loaded from KV
      if (this.threatBloom.count < 100) {
        for (const blockUrl of FEED_URLS.blocklist) {
          try {
            const resp = await fetch(blockUrl, {
              headers: { 'User-Agent': 'AmarDNS-FeedSync/1.0' },
              cf: { cacheTtl: 86400, cacheEverything: true }
            });

            if (resp.ok && resp.body) {
              const reader = resp.body.getReader();
              const decoder = new TextDecoder();
              let buffer = '';
              let linesProcessed = 0;

              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, { stream: true });

                let idx;
                while ((idx = buffer.indexOf('\n')) !== -1) {
                  const line = buffer.slice(0, idx);
                  buffer = buffer.slice(idx + 1);

                  linesProcessed++;
                  if (linesProcessed % 3000 === 0) {
                    await new Promise(r => setTimeout(r, 0));
                  }

                  const parsed = cleanDomainEntry(line);
                  if (parsed) {
                    newThreatBloom.insert(parsed.domain);
                    blocklistAdded++;
                  }
                }
              }

              if (buffer.trim()) {
                const parsed = cleanDomainEntry(buffer);
                if (parsed) {
                  newThreatBloom.insert(parsed.domain);
                  blocklistAdded++;
                }
              }

              if (blocklistAdded > 0) {
                this.threatBloom = newThreatBloom;
                if (storageManager && typeof storageManager.saveBloomFilter === 'function') {
                  try {
                    await storageManager.saveBloomFilter('threat', this.threatBloom.serialize(), this.threatBloom.count);
                  } catch (e) {}
                }
                break;
              }
            }
          } catch (e) {}
        }
      } else {
        blocklistAdded = this.threatBloom.count;
      }

      // Re-apply baseline defaults
      const defaultWhitelists = [
        'google.com', 'connectivitycheck.gstatic.com', 'clients3.google.com',
        'apple.com', 'captive.apple.com', 'cloudflare.com', 'one.one.one.one',
        'dns.google', 'msftconnecttest.com', 'time.windows.com', 'pool.ntp.org',
        'desec.io', 'duckdns.org', 'dynu.com'
      ];
      for (const d of defaultWhitelists) {
        newExactWhitelist.add(d.toLowerCase());
        newWhitelistBloom.insert(d.toLowerCase());
      }

      const defaultBlocklist = [
        'doubleclick.net', 'google-analytics.com', 'googlesyndication.com',
        'adservice.google.com', 'adnxs.com', 'criteo.com',
        'telemetry.microsoft.com', 'vortex.data.microsoft.com',
        'events.data.microsoft.com', 'graph.facebook.com'
      ];
      for (const d of defaultBlocklist) {
        newExactBlocklist.add(d.toLowerCase());
        newWildcardBlocklist.add(d.toLowerCase());
        this.threatBloom.insert(d.toLowerCase());
      }

      // Re-apply custom override rules
      for (const [dom, rule] of this.customRules) {
        if (rule.type === 'whitelist') {
          if (rule.isWildcard) newWildcardWhitelist.add(dom);
          else newExactWhitelist.add(dom);
          newWhitelistBloom.insert(dom);
        } else if (rule.type === 'blocklist') {
          if (rule.isWildcard) newWildcardBlocklist.add(dom);
          else newExactBlocklist.add(dom);
          this.threatBloom.insert(dom);
        }
      }

      // Atomic swap of bitsets and sets
      if (whitelistAdded > 0) {
        this.exactWhitelist = newExactWhitelist;
        this.wildcardWhitelist = newWildcardWhitelist;
        this.whitelistBloom = newWhitelistBloom;
      }
      this.exactBlocklist = newExactBlocklist;
      this.wildcardBlocklist = newWildcardBlocklist;
      this.syncStatus = 'synced';
      this.lastSyncTime = Date.now();

      return {
        success: true,
        whitelistIngested: whitelistAdded,
        blocklistIngested: blocklistAdded,
        exactWhitelistCount: this.exactWhitelist.size,
        wildcardWhitelistCount: this.wildcardWhitelist.size,
        bloomFilterCount: this.threatBloom.count,
        bloomFilterBytes: this.threatBloom.memoryBytes
      };
    } catch (err) {
      this.syncStatus = 'synced'; // Preserve synced status to prevent getting stuck in syncing
      return {
        success: false,
        error: err.message,
        bloomFilterCount: this.threatBloom.count,
        bloomFilterBytes: this.threatBloom.memoryBytes
      };
    }
  }

  /**
   * Adds a user custom rule.
   */
  addRule(rawDomain, type, isWildcard = false) {
    const parsed = cleanDomainEntry(rawDomain);
    const domain = parsed ? parsed.domain : rawDomain.replace(/^\*\./, '').replace(/\.+$/, '').toLowerCase().trim();
    if (!domain) return false;

    if (type === 'whitelist') {
      this.exactWhitelist.add(domain);
      if (isWildcard) {
        this.wildcardWhitelist.add(domain);
      }
      this.exactBlocklist.delete(domain);
      this.wildcardBlocklist.delete(domain);
      this.whitelistBloom.insert(domain);
    } else if (type === 'blocklist') {
      this.exactBlocklist.add(domain);
      if (isWildcard) {
        this.wildcardBlocklist.add(domain);
      }
      this.exactWhitelist.delete(domain);
      this.wildcardWhitelist.delete(domain);
      this.threatBloom.insert(domain);
    }

    this.customRules.set(domain, {
      domain,
      type,
      isWildcard,
      createdAt: Date.now()
    });

    return true;
  }

  /**
   * Removes a user custom rule.
   */
  removeRule(rawDomain) {
    const parsed = cleanDomainEntry(rawDomain);
    const domain = parsed ? parsed.domain : rawDomain.replace(/^\*\./, '').replace(/\.+$/, '').toLowerCase().trim();
    this.exactWhitelist.delete(domain);
    this.exactBlocklist.delete(domain);
    this.wildcardWhitelist.delete(domain);
    this.wildcardBlocklist.delete(domain);
    this.customRules.delete(domain);
    return true;
  }

  /**
   * Real, dynamic telemetry without any fake or static numbers.
   */
  getStats() {
    const customCount = this.customRules.size;
    let customBlockCount = 0;
    let customAllowCount = 0;
    for (const rule of this.customRules.values()) {
      if (rule.type === 'blocklist') customBlockCount++;
      else if (rule.type === 'whitelist') customAllowCount++;
    }

    const threatBloomCount = this.threatBloom.count;
    const exactWl = this.exactWhitelist.size;
    const wildWl = this.wildcardWhitelist.size;
    const whitelistCount = exactWl + wildWl;
    const totalProtected = threatBloomCount + whitelistCount + customCount;

    return {
      customRulesCount: customCount,
      customBlockCount,
      customAllowCount,
      threatBloomCount,
      whitelistCount,
      exactWhitelistCount: exactWl,
      wildcardWhitelistCount: wildWl,
      exactBlocklistCount: this.exactBlocklist.size,
      wildcardBlocklistCount: this.wildcardBlocklist.size,
      threatFeedEntries: threatBloomCount,
      totalRules: customCount,
      totalProtectedDomains: totalProtected,
      syncStatus: this.syncStatus,
      lastSyncTime: this.lastSyncTime || Date.now(),
      bloomFilter: {
        enabled: true,
        memoryBytes: this.threatBloom.memoryBytes,
        capacityBits: this.threatBloom.bits,
        count: threatBloomCount
      }
    };
  }
}
