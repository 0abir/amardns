// CWORKER/test/worker.test.js
// Standalone unit test suite for AmarDNS Cloudflare Worker.

import assert from 'node:assert';
import { parseDnsQuery, buildBlockedResponse, buildServFailResponse, encodeDomain } from '../src/dns/codec.js';
import { RulesEngine, cleanDomainEntry } from '../src/dns/rules.js';
import { BloomFilter } from '../src/security/bloom.js';
import { EdgeCache } from '../src/dns/cache.js';
import { QuotaGuardian } from '../src/storage/quota.js';
import { StorageManager, detectStorageBindings } from '../src/storage/store.js';
import { UpstreamResolver } from '../src/dns/resolver.js';
import { AppRouter } from '../src/api/router.js';
import { CONFIG } from '../src/config.js';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`[FAIL] ${name}: ${err.message}`);
    failed++;
  }
}

async function testAsync(name, fn) {
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`[FAIL] ${name}: ${err.message}`);
    failed++;
  }
}

console.log('--- Starting AmarDNS Cloudflare Worker Unit Tests ---');

// 1. Codec Tests
test('DNS Codec: encodeDomain should format labels correctly', () => {
  const enc = encodeDomain('google.com');
  assert.strictEqual(enc[0], 6);
  assert.strictEqual(enc[7], 3);
  assert.strictEqual(enc[enc.length - 1], 0);
});

test('DNS Codec: parseDnsQuery should decode valid wire packet', () => {
  const query = new Uint8Array([
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
    0x00, 0x01, 0x00, 0x01
  ]);
  const parsed = parseDnsQuery(query);
  assert.strictEqual(parsed.id, 0x1234);
  assert.strictEqual(parsed.domain, 'google.com');
  assert.strictEqual(parsed.qtype, 1);
  assert.strictEqual(parsed.qclass, 1);
});

test('DNS Codec: buildBlockedResponse should construct 0.0.0.0 response for A record', () => {
  const query = { id: 0x5678, domain: 'badtracker.com', qtype: 1 };
  const blocked = buildBlockedResponse(query, 'ZERO_IP');
  const view = new DataView(blocked.buffer);
  assert.strictEqual(view.getUint16(0), 0x5678);
  assert.strictEqual(view.getUint16(2), 0x8180); // NOERROR
  assert.strictEqual(view.getUint16(6), 1); // ANCOUNT=1
});

test('DNS Codec: buildBlockedResponse NXDOMAIN mode', () => {
  const query = { id: 0x9999, domain: 'malware.net', qtype: 1 };
  const blocked = buildBlockedResponse(query, 'NXDOMAIN');
  const view = new DataView(blocked.buffer);
  assert.strictEqual(view.getUint16(0), 0x9999);
  assert.strictEqual(view.getUint16(2), 0x8183); // NXDOMAIN
  assert.strictEqual(view.getUint16(6), 0); // ANCOUNT=0
});

// 2. Universal List Parser Tests (cleanDomainEntry)
test('cleanDomainEntry: parses standard, wildcard, hosts, Adblock syntax, and comments', () => {
  // Comments and empty
  assert.strictEqual(cleanDomainEntry('# comment'), null);
  assert.strictEqual(cleanDomainEntry('! Adblock comment'), null);
  assert.strictEqual(cleanDomainEntry('// JS comment'), null);
  assert.strictEqual(cleanDomainEntry(''), null);

  // Standard domain
  assert.deepStrictEqual(cleanDomainEntry('example.com'), { domain: 'example.com', isWildcard: false });
  assert.deepStrictEqual(cleanDomainEntry('  SUB.EXAMPLE.COM.  '), { domain: 'sub.example.com', isWildcard: false });

  // Wildcards
  assert.deepStrictEqual(cleanDomainEntry('*.evil.com'), { domain: 'evil.com', isWildcard: true });
  assert.deepStrictEqual(cleanDomainEntry('*evil.org'), { domain: 'evil.org', isWildcard: true });

  // Hosts format
  assert.deepStrictEqual(cleanDomainEntry('0.0.0.0 badtracker.net'), { domain: 'badtracker.net', isWildcard: false });
  assert.deepStrictEqual(cleanDomainEntry('127.0.0.1  telemetry.ads.com # tracker'), { domain: 'telemetry.ads.com', isWildcard: false });
  assert.deepStrictEqual(cleanDomainEntry('::1 badactor.info'), { domain: 'badactor.info', isWildcard: false });

  // Adblock / AdGuard syntax
  assert.deepStrictEqual(cleanDomainEntry('||adserver.org^'), { domain: 'adserver.org', isWildcard: false });
  assert.deepStrictEqual(cleanDomainEntry('@@||safe.org^'), { domain: 'safe.org', isWildcard: false });
  assert.deepStrictEqual(cleanDomainEntry('||cdn.ads.com/script.js'), { domain: 'cdn.ads.com', isWildcard: false });

  // Filter raw IP addresses
  assert.strictEqual(cleanDomainEntry('0.0.0.0'), null);
  assert.strictEqual(cleanDomainEntry('127.0.0.1'), null);
});

// 3. Rules Engine Priorities
test('RulesEngine: evaluate exact and wildcard priorities', () => {
  const rules = new RulesEngine();
  rules.initDefaults();

  assert.strictEqual(rules.evaluate('google.com').action, 'ALLOW');
  assert.strictEqual(rules.evaluate('connectivitycheck.gstatic.com').action, 'ALLOW');

  assert.strictEqual(rules.evaluate('doubleclick.net').action, 'BLOCK');
  assert.strictEqual(rules.evaluate('ad.doubleclick.net').action, 'BLOCK');
  assert.strictEqual(rules.evaluate('analytics.google-analytics.com').action, 'BLOCK');

  rules.addRule('eviltracker.xyz', 'blocklist', true);
  assert.strictEqual(rules.evaluate('eviltracker.xyz').action, 'BLOCK');
  assert.strictEqual(rules.evaluate('sub.eviltracker.xyz').action, 'BLOCK');

  rules.addRule('sub.eviltracker.xyz', 'whitelist', false);
  assert.strictEqual(rules.evaluate('sub.eviltracker.xyz').action, 'ALLOW');
  assert.strictEqual(rules.evaluate('other.eviltracker.xyz').action, 'BLOCK');
});

// 4. Cache Tests
testAsync('EdgeCache: memory cache put, get, and eviction', async () => {
  const cache = new EdgeCache({ MAX_MEMORY_CACHE_ENTRIES: 2, DEFAULT_CACHE_TTL: 10 });
  await cache.put('key1', { test: 1 }, 10);
  await cache.put('key2', { test: 2 }, 10);

  const hit1 = await cache.get('key1');
  assert.notStrictEqual(hit1, null);
  assert.strictEqual(hit1.data.test, 1);

  await cache.put('key3', { test: 3 }, 10);
  const hit3 = await cache.get('key3');
  assert.strictEqual(hit3.data.test, 3);
});

// 5. Quota Guardian Tests
test('QuotaGuardian: enforce daily limits and reject overage writes', () => {
  const quota = new QuotaGuardian({ DAILY_KV_WRITE_CAP: '3', DAILY_KV_READ_CAP: '10' });
  assert.strictEqual(quota.canKvWrite(), true);
  quota.recordKvWrite();
  quota.recordKvWrite();
  quota.recordKvWrite();

  assert.strictEqual(quota.canKvWrite(), false);
  const usage = quota.getUsage();
  assert.strictEqual(usage.kv.writes, 3);
  assert.strictEqual(usage.kv.writesRemaining, 0);
  assert.strictEqual(usage.rejectedOperations.writes, 1);
});

// 6. Dynamic Storage Binding Detection Tests
test('StorageManager: detectStorageBindings dynamically auto-discovers ANY KV / D1 / R2 binding', () => {
  const mockKv = { get() {}, put() {}, delete() {}, list() {} };
  const mockD1 = { prepare() {}, batch() {}, exec() {} };
  const mockR2 = { get() {}, put() {}, head() {} };

  const envWithRandomNames = {
    MY_RANDOM_KV_STORE: mockKv,
    PRODUCTION_DATABASE_SQL: mockD1,
    MEDIA_BUCKET: mockR2
  };

  const detected = detectStorageBindings(envWithRandomNames);
  assert.strictEqual(detected.kv, mockKv);
  assert.strictEqual(detected.kvName, 'MY_RANDOM_KV_STORE');
  assert.strictEqual(detected.d1, mockD1);
  assert.strictEqual(detected.d1Name, 'PRODUCTION_DATABASE_SQL');
  assert.strictEqual(detected.r2, mockR2);
  assert.strictEqual(detected.r2Name, 'MEDIA_BUCKET');

  const store = new StorageManager(envWithRandomNames);
  const info = store.getStorageInfo();
  assert.strictEqual(info.kv.bound, true);
  assert.strictEqual(info.kv.name, 'MY_RANDOM_KV_STORE');
  assert.strictEqual(info.d1.bound, true);
  assert.strictEqual(info.d1.name, 'PRODUCTION_DATABASE_SQL');
  assert.strictEqual(info.mode, 'Persistent Edge Store');
});

// 7. Bloom Filter Tests
test('BloomFilter: capacity, bitmasking, and lookup accuracy', () => {
  const bf = new BloomFilter(1024, 7);
  bf.insert('apple.com');
  bf.insert('github.com');

  assert.strictEqual(bf.contains('apple.com'), true);
  assert.strictEqual(bf.contains('github.com'), true);
  assert.strictEqual(bf.contains('google.com'), false);
  assert.strictEqual(bf.contains('sub.apple.com'), false);
  assert.strictEqual(bf.containsWithSubdomains('sub.apple.com'), true);
  assert.strictEqual(bf.containsWithSubdomains('deep.sub.apple.com'), true);
  assert.strictEqual(bf.containsWithSubdomains('fakeapple.com'), false);
});

test('BloomFilter: Threat profile power-of-two 4MB RAM bitset', () => {
  const threatBf = BloomFilter.forThreatFeed();
  assert.strictEqual(threatBf.memoryBytes, 4194304); // Exactly 4MB
  assert.strictEqual(threatBf.bits, 33554432);

  threatBf.insert('evil-tracker.com');
  assert.strictEqual(threatBf.contains('evil-tracker.com'), true);
  assert.strictEqual(threatBf.containsWithSubdomains('ad.evil-tracker.com'), true);
  assert.strictEqual(threatBf.contains('clean-domain.org'), false);
});

// 8. Dynamic Upstream Ranking Tests
test('UpstreamResolver: ranking telemetry order by lowest latency and score', () => {
  const resolver = new UpstreamResolver();
  resolver.upstreams = [
    { provider: 'SlowResolver', url: 'https://slow.com', score: 80, latencyMs: 120, healthy: true },
    { provider: 'FastResolver', url: 'https://fast.com', score: 100, latencyMs: 8, healthy: true },
    { provider: 'DegradedResolver', url: 'https://degraded.com', score: 20, latencyMs: 5, healthy: false }
  ];

  const ranked = resolver.getRankedUpstreams();
  assert.strictEqual(ranked[0].provider, 'FastResolver');
  assert.strictEqual(ranked[1].provider, 'SlowResolver');
  assert.strictEqual(ranked[2].provider, 'DegradedResolver');
});

// 9. Threat Rules & Bloom Filter Priority Integration Tests
test('RulesEngine: Priority hierarchy (Whitelist overrides Bloom Filter threat block)', () => {
  const rules = new RulesEngine();
  rules.initDefaults();

  // Insert into threat bloom filter
  rules.threatBloom.insert('badactor.xyz');
  assert.strictEqual(rules.evaluate('badactor.xyz').action, 'BLOCK');
  assert.strictEqual(rules.evaluate('sub.badactor.xyz').action, 'BLOCK');

  // Whitelist punches hole through threat bloom filter
  rules.addRule('sub.badactor.xyz', 'whitelist', false);
  assert.strictEqual(rules.evaluate('sub.badactor.xyz').action, 'ALLOW');
  assert.strictEqual(rules.evaluate('badactor.xyz').action, 'BLOCK');
});

// 10. Rules Stats Separation Test
test('RulesEngine: getStats clearly separates custom rules from bloom filter counts', () => {
  const rules = new RulesEngine();
  rules.initDefaults();

  const stats0 = rules.getStats();
  assert.strictEqual(stats0.customRulesCount, 0);
  assert.strictEqual(stats0.threatBloomCount, 10); // 10 baseline blocklist domains
  assert.strictEqual(stats0.whitelistCount, 14); // 14 baseline whitelist domains

  rules.addRule('mycustomblock.com', 'blocklist', false);
  rules.addRule('mycustomallow.com', 'whitelist', false);

  const stats1 = rules.getStats();
  assert.strictEqual(stats1.customRulesCount, 2);
  assert.strictEqual(stats1.customBlockCount, 1);
  assert.strictEqual(stats1.customAllowCount, 1);
  assert.strictEqual(stats1.threatBloomCount, 11);
});

// 11. Query Logs & Storage Buffer Tests
testAsync('StorageManager & Router: Query logs ring buffer, filtering, and clearing', async () => {
  const rules = new RulesEngine();
  const cache = new EdgeCache();
  const store = new StorageManager();
  const resolver = new UpstreamResolver();
  const router = new AppRouter({ rules, cache, store, resolver });

  for (let i = 1; i <= 120; i++) {
    store.recordQueryLog({
      domain: `host${i}.test.com`,
      qtype: i % 2 === 0 ? 'A' : 'AAAA',
      clientIp: '1.2.3.4',
      status: i % 3 === 0 ? 'BLOCKED' : 'ALLOWED',
      reason: i % 3 === 0 ? 'rule_match' : 'upstream:cloudflare',
      latencyMs: 12,
      timestamp: Date.now()
    });
  }

  const allLogs = store.getLogs();
  assert.strictEqual(allLogs.length, 100); // Max ring buffer
  assert.strictEqual(allLogs[0].domain, 'host120.test.com');

  const blockedLogs = store.getLogs({ status: 'BLOCKED' });
  assert.strictEqual(blockedLogs.every(l => l.status === 'BLOCKED'), true);

  const aaaaLogs = store.getLogs({ qtype: 'AAAA' });
  assert.strictEqual(aaaaLogs.every(l => l.qtype === 'AAAA'), true);
});

// 12. Router & Dashboard Tests
testAsync('AppRouter: simulated /health, /api/status, and /dashboard handling with hardcoded config', async () => {
  const rules = new RulesEngine();
  rules.initDefaults();
  const cache = new EdgeCache();
  const store = new StorageManager();
  const resolver = new UpstreamResolver();
  const router = new AppRouter({ rules, cache, store, resolver });

  const healthReq = new Request('https://amardns.workers.dev/health');
  const healthRes = await router.handle(healthReq, {}, {});
  assert.strictEqual(healthRes.status, 200);
  const healthJson = await healthRes.json();
  assert.strictEqual(healthJson.ok, true);
  assert.strictEqual(healthJson.status, 'healthy');

  const statusReq = new Request('https://amardns.workers.dev/api/status');
  const statusRes = await router.handle(statusReq, {}, {});
  assert.strictEqual(statusRes.status, 200);
  const statusJson = await statusRes.json();
  assert.strictEqual(statusJson.appName, CONFIG.APP_NAME);

  // Authenticated dashboard using hardcoded master key
  const authDashReq = new Request(`https://amardns.workers.dev/dashboard?key=${CONFIG.DNS_MASTER_KEY}`);
  const authDashRes = await router.handle(authDashReq, {}, {});
  assert.strictEqual(authDashRes.status, 200);
  const dashHtml = await authDashRes.text();
  assert.strictEqual(dashHtml.includes('<!DOCTYPE html>'), true);
  assert.strictEqual(dashHtml.includes('Daily Quota Guardian'), true);
  assert.strictEqual(dashHtml.includes('Threat Feed Shield'), true);
});

setTimeout(() => {
  console.log(`\nTest Summary: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}, 200);
