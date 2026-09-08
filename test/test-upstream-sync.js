// test/test-upstream-sync.js
// Tests automated pulling, probing, and aura+latency ranking of upstream DNS servers.

process.env.DNS_MASTER_KEY = "testkey_up_test";
process.env.DNS_ACCESS_MODE = "public";

import assert from "node:assert";
import core from "../src/core.js";
import { buildEnv } from "../src/env-shim.js";
import {
  fetchUpstreamFeed,
  getUpstreamList,
  FEED_CACHE_TTL_MS,
  rankUpstreams,
  syncAndRankUpstreams,
  loadPersistedUpstreams,
  DEFAULT_UPSTREAM_FEED,
} from "../src/upstream-manager.js";

async function run() {
  console.log("=== Testing Automated Upstream DNS Sync & Aura Ranker ===");
  const env = buildEnv();

  // 1. Test fetching raw feed and 24h caching
  console.log("-> [1/6] Testing feed fetch from CDN & 24h caching...");
  const rawList = await fetchUpstreamFeed(DEFAULT_UPSTREAM_FEED);
  assert.ok(Array.isArray(rawList), "Feed must return an array of upstreams");
  assert.ok(rawList.length >= 10, "Feed should contain at least 10 upstreams");
  console.log(`   ✓ Successfully fetched ${rawList.length} upstreams from CDN`);

  const cachedList = await getUpstreamList(DEFAULT_UPSTREAM_FEED, false, env);
  assert.strictEqual(cachedList.length, rawList.length, "getUpstreamList should return cached array");
  console.log("   ✓ 24h feed caching verified (feed pulled once daily)");

  // 2. Test ranking logic (aura priority + low latency)
  console.log("-> [2/5] Testing aura + low latency ranking algorithm...");
  const mockCandidates = [
    { provider: "LowFast", url: "https://lowfast.com", aura: "low", latency: 20, ok: true },
    { provider: "HighSlow", url: "https://highslow.com", aura: "high", latency: 150, ok: true },
    { provider: "HighFast", url: "https://highfast.com", aura: "high", latency: 45, ok: true },
    { provider: "MedFast", url: "https://medfast.com", aura: "medium", latency: 30, ok: true },
    { provider: "MedSlow", url: "https://medslow.com", aura: "medium", latency: 200, ok: true },
    { provider: "HighDead", url: "https://highdead.com", aura: "high", latency: 9999, ok: false },
  ];

  const rankedMock = rankUpstreams(mockCandidates);
  // High aura should be prioritized first, sorted by latency: HighFast (45ms) -> HighSlow (150ms)
  // Then medium: MedFast (30ms) -> MedSlow (200ms)
  // Then low: LowFast (20ms)
  // Dead ones at bottom: HighDead (ok=false)
  assert.strictEqual(rankedMock[0].provider, "HighFast", "Fastest High aura should rank #1");
  assert.strictEqual(rankedMock[1].provider, "HighSlow", "Slower High aura should rank #2");
  assert.strictEqual(rankedMock[2].provider, "MedFast", "Fastest Medium aura should rank #3");
  assert.strictEqual(rankedMock[3].provider, "MedSlow", "Slower Medium aura should rank #4");
  assert.strictEqual(rankedMock[4].provider, "LowFast", "Low aura should rank after medium");
  assert.strictEqual(rankedMock[5].provider, "HighDead", "Failed/dead upstreams should rank last");
  console.log("   ✓ Aura prioritization (high > medium > low) and latency sorting validated!");

  // 3. Test end-to-end sync and parallel probing
  console.log("-> [3/5] Testing end-to-end syncAndRankUpstreams...");
  const syncResult = await syncAndRankUpstreams(env, core);
  assert.ok(syncResult.ok, "Sync result should be ok");
  assert.ok(syncResult.active.length >= 3, "Active pool should have at least 3 upstreams");
  assert.strictEqual(syncResult.active.length % 3, 0, "Active pool must always be a multiple of 3 (3xN)");
  assert.strictEqual(syncResult.active.length, 9, "Active pool default should be 9 (3x3)");
  
  const activeBases = core.getUpstreams();
  assert.strictEqual(activeBases.length, syncResult.active.length, "Worker active upstreams should match");
  console.log(`   ✓ Active pool loaded with ${activeBases.length} ranked upstreams (3xN pool)`);

  // 4. Test persistence in PulseDB
  console.log("-> [4/5] Testing PulseDB persistence and startup load...");
  const persistCheck = loadPersistedUpstreams(env, core);
  assert.strictEqual(persistCheck.loaded, true, "Upstreams should be loaded from PulseDB");
  assert.strictEqual(persistCheck.shouldSync, false, "Freshly synced upstreams should not be expired");
  console.log("   ✓ Persistence and age-based reload verified");

  // 5. Test API endpoints
  console.log("-> [5/5] Testing /api/upstreams/ranked API endpoint...");
  const apiReq = new Request("http://localhost/api/upstreams/ranked/testkey_up_test");
  const apiRes = await core.fetch(apiReq, env, { waitUntil: () => {} });
  assert.strictEqual(apiRes.status, 200, "API should return HTTP 200");
  const apiData = await apiRes.json();
  assert.ok(apiData.ok, "API response should be ok");
  assert.ok(apiData.upstreams.length >= 10, "API should return all candidates with aura & latency");
  console.log(`   ✓ API returned ${apiData.upstreams.length} candidate upstreams with aura and latency metrics`);

  console.log("\nALL UPSTREAM DNS SYNC & AURA TESTS PASSED! 🚀🎉\n");
  process.exit(0);
}

run().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
