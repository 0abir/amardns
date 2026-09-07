// test/test-nuke.js
// Validates that NUKE resets everything to ground zero / completely hollow.

import assert from "node:assert";
import fs from "node:fs";
import { AeroCache } from "../src/storage/aero-cache.js";
import { PulseDB } from "../src/storage/pulse-db.js";
import {
  _sh, _anomalies, _actions, _aiDecisions, _configDecisions,
  _negCache, _featCache, _feedCache, _answerHistory,
  _autoBlocks, _burstMap, _fpMap, _memBlacklist, _memWhitelist, _memCommon, _dgaLegit,
  _domainIQ, _markov, _ledger, _userMap, _heatmap, _ups, _cb, _upScores, _upMetadata
} from "../src/core/state.js";
import { _hotPut, _hotGet, _episodic, _rewardShaper, _nnStats } from "../src/core/neural-engine.js";
import {
  _gsbCachePut, _gsbCacheGet, _ttlHistory, _swarmMap, _clientNX, _cacheTimings,
  _abirSet, _commonSet, _abirOk, _commonOk, checkBlocklist, checkWhitelist
} from "../src/core/threat-intelligence.js";
import { _gru, _gnn, _spiking, _rl } from "../src/core/neural-models.js";
import { handleApiRoute } from "../src/core/admin-api.js";

async function run() {
  console.log("=== Testing Nuclear Reset (NUKE) Complete Hollow State ===");

  const testWal = `/tmp/test-nuke-db-${Date.now()}.wal`;
  const pulseDb = new PulseDB(testWal);
  pulseDb.boot();

  const aeroCache = new AeroCache({ maxEntries: 1000, maxBytes: 10 * 1024 * 1024 });

  const env = {
    DNS_MASTER_KEY: "test-master-key",
    DNS_ACCESS_MODE: "public",
    pulseDb,
    aeroCache,
  };

  try {
    // 1. Fill AeroCache with records and generate hits/misses
    console.log("-> 1. Populating AeroCache with wire records and hits...");
    const dummyWire = Buffer.from("dummy-dns-response");
    aeroCache.put("google.com", 1, dummyWire, 300);
    aeroCache.put("cloudflare.com", 1, dummyWire, 300);
    aeroCache.get("google.com", 1); // hit
    aeroCache.get("missing.com", 1); // miss
    assert.strictEqual(aeroCache.size, 2);
    assert.ok(aeroCache.getStats().hits >= 1);
    assert.ok(aeroCache.getStats().bytes > 0);

    // 2. Populate PulseDB with blocklists, whitelists, and custom KV
    console.log("-> 2. Populating PulseDB with blocklists, whitelists, and KV...");
    pulseDb.addBlocklist(["malicious.com", "phishing.net", "tracker.org"], "adware");
    pulseDb.addWhitelist("goodsite.org");
    pulseDb.set("custom:setting", "foo-bar");
    pulseDb.set("user:token", "secret123");
    assert.strictEqual(pulseDb.getStats().blocklistDomains, 3);
    assert.strictEqual(pulseDb.getStats().whitelistDomains, 1);
    assert.strictEqual(pulseDb.get("custom:setting"), "foo-bar");

    // 3. Populate in-memory caches, tracking maps, and telemetry counters
    console.log("-> 3. Populating in-memory caches, tracking maps, and telemetry counters...");
    _negCache.set("nxdomain.org", { rcode: 3, exp: Date.now() + 10000 });
    _featCache.set("feature.com", new Float32Array(40));
    _feedCache.set("threat.com", { blocked: true, reason: "feed", exp: Date.now() + 10000 });
    _answerHistory.set("flapping.com", new Set(["1.2.3.4"]));
    _autoBlocks.set("badip", Date.now() + 10000);
    _burstMap.set("bursting.com", { c: 50, ts: Date.now() });
    _fpMap.set("fp.com", Date.now());
    _memBlacklist.add("mem-black.com");
    _memWhitelist.add("mem-white.com");
    _memCommon.add("mem-common.com");
    _dgaLegit.add("legit-dga.com");

    _sh.requests = 1250;
    _sh.cacheHits = 980;
    _sh.cacheMisses = 270;
    _sh.negHits = 45;
    _sh.dgaBlocked = 12;
    _sh.repBlocks = 8;
    _sh.autoBlocks = 5;

    _anomalies.push({ type: "high_rps", t: Date.now() });
    _actions.push({ action: "test_action", t: Date.now() });
    _aiDecisions.push({ decision: "block", t: Date.now() });
    _configDecisions.push({ setting: "ttl", t: Date.now() });

    // 4. Populate AI/ML models & neural caches
    console.log("-> 4. Populating AI models, DomainIQ, Markov, and Neural caches...");
    _domainIQ.see("suspicious.com", "blocked");
    _domainIQ.see("evil.com", "dga");
    assert.ok(_domainIQ.map.size >= 2);

    _markov.track("127.0.0.1", "site-a.com");
    _markov.track("127.0.0.1", "site-b.com");
    assert.ok(_markov.history.size >= 1);

    _ledger.record("dga", "dga123.com", "entropy", "block", 0.95);
    assert.strictEqual(_ledger.entries.length, 1);

    _hotPut("neural_pred_key", { score: 0.9 });
    assert.ok(_hotGet("neural_pred_key"));

    _gsbCachePut("gsb-bad.com", { threat: true }, 60000);
    assert.ok(_gsbCacheGet("gsb-bad.com"));

    _ttlHistory.set("ttl.com", { median: 60, samples: 2, sum: 120 });
    _swarmMap.set("swarm.com", new Set(["10.0.0.1", "10.0.0.2"]));
    _clientNX.set("client1", { nx: 5, total: 10, windowStart: Date.now() });
    _cacheTimings.set("poison.com", { ewma: 20, n: 5 });

    _gru.states.set("ip1", { fwd: new Float32Array(24), bwd: new Float32Array(24), buf: [] });
    _gnn.nodes.set("node1", new Float32Array(8));
    _gnn.edges.set("node1", new Set(["node2"]));
    _spiking.calls = 50;
    _spiking.spikes = 10;
    _rl.calls = 25;
    _rl.cacheHitReward = 1.5;
    _episodic.remember("episodic.com", new Float32Array(32), "blocked");
    assert.ok(_episodic.stats().size >= 1);

    // Verify system is fully populated before NUKE
    assert.ok(_negCache.size > 0);
    assert.ok(_featCache.size > 0);
    assert.ok(_sh.requests > 0);
    assert.ok(_anomalies.length > 0);
    assert.ok(_actions.length > 0);

    // 5. Execute NUKE via POST /api/nuke
    console.log("-> 5. Executing NUKE reset via POST /api/nuke...");
    const dummyReq = new Request("http://localhost/api/nuke", { method: "POST" });
    const resp = await handleApiRoute(dummyReq, "/api/nuke", env, "POST");
    assert.strictEqual(resp.status, 200);

    const body = await resp.json();
    console.log("   -> NUKE response:", JSON.stringify(body, null, 2));
    assert.strictEqual(body.ok, true);
    assert.strictEqual(body.wiped, true);
    assert.strictEqual(body.hollow, true);

    // 6. Verify AeroCache is completely hollow
    console.log("-> 6. Verifying AeroCache is 100% hollow...");
    assert.strictEqual(aeroCache.size, 0, "AeroCache size must be exactly 0");
    assert.strictEqual(aeroCache.currentBytes, 0, "AeroCache currentBytes must be 0");
    assert.strictEqual(aeroCache.stats.hits, 0, "AeroCache hits must be 0");
    assert.strictEqual(aeroCache.stats.misses, 0, "AeroCache misses must be 0");
    assert.strictEqual(aeroCache.stats.puts, 0, "AeroCache puts must be 0");
    assert.strictEqual(aeroCache.stats.evictions, 0, "AeroCache evictions must be 0");
    assert.strictEqual(aeroCache.get("google.com", 1), null, "Previously cached entry must be gone");

    // 7. Verify all in-memory caches and sets are hollow
    console.log("-> 7. Verifying in-memory caches and sets are 100% hollow...");
    assert.strictEqual(_negCache.size, 0, "_negCache must be 0");
    assert.strictEqual(_featCache.size, 0, "_featCache must be 0");
    assert.strictEqual(_feedCache.size, 0, "_feedCache must be 0");
    assert.strictEqual(_answerHistory.size, 0, "_answerHistory must be 0");
    assert.strictEqual(_autoBlocks.size, 0, "_autoBlocks must be 0");
    assert.strictEqual(_burstMap.size, 0, "_burstMap must be 0");
    assert.strictEqual(_fpMap.size, 0, "_fpMap must be 0");
    assert.strictEqual(_memBlacklist.size, 0, "_memBlacklist must be 0");
    assert.strictEqual(_memWhitelist.size, 0, "_memWhitelist must be 0");
    assert.strictEqual(_memCommon.size, 0, "_memCommon must be 0");
    assert.strictEqual(_dgaLegit.size, 0, "_dgaLegit must be 0");

    // 8. Verify threat intelligence caches are hollow
    console.log("-> 8. Verifying threat intelligence caches are 100% hollow...");
    assert.strictEqual(_gsbCacheGet("gsb-bad.com"), null);
    assert.strictEqual(_ttlHistory.size, 0);
    assert.strictEqual(_swarmMap.size, 0);
    assert.strictEqual(_clientNX.size, 0);
    assert.strictEqual(_cacheTimings.size, 0);

    // 9. Verify neural engine and AI models are hollow
    console.log("-> 9. Verifying AI models & neural caches are 100% hollow...");
    assert.strictEqual(_hotGet("neural_pred_key"), null);
    assert.strictEqual(_domainIQ.map.size, 0, "DomainIQ map must be 0");
    assert.strictEqual(_markov.transitions.size, 0, "Markov transitions must be 0");
    assert.strictEqual(_markov.history.size, 0, "Markov history must be 0");
    assert.strictEqual(_ledger.entries.length, 0, "Ledger entries must be 0");
    assert.strictEqual(_gru.states.size, 0, "GRU states must be 0");
    assert.strictEqual(_gnn.nodes.size, 0, "GNN nodes must be 0");
    assert.strictEqual(_gnn.edges.size, 0, "GNN edges must be 0");
    assert.strictEqual(_spiking.calls, 0, "Spiking calls must be 0");
    assert.strictEqual(_rl.calls, 0, "RL calls must be 0");
    assert.strictEqual(_rl.cacheHitReward, 0, "RL cacheHitReward must be 0");
    assert.strictEqual(_episodic.stats().size, 0, "Episodic memory size must be 0");
    assert.strictEqual(_rewardShaper.getStats().totalSignals, 0, "RewardShaper signals must be 0");
    assert.strictEqual(_nnStats.learningCycles, 0, "nnStats learningCycles must be 0");

    // 10. Verify telemetry & counters are all 0
    console.log("-> 10. Verifying telemetry counters & logs are all 0...");
    assert.strictEqual(_sh.requests, 0);
    assert.strictEqual(_sh.cacheHits, 0);
    assert.strictEqual(_sh.cacheMisses, 0);
    assert.strictEqual(_sh.negHits, 0);
    assert.strictEqual(_sh.dgaBlocked, 0);
    assert.strictEqual(_sh.repBlocks, 0);
    assert.strictEqual(_anomalies.length, 0, "_anomalies must be completely empty");
    assert.strictEqual(_actions.length, 0, "_actions must be completely empty");
    assert.strictEqual(_aiDecisions.length, 0, "_aiDecisions must be completely empty");
    assert.strictEqual(_configDecisions.length, 0, "_configDecisions must be completely empty");

    // 11. Verify PulseDB and threat feeds were wiped of old state and reloaded fresh
    console.log("-> 11. Verifying active upstreams and customized feeds loaded right after nuking...");
    assert.strictEqual(pulseDb.get("custom:setting"), null, "Old custom KV must be wiped");
    assert.strictEqual(pulseDb.get("user:token"), null, "Old user KV must be wiped");
    assert.strictEqual(pulseDb.get("config:dns_mode"), "public", "DNS mode must default to public");
    assert.strictEqual(pulseDb.get("config:auto_heal"), "true");
    assert.ok(pulseDb.get("upstreams:active_urls"), "Baseline active upstreams must be populated");
    assert.ok(pulseDb.get("upstreams:ranked"), "Upstreams ranked metadata must be populated in PulseDB");
    assert.strictEqual(_ups.length, 9, "9 baseline active upstreams must be configured");
    assert.ok(Array.isArray(_upMetadata) && _upMetadata.length === 9, "Upstream metadata must be loaded with 9 providers");

    // Verify customized threat feeds reloaded into memory
    assert.strictEqual(_commonOk, true, "Whitelist feed must be marked OK");
    assert.strictEqual(_abirOk, true, "Blocklist feed must be marked OK");
    assert.ok(_commonSet.size > 0, "Whitelist BloomFilter must have loaded domains");
    assert.ok(_abirSet.size > 0, "Blocklist BloomFilter must have loaded domains");

    // PulseDB blocklist & whitelist start at 0 immediately after nuke (only detected traffic is recorded)
    assert.strictEqual(pulseDb.getStats().whitelistDomains, 0, "PulseDB whitelist trie must be hollow initially (detected-only)");
    assert.strictEqual(pulseDb.getStats().blocklistDomains, 0, "PulseDB blocklist trie must be hollow initially (detected-only)");

    // Verify blocklist and whitelist rule matching with live detection recording
    assert.strictEqual(checkBlocklist("010172.com", pulseDb).blocked, true, "Known blocklist domain must be blocked");
    assert.strictEqual(pulseDb.getStats().blocklistDomains, 1, "Detected blocked domain recorded in PulseDB blocklist");
    assert.strictEqual(checkBlocklist("sub.010172.com", pulseDb).blocked, true, "Subdomain of blocklist domain must be blocked");

    assert.strictEqual(checkWhitelist("adguard.com", pulseDb), true, "Known whitelist domain must be whitelisted");
    assert.strictEqual(pulseDb.getStats().whitelistDomains, 1, "Detected whitelisted domain recorded in PulseDB whitelist");
    assert.strictEqual(checkWhitelist("adblockplus.org", pulseDb), true, "Known whitelist domain must be whitelisted");
    assert.strictEqual(pulseDb.getStats().whitelistDomains, 2, "Second detected whitelisted domain recorded in PulseDB whitelist");

    // Test cross-check: Whitelist ALWAYS prioritizes over blocklist
    // If a domain matches blocklist but is also in whitelist, checkBlocklist MUST NOT block it
    pulseDb.addWhitelist("safe.010172.com");
    assert.strictEqual(checkBlocklist("safe.010172.com", pulseDb).blocked, false, "Whitelisted subdomain must bypass blocklist");
    assert.strictEqual(checkBlocklist("other.010172.com", pulseDb).blocked, true, "Non-whitelisted subdomain remains blocked");

    // 12. Also test alternative routes: /api/nuclear-wipe with DELETE
    console.log("-> 12. Testing alternative alias DELETE /api/nuclear-wipe...");
    const delReq = new Request("http://localhost/api/nuclear-wipe", { method: "DELETE" });
    const delResp = await handleApiRoute(delReq, "/api/nuclear-wipe", env, "DELETE");
    assert.strictEqual(delResp.status, 200);
    const delBody = await delResp.json();
    assert.strictEqual(delBody.ok, true);
    assert.strictEqual(delBody.hollow, true);
    assert.strictEqual(_ups.length, 9, "Upstreams must remain active after DELETE wipe");
    assert.strictEqual(pulseDb.getStats().whitelistDomains, 0, "Whitelist starts hollow after DELETE wipe");
    assert.strictEqual(pulseDb.getStats().blocklistDomains, 0, "Blocklist starts hollow after DELETE wipe");

    // 13. Verify post-nuke resolver health (resolving a live DNS query works cleanly)
    console.log("-> 13. Testing post-nuke DNS query resolution...");
    const { resolveDns } = await import("../src/core/dns-protocol.js");
    const { makeDnsProbePacket } = await import("../src/upstream-manager.js");
    const probe = makeDnsProbePacket("example.com");
    const dnsResp = await resolveDns(probe, "127.0.0.1", env);
    assert.strictEqual(dnsResp.status, 200, "Post-nuke DNS query must return HTTP 200");
    const respWire = await dnsResp.arrayBuffer();
    assert.ok(respWire.byteLength >= 12, "Post-nuke DNS response must have valid DNS wire header");
    console.log("   ✓ Post-nuke DNS resolution succeeds cleanly!");

    console.log("\nALL NUCLEAR HOLLOW RESET TESTS PASSED! 💥🧹🎉\n");
  } finally {
    pulseDb.close();
    try {
      if (fs.existsSync(testWal)) fs.unlinkSync(testWal);
      if (fs.existsSync(`${testWal}.compact`)) fs.unlinkSync(`${testWal}.compact`);
    } catch {}
  }
}

run().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
