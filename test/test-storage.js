// test/test-storage.js
import assert from "node:assert";
import fs from "node:fs";
import { AeroCache } from "../src/storage/aero-cache.js";
import { PulseDB, SuffixTrie } from "../src/storage/pulse-db.js";

async function run() {
  console.log("=== Testing AeroCache & PulseDB Engines ===");

  // --- AeroCache Tests ---
  console.log("1. Testing AeroCache...");
  const cache = new AeroCache({ maxEntries: 10, maxBytes: 1024 * 1024, minTtl: 1, maxTtl: 10 });

  // Basic put & get
  const dummyWire = Buffer.from("dummy-dns-response-packet");
  cache.put("example.com", 1, dummyWire, 5);

  const hit = cache.get("example.com", 1);
  assert.ok(hit, "Cache should hit for example.com");
  assert.strictEqual(Buffer.from(hit).toString(), "dummy-dns-response-packet");

  const miss = cache.get("nonexistent.com", 1);
  assert.strictEqual(miss, null, "Cache should miss for nonexistent.com");

  // TTL expiration & Micro-sweeper cleaning rotation
  cache.put("expire-fast.com", 1, dummyWire, 1);
  await new Promise((r) => setTimeout(r, 1100));
  const purged = cache.sweep(100);
  assert.ok(purged >= 1, "Micro-sweeper must purge expired entries");
  assert.strictEqual(cache.get("expire-fast.com", 1), null, "Expired entry must return null");

  // S3-FIFO eviction under saturation
  for (let i = 0; i < 20; i++) {
    cache.put(`domain-${i}.com`, 1, dummyWire, 60);
  }
  assert.ok(cache.map.size <= 10, `Cache size (${cache.map.size}) must not exceed maxEntries 10`);
  console.log("   ✓ AeroCache put/get/TTL/eviction and micro-sweep rotation passed!");

  // --- SuffixTrie Tests ---
  console.log("2. Testing SuffixTrie (Domain wildcard matching)...");
  const trie = new SuffixTrie();
  trie.add("doubleclick.net", "adware");
  trie.add("malware.badsite.org", "malware");

  // Exact matches
  assert.strictEqual(trie.check("doubleclick.net").matched, true);
  assert.strictEqual(trie.check("malware.badsite.org").matched, true);

  // Subdomain wildcard matches
  assert.strictEqual(trie.check("ads.doubleclick.net").matched, true, "Subdomain must match parent");
  assert.strictEqual(trie.check("tracker.sub.doubleclick.net").matched, true, "Deep subdomain must match parent");
  assert.strictEqual(trie.check("deep.malware.badsite.org").matched, true);

  // Unrelated domains
  assert.strictEqual(trie.check("notdoubleclick.net").matched, false);
  assert.strictEqual(trie.check("google.com").matched, false);
  assert.strictEqual(trie.check("badsite.org").matched, false, "Parent of blocked subdomain should not be blocked");

  // Removal
  trie.remove("doubleclick.net");
  assert.strictEqual(trie.check("doubleclick.net").matched, false);
  assert.strictEqual(trie.check("ads.doubleclick.net").matched, false);
  console.log("   ✓ SuffixTrie reverse label matching passed!");

  // --- PulseDB Engine Tests ---
  console.log("3. Testing PulseDB (WAL Persistence, Recovery & Compaction)...");
  const testWal = `/tmp/test-pulsedb-${Date.now()}.wal`;
  try {
    const db = new PulseDB(testWal);
    db.boot();

    // Blocklist operations
    db.addBlocklist(["track.com", "telemetry.io"], "adblock");
    db.addWhitelist("allowed.track.com");

    assert.strictEqual(db.checkBlocklist("track.com").blocked, true);
    assert.strictEqual(db.checkBlocklist("sub.track.com").blocked, true);
    assert.strictEqual(db.checkBlocklist("allowed.track.com").blocked, false, "Whitelist takes precedence");

    // Aero operations & TTL rotation
    db.set("config:dns_mode", "public");
    assert.strictEqual(db.get("config:dns_mode"), "public");
    db.set("config:test_num", 12345);
    assert.strictEqual(db.get("config:test_num"), 12345);
    db.set("temp:key", "to-be-purged", 1);
    await new Promise((r) => setTimeout(r, 1100));
    const aeroPurged = db.sweepExpiredAero(50);
    assert.strictEqual(aeroPurged, 1, "PulseDB sweepExpiredAero must purge expired Aero keys");
    assert.strictEqual(db.get("temp:key"), null);

    const stats = db.getStats();
    assert.ok(stats.writeQueue, "PulseDB stats must include writeQueue telemetry");
    assert.strictEqual(typeof stats.writeQueue.pending, "number");

    db.close();

    // Re-open and verify persistence (Crash recovery test)
    console.log("   -> Replaying WAL from disk...");
    const db2 = new PulseDB(testWal);
    db2.boot();

    assert.strictEqual(db2.checkBlocklist("track.com").blocked, true, "Blocklist must survive restart");
    assert.strictEqual(db2.checkBlocklist("sub.track.com").blocked, true);
    assert.strictEqual(db2.checkBlocklist("allowed.track.com").blocked, false);
    assert.strictEqual(db2.get("config:dns_mode"), "public", "Aero must survive restart");
    assert.strictEqual(db2.get("config:test_num"), 12345);

    // Compaction test
    console.log("   -> Testing atomic compaction...");
    db2.removeBlocklist("telemetry.io");
    db2.delete("config:test_num");
    db2.compact();

    assert.strictEqual(db2.checkBlocklist("track.com").blocked, true);
    assert.strictEqual(db2.checkBlocklist("telemetry.io").blocked, false);
    assert.strictEqual(db2.get("config:test_num"), null);
    db2.close();

    // Verify post-compaction replay
    const db3 = new PulseDB(testWal);
    db3.boot();
    assert.strictEqual(db3.checkBlocklist("track.com").blocked, true);
    assert.strictEqual(db3.get("config:dns_mode"), "public");
    assert.strictEqual(db3.get("config:test_num"), null);
    db3.close();

    console.log("   ✓ PulseDB WAL replay and compaction passed!");
  } finally {
    try {
      if (fs.existsSync(testWal)) fs.unlinkSync(testWal);
      if (fs.existsSync(`${testWal}.compact`)) fs.unlinkSync(`${testWal}.compact`);
    } catch {}
  }

  console.log("\nALL AEROCACHE & PULSEDB UNIT TESTS PASSED! 🎉\n");
}

run().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
