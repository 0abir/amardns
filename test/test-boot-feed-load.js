// test/test-boot-feed-load.js
// Verifies threat feeds automatically load on startup even when PulseDB is pre-populated with whitelist entries

import assert from "node:assert";
import fs from "node:fs";
import { PulseDB } from "../src/storage/pulse-db.js";
import { syncThreatFeeds, _abirOk, _commonOk, _abirSet, _commonSet, _abirCrossMatched, _commonCrossMatched, _abirTotalEntries, _commonTotalEntries } from "../src/core/threat-intelligence.js";
import { setEnv } from "../src/core/state.js";

async function main() {
  console.log("=== Testing Automatic Threat Feed Load On Startup (No NUKE required) ===");

  const dbPath = "/tmp/test-boot-pulse-" + Date.now() + ".wal";
  const pdb = new PulseDB(dbPath);
  // Pre-populate whitelist so whitelistTrie.size > 0
  pdb.addWhitelist(["existing-allowed-domain.org", "adguard.com"]);
  assert.ok(pdb.whitelistTrie.size > 0, "PulseDB whitelistTrie must be non-empty on boot");

  const env = { pulseDb: pdb, DNS_MASTER_KEY: "testkey" };
  setEnv(env);

  console.log("-> [1/2] Triggering boot sync with non-empty database...");
  await syncThreatFeeds(true, env);

  console.log("-> [2/2] Validating feed in-memory state and cross-match verification...");
  assert.strictEqual(_abirOk, true, "ABIR blocklist feed must be OK on startup");
  assert.strictEqual(_commonOk, true, "Common whitelist feed must be OK on startup");
  assert.strictEqual(_abirCrossMatched, true, "ABIR blocklist must be 100% cross-matched with total_blocked.txt");
  assert.strictEqual(_commonCrossMatched, true, "Common whitelist must be 100% cross-matched with total_whitelisted.txt");
  assert.ok(Math.abs(_abirSet.size - _abirTotalEntries) <= 1, `ABIR blocklist set (${_abirSet.size}) must match total_blocked.txt (${_abirTotalEntries})`);
  assert.ok(Math.abs(_commonSet.size - _commonTotalEntries) <= 1, `Common whitelist set (${_commonSet.size}) must match total_whitelisted.txt (${_commonTotalEntries})`);

  console.log(`   ✓ Successfully cross-matched ${_abirSet.size} blocklist and ${_commonSet.size} whitelist domains!`);

  pdb.close();
  try {
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
  } catch (_) {}

  console.log("\nAUTOMATIC STARTUP FEED LOADING TEST PASSED! 🚀🎉\n");
}

main().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
