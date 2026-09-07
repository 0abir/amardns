// test/test-overview-cards.js
// Verifies Overview tab 30-card grid, new metrics, and Aero/Pulse migration

import assert from "node:assert";
import { ADMIN_HTML } from "../src/core/dashboard-html.js";

async function main() {
  console.log("=== Testing Overview 30-Card Grid & Metric Integrity ===");

  console.log("-> [1/4] Verifying exact 30-card count in stats array...");
  const idx = ADMIN_HTML.indexOf("var stats=[");
  const end = ADMIN_HTML.indexOf("];", idx);
  assert.ok(idx !== -1 && end !== -1, "stats array must exist");
  const statsSlice = ADMIN_HTML.slice(idx, end + 2);
  const cardMatches = [...statsSlice.matchAll(/id:\x27[^\x27]+\x27/g)];
  assert.strictEqual(cardMatches.length, 30, `Expected exactly 30 cards, found ${cardMatches.length}`);
  console.log("   ✓ Exactly 30 cards present in Overview dashboard grid");

  console.log("-> [2/4] Verifying upgraded essential metric cards...");
  assert.ok(statsSlice.includes("id:'lat'"), "Must include Avg Latency card");
  assert.ok(statsSlice.includes("label:'Avg Latency'"), "Avg Latency card label");
  assert.ok(statsSlice.includes("id:'upstreams'"), "Must include Upstreams card");
  assert.ok(statsSlice.includes("label:'Upstreams'"), "Upstreams card label");
  assert.ok(statsSlice.includes("id:'blk_rate'"), "Must include Block Rate card");
  assert.ok(statsSlice.includes("label:'Block Rate'"), "Block Rate card label");
  assert.ok(statsSlice.includes("id:'aero_cache'"), "Must include AERO Cache card");
  assert.ok(statsSlice.includes("label:'AERO Cache'"), "AERO Cache card label");
  console.log("   ✓ All 4 upgraded metric cards verified");

  console.log("-> [3/4] Verifying removal of redundant / offline cards...");
  assert.ok(!statsSlice.includes("id:'cache_recs'"), "Old redundant Cached Records card removed");
  assert.ok(!statsSlice.includes("id:'brainsize'"), "Old Brain Size placeholder card removed");
  assert.ok(!statsSlice.includes("id:'gsb'"), "Old GSB OFFLINE card removed");
  assert.ok(!statsSlice.includes("id:'data'"), "Old Data Integrity card removed");
  console.log("   ✓ Redundant / confusing cards successfully replaced");

  console.log("-> [4/4] Verifying CSS renaming from old bar to pulsebar...");
  assert.ok(ADMIN_HTML.includes(".pulsebar"), "Must include .pulsebar CSS class");
  assert.ok(ADMIN_HTML.includes(".pulsebar-wrap"), "Must include .pulsebar-wrap CSS class");
  const legacyBar = [".", "d", "1", "bar"].join("");
  assert.ok(!ADMIN_HTML.includes(legacyBar), "Must NOT include legacy bar CSS class");
  console.log("   ✓ CSS classes renamed cleanly");

  console.log("\nALL OVERVIEW CARDS & METRIC INTEGRITY TESTS PASSED! 📊🚀🎉\n");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
