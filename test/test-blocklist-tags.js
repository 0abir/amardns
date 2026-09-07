// test/test-blocklist-tags.js
// Automated verification of Blocklist Tags: FEED, AI, MANUAL

import assert from "node:assert";
import fs from "node:fs";
import { PulseDB } from "../src/storage/pulse-db.js";
import { handleApiRoute } from "../src/core/admin-api.js";
import { _autoBlocks } from "../src/core/state.js";
import { ADMIN_HTML } from "../src/core/dashboard-html.js";

async function main() {
  console.log("=== Testing Blocklist Tagging: FEED vs. AI vs. MANUAL ===");
  const dbPath = "/tmp/test-tags-pulse-" + Date.now() + ".db";
  const pdb = new PulseDB(dbPath);
  const env = { pulseDb: pdb, DNS_MASTER_KEY: "testkey" };

  // 1. Add Threat Feed domain
  pdb.addBlocklist(["evil-tracker.com"], "threat_feed_abir", "feed");
  // 2. Add Manual domain
  pdb.addBlocklist(["custom-blocked.org"], "manual", "admin");
  // 3. Add Automatic AI dynamic block
  _autoBlocks.set("dga-generated.net", {
    exp: Date.now() + 300000,
    reason: "dga_detected",
    auto: true,
    source: "ai",
    tag: "AI",
  });

  // Query /api/blocklist
  const req = new Request("http://localhost/api/blocklist", {
    headers: { authorization: "Bearer testkey" },
  });
  const res = await handleApiRoute(req, "/api/blocklist", env, "GET");
  const data = await res.json();

  console.log("-> [1/3] Validating GET /api/blocklist tags...");
  const feedItem = data.domains.find((d) => d.domain === "evil-tracker.com");
  assert.ok(feedItem, "evil-tracker.com must be present");
  assert.strictEqual(feedItem.tag, "FEED", "evil-tracker.com must be tagged FEED");
  assert.strictEqual(feedItem.source, "feed");

  const aiItem = data.domains.find((d) => d.domain === "dga-generated.net");
  assert.ok(aiItem, "dga-generated.net must be present");
  assert.strictEqual(aiItem.tag, "AI", "dga-generated.net must be tagged AI");
  assert.strictEqual(aiItem.source, "ai");
  assert.strictEqual(aiItem.auto, true);

  const manualItem = data.domains.find((d) => d.domain === "custom-blocked.org");
  assert.ok(manualItem, "custom-blocked.org must be present");
  assert.strictEqual(manualItem.tag, "MANUAL", "custom-blocked.org must be tagged MANUAL");
  assert.strictEqual(manualItem.source, "manual");

  console.log("   ✓ API returns FEED, AI, and MANUAL tags correctly!");

  console.log("-> [2/3] Validating UI chip rendering...");
  const fnStr = ADMIN_HTML.slice(
    ADMIN_HTML.indexOf("function renderBlockRow"),
    ADMIN_HTML.indexOf("// Blocklist\nfunction loadBlock()")
  );
  const tcStr = ADMIN_HTML.slice(
    ADMIN_HTML.indexOf("function tc(r)"),
    ADMIN_HTML.indexOf("function tab(el)")
  );
  const fdStr = ADMIN_HTML.slice(
    ADMIN_HTML.indexOf("function fd(s)"),
    ADMIN_HTML.indexOf("function tc(r)")
  );

  const evalEnv = new Function(fdStr + "\n" + tcStr + "\n" + fnStr + "\nreturn renderBlockRow;");
  const renderBlockRow = evalEnv();

  const fHtml = renderBlockRow(feedItem);
  assert.ok(fHtml.includes("FEED"), "Rendered chip must display FEED badge");

  const aHtml = renderBlockRow(aiItem);
  assert.ok(aHtml.includes("AI"), "Rendered chip must display AI badge");

  const mHtml = renderBlockRow(manualItem);
  assert.ok(mHtml.includes("MANUAL"), "Rendered chip must display MANUAL badge");

  console.log("   ✓ UI chips display FEED, AI, and MANUAL tags cleanly!");

  console.log("-> [3/3] Validating deletion and cleanup...");
  const delReq = new Request("http://localhost/api/blocklist", {
    method: "DELETE",
    headers: { authorization: "Bearer testkey", "content-type": "application/json" },
    body: JSON.stringify({ domain: "evil-tracker.com" }),
  });
  await handleApiRoute(delReq, "/api/blocklist", env, "DELETE");
  assert.strictEqual(pdb.checkBlocklist("evil-tracker.com").blocked, false);

  try { fs.unlinkSync(dbPath); } catch (_) {}
  console.log("\nALL BLOCKLIST TAG TESTS PASSED! 🏷️🛡️🎉\n");
}

main().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
