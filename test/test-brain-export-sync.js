// test/test-brain-export-sync.js
// Tests AI brain export, import, serialization chunking, and storage adapter persistence.

process.env.DNS_MASTER_KEY = "testkey_sync_99";
process.env.DNS_ACCESS_MODE = "public";

import assert from "node:assert";
import core from "../src/core.js";
import { buildEnv } from "../src/env-shim.js";
import {
  _brainExport,
  _brainExportParts,
  _brainImport,
  brainSync,
  aeroPut,
  aeroGet
} from "../src/core/storage-adapter.js";
import { _brainPrune } from "../src/core/neural-engine.js";

async function run() {
  console.log("=== Testing AI Brain Export, Import & Storage Adapters ===");
  const env = buildEnv();
  const ctx = {
    waitUntil: (p) => Promise.resolve(p).catch(() => {})
  };

  // 1. Direct _brainExportParts() call
  console.log("-> [1/6] Testing direct _brainExportParts()...");
  const parts = _brainExportParts();
  assert.ok(parts, "parts should not be null");
  assert.ok(parts.meta, "parts.meta should exist");
  assert.ok(parts.rhythm, "parts.rhythm should exist");
  assert.ok(parts.nn_dtn, "parts.nn_dtn should exist");
  assert.ok(parts.nn_stats, "parts.nn_stats should exist");
  console.log("   ✓ _brainExportParts returned valid serialized components (keys:", Object.keys(parts).length, ")");

  // 2. Direct _brainExport() call
  console.log("-> [2/6] Testing direct _brainExport()...");
  const exported = _brainExport();
  assert.ok(exported.hot, "exported.hot should exist");
  assert.ok(typeof exported.hot === "string", "exported.hot should be a string");
  const parsedHot = JSON.parse(exported.hot);
  assert.ok(parsedHot.nn, "parsedHot.nn should exist");
  assert.ok(parsedHot.nnStats, "parsedHot.nnStats should exist");
  console.log("   ✓ _brainExport successfully assembled hot state (brainVersion:", parsedHot.nnStats.brainVersion, ")");

  // 3. GET /api/ai/export/:key endpoint
  console.log("-> [3/6] Testing GET /api/ai/export/:key API route...");
  const exportReq = new Request("http://localhost/api/ai/export/testkey_sync_99", {
    method: "GET"
  });
  const exportRes = await core.fetch(exportReq, env, ctx);
  assert.strictEqual(exportRes.status, 200, "export API route should return 200 OK");
  const exportData = await exportRes.json();
  assert.ok(exportData.hot, "export API payload should contain hot brain state");
  console.log("   ✓ /api/ai/export returned 200 OK with valid neural payload");

  // 4. POST /api/ai/import/:key endpoint
  console.log("-> [4/6] Testing POST /api/ai/import/:key API route...");
  const importReq = new Request("http://localhost/api/ai/import/testkey_sync_99", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      hot: exportData.hot,
      markov: "[]"
    })
  });
  const importRes = await core.fetch(importReq, env, ctx);
  assert.strictEqual(importRes.status, 200, "import API route should return 200 OK");
  const importData = await importRes.json();
  assert.strictEqual(importData.ok, true, "import should succeed with ok: true");
  console.log("   ✓ /api/ai/import successfully imported neural state");

  // 5. brainSync() execution
  console.log("-> [5/6] Testing brainSync(force=true)...");
  await brainSync(true);
  console.log("   ✓ brainSync completed cleanly without unhandled exceptions");

  // 6. _brainPrune() execution
  console.log("-> [6/6] Testing _brainPrune()...");
  _brainPrune();
  console.log("   ✓ _brainPrune executed successfully");

  console.log("\nALL BRAIN EXPORT, IMPORT & STORAGE ADAPTER TESTS PASSED! 🧠💾🎉\n");
  process.exit(0);
}

run().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
