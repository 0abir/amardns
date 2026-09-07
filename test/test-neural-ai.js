// test/test-neural-ai.js
// Tests the 20-model Neural AI stack, RL dynamic cache TTL, brand spoofing guard, and perpetual learning engine.

process.env.DNS_MASTER_KEY = "testkey_ai_99";
process.env.DNS_ACCESS_MODE = "public";
process.env.UPSTREAM_BASES = JSON.stringify([
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/dns-query"
]);

import assert from "node:assert";
import core from "../src/core.js";
import { buildEnv } from "../src/env-shim.js";

function makeDnsQueryPacket(name, qtype = 1) {
  const parts = name.split(".").filter(Boolean);
  const bufs = [];
  for (const p of parts) {
    bufs.push(p.length);
    for (let i = 0; i < p.length; i++) bufs.push(p.charCodeAt(i));
  }
  bufs.push(0);
  const q = new Uint8Array(12 + bufs.length + 4);
  q[0] = 0x55;
  q[1] = 0xaa;
  q[2] = 0x01; // RD = 1
  q[5] = 0x01; // QDCOUNT = 1
  q.set(bufs, 12);
  const tailIdx = 12 + bufs.length;
  q[tailIdx] = (qtype >> 8) & 0xff;
  q[tailIdx + 1] = qtype & 0xff;
  q[tailIdx + 2] = 0x00;
  q[tailIdx + 3] = 0x01; // IN class
  return q.buffer;
}

async function run() {
  console.log("=== Testing Neural AI & Threat Intelligence Engine ===");
  const env = buildEnv();
  const ctx = {
    waitUntil: (p) => Promise.resolve(p).catch(() => {})
  };

  // 1. Test DGA test endpoint
  console.log("-> [1/5] Testing /api/dga-test endpoint...");
  const dgaReq = new Request("http://localhost/api/dga-test/testkey_ai_99", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain: "paypa1.com" })
  });
  const dgaRes = await core.fetch(dgaReq, env, ctx);
  assert.strictEqual(dgaRes.status, 200, "dga-test should return 200");
  const dgaData = await dgaRes.json();
  console.log("   ✓ Alike & DGA detection:", dgaData);
  assert.ok(dgaData.alike, "Should detect alike spoofing brand");

  // 2. Test brand impersonation blocking in resolution
  console.log("-> [2/5] Testing real-time Brand Impersonation NXDOMAIN block...");
  const spoofQuery = makeDnsQueryPacket("paypa1.com");
  const spoofReq = new Request("http://localhost/dns-query", {
    method: "POST",
    headers: { "content-type": "application/dns-message" },
    body: spoofQuery
  });
  const spoofRes = await core.fetch(spoofReq, env, ctx);
  const spoofBuf = new Uint8Array(await spoofRes.arrayBuffer());
  const rcode = spoofBuf[3] & 0x0f;
  assert.strictEqual(rcode, 3, "Brand spoof domain must be blocked with NXDOMAIN (RCODE 3)");
  console.log("   ✓ paypa1.com blocked with NXDOMAIN");

  // 3. Test clean resolution with Attention-based upstream selection & Online Learning
  console.log("-> [3/5] Testing clean query with Attention Upstream selection & Learning...");
  const cleanQuery = makeDnsQueryPacket("example.com");
  const cleanReq = new Request("http://localhost/dns-query", {
    method: "POST",
    headers: { "content-type": "application/dns-message" },
    body: cleanQuery
  });
  const cleanRes = await core.fetch(cleanReq, env, ctx);
  assert.strictEqual(cleanRes.status, 200, "Clean query should return 200");
  const cleanBuf = new Uint8Array(await cleanRes.arrayBuffer());
  assert.strictEqual(cleanBuf[3] & 0x0f, 0, "Clean query should return NOERROR (RCODE 0)");
  console.log("   ✓ example.com resolved successfully");

  // 4. Test cache hit with RL reward feedback
  console.log("-> [4/5] Testing cache hit with RL reward signals...");
  const hitReq = new Request("http://localhost/dns-query", {
    method: "POST",
    headers: { "content-type": "application/dns-message" },
    body: cleanQuery
  });
  const hitRes = await core.fetch(hitReq, env, ctx);
  assert.strictEqual(hitRes.headers.get("x-cache"), "HIT", "Second request should be a cache HIT");
  console.log("   ✓ Cache hit verified with RL reward loop");

  // Allow background learning tick to settle
  await new Promise(r => setTimeout(r, 150));

  // 5. Check Perpetual AI status telemetry
  console.log("-> [5/5] Checking Perpetual AI telemetry from /api/status...");
  const statusReq = new Request("http://localhost/api/status/testkey_ai_99");
  const statusRes = await core.fetch(statusReq, env, ctx);
  assert.strictEqual(statusRes.status, 200, "Status endpoint should return 200");
  const status = await statusRes.json();
  
  assert.ok(status.perpetualAI, "perpetualAI object should be present");
  assert.ok(status.perpetualAI.nn.mhaSelections > 0, "MHA upstream selections must be > 0");
  assert.ok(status.perpetualAI.nn.dtnInferences > 0, "DTN inferences must be > 0");
  assert.ok(status.perpetualAI.nn.rlDecisions > 0, "RL cache decisions must be > 0");

  console.log("   ✓ Neural AI stats active:", {
    mhaSelections: status.perpetualAI.nn.mhaSelections,
    dtnInferences: status.perpetualAI.nn.dtnInferences,
    dtnCalls: status.perpetualAI.nn.dtnCalls,
    rlDecisions: status.perpetualAI.nn.rlDecisions,
    learningCycles: status.ai.learningCycles,
    domainIQSize: status.perpetualAI.domainIQ.size
  });

  console.log("\nALL NEURAL AI & THREAT ENGINE TESTS PASSED! 🧠🎉\n");
  process.exit(0);
}

run().catch(err => {
  console.error("Test failed:", err);
  process.exit(1);
});
