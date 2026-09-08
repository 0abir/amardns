// test/test-suspicious-clients.js
// Verifies query fingerprinting, rogue user detection, and suspicious client display

import assert from "node:assert";
import { _fpMap, _sh } from "../src/core/state.js";
import { fpCheck, clientNxCheck, _clientNX } from "../src/core/threat-intelligence.js";
import { buildStatus } from "../src/core/admin-api.js";
import { ADMIN_HTML } from "../src/core/dashboard-html.js";

async function main() {
  console.log("=== Testing Query Fingerprinting & Rogue Client Detection ===");

  // Reset state
  _fpMap.clear();
  _clientNX.clear();
  _sh.fpEvents = 0;
  _sh.cnxfAlarms = 0;

  console.log("-> [1/6] Testing normal user browsing behavior (immunity)...");
  const normalClient = "192.168.1.50";
  for (let i = 0; i < 15; i++) {
    fpCheck(normalClient, `service-${i}.google.com`, 1.2);
  }
  const normalStatus = buildStatus({});
  const normalFps = normalStatus.ai.fpSuspicious || [];
  assert.strictEqual(normalFps.length, 0, "Legitimate users must NOT be flagged as suspicious");
  console.log("   ✓ Legitimate browsing traffic verified clean (0 false positives)");

  console.log("-> [2/6] Testing DNS scanner detection (DNS_SCAN)...");
  const scannerClient = "10.0.0.99";
  for (let i = 0; i < 35; i++) {
    fpCheck(scannerClient, `probe-target-${i}.xyz`, 5);
  }
  const scanStatus = buildStatus({});
  const scanFps = scanStatus.ai.fpSuspicious || [];
  assert.ok(scanFps.length > 0, "Scanner must be flagged in fpSuspicious");
  const scanMatch = scanFps.find((f) => f.ip === scannerClient);
  assert.ok(scanMatch, "Scanner IP must be present in fpSuspicious");
  assert.strictEqual(scanMatch.type, "DNS_SCAN", `Expected DNS_SCAN, got ${scanMatch.type}`);
  console.log(`   ✓ Scanner correctly caught and flagged: ${scanMatch.ip} -> ${scanMatch.type} (${scanMatch.queries} queries)`);

  console.log("-> [3/6] Testing high-volume query stress flooder (QUERY_STRESS)...");
  const flooderClient = "10.0.0.88";
  for (let i = 0; i < 110; i++) {
    fpCheck(flooderClient, "flooded-endpoint.com", 25);
  }
  const floodStatus = buildStatus({});
  const floodFps = floodStatus.ai.fpSuspicious || [];
  const floodMatch = floodFps.find((f) => f.ip === flooderClient);
  assert.ok(floodMatch, "Flooder IP must be present in fpSuspicious");
  assert.strictEqual(floodMatch.type, "QUERY_STRESS", `Expected QUERY_STRESS, got ${floodMatch.type}`);
  console.log(`   ✓ High-volume flooder caught: ${floodMatch.ip} -> ${floodMatch.type} (${floodMatch.queries} queries)`);

  console.log("-> [4/6] Testing DNS tunneling / data exfiltration (DNS_TUNNEL_SUSPECT)...");
  const tunnelClient = "10.0.0.77";
  const highEntropyDomain = "a9f8b2c4d1e0a7f6e5d4c3b2a1z8y7x6w5v4u3t2s1.tunnel.exfil.org";
  fpCheck(tunnelClient, highEntropyDomain, 6);
  const tunnelStatus = buildStatus({});
  const tunnelFps = tunnelStatus.ai.fpSuspicious || [];
  const tunnelMatch = tunnelFps.find((f) => f.ip === tunnelClient);
  assert.ok(tunnelMatch, "Tunneling IP must be present in fpSuspicious");
  assert.strictEqual(tunnelMatch.type, "DNS_TUNNEL_SUSPECT", `Expected DNS_TUNNEL_SUSPECT, got ${tunnelMatch.type}`);
  console.log(`   ✓ DNS tunnel exfiltration caught: ${tunnelMatch.ip} -> ${tunnelMatch.type}`);

  console.log("-> [5/6] Testing NXDOMAIN brute-force dictionary scanner (NX_SCANNER)...");
  const nxClient = "10.0.0.66";
  // Simulate 15 queries where 12 return NXDOMAIN (rcode 3)
  for (let i = 0; i < 15; i++) {
    fpCheck(nxClient, `nonexistent-${i}.test`, 2);
    if (i < 12) {
      clientNxCheck(nxClient, 3);
    }
  }
  const nxStatus = buildStatus({});
  const nxFps = nxStatus.ai.fpSuspicious || [];
  const nxMatch = nxFps.find((f) => f.ip === nxClient);
  assert.ok(nxMatch, "NX brute-force scanner must be present in fpSuspicious");
  assert.strictEqual(nxMatch.type, "NX_SCANNER", `Expected NX_SCANNER, got ${nxMatch.type}`);
  console.log(`   ✓ NX dictionary scanner caught: ${nxMatch.ip} -> ${nxMatch.type}`);

  console.log("-> [6/6] Verifying dashboard HTML rendering of dp-fp panel...");
  assert.ok(ADMIN_HTML.includes("Query Fingerprinting — Suspicious Clients"), "Must include Query Fingerprinting header");
  assert.ok(ADMIN_HTML.includes("id=\"dp-fp\""), "Must include dp-fp container");
  assert.ok(ADMIN_HTML.includes("fpSuspicious"), "Must wire ai.fpSuspicious to dp-fp");
  assert.ok(ADMIN_HTML.includes("No suspicious clients"), "Must include clean state text");
  console.log("   ✓ Dashboard UI dp-fp panel verified and properly bound to live telemetry");

  console.log("\nALL QUERY FINGERPRINTING & ROGUE CLIENT DETECTION TESTS PASSED! 🕵️🛡️🎉\n");
}

main().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
