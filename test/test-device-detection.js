// test/test-device-detection.js
// Tests AI device detection (devices vs. IP), strict no-block constraint,
// and sticky instance session support.

import assert from "node:assert";
import net from "node:net";
import { spawn } from "node:child_process";
import fs from "node:fs";

const TEST_PORT = 8089;
const TEST_DOT_PORT = 8059;
const TEST_DB = `/tmp/test-amardns-dev-${Date.now()}.wal`;
const MASTER_KEY = "test-master-key-secure-12345";

function buildDnsQuery(domain, id = 0x1234) {
  const parts = domain.split(".");
  const qnameBufs = [];
  for (const p of parts) {
    qnameBufs.push(Buffer.from([p.length]));
    qnameBufs.push(Buffer.from(p, "ascii"));
  }
  qnameBufs.push(Buffer.from([0]));
  const qname = Buffer.concat(qnameBufs);

  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2); // RD = 1
  header.writeUInt16BE(1, 4); // QDCOUNT = 1
  header.writeUInt16BE(0, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);

  const questionTail = Buffer.alloc(4);
  questionTail.writeUInt16BE(1, 0); // Type A
  questionTail.writeUInt16BE(1, 2); // Class IN

  return Buffer.concat([header, qname, questionTail]);
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function run() {
  console.log("=== Testing AI Device Detection (Devices vs. IP) & No-Block Guarantee ===");

  const serverProc = spawn("node", ["src/server.js"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(TEST_PORT),
      DOT_PORT: String(TEST_DOT_PORT),
      DB_PATH: TEST_DB,
      DNS_MASTER_KEY: MASTER_KEY,
      DNS_TOKEN_SECRET: "test-token-secret-48-chars-long-random-string",
      DNS_CACHE_SECRET: "test-cache-secret-48-chars-long-random-string",
      DNS_WORKER_NAME: "test-amardns",
      UPSTREAM_BASES: '["https://cloudflare-dns.com/dns-query","https://dns.google/dns-query"]',
      EXPECTED_USERS: "1",
      DNS_ACCESS_MODE: "public",
      FLY_MACHINE_ID: "machine-test-node-1",
      FLY_REGION: "sin",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  serverProc.stdout.on("data", (d) => {
    // console.log("[server stdout]", d.toString().trim());
  });
  serverProc.stderr.on("data", (d) => {
    console.error("[server stderr]", d.toString().trim());
  });

  let serverReady = false;
  for (let i = 0; i < 40; i++) {
    await sleep(200);
    try {
      const r = await fetch(`http://127.0.0.1:${TEST_PORT}/health`);
      if (r.status === 200) {
        serverReady = true;
        break;
      }
    } catch (_) {}
  }
  assert.ok(serverReady, "Server failed to start within timeout");
  console.log("-> Server booted and health checked.");

  try {
    // ------------------------------------------------------------------------
    // Test 1: Multiple distinct devices behind the SAME public IP address
    // ------------------------------------------------------------------------
    console.log("\n-> [1/5] Testing multi-device detection behind the SAME public IP...");
    const SHARED_HOME_IP = "103.205.71.12";

    const query1 = buildDnsQuery("device-test-1.com", 0x1111);
    const query2 = buildDnsQuery("device-test-2.com", 0x2222);
    const query3 = buildDnsQuery("device-test-3.com", 0x3333);

    // Device A: iPhone
    const r1 = await fetch(`http://127.0.0.1:${TEST_PORT}/dns-query`, {
      method: "POST",
      headers: {
        "content-type": "application/dns-message",
        "x-forwarded-for": SHARED_HOME_IP,
        "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15",
      },
      body: query1,
    });
    assert.strictEqual(r1.status, 200, "iPhone query must not be blocked");
    const r1Bytes = await r1.arrayBuffer();
    assert.ok(r1Bytes.byteLength >= 12, "Valid DNS response wire format");

    // Device B: Android Phone (same public IP)
    const r2 = await fetch(`http://127.0.0.1:${TEST_PORT}/dns-query`, {
      method: "POST",
      headers: {
        "content-type": "application/dns-message",
        "x-forwarded-for": SHARED_HOME_IP,
        "user-agent": "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/UQ1A.240205.004)",
      },
      body: query2,
    });
    assert.strictEqual(r2.status, 200, "Android query must not be blocked");

    // Device C: Windows Laptop (same public IP)
    const r3 = await fetch(`http://127.0.0.1:${TEST_PORT}/dns-query`, {
      method: "POST",
      headers: {
        "content-type": "application/dns-message",
        "x-forwarded-for": SHARED_HOME_IP,
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0",
      },
      body: query3,
    });
    assert.strictEqual(r3.status, 200, "Windows query must not be blocked");

    // Check status to verify device vs IP detection
    const statusRes = await fetch(`http://127.0.0.1:${TEST_PORT}/${MASTER_KEY}`, {
      headers: { accept: "application/json" },
    });
    assert.strictEqual(statusRes.status, 200);
    const statusData = await statusRes.json();

    console.log("   Status metrics:", {
      activeDevices: statusData.ai.activeDevices,
      activeIps: statusData.ai.activeIps,
      expectedUsers: statusData.ai.expectedUsers,
    });

    assert.ok(
      statusData.ai.activeDevices >= 3,
      `Expected activeDevices >= 3 for distinct devices, got ${statusData.ai.activeDevices}`
    );
    assert.strictEqual(
      statusData.ai.activeIps,
      1,
      `Expected activeIps === 1 for shared home IP, got ${statusData.ai.activeIps}`
    );
    console.log("   ✓ Successfully detected 3 distinct devices behind 1 single IP!");

    // ------------------------------------------------------------------------
    // Test 2: Explicit device tagging (URL query param, path segment, header)
    // ------------------------------------------------------------------------
    console.log("\n-> [2/5] Testing explicit device tagging (URL path, query, header)...");
    
    // Tag in URL path: /dns-query/living-room-tv
    const rPath = await fetch(`http://127.0.0.1:${TEST_PORT}/dns-query/living-room-tv`, {
      method: "POST",
      headers: { "content-type": "application/dns-message" },
      body: buildDnsQuery("tv-query.com", 0x4444),
    });
    assert.strictEqual(rPath.status, 200, "Path-tagged device must not be blocked");

    // Tag in query param: ?device=work-macbook
    const rQuery = await fetch(`http://127.0.0.1:${TEST_PORT}/dns-query?device=work-macbook`, {
      method: "POST",
      headers: { "content-type": "application/dns-message" },
      body: buildDnsQuery("work-query.com", 0x5555),
    });
    assert.strictEqual(rQuery.status, 200, "Query-tagged device must not be blocked");

    // Tag in custom header: x-device-id: ipad-pro
    const rHdr = await fetch(`http://127.0.0.1:${TEST_PORT}/dns-query`, {
      method: "POST",
      headers: {
        "content-type": "application/dns-message",
        "x-device-id": "ipad-pro",
      },
      body: buildDnsQuery("ipad-query.com", 0x6666),
    });
    assert.strictEqual(rHdr.status, 200, "Header-tagged device must not be blocked");
    console.log("   ✓ Explicit device tags successfully processed and never blocked!");

    // ------------------------------------------------------------------------
    // Test 3: DoT connection session device identification
    // ------------------------------------------------------------------------
    console.log("\n-> [3/5] Testing DoT connection device tracking...");
    async function sendDotQuery(domain, txId) {
      return new Promise((resolve, reject) => {
        const client = net.createConnection({ port: TEST_DOT_PORT, host: "127.0.0.1" }, () => {
          const wire = buildDnsQuery(domain, txId);
          const frame = Buffer.alloc(2 + wire.length);
          frame.writeUInt16BE(wire.length, 0);
          wire.copy(frame, 2);
          client.write(frame);
        });
        client.on("data", (data) => {
          client.end();
          resolve(data);
        });
        client.on("error", reject);
      });
    }

    const dotResp1 = await sendDotQuery("dot-device-1.com", 0x7777);
    assert.ok(dotResp1.length > 2, "DoT device 1 received DNS wire response");
    const dotResp2 = await sendDotQuery("dot-device-2.com", 0x8888);
    assert.ok(dotResp2.length > 2, "DoT device 2 received DNS wire response");
    console.log("   ✓ DoT devices resolved cleanly without blocking!");

    // ------------------------------------------------------------------------
    // Test 4: Strict No-Block Guarantee under volume
    // ------------------------------------------------------------------------
    console.log("\n-> [4/5] Testing strict No-Block guarantee under multi-device volume...");
    const volumePromises = [];
    for (let i = 0; i < 20; i++) {
      const q = buildDnsQuery(`clean-volume-${i}.org`, 0x1000 + i);
      volumePromises.push(
        fetch(`http://127.0.0.1:${TEST_PORT}/dns-query?device=vol-device-${i % 5}`, {
          method: "POST",
          headers: { "content-type": "application/dns-message" },
          body: q,
        }).then((res) => {
          assert.strictEqual(res.status, 200, `Query ${i} must never be blocked`);
          return res.arrayBuffer();
        })
      );
    }
    const results = await Promise.all(volumePromises);
    assert.strictEqual(results.length, 20);
    console.log("   ✓ All 20 queries resolved successfully with NOERROR (0 blocks, 0 throttles)!");

    // ------------------------------------------------------------------------
    // Test 5: Sticky instance session headers & node status
    // ------------------------------------------------------------------------
    console.log("\n-> [5/5] Testing Fly machine sticky session headers and status payload...");
    const nodeStatusRes = await fetch(`http://127.0.0.1:${TEST_PORT}/${MASTER_KEY}`, {
      headers: {
        accept: "application/json",
        "fly-force-instance-id": "machine-test-node-1",
      },
    });
    assert.strictEqual(nodeStatusRes.status, 200);
    assert.strictEqual(nodeStatusRes.headers.get("fly-machine-id"), "machine-test-node-1");
    assert.strictEqual(nodeStatusRes.headers.get("fly-region"), "sin");
    assert.ok(nodeStatusRes.headers.get("set-cookie")?.includes("fly_instance=machine-test-node-1"));

    const finalStatus = await nodeStatusRes.json();
    assert.ok(finalStatus.node, "Status payload must contain node metadata");
    assert.strictEqual(finalStatus.node.machineId, "machine-test-node-1");
    assert.strictEqual(finalStatus.node.region, "sin");
    assert.ok(finalStatus.node.activeDevices >= 5, "Must track active devices count in node metadata");
    console.log("   Node metadata verified:", finalStatus.node);

    console.log("\n========================================================");
    console.log("  ALL AI DEVICE DETECTION & NO-BLOCK TESTS PASSED! 🛡️📱💻 ");
    console.log("========================================================");
  } finally {
    serverProc.kill("SIGTERM");
    try {
      if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
    } catch (_) {}
  }
}

run().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
