// test/test-access-mode.js
import assert from "node:assert";
import net from "node:net";
import { spawn } from "node:child_process";
import fs from "node:fs";

const TEST_PORT = 8085;
const TEST_DOT_PORT = 8055;
const TEST_DB = `/tmp/test-access-mode-${Date.now()}.wal`;
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

async function queryDot(port, queryWire) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ port, host: "127.0.0.1" }, () => {
      const frame = Buffer.alloc(2 + queryWire.length);
      frame.writeUInt16BE(queryWire.length, 0);
      queryWire.copy(frame, 2);
      sock.write(frame);
    });

    let rx = Buffer.alloc(0);
    sock.on("data", (chunk) => {
      rx = Buffer.concat([rx, chunk]);
      if (rx.length >= 2) {
        const expectedLen = rx.readUInt16BE(0);
        if (rx.length >= 2 + expectedLen) {
          sock.end();
          resolve(rx.subarray(2, 2 + expectedLen));
        }
      }
    });

    sock.on("error", reject);
    setTimeout(() => {
      sock.destroy();
      reject(new Error("DoT timeout"));
    }, 4000);
  });
}

async function run() {
  console.log("=== Testing Public vs Private DNS Access Mode ===");

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
      DNS_WORKER_NAME: "test-access-mode",
      DNS_ACCESS_MODE: "private", // start in private mode
      UPSTREAM_BASES: '["https://cloudflare-dns.com/dns-query","https://dns.google/dns-query"]',
      EXPECTED_USERS: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  serverProc.stderr.on("data", (d) => process.stderr.write(d));
  serverProc.stdout.on("data", (d) => process.stdout.write(d));

  let started = false;
  for (let i = 0; i < 30; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${TEST_PORT}/health`);
      if (r.ok) {
        started = true;
        break;
      }
    } catch (_) {}
    await sleep(200);
  }
  assert.ok(started, "Server failed to start in time");
  console.log("-> Server booted in PRIVATE mode.");

  try {
    // 1. In Private Mode: Unauthenticated DoH should be 401
    console.log("-> [1/6] Testing unauthenticated DoH query in PRIVATE mode...");
    const dohUnauth = await fetch(`http://127.0.0.1:${TEST_PORT}/resolve?name=cloudflare.com&type=A`);
    assert.strictEqual(dohUnauth.status, 401, `Expected 401 Unauthorized, got ${dohUnauth.status}`);
    console.log("   ✓ Correctly rejected unauthenticated DoH with 401");

    // 2. In Private Mode: Unauthenticated DoT should return SERVFAIL (RCODE=2)
    console.log("-> [2/6] Testing unauthenticated DoT query in PRIVATE mode...");
    const dotResp1 = await queryDot(TEST_DOT_PORT, buildDnsQuery("cloudflare.com", 0x4321));
    const rcode1 = dotResp1.readUInt16BE(2) & 0x000f;
    assert.strictEqual(rcode1, 2, `Expected SERVFAIL (RCODE 2), got ${rcode1}`);
    console.log("   ✓ Correctly rejected unauthenticated DoT with SERVFAIL");

    // 3. Switch to Public Mode via Admin API
    console.log("-> [3/6] Toggling mode to PUBLIC via /api/settings/dns-mode...");
    const toggleRes = await fetch(`http://127.0.0.1:${TEST_PORT}/api/settings/dns-mode/${MASTER_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: "public" }),
    });
    assert.strictEqual(toggleRes.status, 200);
    const toggleData = await toggleRes.json();
    assert.strictEqual(toggleData.mode, "public");
    console.log("   ✓ API successfully returned mode: public");

    // Check status endpoint reflects public mode
    const statusRes = await fetch(`http://127.0.0.1:${TEST_PORT}/api/status/${MASTER_KEY}`);
    const statusData = await statusRes.json();
    assert.strictEqual(statusData.config.dnsMode, "public");
    console.log("   ✓ Status config.dnsMode is now 'public'");

    // 4. In Public Mode: Unauthenticated DoH should succeed (200 OK)
    console.log("-> [4/6] Testing unauthenticated DoH query in PUBLIC mode...");
    const dohPub = await fetch(`http://127.0.0.1:${TEST_PORT}/resolve?name=cloudflare.com&type=A`);
    assert.strictEqual(dohPub.status, 200, `Expected 200 OK in public mode, got ${dohPub.status}`);
    assert.strictEqual(dohPub.headers.get("content-type"), "application/dns-message");
    const dohPubBody = await dohPub.arrayBuffer();
    assert.ok(dohPubBody.byteLength > 12, "Expected valid DNS response bytes");
    console.log("   ✓ Correctly resolved DoH query without authentication in PUBLIC mode");

    // 5. In Public Mode: DoT query should succeed (RCODE=0, NOERROR)
    console.log("-> [5/6] Testing unauthenticated DoT query in PUBLIC mode (Android Private DNS)...");
    const dotResp2 = await queryDot(TEST_DOT_PORT, buildDnsQuery("cloudflare.com", 0x7777));
    const rcode2 = dotResp2.readUInt16BE(2) & 0x000f;
    assert.strictEqual(rcode2, 0, `Expected NOERROR (RCODE 0), got ${rcode2}`);
    const txId2 = dotResp2.readUInt16BE(0);
    assert.strictEqual(txId2, 0x7777, "Transaction ID must match query ID");
    console.log("   ✓ Correctly resolved DoT query without authentication in PUBLIC mode (NOERROR)");

    // 6. Switch back to Private Mode
    console.log("-> [6/6] Toggling mode back to PRIVATE...");
    const toggleBack = await fetch(`http://127.0.0.1:${TEST_PORT}/api/settings/dns-mode/${MASTER_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: "private" }),
    });
    assert.strictEqual(toggleBack.status, 200);
    const toggleBackData = await toggleBack.json();
    assert.strictEqual(toggleBackData.mode, "private");

    const dohPrivateAgain = await fetch(`http://127.0.0.1:${TEST_PORT}/resolve?name=cloudflare.com&type=A`);
    assert.strictEqual(dohPrivateAgain.status, 401, "Expected 401 Unauthorized after switching back to private");
    console.log("   ✓ Enforcement restored: unauthenticated query rejected with 401");

    console.log("\nALL PUBLIC/PRIVATE ACCESS MODE TESTS PASSED SUCCESSFULLY! 🎉\n");
  } finally {
    serverProc.kill("SIGINT");
    try {
      if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
      if (fs.existsSync(`${TEST_DB}-wal`)) fs.unlinkSync(`${TEST_DB}-wal`);
      if (fs.existsSync(`${TEST_DB}-shm`)) fs.unlinkSync(`${TEST_DB}-shm`);
    } catch (_) {}
  }
}

run().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
