// test/test-dot-doh.js
import assert from "node:assert";
import net from "node:net";
import { spawn } from "node:child_process";
import fs from "node:fs";

const TEST_PORT = 8081;
const TEST_DOT_PORT = 8054;
const TEST_DB = `/tmp/test-amardns-${Date.now()}.wal`;
const MASTER_KEY = "test-master-key-secure-12345";

function buildDnsQuery(domain, id = 0x1234) {
  const parts = domain.split(".");
  const qnameBufs = [];
  for (const p of parts) {
    qnameBufs.push(Buffer.from([p.length]));
    qnameBufs.push(Buffer.from(p, "ascii"));
  }
  qnameBufs.push(Buffer.from([0])); // null terminator
  const qname = Buffer.concat(qnameBufs);

  // 12-byte header
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0); // ID
  header.writeUInt16BE(0x0100, 2); // RD = 1 (recursion desired)
  header.writeUInt16BE(1, 4); // QDCOUNT = 1
  header.writeUInt16BE(0, 6); // ANCOUNT = 0
  header.writeUInt16BE(0, 8); // NSCOUNT = 0
  header.writeUInt16BE(0, 10); // ARCOUNT = 0

  // Question: QNAME + QTYPE(1=A) + QCLASS(1=IN)
  const questionTail = Buffer.alloc(4);
  questionTail.writeUInt16BE(1, 0); // Type A
  questionTail.writeUInt16BE(1, 2); // Class IN

  return Buffer.concat([header, qname, questionTail]);
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function run() {
  console.log("=== Starting End-to-End Tests for DoH and DoT ===");

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
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  serverProc.stdout.on("data", (d) => console.log(`[server stdout] ${d.toString().trim()}`));
  serverProc.stderr.on("data", (d) => console.error(`[server stderr] ${d.toString().trim()}`));

  // Wait for server to start listening
  console.log("Waiting for server to initialize...");
  for (let i = 0; i < 30; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${TEST_PORT}/health`);
      if (res.status === 200) {
        console.log("Server HTTP is up!");
        break;
      }
    } catch {
      await sleep(200);
    }
  }

  try {
    // 1. Test Health Check
    console.log("1. Testing GET /health...");
    const healthRes = await fetch(`http://127.0.0.1:${TEST_PORT}/health`);
    assert.strictEqual(healthRes.status, 200);
    const healthText = await healthRes.text();
    assert.strictEqual(healthText, "ok");
    console.log("✓ /health passed!");

    // 2. Test DoH query (via POST /dns-query/<master_key>)
    console.log("2. Testing DoH via HTTP POST /dns-query/<master_key>...");
    const dnsQueryBuf = buildDnsQuery("example.com", 0x4321);
    const dohRes = await fetch(`http://127.0.0.1:${TEST_PORT}/dns-query/${MASTER_KEY}`, {
      method: "POST",
      headers: {
        "content-type": "application/dns-message",
      },
      body: dnsQueryBuf,
    });
    assert.strictEqual(dohRes.status, 200, `DoH returned status ${dohRes.status}`);
    const dohAnswer = Buffer.from(await dohRes.arrayBuffer());
    assert.ok(dohAnswer.length >= 12, "DoH answer too short");
    const dohId = dohAnswer.readUInt16BE(0);
    assert.strictEqual(dohId, 0x4321, "DoH transaction ID mismatch");
    const dohFlags = dohAnswer.readUInt16BE(2);
    assert.ok((dohFlags & 0x8000) !== 0, "DoH response bit not set");
    console.log(`✓ DoH query passed (received ${dohAnswer.length} bytes)!`);

    // 3. Test DoT (TCP stream)
    console.log(`3. Testing DoT via TCP 127.0.0.1:${TEST_DOT_PORT}...`);
    await new Promise((resolve, reject) => {
      const socket = net.connect({ host: "127.0.0.1", port: TEST_DOT_PORT }, () => {
        const query = buildDnsQuery("example.com", 0x5678);
        const lenPrefix = Buffer.alloc(2);
        lenPrefix.writeUInt16BE(query.length, 0);

        // Send 2-byte length + wire query
        socket.write(Buffer.concat([lenPrefix, query]));
      });

      let buf = Buffer.alloc(0);
      socket.on("data", (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.length >= 2) {
          const respLen = buf.readUInt16BE(0);
          if (buf.length >= 2 + respLen) {
            const resp = buf.subarray(2, 2 + respLen);
            console.log("DoT raw resp bytes:", resp.length, "hex:", resp.toString("hex"), "text:", resp.toString("utf8"));
            assert.ok(resp.length >= 12, "DoT answer too short");
            const id = resp.readUInt16BE(0);
            assert.strictEqual(id, 0x5678, "DoT transaction ID mismatch");
            const flags = resp.readUInt16BE(2);
            assert.ok((flags & 0x8000) !== 0, "DoT response QR bit not set");
            console.log(`✓ DoT TCP query passed (received ${resp.length} bytes, flags=0x${flags.toString(16)})!`);
            socket.end();
            resolve();
          }
        }
      });

      socket.on("error", reject);
    });

    // 4. Test DoT with PROXY protocol v1
    console.log("4. Testing DoT with PROXY protocol v1 header...");
    await new Promise((resolve, reject) => {
      const socket = net.connect({ host: "127.0.0.1", port: TEST_DOT_PORT }, () => {
        const proxyHeader = Buffer.from("PROXY TCP4 203.0.113.195 127.0.0.1 54321 8054\r\n", "ascii");
        const query = buildDnsQuery("example.com", 0x789a);
        const lenPrefix = Buffer.alloc(2);
        lenPrefix.writeUInt16BE(query.length, 0);

        socket.write(Buffer.concat([proxyHeader, lenPrefix, query]));
      });

      let buf = Buffer.alloc(0);
      socket.on("data", (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.length >= 2) {
          const respLen = buf.readUInt16BE(0);
          if (buf.length >= 2 + respLen) {
            const resp = buf.subarray(2, 2 + respLen);
            const id = resp.readUInt16BE(0);
            assert.strictEqual(id, 0x789a, "PROXY v1 DoT transaction ID mismatch");
            console.log(`✓ DoT with PROXY v1 header passed!`);
            socket.end();
            resolve();
          }
        }
      });

      socket.on("error", reject);
    });

    // 5. Test Pipelined DoT queries on a single persistent TCP connection (Android behavior)
    console.log("5. Testing persistent TCP connection with multiple pipelined DoT queries...");
    await new Promise((resolve, reject) => {
      const socket = net.connect({ host: "127.0.0.1", port: TEST_DOT_PORT }, () => {
        const q1 = buildDnsQuery("google.com", 0x1111);
        const l1 = Buffer.alloc(2);
        l1.writeUInt16BE(q1.length, 0);

        const q2 = buildDnsQuery("cloudflare.com", 0x2222);
        const l2 = Buffer.alloc(2);
        l2.writeUInt16BE(q2.length, 0);

        // Send two queries over the same socket
        socket.write(Buffer.concat([l1, q1, l2, q2]));
      });

      let buf = Buffer.alloc(0);
      const receivedIds = new Set();

      socket.on("data", (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        while (buf.length >= 2) {
          const respLen = buf.readUInt16BE(0);
          if (buf.length < 2 + respLen) break;
          const resp = buf.subarray(2, 2 + respLen);
          buf = buf.subarray(2 + respLen);

          const id = resp.readUInt16BE(0);
          receivedIds.add(id);

          if (receivedIds.has(0x1111) && receivedIds.has(0x2222)) {
            console.log("✓ Persistent DoT pipelining passed (received both 0x1111 and 0x2222)!");
            socket.end();
            resolve();
            break;
          }
        }
      });

      socket.on("error", reject);
    });

    // 6. Test Admin Dashboard at /<master_key>
    console.log("6. Testing admin dashboard at /<master_key>...");
    const dashRes = await fetch(`http://127.0.0.1:${TEST_PORT}/${MASTER_KEY}`);
    assert.strictEqual(dashRes.status, 200, `Dashboard returned status ${dashRes.status}`);
    const dashHtml = await dashRes.text();
    assert.ok(dashHtml.includes("Amar DNS"), "Dashboard HTML did not include Amar DNS");
    console.log("✓ Admin dashboard loaded successfully!");

    // 7. Test Manual Blocklist: Add domain via API and verify NXDOMAIN on both DoH and DoT
    console.log("7. Testing manual blocklist addition and enforcement...");
    const addBlRes = await fetch(`http://127.0.0.1:${TEST_PORT}/api/blocklist/${MASTER_KEY}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        domain: "ads.blocked-tracker.com",
        reason: "manual test block",
      }),
    });
    assert.strictEqual(addBlRes.status, 200);
    const addBlJson = await addBlRes.json();
    assert.strictEqual(addBlJson.ok, true);
    assert.strictEqual(addBlJson.added, 1);
    console.log("✓ Added 'ads.blocked-tracker.com' to manual blocklist!");

    // Verify blocked via DoH
    const blockedDohQuery = buildDnsQuery("ads.blocked-tracker.com", 0x9999);
    const blockedDohRes = await fetch(`http://127.0.0.1:${TEST_PORT}/dns-query/${MASTER_KEY}`, {
      method: "POST",
      headers: { "content-type": "application/dns-message" },
      body: blockedDohQuery,
    });
    const blockedDohAns = Buffer.from(await blockedDohRes.arrayBuffer());
    const blockedDohFlags = blockedDohAns.readUInt16BE(2);
    const dohRcode = blockedDohFlags & 0x000f;
    assert.strictEqual(dohRcode, 3, `Expected NXDOMAIN (3), got ${dohRcode}`);
    console.log("✓ Blocklist enforced on DoH (returned NXDOMAIN)!");

    // Verify blocked on subdomain via DoT
    await new Promise((resolve, reject) => {
      const socket = net.connect({ host: "127.0.0.1", port: TEST_DOT_PORT }, () => {
        const query = buildDnsQuery("sub.ads.blocked-tracker.com", 0x8888);
        const lenPrefix = Buffer.alloc(2);
        lenPrefix.writeUInt16BE(query.length, 0);
        socket.write(Buffer.concat([lenPrefix, query]));
      });

      let buf = Buffer.alloc(0);
      socket.on("data", (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.length >= 2) {
          const respLen = buf.readUInt16BE(0);
          if (buf.length >= 2 + respLen) {
            const resp = buf.subarray(2, 2 + respLen);
            const id = resp.readUInt16BE(0);
            assert.strictEqual(id, 0x8888);
            const flags = resp.readUInt16BE(2);
            const dotRcode = flags & 0x000f;
            assert.strictEqual(dotRcode, 3, `Expected NXDOMAIN (3), got ${dotRcode}`);
            console.log("✓ Blocklist enforced on DoT subdomain (returned NXDOMAIN)!");
            socket.end();
            resolve();
          }
        }
      });
      socket.on("error", reject);
    });

    console.log("\n========================================================");
    console.log("  ALL TESTS PASSED: DoH, DoT & MANUAL BLOCKLIST WORK!  ");
    console.log("========================================================");
  } finally {
    serverProc.kill("SIGTERM");
    try {
      fs.unlinkSync(TEST_DB);
      fs.unlinkSync(`${TEST_DB}-wal`);
      fs.unlinkSync(`${TEST_DB}-shm`);
    } catch {}
  }
}

run().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
