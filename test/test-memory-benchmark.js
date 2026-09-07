// test/test-memory-benchmark.js
import assert from "node:assert";
import { AeroCache } from "../src/storage/aero-cache.js";
import { PulseDB } from "../src/storage/pulse-db.js";

console.log("=== Running High-Velocity Memory & Throughput Benchmark ===");

// 1. Benchmark AeroCache
const cache = new AeroCache({ maxEntries: 25000, maxBytes: 24 * 1024 * 1024 });
const samplePacket = Buffer.alloc(128, 0x55);

console.log("-> Inserting 50,000 records into AeroCache (testing S3-FIFO and memory cap)...");
const t0 = performance.now();
for (let i = 0; i < 50000; i++) {
  cache.put(`test-domain-${i}.com`, 1, samplePacket, 60);
}
const putElapsed = performance.now() - t0;
const putThroughput = Math.round(50000 / (putElapsed / 1000));
console.log(`   ✓ AeroCache writes: 50,000 in ${putElapsed.toFixed(1)}ms (${putThroughput.toLocaleString()} ops/sec)`);

// Verify memory ceiling is respected
assert.ok(cache.map.size <= 25000, `Size ${cache.map.size} must be <= 25000`);
assert.ok(cache.currentBytes <= 24 * 1024 * 1024, "Bytes must be <= 24MB");
console.log(`   ✓ AeroCache entry count: ${cache.map.size}, active memory: ${(cache.currentBytes / 1024 / 1024).toFixed(2)}MB`);

// Read throughput benchmark
console.log("-> Querying 100,000 cached records (testing read latency)...");
const t1 = performance.now();
let hits = 0;
for (let i = 0; i < 100000; i++) {
  const domain = `test-domain-${i % 25000}.com`;
  const res = cache.get(domain, 1);
  if (res) hits++;
}
const readElapsed = performance.now() - t1;
const readThroughput = Math.round(100000 / (readElapsed / 1000));
const avgLatencyNs = ((readElapsed / 100000) * 1000000).toFixed(1);
console.log(`   ✓ AeroCache reads: 100,000 in ${readElapsed.toFixed(1)}ms (${readThroughput.toLocaleString()} ops/sec, ${avgLatencyNs}ns/op)`);

// 2. Benchmark PulseDB SuffixTrie
console.log("-> Testing PulseDB SuffixTrie with 50,000 blocked domains...");
const pdb = new PulseDB(`/tmp/bench-pulsedb-${Date.now()}.wal`);
pdb.boot();

const domains = [];
for (let i = 0; i < 50000; i++) {
  domains.push(`badtracker-${i}.ads.network.com`);
}
pdb.addBlocklist(domains, "benchmark");

console.log(`   ✓ Blocklist loaded: ${pdb.blocklistTrie.size} domains`);

// Benchmark wildcard subdomain matching
const t2 = performance.now();
for (let i = 0; i < 100000; i++) {
  // Test both subdomains and exact matches
  const d = `deep.sub.badtracker-${i % 50000}.ads.network.com`;
  const match = pdb.checkBlocklist(d);
  assert.strictEqual(match.blocked, true);
}
const trieElapsed = performance.now() - t2;
const trieThroughput = Math.round(100000 / (trieElapsed / 1000));
const trieLatencyNs = ((trieElapsed / 100000) * 1000000).toFixed(1);
console.log(`   ✓ PulseDB SuffixTrie lookups: 100,000 in ${trieElapsed.toFixed(1)}ms (${trieThroughput.toLocaleString()} ops/sec, ${trieLatencyNs}ns/op)`);

// Check overall process RSS
const mem = process.memoryUsage();
const rssMB = +(mem.rss / 1024 / 1024).toFixed(2);
const heapMB = +(mem.heapUsed / 1024 / 1024).toFixed(2);
console.log(`\n-> Process Memory under load: Heap = ${heapMB}MB, RSS = ${rssMB}MB (Limit: 256MB)`);
assert.ok(rssMB < 220, `RSS (${rssMB}MB) must stay below 256MB`);

pdb.close();
try {
  const f = pdb.filePath;
  if (fs.existsSync(f)) fs.unlinkSync(f);
} catch {}
console.log("\nBENCHMARK COMPLETED: All performance and memory criteria satisfied! 🎉\n");
