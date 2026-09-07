// src/upstream-manager.js
// Automated Upstream DNS Fetcher & Latency/Aura Ranker for AmarDNS.
// Source feed: https://cdn.jsdelivr.net/gh/abir614/-@latest/dns-upstream.json
// Prioritizes "aura" (high > medium > low), ranked by aura + low latency.

import logger from "./logger.js";

export const DEFAULT_UPSTREAM_FEED =
  "https://cdn.jsdelivr.net/gh/abir614/-@latest/dns-upstream.json";

const AURA_PRIORITY = {
  high: 1,
  medium: 2,
  low: 3,
};

const SYNC_INTERVAL_MS = 24 * 60 * 60 * 1000;

/**
 * Creates a minimal valid DNS query packet (12-byte header + question section)
 * for probing DoH endpoints. Default question is A record for "example.com".
 */
export function makeDnsProbePacket(name = "example.com") {
  const parts = name.split(".").filter(Boolean);
  const bufs = [];
  for (const p of parts) {
    bufs.push(p.length);
    for (let i = 0; i < p.length; i++) bufs.push(p.charCodeAt(i));
  }
  bufs.push(0);
  const q = new Uint8Array(12 + bufs.length + 4);
  q[0] = 0x12;
  q[1] = 0x34;
  q[2] = 0x01; // RD = 1
  q[5] = 0x01; // QDCOUNT = 1
  q.set(bufs, 12);
  const tailIdx = 12 + bufs.length;
  q[tailIdx + 1] = 0x01; // QTYPE = 1 (A)
  q[tailIdx + 3] = 0x01; // QCLASS = 1 (IN)
  return q.buffer;
}

function queryToBase64Url(buf) {
  const bytes = new Uint8Array(buf);
  let str = "";
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * Fetches the upstream JSON feed.
 */
export async function fetchUpstreamFeed(feedUrl = DEFAULT_UPSTREAM_FEED, timeoutMs = 8000) {
  const resp = await fetch(feedUrl, {
    headers: {
      Accept: "application/json",
      "User-Agent": "AmarDNS/1.0",
    },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!resp.ok) {
    throw new Error(`Failed to fetch upstream DNS feed: HTTP ${resp.status}`);
  }
  const data = await resp.json();
  if (!Array.isArray(data.dns_over_https)) {
    throw new Error("Invalid feed format: missing 'dns_over_https' array");
  }
  return data.dns_over_https;
}

/**
 * Probes a single DoH upstream to measure real-time latency and reachability.
 */
export async function probeUpstream(upstream, probeB64, timeoutMs = 3500, probeBytes = null) {
  const start = performance.now();
  const url = upstream.url;
  try {
    let resp = null;
    const body = probeBytes || (typeof makeDnsProbePacket === "function" ? new Uint8Array(makeDnsProbePacket()) : null);
    if (body) {
      try {
        resp = await fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/dns-message",
            Accept: "application/dns-message",
            "User-Agent": "AmarDNS-Probe/1.0",
            "Cache-Control": "no-store",
          },
          body: body,
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch (_) {}
    }

    if (!resp || !resp.ok) {
      resp = await fetch(`${url}?dns=${probeB64}`, {
        headers: {
          Accept: "application/dns-message",
          "User-Agent": "AmarDNS-Probe/1.0",
          "Cache-Control": "no-store",
        },
        signal: AbortSignal.timeout(timeoutMs),
      });
    }

    const latency = Math.round(performance.now() - start);
    if (!resp.ok) {
      return {
        ...upstream,
        latency: 9999,
        ok: false,
        err: `HTTP ${resp.status}`,
        lastTested: Date.now(),
      };
    }
    const buf = await resp.arrayBuffer();
    if (buf.byteLength < 12) {
      return {
        ...upstream,
        latency: 9999,
        ok: false,
        err: "Malformed DNS response",
        lastTested: Date.now(),
      };
    }
    return {
      ...upstream,
      latency: Math.max(1, latency),
      ok: true,
      lastTested: Date.now(),
    };
  } catch (err) {
    return {
      ...upstream,
      latency: 9999,
      ok: false,
      err: err.name === "TimeoutError" ? "Timeout" : err.message,
      lastTested: Date.now(),
    };
  }
}

/**
 * Sorts upstreams based on:
 * 1. Reachability (ok = true prioritized over offline/failed)
 * 2. Aura (high = 1, medium = 2, low = 3)
 * 3. Latency (ascending milliseconds)
 */
export function rankUpstreams(probedList) {
  const sorted = [...probedList];
  sorted.sort((a, b) => {
    // 1. Healthy upstreams beat unreachable ones
    if (a.ok !== b.ok) {
      return a.ok ? -1 : 1;
    }

    // 2. Aura priority (high > medium > low)
    const auraA = AURA_PRIORITY[a.aura?.toLowerCase()] || 99;
    const auraB = AURA_PRIORITY[b.aura?.toLowerCase()] || 99;
    if (auraA !== auraB) {
      return auraA - auraB;
    }

    // 3. Lowest latency first
    return a.latency - b.latency;
  });

  return sorted;
}

/**
 * Performs full sync:
 * 1. Fetches DNS feed from CDN
 * 2. Probes all upstreams concurrently
 * 3. Ranks by aura + low latency
 * 4. Persists ranked candidates to PulseDB
 * 5. Hot-reloads top 8 upstreams in the worker
 */
export async function syncAndRankUpstreams(env, worker, options = {}) {
  const feedUrl = options.feedUrl || env?.UPSTREAM_FEED_URL || DEFAULT_UPSTREAM_FEED;
  const timeoutMs = options.probeTimeoutMs || 3500;
  logger.debug(`[upstream-syncer] Pulling upstream DNS list from ${feedUrl}...`);

  const rawList = await fetchUpstreamFeed(feedUrl);
  logger.debug(`[upstream-syncer] Probing ${rawList.length} DoH upstreams in parallel...`);

  const probePacket = makeDnsProbePacket();
  const probeB64 = queryToBase64Url(probePacket);
  const probeBytes = new Uint8Array(probePacket);

  // Probe all candidates concurrently
  const probed = await Promise.all(
    rawList.map((u) => probeUpstream(u, probeB64, timeoutMs, probeBytes))
  );

  // Rank according to: aura + low latency
  const ranked = rankUpstreams(probed);

  // Select 3xN active upstreams (default 9 = 3x3, guaranteed multiple of 3 for desktop & mobile grid)
  const target = options.poolSize || options.targetCount || 9;
  const multipleOf3 = Math.max(3, Math.floor(target / 3) * 3);
  const maxAvailable3xN = Math.floor(ranked.length / 3) * 3;
  const activeCount = maxAvailable3xN >= 3
    ? Math.min(maxAvailable3xN, multipleOf3)
    : ranked.length;

  const activeUpstreams = ranked.slice(0, activeCount);
  const activeUrls = activeUpstreams.map((u) => u.url);

  logger.debug(`[upstream-syncer] Ranked top ${activeUpstreams.length} active upstreams (3xN pool):`);
  activeUpstreams.forEach((u, i) => {
    logger.debug(
      `   ${i + 1}. [${(u.aura || "unknown").toUpperCase()}] ${u.provider.padEnd(24)} -> ${u.latency}ms (${u.url})`
    );
  });

  // Persist to PulseDB if available
  const pdb = env?.pulseDb;
  if (pdb && typeof pdb.set === "function") {
    try {
      pdb.set("upstreams:ranked", JSON.stringify(ranked));
      pdb.set("upstreams:last_sync", String(Date.now()));
      pdb.set("upstreams:active_urls", JSON.stringify(activeUrls));
    } catch (e) {
      logger.error("[upstream-syncer] Failed to persist upstreams to PulseDB:", e.message);
    }
  }

  // Hot-reload into the running worker
  if (worker && typeof worker.setUpstreams === "function") {
    worker.setUpstreams(activeUrls, ranked);
  }

  return {
    ok: true,
    count: ranked.length,
    active: activeUpstreams,
    fullRanked: ranked,
    timestamp: Date.now(),
  };
}

/**
 * Loads previously persisted ranked upstreams from PulseDB on boot.
 * Determines if a background sync is due (> 7 days or missing).
 */
export function loadPersistedUpstreams(env, worker) {
  const pdb = env?.pulseDb;
  if (!pdb || typeof pdb.get !== "function") {
    return { shouldSync: true, loaded: false };
  }

  const savedRanked = pdb.get("upstreams:ranked", null);
  const lastSyncStr = pdb.get("upstreams:last_sync", null);
  const lastSync = lastSyncStr ? parseInt(lastSyncStr, 10) : 0;
  const now = Date.now();
  const ageMs = now - lastSync;
  const isExpired = !lastSync || ageMs >= SYNC_INTERVAL_MS;

  if (savedRanked) {
    try {
      const ranked = JSON.parse(savedRanked);
      if (Array.isArray(ranked) && ranked.length > 0) {
        const maxAvailable3xN = Math.floor(ranked.length / 3) * 3;
        const activeCount = maxAvailable3xN >= 3 ? Math.min(maxAvailable3xN, 9) : ranked.length;
        const activeUrls = ranked.slice(0, activeCount).map((u) => u.url);
        if (worker && typeof worker.setUpstreams === "function") {
          worker.setUpstreams(activeUrls, ranked);
          logger.debug(`[upstream-syncer] Loaded ${activeUrls.length} persisted upstreams (3xN pool) from PulseDB (age: ${(ageMs / 86400000).toFixed(1)} days).`);
        }
        const needsSync = isExpired || activeUrls.length < 9 || activeUrls.length % 3 !== 0;
        return { shouldSync: needsSync, loaded: true, count: ranked.length };
      }
    } catch (e) {
      logger.error("[upstream-syncer] Failed to parse saved upstreams:", e.message);
    }
  }

  return { shouldSync: true, loaded: false };
}
