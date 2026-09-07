// src/core/http2-doh.js
// Native HTTP/2 client for DoH resolvers that require RFC 8484 HTTP/2 (e.g., Quad9 Anycast POPs)
// Supports session multiplexing, connection caching, and automatic error recovery.

import http2 from "node:http2";

const sessions = new Map();

function getOrCreateClient(origin) {
  let entry = sessions.get(origin);
  if (entry && !entry.client.destroyed && !entry.client.closed) {
    entry.lastUsed = Date.now();
    return entry.client;
  }
  const client = http2.connect(origin);
  client.on("error", () => {
    sessions.delete(origin);
    try { client.destroy(); } catch (_) {}
  });
  client.on("close", () => {
    sessions.delete(origin);
  });
  sessions.set(origin, { client, lastUsed: Date.now() });
  return client;
}

// Clean idle connections after 60s
if (typeof setInterval !== "undefined") {
  const cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [origin, entry] of sessions.entries()) {
      if (now - entry.lastUsed > 60000 || entry.client.destroyed || entry.client.closed) {
        try { entry.client.destroy(); } catch (_) {}
        sessions.delete(origin);
      }
    }
  }, 30000);
  if (cleanupTimer.unref) cleanupTimer.unref();
}

/**
 * Sends a DoH wire query over native HTTP/2.
 * @param {string} urlStr - Full DoH URL (e.g. "https://dns.quad9.net/dns-query")
 * @param {Uint8Array|Buffer} queryBuf - DNS wire format packet
 * @param {number} [timeoutMs=3500] - Request timeout in ms
 * @returns {Promise<Buffer>} DNS response packet
 */
export function queryHttp2(urlStr, queryBuf, timeoutMs = 3500) {
  return new Promise((resolve, reject) => {
    try {
      const u = new URL(urlStr);
      const client = getOrCreateClient(u.origin);
      let settled = false;

      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          reject(new Error("Timeout"));
        }
      }, timeoutMs);

      const payload = Buffer.isBuffer(queryBuf) ? queryBuf : Buffer.from(queryBuf);
      const req = client.request({
        ":method": "POST",
        ":path": u.pathname + (u.search || ""),
        "content-type": "application/dns-message",
        "accept": "application/dns-message",
        "user-agent": "AmarDNS-DoH/2.0",
        "content-length": String(payload.byteLength),
      });

      const chunks = [];
      req.on("response", (headers) => {
        const status = headers[":status"];
        if (status !== 200) {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            reject(new Error(`HTTP ${status}`));
          }
        }
      });

      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          resolve(Buffer.concat(chunks));
        }
      });
      req.on("error", (err) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(err);
        }
      });

      req.write(payload);
      req.end();
    } catch (err) {
      reject(err);
    }
  });
}
