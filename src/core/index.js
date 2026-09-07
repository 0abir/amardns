// src/core/index.js
// Core orchestrator and Cloudflare Worker / Fetch API request dispatcher.

import {
  DNS_CT, DNS_H, CORS_H, MAX_DNS_QUERY, MAX_ADMIN_BODY,
  OPEN_ACCESS, _enc, HMAC_WINDOW_S, NO_CACHE_H, SECURITY_H
} from "./constants.js";
import {
  setEnv, setCtx, setSafeBrowsingKeys, setBrandsList,
  setWorkerId, setIsolateId, setWorkerStartTs, _ISOLATE_ID,
  _workerStartTs, _dnsMode, _setDnsMode, getDnsMode, _sh, _ups, _upMetadata, _listsPreloaded
} from "./state.js";
import {
  _checkDayReset, _log, _getHmacKey, checkAuth, fnv1a32,
  checkAuthRateLimit, recordAuthFailure, resetAuthFailure
} from "./telemetry.js";
import { preloadLists, syncThreatFeeds, checkBlocklist, checkWhitelist } from "./threat-intelligence.js";
import { setUpstreams, _loadUpstreams, resolveDns } from "./dns-protocol.js";

let _lastBrandsRaw = null;
let _lastKeysRaw = null;

const workerInstance = {
  setUpstreams,
  getUpstreams: () => _ups,
  getUpstreamMetadata: () => _upMetadata,
  _setDnsMode,
  getDnsMode,
  preloadLists,
  syncThreatFeeds,
  checkBlocklist,
  checkWhitelist,
  _loadUpstreams,
  resolveDns,
  async scheduled(event, env, ctx) {
    setEnv(env);
    setCtx(ctx);
    ctx.waitUntil(
      (async () => {
        if (!_listsPreloaded && env?.pulseDb) {
          preloadLists(env);
        }
        _log("scheduled_tick", { cron: event.cron });
      })(),
    );
  },
  async fetch(request, env, ctx) {
    if (env.BRANDS_LIST && env.BRANDS_LIST !== _lastBrandsRaw) {
      _lastBrandsRaw = env.BRANDS_LIST;
      setBrandsList(env.BRANDS_LIST.split(",").map(b => b.trim().toLowerCase()));
    }
    if (env.SAFE_BROWSING_KEYS && env.SAFE_BROWSING_KEYS !== _lastKeysRaw) {
      _lastKeysRaw = env.SAFE_BROWSING_KEYS;
      setSafeBrowsingKeys(env.SAFE_BROWSING_KEYS.split(",").map(k => k.trim()));
    }
    try {
      return await _handleRequest(request, env, ctx);
    } catch (e) {
      console.error(
        JSON.stringify({
          event: "unhandled_exception",
          err: e?.message,
          stack: e?.stack?.slice(0, 300),
        }),
      );
      const url = new URL(request.url);
      const isDns =
        url.pathname.includes("/dns-query") ||
        url.pathname.includes("/resolve");
      return new Response(JSON.stringify({ error: "Internal Server Error" }), {
        status: 500,
        headers: {
          "content-type": "application/json",
          ...(isDns ? DNS_H : CORS_H),
        },
      });
    }
  },
};
export default workerInstance;
export async function _handleRequest(request, env, ctx) {
  const key = env.DNS_MASTER_KEY;
  if (!key || key.length < 3 || key.length > 50) {
    console.error(
      `Config Error: DNS_MASTER_KEY is ${key ? `length ${key.length}` : "missing"}.`,
    );
    return new Response("WRONG KEY", {
      status: 500,
      headers: { "Content-Type": "text/plain" },
    });
  }
  setEnv(env);
  setCtx(ctx);
  setWorkerId(env.DNS_WORKER_NAME || "default");
  if (!_ISOLATE_ID) setIsolateId(crypto.randomUUID().slice(0, 16));
  if (!_workerStartTs) setWorkerStartTs(Date.now());
  _checkDayReset();
  if (_ups.length === 0) _loadUpstreams(env);
  if (!_listsPreloaded && env?.pulseDb) {
    preloadLists(env);
  }
  const url = new URL(request.url);
  const { pathname: pathname } = url;
  const { method: method } = request;
  const isDnsPath =
    pathname === "/dns-query" ||
    pathname === "/resolve" ||
    pathname.startsWith("/dns-query/") ||
    pathname.startsWith("/resolve/") ||
    (pathname === "/" && (url.searchParams.has("dns") || url.searchParams.has("name") || request.headers.get("content-type")?.toLowerCase().includes("application/dns-message")));
  if (method === "OPTIONS")
    return new Response(null, {
      status: 204,
      headers: isDnsPath ? DNS_H : CORS_H,
    });
  if (isDnsPath) {
    if (_dnsMode === "private") {
      const hasMaster =
        typeof env.DNS_MASTER_KEY === "string" && env.DNS_MASTER_KEY.length > 0;
      const hasToken =
        typeof env.DNS_TOKEN_SECRET === "string" &&
        env.DNS_TOKEN_SECRET.length > 0;
      if (hasMaster || hasToken) {
        const authHeader = request.headers.get("authorization") || "";
        let dnsAuthed = false;
        if (authHeader.startsWith("Bearer ")) {
          const tok = authHeader.slice(7).trim();
          if (hasToken && tok.length === 72) {
            const tsHex = tok.slice(0, 8);
            const sigHex = tok.slice(8);
            if (/^[0-9a-f]{8}$/.test(tsHex) && /^[0-9a-f]{64}$/.test(sigHex)) {
              const ts = parseInt(tsHex, 16);
              if (Math.abs(Date.now() / 1e3 - ts) <= HMAC_WINDOW_S) {
                const sigBuf = new Uint8Array(32);
                for (let i = 0; i < 32; i++)
                  sigBuf[i] = parseInt(sigHex.slice(i * 2, i * 2 + 2), 16);
                try {
                  dnsAuthed = await crypto.subtle.verify(
                    "HMAC",
                    await _getHmacKey(env),
                    sigBuf,
                    _enc.encode(tsHex + "/dns-query"),
                  );
                } catch (_) {}
              }
            }
          }
        } else if (authHeader.startsWith("Masterkey ")) {
          const key = authHeader.slice(10).trim();
          if (hasMaster && key.length === env.DNS_MASTER_KEY.length) {
            let diff = 0;
            for (let i = 0; i < env.DNS_MASTER_KEY.length; i++)
              diff |= key.charCodeAt(i) ^ env.DNS_MASTER_KEY.charCodeAt(i);
            dnsAuthed = diff === 0;
          }
        }
        if (!dnsAuthed) {
          const lastSlash = pathname.lastIndexOf("/");
          if (lastSlash !== -1) {
            const seg = pathname.slice(lastSlash + 1);
            if (seg.length > 0) {
              if (hasMaster && seg.length === env.DNS_MASTER_KEY.length) {
                let diff = 0;
                for (let i = 0; i < env.DNS_MASTER_KEY.length; i++)
                  diff |= seg.charCodeAt(i) ^ env.DNS_MASTER_KEY.charCodeAt(i);
                if (diff === 0) dnsAuthed = true;
              }
              if (!dnsAuthed && hasToken && seg.length === 72) {
                const tsHex = seg.slice(0, 8),
                  sigHex = seg.slice(8);
                if (
                  /^[0-9a-f]{8}$/.test(tsHex) &&
                  /^[0-9a-f]{64}$/.test(sigHex)
                ) {
                  const ts = parseInt(tsHex, 16);
                  if (Math.abs(Date.now() / 1e3 - ts) <= HMAC_WINDOW_S) {
                    const sigBuf = new Uint8Array(32);
                    for (let i = 0; i < 32; i++)
                      sigBuf[i] = parseInt(sigHex.slice(i * 2, i * 2 + 2), 16);
                    try {
                      const basePath =
                        pathname.slice(0, lastSlash) || "/dns-query";
                      dnsAuthed = await crypto.subtle.verify(
                        "HMAC",
                        await _getHmacKey(env),
                        sigBuf,
                        _enc.encode(tsHex + basePath),
                      );
                    } catch (_) {}
                  }
                }
              }
            }
          }
        }
        if (!dnsAuthed) {
          _sh.authFails++;
          _log("dns_auth_fail", {
            path: pathname,
            ip: request.headers.get("cf-connecting-ip") || "?",
          });
          return new Response(JSON.stringify({ error: "Unauthorized" }), {
            status: 401,
            headers: {
              "content-type": "application/json",
              "www-authenticate": "Bearer, Masterkey",
              ...DNS_H,
            },
          });
        }
      }
    }
    let dnsQuery;
    if (method === "GET") {
      const dns = url.searchParams.get("dns");
      if (dns) {
        if (typeof Buffer !== "undefined") {
          const b = Buffer.from(dns, "base64url");
          dnsQuery = b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
        } else {
          const b64 = dns.replace(/-/g, "+").replace(/_/g, "/");
          const raw = atob(b64);
          const buf = new Uint8Array(raw.length);
          for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
          dnsQuery = buf.buffer;
        }
      } else if (url.searchParams.has("name")) {
        const name = url.searchParams.get("name").trim();
        const typeStr = (url.searchParams.get("type") || "A").toUpperCase();
        const typeNum =
          typeStr === "AAAA"
            ? 28
            : typeStr === "HTTPS"
              ? 65
              : typeStr === "MX"
                ? 15
                : typeStr === "TXT"
                  ? 16
                  : 1;
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
        q[2] = 0x01;
        q[3] = 0x00;
        q[4] = 0x00;
        q[5] = 0x01;
        q.set(bufs, 12);
        const tailIdx = 12 + bufs.length;
        q[tailIdx] = (typeNum >> 8) & 0xff;
        q[tailIdx + 1] = typeNum & 0xff;
        q[tailIdx + 2] = 0x00;
        q[tailIdx + 3] = 0x01;
        dnsQuery = q.buffer;
      } else {
        return new Response("Missing dns or name param", { status: 400 });
      }
    } else if (method === "POST") {
      const cLen = parseInt(request.headers.get("content-length") || "0");
      if (cLen > MAX_DNS_QUERY)
        return new Response("Query too large", { status: 413 });
      const ct = (request.headers.get("content-type") || "").toLowerCase();
      if (ct !== DNS_CT && !ct.includes("application/dns-message"))
        return new Response("Bad Content-Type", { status: 415 });
      dnsQuery = await request.arrayBuffer();
    } else return new Response("Method Not Allowed", { status: 405 });
    if (dnsQuery.byteLength > MAX_DNS_QUERY)
      return new Response("Query too large", { status: 413 });
    const rawIp =
      request.headers.get("cf-connecting-ip") ||
      request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      "0.0.0.0";
    const clientIp = fnv1a32(rawIp);
    return await resolveDns(dnsQuery, clientIp, env);
  }
  const rawIp =
    request.headers.get("cf-connecting-ip") ||
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    request.headers.get("x-real-ip") ||
    "0.0.0.0";

  if (checkAuthRateLimit(rawIp)) {
    return new Response(JSON.stringify({ error: "Too Many Requests: Auth rate limit exceeded. Try again in 60s." }), {
      status: 429,
      headers: {
        "content-type": "application/json",
        "retry-after": "60",
        ...NO_CACHE_H,
        ...SECURITY_H,
      },
    });
  }

  const cLen = parseInt(request.headers.get("content-length") || "0");
  if (cLen > MAX_ADMIN_BODY)
    return new Response("Request too large", { status: 413 });
  const authedPath = await checkAuth(pathname, env, request);
  if (authedPath === null || authedPath === OPEN_ACCESS) {
    if (pathname === "/dns-query" || pathname === "/resolve") {
      return new Response("Not Found", { status: 404 });
    }
    // Beautiful Gateway Portal instead of plain text "Not Found" for browser users & root "/"
    if (pathname === "/" || request.headers.get("accept")?.includes("text/html")) {
      const { GATEWAY_HTML } = await import("./gateway-html.js");
      return new Response(GATEWAY_HTML, {
        status: 200,
        headers: {
          "content-type": "text/html;charset=utf-8",
          "cache-control": "no-cache, no-store, must-revalidate",
          ...SECURITY_H,
        },
      });
    }
    recordAuthFailure(rawIp);
    _sh.authFails++;
    _log("auth_fail", { path: pathname, ip: rawIp });
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: {
        "content-type": "application/json",
        ...NO_CACHE_H,
        ...SECURITY_H,
      },
    });
  }
  resetAuthFailure(rawIp);
  const { handleAdmin } = await import("./admin-api.js");
  return await handleAdmin(request, url, env, authedPath);
}
