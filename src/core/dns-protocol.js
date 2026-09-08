// src/core/dns-protocol.js
// DNS wire format parser, synthesizers (NXDOMAIN/SERVFAIL), in-memory caching, upstream resolver pool, and resolution engine.

import {
  DNS_H, DNS_CT, NEG_TTL_MS, NEG_SRVFAIL_MS, NEG_MAX,
  MIN_CACHE_TTL, DEF_CACHE_TTL, _decoder, DGA_BLOCK_SCORE
} from "./constants.js";
import {
  _negCache, _sh, _runtimeConfig, _stress, _rndData, _env, _ucb, _kf,
  _ctx, _burstMap, _aiDecisions, _configDecisions, _domainIQ, _markov,
  _blockingEnabled, _lastLbMode, setLastLbMode
} from "./state.js";
export { _lastLbMode };
import {
  _trackRequest, _calcStress, _log, _action, _aiDecision,
  setUserEstimate, setUserModeAuto, _heatmapUpdate
} from "./telemetry.js";
import {
  checkBlocklist, checkWhitelist, alikeDomainCheck, checkGoogleSafeBrowsing,
  autoBlockSet, dgaScore, rebindCheck, qtypeAbuseCheck,
  answerDriftCheck, multiQuestionCheck, cbCheck,
  isKnownLegitDomain, dccClassify,
  fpCheck, burstCheck, swarmCheck, clientNxCheck, ttlCheck, poisonGuardCheck
} from "./threat-intelligence.js";
import {
  nnThreatScore, nnSelectUpstream, nnCacheTTL, nnCacheSignal,
  _perpetualLearnTick, _nnStats
} from "./neural-engine.js";
import { queryHttp2 } from "./http2-doh.js";

export let _ups = [];
export let _upScores = [];
export let _cb = [];
export let _upMetadata = null;

export function _view(buf) {
  if (!buf) return null;
  if (buf instanceof DataView) return buf;
  if (buf instanceof ArrayBuffer) return new DataView(buf);
  if (ArrayBuffer.isView(buf)) return new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const u8 = new Uint8Array(buf);
  return new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
}

export function parseDnsQuestion(buf) {
  try {
    const view = _view(buf);
    if (!view || buf.byteLength < 12) return null;
    const id = view.getUint16(0);
    const flags = view.getUint16(2);
    const qdcount = view.getUint16(4);
    let offset = 12;
    const labels = [];
    const byteLen = buf.byteLength;
    let totalLen = 0;
    while (offset < byteLen) {
      if (labels.length > 128) return null; // Decompression / label bomb protection
      const len = view.getUint8(offset++);
      if (len === 0) break;
      if ((len & 192) === 192) {
        offset++;
        break;
      }
      if (len > 63 || offset + len > byteLen) return null; // RFC 1035 max label length is 63
      totalLen += len + 1;
      if (totalLen > 255) return null; // RFC 1035 max domain name length is 255
      const labelBytes = new Uint8Array(view.buffer, view.byteOffset + offset, len);
      for (let i = 0; i < len; i++) {
        const c = labelBytes[i];
        if (c < 32 || c === 127) return null; // Reject control characters
      }
      labels.push(_decoder.decode(labelBytes).toLowerCase());
      offset += len;
    }
    if (offset + 4 > byteLen) return null;
    const qtype = view.getUint16(offset);
    const qclass = view.getUint16(offset + 2);
    return {
      id: id,
      flags: flags,
      qdcount: qdcount,
      name: labels.join("."),
      qtype: qtype,
      qclass: qclass,
      headerFlags: flags,
    };
  } catch (_) {
    return null;
  }
}
export function extractEdnsBufSize(buf) {
  try {
    const view = _view(buf);
    if (!view || buf.byteLength < 12) return 0;
    const qdcount = view.getUint16(4);
    const arcount = view.getUint16(10);
    if (arcount === 0) return 0;
    let offset = 12;
    for (let q = 0; q < qdcount; q++) {
      while (offset < buf.byteLength) {
        const len = view.getUint8(offset++);
        if (len === 0) break;
        if ((len & 192) === 192) {
          offset++;
          break;
        }
        offset += len;
      }
      offset += 4;
    }
    if (offset + 11 <= buf.byteLength) {
      if (view.getUint8(offset) === 0) {
        offset++;
        const rtype = view.getUint16(offset);
        if (rtype === 41) {
          return view.getUint16(offset + 2);
        }
      }
    }
    return 0;
  } catch (_) {
    return 0;
  }
}
export function extractAnswerIPs(buf) {
  try {
    const view = _view(buf);
    if (!view || buf.byteLength < 12) return [];
    const qdcount = view.getUint16(4);
    const ancount = view.getUint16(6);
    if (ancount === 0) return [];
    let offset = 12;
    for (let q = 0; q < qdcount; q++) {
      while (offset < buf.byteLength) {
        const len = view.getUint8(offset++);
        if (len === 0) break;
        if ((len & 192) === 192) {
          offset++;
          break;
        }
        offset += len;
      }
      offset += 4;
    }
    const ips = [];
    for (let a = 0; a < ancount && offset + 10 < buf.byteLength; a++) {
      if ((view.getUint8(offset) & 192) === 192) offset += 2;
      else {
        while (offset < buf.byteLength && view.getUint8(offset) !== 0) offset++;
        offset++;
      }
      const rtype = view.getUint16(offset);
      offset += 2;
      offset += 2;
      offset += 4;
      const rdlen = view.getUint16(offset);
      offset += 2;
      if (rtype === 1 && rdlen === 4) {
        ips.push(
          `${view.getUint8(offset)}.${view.getUint8(offset + 1)}.${view.getUint8(offset + 2)}.${view.getUint8(offset + 3)}`,
        );
      } else if (rtype === 28 && rdlen === 16) {
        const parts = [];
        for (let i = 0; i < 8; i++)
          parts.push(view.getUint16(offset + i * 2).toString(16));
        ips.push(parts.join(":"));
      }
      offset += rdlen;
    }
    return ips;
  } catch (_) {
    return [];
  }
}
export function extractTTL(buf) {
  try {
    const view = _view(buf);
    if (!view || buf.byteLength < 12) return null;
    const qdcount = view.getUint16(4);
    const ancount = view.getUint16(6);
    if (ancount === 0) return null;
    let offset = 12;
    for (let q = 0; q < qdcount; q++) {
      while (offset < buf.byteLength) {
        const len = view.getUint8(offset++);
        if (len === 0) break;
        if ((len & 192) === 192) {
          offset++;
          break;
        }
        offset += len;
      }
      offset += 4;
    }
    if ((view.getUint8(offset) & 192) === 192) offset += 2;
    else {
      while (offset < buf.byteLength && view.getUint8(offset) !== 0) offset++;
      offset++;
    }
    offset += 4;
    return view.getUint32(offset);
  } catch (_) {
    return null;
  }
}
export function getRcode(buf) {
  try {
    const view = _view(buf);
    return view ? (view.getUint16(2) & 15) : 2;
  } catch (_) {
    return 2;
  }
}
export function makeNxResponse(queryBuf) {
  try {
    const qView = _view(queryBuf);
    const len = queryBuf.byteLength;
    const resp = new Uint8Array(len);
    if (ArrayBuffer.isView(queryBuf)) {
      resp.set(new Uint8Array(queryBuf.buffer, queryBuf.byteOffset, len));
    } else {
      resp.set(new Uint8Array(queryBuf));
    }
    const dv = new DataView(resp.buffer);
    const flags = qView ? qView.getUint16(2) : 0x0100;
    dv.setUint16(2, (flags & 30720) | 33155);
    dv.setUint16(6, 0);
    return resp.buffer;
  } catch (_) {
    return queryBuf;
  }
}
export function makeServfailResponse(queryBuf) {
  try {
    const qView = _view(queryBuf);
    const len = queryBuf.byteLength;
    const resp = new Uint8Array(len);
    if (ArrayBuffer.isView(queryBuf)) {
      resp.set(new Uint8Array(queryBuf.buffer, queryBuf.byteOffset, len));
    } else {
      resp.set(new Uint8Array(queryBuf));
    }
    const dv = new DataView(resp.buffer);
    const flags = qView ? qView.getUint16(2) : 0x0100;
    dv.setUint16(2, (flags & 30720) | 33154);
    dv.setUint16(6, 0);
    return resp.buffer;
  } catch (_) {
    return queryBuf;
  }
}
export function _cacheKey(name, qtype) {
  return `dns:${name}:${qtype}`;
}
export function cacheGet(name, qtype) {
  const key = _cacheKey(name, qtype);
  const neg = _negCache.get(key);
  if (neg) {
    if (Date.now() < neg.exp) {
      _sh.negHits++;
      _negCache.delete(key);
      _negCache.set(key, neg);
      return { negative: true, rcode: neg.rcode };
    }
    _negCache.delete(key);
  }
  const cache = _env?.aeroCache;
  if (!cache) return null;
  const wire = cache.get(name, qtype);
  if (!wire) return null;
  return wire;
}
export function cachePut(name, qtype, buf, ttl) {
  const cache = _env?.aeroCache;
  if (!cache) return;
  const clampedTtl = Math.max(
    MIN_CACHE_TTL,
    Math.min(_runtimeConfig.maxCacheTtl, ttl),
  );
  cache.put(name, qtype, buf, clampedTtl);
}
export function negCacheSet(name, qtype, rcode) {
  const ttl = rcode === 2 ? NEG_SRVFAIL_MS : NEG_TTL_MS;
  const key = _cacheKey(name, qtype);
  _negCache.delete(key);
  if (_negCache.size >= NEG_MAX)
    _negCache.delete(_negCache.keys().next().value);
  _negCache.set(key, { exp: Date.now() + ttl, rcode: rcode });
}
export function setUpstreams(newBases, metadata = null, silent = false) {
  if (!Array.isArray(newBases) || newBases.length === 0) return;
  // Always pick 3xN pool (multiple of 3, e.g. 9 = 3x3)
  const multipleOf3 = Math.max(3, Math.floor(newBases.length / 3) * 3);
  _ups = newBases.slice(0, multipleOf3 > 0 ? multipleOf3 : newBases.length);
  _upMetadata = metadata;
  _upScores = Array.from({ length: _ups.length }, () => new Float32Array(32));
  _cb = Array.from({ length: _ups.length }, () => ({
    errors: 0,
    total: 0,
    open: false,
    openTs: 0,
  }));
  _ucb.rewards = new Float32Array(_ups.length);
  _ucb.pulls = new Uint32Array(_ups.length);
  if (!silent) {
    _log("upstreams_reloaded", { count: _ups.length, bases: _ups });
  }
}
export function _loadUpstreams(env) {
  if (_ups.length > 0) return;
  let bases = [];
  if (env.UPSTREAM_BASES) {
    try {
      bases = JSON.parse(env.UPSTREAM_BASES);
    } catch (_) {}
  }
  if (bases.length === 0) {
    for (let i = 0; i < 15; i++) {
      const v = env[`UPSTREAM_BASE_${i}`];
      if (v) bases.push(v);
    }
  }
  if (bases.length === 0 && env?.pulseDb) {
    try {
      const savedRanked = env.pulseDb.get("upstreams:ranked", null);
      if (savedRanked) {
        const parsed = JSON.parse(savedRanked);
        if (Array.isArray(parsed) && parsed.length > 0) {
          const maxAvailable3xN = Math.floor(parsed.length / 3) * 3;
          const count = maxAvailable3xN >= 3 ? Math.min(maxAvailable3xN, 9) : parsed.length;
          bases = parsed.slice(0, count).map((u) => u.url);
          _upMetadata = parsed;
        }
      }
    } catch (_) {}
  }
  if (bases.length === 0)
    bases = [
      "https://cloudflare-dns.com/dns-query",
      "https://1.1.1.1/dns-query",
      "https://1.0.0.1/dns-query",
      "https://dns.google/dns-query",
      "https://8.8.8.8/dns-query",
      "https://8.8.4.4/dns-query",
      "https://dns.quad9.net/dns-query",
      "https://doh.opendns.com/dns-query",
      "https://dns.adguard-dns.com/dns-query",
    ];
  setUpstreams(bases, _upMetadata);
  const eu = env?.EXPECTED_USERS;
  if (eu && String(eu).toUpperCase() !== "AI") {
    const parsed = parseInt(eu, 10);
    if (!isNaN(parsed) && parsed > 0) {
      setUserModeAuto(false); setUserEstimate(parsed);
      _kf.x = parsed;
    }
  } else {
    setUserModeAuto(true);
  }
}
export async function fetchUpstream(dnsQuery, upIdx, signal) {
  const base = _ups[upIdx];
  if (!base) return null;
  if (signal?.aborted) return null;
  const start = Date.now();
  try {
    let resp = null;
    let buf = null;
    try {
      resp = await fetch(base, {
        method: "POST",
        headers: {
          "Content-Type": DNS_CT,
          Accept: DNS_CT,
          "User-Agent": _rndData(),
          "Cache-Control": "no-store",
        },
        body: dnsQuery,
        signal: signal || AbortSignal.timeout(_runtimeConfig.fetchTimeoutMs),
        cf: { cacheEverything: false },
      });
    } catch (fetchErr) {
      if (signal?.aborted) return null;
    }

    if (resp && resp.ok) {
      buf = await resp.arrayBuffer();
    } else {
      // Fallback to native HTTP/2 for resolvers enforcing HTTP/2 (e.g. Quad9 Anycast POPs)
      const h2Buf = await queryHttp2(base, dnsQuery, _runtimeConfig.fetchTimeoutMs);
      if (h2Buf && h2Buf.byteLength >= 12) {
        buf = h2Buf.buffer.slice(h2Buf.byteOffset, h2Buf.byteOffset + h2Buf.byteLength);
      } else {
        throw new Error(resp ? `HTTP ${resp.status}` : "Resolution failed");
      }
    }
    const latency = Date.now() - start;
    const scores = _upScores[upIdx];
    if (scores) {
      scores[_ucb.pulls[upIdx] % 32] = latency;
    }
    _ucb.reward(upIdx, Math.max(0, 1 - latency / 2e3));
    cbCheck(upIdx, true);
    _domainIQ.see(`_up${upIdx}`, "good");
    return { buf: buf, latency: latency, upIdx: upIdx };
  } catch (e) {
    const latency = Date.now() - start;
    // CRITICAL: Do NOT penalize upstream as an error if the request was intentionally aborted because another hedged resolver won the race!
    const isAborted = signal?.aborted || e.name === "AbortError" || e.message?.toLowerCase().includes("abort");
    if (!isAborted) {
      cbCheck(upIdx, false);
      _ucb.reward(upIdx, 0);
      _log("upstream_error", {
        upstream: upIdx,
        err: e.message,
        latency: latency,
      });
    }
    return null;
  }
}

export async function queryUpstreams(dnsQuery, rps) {
  const n = _ups.length;
  if (n === 0) return null;
  for (let i = 0; i < n; i++) cbCheck(i, null);
  let lbMode = "BALANCED";
  if (rps > _runtimeConfig.lbFloodRps || _stress > _runtimeConfig.lbFloodStress)
    lbMode = "STRESS";
  else if (
    rps < _runtimeConfig.lbFastRps &&
    _stress < _runtimeConfig.lbFastStress
  )
    lbMode = "FAST";
  if (lbMode !== _lastLbMode) {
    const lbDec = {
      t: Date.now(),
      decision: "lb_mode_change",
      profile: lbMode,
      stress: +_stress.toFixed(3),
      rps: +rps.toFixed(2),
      changed: { lbMode: { from: _lastLbMode, to: lbMode } },
      snapshot: { ..._runtimeConfig, lbMode: lbMode },
    };
    _configDecisions.push(lbDec);
    if (_configDecisions.length > 200) _configDecisions.shift();
    _aiDecisions.push({
      t: lbDec.t,
      decision: "lb_mode:" + _lastLbMode + "->" + lbMode,
      factors: {
        stress: lbDec.stress,
        rps: lbDec.rps,
        floodRps: _runtimeConfig.lbFloodRps,
        fastRps: _runtimeConfig.lbFastRps,
      },
    });
    if (_aiDecisions.length > 100) _aiDecisions.shift();
  }
  setLastLbMode(lbMode);
  const available = _ups.map((_, i) => i).filter((i) => !_cb[i]?.open);
  if (available.length === 0) {
    _cb.forEach((c) => {
      c.open = false;
    });
    return null;
  }
  if (lbMode === "FAST") {
    const _attnBest = nnSelectUpstream(n);
    const best = _cb[_attnBest]?.open ? _ucb.select(n) : _attnBest;
    if (_cb[best]?.open) return null;
    return await fetchUpstream(dnsQuery, best, AbortSignal.timeout(3e3));
  }
  function wrapFetch(dnsQuery, upIdx, signal) {
    return fetchUpstream(dnsQuery, upIdx, signal).then((res) => {
      if (!res || !res.buf) throw new Error("no_answer");
      return res;
    });
  }

  if (lbMode === "STRESS") {
    const ac = new AbortController();
    const promises = available.map((i) => wrapFetch(dnsQuery, i, ac.signal));
    try {
      const result = await Promise.any(promises);
      ac.abort();
      return result;
    } catch (_) {
      return null;
    }
  }
  const sorted = available.sort((a, b) => {
    const pullsA = _ucb.pulls[a],
      pullsB = _ucb.pulls[b];
    const scoreA = pullsA > 0 ? _ucb.rewards[a] / pullsA : 0.5;
    const scoreB = pullsB > 0 ? _ucb.rewards[b] / pullsB : 0.5;
    return scoreB - scoreA;
  });
  const top = sorted.slice(0, Math.min(3, sorted.length));
  const ac = new AbortController();
  let hedgeTimer = null;
  const first = wrapFetch(dnsQuery, top[0], ac.signal);
  let result = null;
  if (top.length > 1) {
    const hedge = _runtimeConfig.hedgeMs || 20;
    const second = new Promise((resolve, reject) => {
      hedgeTimer = setTimeout(() => {
        if (ac.signal.aborted) return reject(new Error("aborted"));
        wrapFetch(dnsQuery, top[1], ac.signal).then(resolve, reject);
      }, hedge);
    });
    try {
      result = await Promise.any([first, second]);
    } catch (_) {
      if (top.length > 2 && !ac.signal.aborted) {
        result = await fetchUpstream(dnsQuery, top[2], ac.signal).catch(
          () => null,
        );
      }
    }
  } else {
    result = await first.catch(() => null);
  }
  if (hedgeTimer) clearTimeout(hedgeTimer);
  if (result) ac.abort();
  return result;
}
export async function resolveDns(dnsQuery, clientIp, env, clientMeta = null) {
  const parsed = parseDnsQuestion(dnsQuery);
  if (!parsed) return new Response(null, { status: 400 });
  const { name: name, qtype: qtype, qdcount: qdcount } = parsed;
  const deviceId = clientMeta?.deviceId || clientIp;
  const deviceType = clientMeta?.deviceType || "generic";
  const rps = _trackRequest(clientIp, deviceId, deviceType);
  _calcStress(rps);
  fpCheck(clientIp, name, rps);
  burstCheck(clientIp);
  swarmCheck(name, clientIp);
  const cached = cacheGet(name, qtype);
  if (cached) {
    if (cached.negative) {
      return new Response(
        cached.rcode === 3
          ? makeNxResponse(dnsQuery)
          : makeServfailResponse(dnsQuery),
        { headers: { "content-type": DNS_CT, ...DNS_H } },
      );
    }
    nnCacheSignal(true);
    if (clientIp) {
      _ctx?.waitUntil(
        (async () => {
          _markov.track(clientIp, name);
        })(),
      );
    }
    const outBuf = new Uint8Array(cached.byteLength);
    outBuf.set(cached);
    if (dnsQuery && dnsQuery.byteLength >= 2) {
      const qView = new Uint8Array(dnsQuery);
      outBuf[0] = qView[0];
      outBuf[1] = qView[1];
    }
    return new Response(outBuf, {
      headers: { "content-type": DNS_CT, "x-cache": "HIT", ...DNS_H },
    });
  }
  _sh.cacheMisses++;
  if (multiQuestionCheck(qdcount)) {
    _log("multi_question_abuse", {
      name: name,
      qdcount: qdcount,
      client: clientIp,
    });
    return new Response(makeServfailResponse(dnsQuery), {
      headers: { "content-type": DNS_CT, ...DNS_H },
    });
  }
  const qtypeAbuse = qtypeAbuseCheck(qtype);
  if (qtypeAbuse) {
    _log("qtype_abuse", {
      name: name,
      qtype: qtype,
      reason: qtypeAbuse,
      client: clientIp,
    });
    return new Response(makeNxResponse(dnsQuery), {
      headers: { "content-type": DNS_CT, ...DNS_H },
    });
  }
  const db = env?.pulseDb;
  if (isKnownLegitDomain(name) || checkWhitelist(name, db)) {
    _domainIQ.see(name, "good");
    const result = await queryUpstreams(dnsQuery, rps);
    if (!result?.buf)
      return new Response(makeServfailResponse(dnsQuery), {
        headers: { "content-type": DNS_CT, ...DNS_H },
      });
    const ttl = extractTTL(result.buf) || DEF_CACHE_TTL;
    ttlCheck(name, ttl);
    poisonGuardCheck(name, result.latency || 20);
    _ctx?.waitUntil(
      (async () => {
        const _rlTTL = nnCacheTTL(name, clientIp, rps, 0, 0, result.latency || 20, ttl);
        cachePut(name, qtype, result.buf, _rlTTL || ttl);
        _heatmapUpdate(name);
        _perpetualLearnTick(name, getRcode(result.buf), rps, "resolved", result.idx, result.latency || 20);
      })(),
    );
    return new Response(result.buf, {
      headers: {
        "content-type": DNS_CT,
        "x-cache": "MISS",
        "x-whitelist": "1",
        ...DNS_H,
      },
    });
  }
  if (_blockingEnabled) {
    const blockResult = checkBlocklist(name, db);
    if (blockResult.blocked) {
      if (blockResult.reason === "threat_feed_abir" || blockResult.source === "abir_feed" || blockResult.source === "feed") {
        _sh.abirBlocks++;
      } else {
        _sh.repBlocks++;
      }
      const cat = dccClassify(name);
      if (cat) _sh.dccHits++;
      _domainIQ.see(name, "blocked");
      _action("blocklist_block", blockResult.reason, {
        domain: name,
        client: clientIp,
      });
      return new Response(makeNxResponse(dnsQuery), {
        headers: { "content-type": DNS_CT, ...DNS_H },
      });
    }

    // Alike / Homoglyph Brand Impersonation check
    const alike = alikeDomainCheck(name, db);
    if (alike.detected) {
      _sh.alikeBlocks++;
      _domainIQ.see(name, "dga");
      autoBlockSet(name, alike.reason || "brand_impersonation", 300);
      _action("alike_domain_block", alike.reason, {
        domain: name,
        brand: alike.brand,
        client: clientIp,
      });
      _aiDecision("alike_block", {
        domain: name,
        reason: alike.reason,
        brand: alike.brand || "?",
      });
      return new Response(makeNxResponse(dnsQuery), {
        headers: { "content-type": DNS_CT, ...DNS_H },
      });
    }

    // Neural AI Threat Scoring (Liquid, Spiking, DTN, MoE, GRU, Autoencoder, Forest, BNN)
    const { score: _nnScore, reason: _nnReason } = nnThreatScore(
      name,
      clientIp,
      rps,
      _domainIQ.riskScore(name),
      _markov.predict(name) ? 1 : 0,
      !!_burstMap.get(clientIp)?.count,
    );
    const heuristicScore = dgaScore(name);
    const shouldBlock =
      heuristicScore >= DGA_BLOCK_SCORE && _nnScore >= DGA_BLOCK_SCORE;
    if (shouldBlock) {
      _sh.dgaBlocked++;
      _domainIQ.see(name, "dga");
      autoBlockSet(name, "dga_classifier", 300);
      _action("dga_block", "dga_classifier", {
        domain: name,
        score: heuristicScore,
        nnScore: _nnScore,
        client: clientIp,
      });
      _aiDecision("dga_block", {
        domain: name,
        score: heuristicScore,
        nn: _nnScore,
        cycles: _nnStats.learningCycles,
      });
      return new Response(makeNxResponse(dnsQuery), {
        headers: { "content-type": DNS_CT, ...DNS_H },
      });
    }

    // Google Safe Browsing Cloud Threat Check (Malware, Phishing, Social Engineering)
    try {
      const gsb = await checkGoogleSafeBrowsing(name);
      if (gsb?.threat) {
        _sh.gsbBlocks++;
        _domainIQ.see(name, "gsb");
        autoBlockSet(name, "google_safe_browsing", 3600);
        _action("gsb_block", "google_safe_browsing", {
          domain: name,
          client: clientIp,
          matches: gsb.matches,
        });
        _aiDecision("gsb_block", {
          domain: name,
          threatTypes: (gsb.matches || []).map((m) => m.threatType).join(","),
        });
        return new Response(makeNxResponse(dnsQuery), {
          headers: { "content-type": DNS_CT, ...DNS_H },
        });
      }
    } catch (_) {}
  }

  const result = await queryUpstreams(dnsQuery, rps);
  if (!result?.buf) {
    negCacheSet(name, qtype, 2);
    return new Response(makeServfailResponse(dnsQuery), {
      headers: { "content-type": DNS_CT, ...DNS_H },
    });
  }
  const { buf: buf, latency: latency } = result;
  const rcode = getRcode(buf);
  if (rcode === 3) {
    _sh.nxAlarms++;
    clientNxCheck(clientIp, 3);
    negCacheSet(name, qtype, 3);
    _domainIQ.see(name, "nx");
    return new Response(makeNxResponse(dnsQuery), {
      headers: { "content-type": DNS_CT, ...DNS_H },
    });
  }
  if (rcode !== 0) {
    negCacheSet(name, qtype, rcode);
    return new Response(buf, { headers: { "content-type": DNS_CT, ...DNS_H } });
  }
  const ips = extractAnswerIPs(buf);
  const ttl = extractTTL(buf) || DEF_CACHE_TTL;
  ttlCheck(name, ttl);
  poisonGuardCheck(name, latency);
  if (ips.length > 0) {
    if (_blockingEnabled && rebindCheck(name, ips)) {
      _sh.rebindBlocks++;
      _action("rebind_block", "dns_rebinding", {
        domain: name,
        ips: ips,
        client: clientIp,
      });
      return new Response(makeServfailResponse(dnsQuery), {
        headers: { "content-type": DNS_CT, ...DNS_H },
      });
    }
    if (answerDriftCheck(name, ips))
      _log("answer_drift", { domain: name, ips: ips });
  }
  _domainIQ.see(name, "good");
  _ctx?.waitUntil(
    (async () => {
      const _rlTTL = nnCacheTTL(
        name,
        clientIp,
        rps,
        _domainIQ.riskScore(name),
        _markov.predict(name) ? 1 : 0,
        latency,
        ttl,
      );
      cachePut(name, qtype, buf, _rlTTL || ttl);
      _heatmapUpdate(name);
      if (clientIp) _markov.track(clientIp, name);
      _perpetualLearnTick(name, rcode, rps, "resolved", result.idx, latency);
    })(),
  );
  return new Response(buf, {
    headers: {
      "content-type": DNS_CT,
      "x-cache": "MISS",
      "x-latency": String(latency),
      ...DNS_H,
    },
  });
}
