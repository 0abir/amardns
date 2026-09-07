// src/core/telemetry.js
// Logging, rate tracking, stress metrics, HMAC authentication tokens, and system adaptation loops.

import {
  OPEN_ACCESS, _enc, KV_BUCKET_CAP, KV_REFILL_PER_MIN,
  HMAC_WINDOW_S, HEATMAP_MAX, FEED_CACHE_MAX, NEG_MAX, EWMA_FAST,
  GSB_CACHE_MAX
} from "./constants.js";
import {
  _workerId, _workerStartTs, _anomalies, _obs, _actions,
  _aiDecisions, _rpsHistory,
  _stressHistory,
  _hmacCache, _sh, _heatmap, _heatmapFlushTs,
  _runtimeConfig, _lastLbMode, setLastLbMode, _userMap, _deviceMap,
  _userRing, _featCache, _autoBlocks,
  _burstMap, _fpMap, _domainIQ,
  _configDecisions, _kf, _anomaly, _ctx, _feedCache, _negCache, _answerHistory,
  _log
} from "./state.js";
import { _clientNX, _cacheTimings, _ttlHistory, _swarmMap, _gsbCache } from "./threat-intelligence.js";
import { _brainPrune } from "./neural-engine.js";

import {
  resetStorageQuotas, accountKvWrite, _dayStr, _kvW, _kvR, _d1W, _d1R, _kvThrottle, _d1Throttle,
  kvPut
} from "./storage-adapter.js";
import logger from "../logger.js";

export let _kvBucket = 10;
export let _kvBucketTs = 0;
export let _rpsSmooth = 0;
export let _rpsPeak = 0;
export let _rpsIdx = 0;
export let _rpsTotal = 0;
export let _stressIdx = 0;
export let _stress = 0;
export let _userWinStart = 0;
export let _userRingIdx = 0;
export let _userSamples = 0;
export let _userRingFull = false;
export let _userEwmaFast = 0;
export let _userEwmaSlow = 0;
export let _userPeak = 0;
export let _userEstimate = 1;
export let _userModeAuto = true;

export function setUserEstimate(est, samples = 0) {
  _userEstimate = est;
  if (samples) _userSamples = samples;
}
export function setUserModeAuto(val) {
  _userModeAuto = val;
}
export function setStress(s) {
  _stress = s;
}

export function resetTelemetry() {
  _rpsSmooth = 0;
  _rpsPeak = 0;
  _rpsIdx = 0;
  _rpsTotal = 0;
  _stressIdx = 0;
  _stress = 0;
  _userWinStart = 0;
  _userRingIdx = 0;
  _userSamples = 0;
  _userRingFull = false;
  _userEwmaFast = 0;
  _userEwmaSlow = 0;
  _userPeak = 0;
  _userEstimate = 1;
  _userModeAuto = true;
  if (_rpsHistory?.fill) _rpsHistory.fill(0);
  if (_stressHistory?.fill) _stressHistory.fill(0);
  if (_userRing?.fill) _userRing.fill(0);
  if (_userMap?.clear) _userMap.clear();
  if (_deviceMap?.clear) _deviceMap.clear();
  if (_heatmap?.clear) _heatmap.clear();
}

export function _utcDay() {
  return new Date().toISOString().slice(0, 10);
}
export function fnv1a32(str) {
  let h = 2166136261 >>> 0;
  for (let i = 0, n = str.length; i < n; i++) {
    h = Math.imul(h ^ str.charCodeAt(i), 16777619) >>> 0;
  }
  return h.toString(16);
}
export function _onlineSince() {
  if (!_workerStartTs) return "";
  const ms = Date.now() - _workerStartTs;
  const s = Math.floor(ms / 1e3);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  const d = Math.floor(h / 24);
  if (d < 7) return `${d}d`;
  const w = Math.floor(d / 7);
  if (w < 5) return `${w}w`;
  const mo = Math.floor(d / 30);
  if (mo < 12) return `${mo}mo`;
  return `${Math.floor(d / 365)}y`;
}
export { _log };
export function _action(action, reason, data = {}) {
  const entry = { t: Date.now(), action: action, reason: reason, ...data };
  _actions.push(entry);
  if (_actions.length > 100) _actions.splice(0, 50);
  logger.debug(
    JSON.stringify({
      event: "action",
      action: action,
      reason: reason,
      ...data,
    }),
  );
}
export function _aiDecision(decision, factors) {
  _aiDecisions.push({ t: Date.now(), decision: decision, factors: factors });
  if (_aiDecisions.length > 100) _aiDecisions.shift();
}
export function _kvBucketRefill() {
  const now = Date.now();
  const elapsed = (now - _kvBucketTs) / 6e4;
  _kvBucket = Math.min(KV_BUCKET_CAP, _kvBucket + elapsed * KV_REFILL_PER_MIN);
  _kvBucketTs = now;
}
export function _kvCanWrite() {
  return true;
}
export function _kvAccountWrite() {
  accountKvWrite();
}
let _lastDayCheck = 0;
export function _checkDayReset() {
  const now = Date.now();
  if (now - _lastDayCheck < 60000) return;
  _lastDayCheck = now;
  const today = _utcDay();
  if (today !== _dayStr) {
    resetStorageQuotas(today);
  }
}
export function _getRps() {
  return _rpsSmooth;
}
export function _trackRequest(clientIp, deviceId, deviceType) {
  _sh.requests++;
  const now = Date.now();
  const devKey = deviceId || clientIp || "device_unknown";
  if (_deviceMap && _deviceMap.size < 10000) {
    const existing = _deviceMap.get(devKey);
    _deviceMap.set(devKey, {
      lastSeen: now,
      ip: clientIp || "0.0.0.0",
      type: deviceType || "doh",
      count: (existing?.count || 0) + 1,
    });
  }
  if (clientIp && _userMap.size < 10000) _userMap.set(clientIp, now);

  // Observational telemetry only: never blocks or throttles user traffic
  const bucket = Math.floor(now / 1e3);
  if (bucket !== _rpsIdx) {
    const prevCount = _rpsHistory[_rpsIdx % 60] || 0;
    _rpsSmooth = EWMA_FAST * prevCount + (1 - EWMA_FAST) * _rpsSmooth;
    if (_rpsSmooth > _rpsPeak) _rpsPeak = _rpsSmooth;
    _rpsHistory[bucket % 60] = 0;
    _rpsIdx = bucket;
  }
  _rpsHistory[bucket % 60] = (_rpsHistory[bucket % 60] || 0) + 1;
  _rpsTotal++;
  return _getRps();
}
export function _calcStress(rps) {
  const rpsLoad = Math.min(1, rps / 500) ** 1.2;
  const memLoad = _sh.memPressure ? 0.5 : 0;
  const instant = Math.min(1, 0.03 + rpsLoad + memLoad);
  _stressHistory[_stressIdx] = instant;
  _stressIdx = (_stressIdx + 1) % 10;
  _stress = _stressHistory.reduce((a, b) => a + b, 0) / 10;
  return _stress;
}
const _HEX = Array.from({ length: 256 }, (_, i) =>
  i.toString(16).padStart(2, "0"),
);
export function bufToHex(buf) {
  const b = new Uint8Array(buf);
  let s = "";
  for (let i = 0, n = b.length; i < n; i++) s += _HEX[b[i]];
  return s;
}

/**
 * Constant-time comparison between two strings via SHA-256 digest XOR.
 * Prevents timing side-channel attacks on secret keys regardless of input length.
 */
export async function timingSafeEqualStr(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", _enc.encode(a)),
    crypto.subtle.digest("SHA-256", _enc.encode(b)),
  ]);
  const ba = new Uint8Array(ha), bb = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= ba[i] ^ bb[i];
  return diff === 0;
}

// Anti-brute-force rate limiter for authentication attempts (10 fails / 60s per IP)
const _authFailMap = new Map();
const AUTH_FAIL_LIMIT = 10;
const AUTH_FAIL_WINDOW = 60 * 1000;

export function checkAuthRateLimit(clientIp) {
  if (!clientIp) return false;
  const now = Date.now();
  const entry = _authFailMap.get(clientIp);
  if (!entry) return false;
  if (now > entry.resetTs) {
    _authFailMap.delete(clientIp);
    return false;
  }
  return entry.count >= AUTH_FAIL_LIMIT;
}

export function recordAuthFailure(clientIp) {
  if (!clientIp) return;
  const now = Date.now();
  if (_authFailMap.size > 2000) {
    for (const [k, v] of _authFailMap) {
      if (now > v.resetTs) _authFailMap.delete(k);
    }
  }
  const entry = _authFailMap.get(clientIp);
  if (!entry || now > entry.resetTs) {
    _authFailMap.set(clientIp, { count: 1, resetTs: now + AUTH_FAIL_WINDOW });
  } else {
    entry.count++;
  }
}

export function resetAuthFailure(clientIp) {
  if (clientIp) _authFailMap.delete(clientIp);
}

export async function _getHmacKey(env) {
  if (_hmacCache.has(env)) return _hmacCache.get(env);
  const secret = env?.DNS_TOKEN_SECRET;
  if (!secret || typeof secret !== "string" || secret.length === 0) {
    throw new Error("DNS_TOKEN_SECRET is not configured");
  }
  const key = await crypto.subtle.importKey(
    "raw",
    _enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  _hmacCache.set(env, key);
  return key;
}
export async function checkAuth(path, env, request = null) {
  const cleanPath = path && path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : (path || "/");
  const masterKey = env.DNS_MASTER_KEY;
  if (typeof masterKey === "string" && masterKey.length > 0) {
    if (request && typeof request.headers?.get === "function") {
      const authHeader = request.headers.get("authorization");
      const apiKeyHeader = request.headers.get("x-api-key") || request.headers.get("x-master-key") || request.headers.get("x-auth-key");
      const bearer = authHeader?.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;
      const keyCandidate = bearer || apiKeyHeader;
      if (keyCandidate) {
        const match = await timingSafeEqualStr(keyCandidate, masterKey);
        if (match) {
          if (request) request.authRole = "admin";
          const lastSlash = cleanPath.lastIndexOf("/");
          if (lastSlash !== -1) {
            const seg = cleanPath.slice(lastSlash + 1);
            if (seg.length > 0 && (await timingSafeEqualStr(seg, masterKey))) {
              return lastSlash === 0 ? "/" : cleanPath.slice(0, lastSlash);
            }
          }
          return cleanPath;
        }
      }
    }
    const lastSlash = cleanPath.lastIndexOf("/");
    if (lastSlash !== -1) {
      const seg = cleanPath.slice(lastSlash + 1);
      const base = lastSlash === 0 ? "/" : cleanPath.slice(0, lastSlash);
      if (seg.length > 0) {
        const match = await timingSafeEqualStr(seg, masterKey);
        if (match) {
          if (request) request.authRole = "admin";
          return base;
        }
      }
    }
  }
  const tokenSecret = env.DNS_TOKEN_SECRET;
  if (typeof tokenSecret !== "string" || tokenSecret.length === 0) {
    _log("admin_no_auth_configured", { path: cleanPath });
    return null;
  }
  const lastSlash = cleanPath.lastIndexOf("/");
  let token = lastSlash !== -1 ? cleanPath.slice(lastSlash + 1) : "";
  let base = lastSlash === 0 ? "/" : (lastSlash !== -1 ? cleanPath.slice(0, lastSlash) : cleanPath);

  // Support tokens supplied in Authorization Bearer or X-Auth-Key/X-Api-Key headers
  if (token.length !== 80 && token.length !== 72) {
    const authH = request?.headers?.get("authorization");
    const bearerTok = authH?.startsWith("Bearer ") ? authH.slice(7).trim() : null;
    const customTok = request?.headers?.get("x-api-key") || request?.headers?.get("x-auth-key");
    const candidateTok = bearerTok || customTok;
    if (candidateTok && (candidateTok.length === 80 || candidateTok.length === 72)) {
      token = candidateTok;
      base = cleanPath;
    } else {
      return null;
    }
  }

  let ts = 0;
  let ttl = 7200;
  let tsHex = "";
  let ttlHex = "";
  let sigHex = "";

  if (token.length === 80) {
    tsHex = token.slice(0, 8);
    ttlHex = token.slice(8, 16);
    sigHex = token.slice(16);
    if (!/^[0-9a-f]{8}$/.test(tsHex) || !/^[0-9a-f]{8}$/.test(ttlHex) || !/^[0-9a-f]{64}$/.test(sigHex))
      return null;
    ts = parseInt(tsHex, 16);
    ttl = parseInt(ttlHex, 16);
  } else if (token.length === 72) {
    tsHex = token.slice(0, 8);
    sigHex = token.slice(8);
    if (!/^[0-9a-f]{8}$/.test(tsHex) || !/^[0-9a-f]{64}$/.test(sigHex))
      return null;
    ts = parseInt(tsHex, 16);
    ttl = HMAC_WINDOW_S;
  } else {
    return null;
  }

  const nowS = Math.floor(Date.now() / 1e3);
  if (nowS < ts - 60 || nowS > ts + ttl) return null;

  const sigBuf = new Uint8Array(32);
  for (let i = 0; i < 32; i++)
    sigBuf[i] = parseInt(sigHex.slice(i * 2, i * 2 + 2), 16);

  const hmacKey = await _getHmacKey(env);

  // 1. Check VIEW_ONLY scope: Allows dashboard and any GET/HEAD endpoints
  const okView = await crypto.subtle.verify(
    "HMAC",
    hmacKey,
    sigBuf,
    _enc.encode(tsHex + (ttlHex || "") + "VIEW_ONLY"),
  );
  if (okView) {
    if (request) request.authRole = "view";
    return base;
  }

  // 2. Check exact path scope (e.g. tsHex + ttlHex + base)
  const okPath = await crypto.subtle.verify(
    "HMAC",
    hmacKey,
    sigBuf,
    _enc.encode(tsHex + (ttlHex || "") + base),
  );
  if (okPath) {
    if (request) request.authRole = "view";
    return base;
  }

  // 3. Fallback for legacy tokens signed with "/"
  if (base.startsWith("/api/")) {
    const okRoot = await crypto.subtle.verify(
      "HMAC",
      hmacKey,
      sigBuf,
      _enc.encode(tsHex + (ttlHex || "") + "/"),
    );
    if (okRoot) {
      if (request) request.authRole = "view";
      return base;
    }
  }

  return null;
}
export async function generateToken(targetPath, env, ttlSeconds = 86400) {
  const ts = Math.floor(Date.now() / 1e3);
  const tsHex = ts.toString(16).padStart(8, "0");
  const ttlHex = Math.max(60, ttlSeconds).toString(16).padStart(8, "0");
  const scope = (!targetPath || targetPath === "/" || targetPath === "/dashboard") ? "VIEW_ONLY" : targetPath;
  const sig = await crypto.subtle.sign(
    "HMAC",
    await _getHmacKey(env),
    _enc.encode(tsHex + ttlHex + scope),
  );
  return tsHex + ttlHex + bufToHex(sig);
}

export function _heatmapUpdate(domain) {
  const h = new Date().getUTCHours();
  let rec = _heatmap.get(domain);
  if (!rec) {
    if (_heatmap.size >= HEATMAP_MAX)
      _heatmap.delete(_heatmap.keys().next().value);
    rec = { hourly: new Uint16Array(24), total: 0, lastSeen: 0 };
    _heatmap.set(domain, rec);
  }
  if (rec.hourly[h] < 65535) rec.hourly[h]++;
  rec.total++;
  rec.lastSeen = Date.now();
}
export function _adaptiveConfigTick() {
  const _prev = {
    maxCacheTtl: _runtimeConfig.maxCacheTtl,
    cbThreshold: _runtimeConfig.cbThreshold,
    fetchTimeoutMs: _runtimeConfig.fetchTimeoutMs,
    burstThreshold: _runtimeConfig.burstThreshold,
    lbFloodRps: _runtimeConfig.lbFloodRps,
    lbFastRps: _runtimeConfig.lbFastRps,
  };
  let stressProfile;
  if (_stress > 0.8) {
    _runtimeConfig.maxCacheTtl = 7200;
    _runtimeConfig.cbThreshold = 0.65;
    _runtimeConfig.fetchTimeoutMs = 5e3;
    stressProfile = "HIGH_STRESS";
  } else if (_stress > 0.5) {
    _runtimeConfig.maxCacheTtl = 3600;
    _runtimeConfig.cbThreshold = 0.5;
    _runtimeConfig.fetchTimeoutMs = 3e3;
    stressProfile = "MED_STRESS";
  } else {
    _runtimeConfig.maxCacheTtl = 1800;
    _runtimeConfig.cbThreshold = 0.45;
    _runtimeConfig.fetchTimeoutMs = 2500;
    stressProfile = "NORMAL";
  }
  _runtimeConfig.burstThreshold = Math.max(60, Math.round(_rpsSmooth * 3));
  _runtimeConfig.lbFloodRps = Math.max(100, _userEstimate * 2);
  _runtimeConfig.lbFastRps = Math.max(2, Math.round(_userEstimate / 10));
  const changed = {};
  if (_runtimeConfig.maxCacheTtl !== _prev.maxCacheTtl)
    changed.maxCacheTtl = {
      from: _prev.maxCacheTtl,
      to: _runtimeConfig.maxCacheTtl,
    };
  if (_runtimeConfig.cbThreshold !== _prev.cbThreshold)
    changed.cbThreshold = {
      from: _prev.cbThreshold,
      to: _runtimeConfig.cbThreshold,
    };
  if (_runtimeConfig.fetchTimeoutMs !== _prev.fetchTimeoutMs)
    changed.fetchTimeoutMs = {
      from: _prev.fetchTimeoutMs,
      to: _runtimeConfig.fetchTimeoutMs,
    };
  if (_runtimeConfig.burstThreshold !== _prev.burstThreshold)
    changed.burstThreshold = {
      from: _prev.burstThreshold,
      to: _runtimeConfig.burstThreshold,
    };
  if (_runtimeConfig.lbFloodRps !== _prev.lbFloodRps)
    changed.lbFloodRps = {
      from: _prev.lbFloodRps,
      to: _runtimeConfig.lbFloodRps,
    };
  if (_runtimeConfig.lbFastRps !== _prev.lbFastRps)
    changed.lbFastRps = { from: _prev.lbFastRps, to: _runtimeConfig.lbFastRps };
  if (Object.keys(changed).length > 0) {
    const dec = {
      t: Date.now(),
      decision: "config_adapt",
      profile: stressProfile,
      stress: +_stress.toFixed(3),
      rps: +(_rpsSmooth || 0).toFixed(2),
      userEst: +(_userEstimate || 0).toFixed(1),
      changed: changed,
      snapshot: { ..._runtimeConfig },
    };
    _configDecisions.push(dec);
    if (_configDecisions.length > 200) _configDecisions.shift();
    _aiDecisions.push({
      t: dec.t,
      decision: "config_adapt:" + stressProfile,
      factors: {
        stress: dec.stress,
        rps: dec.rps,
        changed: Object.keys(changed).join(","),
        details: changed,
      },
    });
    if (_aiDecisions.length > 100) _aiDecisions.shift();
  }
}
export function _updateUserEstimate() {
  const now = Date.now();
  if (now - _userWinStart < 3e4) return;
  _userWinStart = now;

  // Active sliding window: 5 minutes (300,000 ms) for active devices
  const activeCutoff = now - 300000;
  if (_deviceMap) {
    for (const [k, v] of _deviceMap) {
      if (v.lastSeen < activeCutoff) _deviceMap.delete(k);
    }
  }
  if (_userMap) {
    for (const [k, ts] of _userMap) {
      if (typeof ts === "number" && ts < activeCutoff) _userMap.delete(k);
    }
  }

  const deviceCount = _deviceMap && _deviceMap.size > 0 ? _deviceMap.size : (_userMap?.size || 1);
  _userRing[_userRingIdx] = deviceCount;
  _userRingIdx = (_userRingIdx + 1) % 20;
  _userSamples++;
  if (!_userRingFull && _userRingIdx === 0) _userRingFull = true;
  _userEwmaFast =
    _userEwmaFast === 0 ? deviceCount : 0.35 * deviceCount + 0.65 * _userEwmaFast;
  _userEwmaSlow =
    _userEwmaSlow === 0 ? deviceCount : 0.04 * deviceCount + 0.96 * _userEwmaSlow;
  _userPeak = Math.max(_userPeak * 0.997, deviceCount);
  if (_userModeAuto) {
    const kfEst = _kf.update(deviceCount);
    const n = _userRingFull ? 20 : Math.max(1, _userRingIdx);
    const sorted = [..._userRing.slice(0, n)].sort((a, b) => a - b);
    const median = sorted[Math.floor(n / 2)] || deviceCount;
    const blend = Math.min(0.8, _userSamples / 20);
    _userEstimate = Math.max(
      1,
      Math.round(blend * kfEst + (1 - blend) * median),
    );
    _anomaly.update(deviceCount);
  }
  _ctx?.waitUntil(
    kvPut(
      "ai:user:state",
      { kf: { x: _kf.x, P: _kf.P }, estimate: _userEstimate, devices: deviceCount },
      300,
    ),
  );
}

export function getActiveDeviceCount() {
  return _deviceMap && _deviceMap.size > 0 ? _deviceMap.size : 1;
}

export function getActiveIpCount() {
  return _userMap && _userMap.size > 0 ? _userMap.size : 1;
}
export function _memCheck() {
  const MAX_MAP_SIZE = 5e3;
  const maps = [_burstMap, _fpMap, _clientNX, _cacheTimings, _ttlHistory];
  maps.forEach((m) => {
    if (m.size > MAX_MAP_SIZE) {
      const iter = m.keys();
      for (let i = 0; i < 500; i++) m.delete(iter.next().value);
    }
  });
  if (_heatmap.size > 1500) {
    let count = 0;
    for (const [k] of _heatmap) {
      _heatmap.delete(k);
      if (++count >= 300) break;
    }
  }
  if (_gsbCache.size > GSB_CACHE_MAX * 0.9) {
    let c = 0;
    for (const k of _gsbCache.keys()) {
      _gsbCache.delete(k);
      if (++c >= 500) break;
    }
  }
  if (_feedCache.size > FEED_CACHE_MAX * 0.9) {
    let c = 0;
    for (const k of _feedCache.keys()) {
      _feedCache.delete(k);
      if (++c >= 500) break;
    }
  }
  if (_negCache.size > NEG_MAX * 0.9) {
    const now = Date.now();
    for (const [k, v] of _negCache) if (v.exp < now) _negCache.delete(k);
    if (_negCache.size > NEG_MAX * 0.9) {
      let count = 0;
      for (const [k] of _negCache) {
        _negCache.delete(k);
        if (++count >= 500) break;
      }
    }
  }
  if (_answerHistory.size > 5e3) {
    let count = 0;
    for (const k of _answerHistory.keys()) {
      _answerHistory.delete(k);
      if (++count >= 1e3) break;
    }
  }
  if (_swarmMap.size > 3e3) {
    let count = 0;
    for (const k of _swarmMap.keys()) {
      _swarmMap.delete(k);
      if (++count >= 1e3) break;
    }
  }
}
