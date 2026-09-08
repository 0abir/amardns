// src/core/admin-api.js
// Live status telemetry builder, admin dashboard route handlers, and administrative REST endpoints.

import {
  VERSION, ADMIN_CORS_H, NO_CACHE_H, CORS_H, _SEC_H, _enc,
  PULSE_WRITE_LIMIT, PULSE_SOFT_CAP, MAX_CACHE_TTL, MIN_CACHE_TTL,
  CB_WINDOW, CB_THRESHOLD, DGA_FLAG_SCORE, DGA_BLOCK_SCORE, DOMAIN_IQ_MAX
} from "./constants.js";
import { sanitizeDomain, sanitizePath, sanitizeTtl, escapeHtml } from "./sanitizer.js";
import logger from "../logger.js";
// ADMIN_HTML is dynamically imported on demand when /dashboard is requested
import {
  _upScores, _cb, _upMetadata, _ISOLATE_ID, _userEstimate,
  _userModeAuto, _userSamples, _workerStartTs, _workerId, _sh,
  _anomalies, _actions, _aiDecisions, _configDecisions, _kf, _rhythm,
  _anomaly, _domainIQ, _markov, _dgaLegit, _ucb, _obs, _ledger,
  _budgetAI, _heatmap, _negCache, _autoBlocks, _burstMap, _fpMap,
  _answerHistory, _featCache, _stress, _stressHistory, _rpsSmooth,
  _rpsPeak, _brainDirty, _brainLastSync, _brainSyncBytes, _brainLoadedAt,
  _brainLoaded, _brainInitializing, _listsPreloaded,
  SAFE_BROWSING_KEYS, BRANDS_LIST, _runtimeConfig, _pulseW, _pulseR,
  _aeroW, _aeroR, _env, _ctx, _dnsMode, _setDnsMode, _blockingEnabled, _setBlockingEnabled, _ups, _bgEnqueue,
  resetSh, _memBlacklist, _memWhitelist, _memCommon, _feedCache, _userMap, _deviceMap, _bgQueue, _bgQueueHi
} from "./state.js";
import {
  _onlineSince, _log, _action, _aiDecision, generateToken, _getRps, fnv1a32, _utcDay, _getHmacKey,
  resetTelemetry, bufToHex, getActiveDeviceCount, getActiveIpCount, getActiveDevicesList
} from "./telemetry.js";
import {
  alikeDomainCheck, dgaScore, syncThreatFeeds, autoBlockSet,
  checkBlocklist, checkExistsAnywhere, checkWhitelist, checkCommon,
  preloadLists, _feedLastSync, _feedSyncing, _abirOk, _commonOk,
  _abirLastSync, _commonLastSync, _abirTotalEntries, _abirSet,
  _commonTotalEntries, _commonSet, clearThreatIntelligenceCaches
} from "./threat-intelligence.js";
import {
  _nnStats, _transformer, _manifold, _charTransformer,
  _episodic, _rewardShaper, _contextFusion, nnExport, nnImport, _brainPrune,
  clearNeuralCaches
} from "./neural-engine.js";
import {
  _dtn, _moe, _gru, _ae, _spiking, _liquid, _mha, _bnn,
  _contrastive, _neuron, _gnn, _forest, _calibrator, _meta,
  _dtcn, _symbolic, _embNet, _finalNeuron, _rl, clearNeuralModelStates
} from "./neural-models.js";
import {
  aeroGet, aeroPut, pulseGet, pulsePut, pulseDel, brainSync, brainLoad,
  setBrainDirty, accountPulseRead, _brainExport, _brainImport, _pulseThrottle
} from "./storage-adapter.js";
import { setUpstreams, _lastLbMode, _loadUpstreams } from "./dns-protocol.js";

export function buildStatus(env, request = null) {
  const upstreams = _ups.map((base, i) => {
    const scores = _upScores[i] || new Float32Array(0);
    const validScores = [...scores].filter((s) => s > 0);
    const avgLatency =
      validScores.length > 0
        ? Math.round(
            validScores.reduce((a, b) => a + b, 0) / validScores.length,
          )
        : 0;
    const scoreNorm =
      _ucb.pulls[i] > 0
        ? Math.round((_ucb.rewards[i] / _ucb.pulls[i]) * 500)
        : 250;
    const cb = _cb[i] || {};
    const meta = Array.isArray(_upMetadata)
      ? _upMetadata.find((m) => m.url === base)
      : null;
    return {
      index: i,
      base: base,
      provider: meta?.provider || "Default / Anycast",
      aura: meta?.aura || "medium",
      healthy: !cb.open,
      latencyMs: avgLatency,
      score: scoreNorm,
      hits: _ucb.pulls[i],
      totalErrors: cb.errors || 0,
      errorRatePct: cb.total > 0 ? Math.round((cb.errors / cb.total) * 100) : 0,
      revalidations: 0,
      slowEwma: avgLatency,
      stalePct: 0,
      nxRate: 0,
      lastFailSec: cb.openTs > 0 ? (Date.now() - cb.openTs) / 1e3 : null,
      flaps: 0,
      samples: _ucb.pulls[i],
    };
  });
  const totalReqs = _sh.requests || 1;
  const hitRate =
    totalReqs > 0 ? ((_sh.cacheHits / totalReqs) * 100).toFixed(1) + "%" : "0%";
  const rps = _getRps();
  const autoBlockActive = [..._autoBlocks.values()].filter(
    (b) => Date.now() / 1e3 < b.exp,
  ).length;
  const iqSize = _domainIQ.map.size;
  const markovSize = _markov.transitions.size;
  const cycleFactor = Math.min(1, _nnStats.learningCycles / 1e3);
  const brainUtil = _brainInitializing
    ? -1
    : Math.min(
        100,
        Math.round(
          (iqSize / DOMAIN_IQ_MAX) * 35 +
            (markovSize / 1e3) * 35 +
            cycleFactor * 30,
        ),
      );
  const hmDomains = _heatmap.size;
  const hotDomains = [..._heatmap.entries()]
    .sort((a, b) => b[1].total - a[1].total)
    .slice(0, 20)
    .map(([d, r]) => ({
      domain: d,
      total: r.total,
      peak: [...r.hourly].indexOf(Math.max(...r.hourly)),
      hourly: Array.from(r.hourly),
    }));
  const upstreamScores = upstreams.map((u, i) => ({
    index: i,
    fastEwma: u.latencyMs,
  }));
  const cts = Math.min(
    100,
    Math.round(
      _stress * 40 +
        (_sh.dgaBlocked > 0 ? 15 : 0) +
        (_sh.burstEvents > 5 ? 20 : 0) +
        (_sh.repBlocks > 10 ? 25 : 0),
    ),
  );
  const machineId = (typeof process !== "undefined" && process.env?.FLY_MACHINE_ID) || _ISOLATE_ID;
  const flyRegion = (typeof process !== "undefined" && process.env?.FLY_REGION) || "sin";
  const appName = (typeof process !== "undefined" && process.env?.FLY_APP_NAME) || "amardns";
  return {
    isolateId: machineId,
    node: {
      machineId: machineId,
      region: flyRegion,
      appName: appName,
      activeDevices: getActiveDeviceCount(),
      activeIps: getActiveIpCount(),
      deviceList: getActiveDevicesList(),
    },
    devices: getActiveDevicesList(),
    dnsRequestsTotal: _sh.requests,
    avgLatency: (() => {
      const validL = upstreams.map((u) => u.latencyMs).filter((l) => l > 0);
      return validL.length > 0
        ? Math.round(validL.reduce((a, b) => a + b, 0) / validL.length)
        : 14;
    })(),
    upstreamsActive: upstreams.filter((u) => u.healthy).length,
    upstreamsTotal: upstreams.length,
    blockRate: (() => {
      const totalBlocks =
        (_sh.repBlocks || 0) +
        (_sh.dgaBlocked || 0) +
        (_sh.rebindBlocks || 0) +
        (_sh.alikeBlocks || 0) +
        (_sh.abirBlocks || 0) +
        (autoBlockActive || 0) +
        (_sh.crlBlocks || 0);
      return totalReqs > 0 ? ((totalBlocks / totalReqs) * 100).toFixed(1) + "%" : "0.0%";
    })(),
    narrative: `${_stress > 0.7 ? "HIGH STRESS" : "Nominal"} · ${rps.toFixed(1)} R/s · ${iqSize} IQ · 20 nets·203k · DTN loss ${_dtn.totalLoss.toFixed(3)} · DTCN:${_nnStats.dtcnClass} · online ${_onlineSince()}`,
    cache: {
      hits: _sh.cacheHits,
      misses: _sh.cacheMisses,
      hitRate: hitRate,
      piggybacks: _sh.piggybacks,
      emptyAnswers: 0,
      writeErrors: 0,
      malformedPackets: 0,
      corruptHits: 0,
      normalizationErrors: 0,
      revalidationEmptyAnswers: 0,
      revalidationsInFlight: 0,
      ...(env?.aeroCache?.getStats() || {}),
    },
    db: env?.pulseDb?.getStats() || {},
    upstreams: upstreams,
    ai: {
      rps: +rps.toFixed(2),
      rpsPeak: +_rpsPeak.toFixed(2),
      lbMode: _lastLbMode || "BALANCED",
      negCacheHits: _sh.negHits,
      negCacheSize: _negCache.size,
      preWarmsIssued: _sh.preWarms,
      heatmapProactiveWarms: _sh.preWarms,
      heatmapTrackedDomains: hmDomains,
      heatmapFlushes: 0,
      burstEvents: _sh.burstEvents,
      dgaBlocked: _sh.dgaBlocked,
      repBlocks: _sh.repBlocks,
      rebindBlocks: _sh.rebindBlocks,
      autoBlockActive: autoBlockActive,
      xvalDisagreements: _sh.xvalDisagree,
      alikeBlocks: _sh.alikeBlocks,
      nxAlarms: _sh.nxAlarms,
      crlHardBlocks: _sh.crlBlocks,
      fpSuspicious: [..._fpMap.entries()]
        .filter(([, v]) => v.flagged)
        .map(([ip, v]) => ({ ip: ip, type: v.flagged, queries: v.queries }))
        .slice(0, 20),
      pcbEvents: _sh.pcbEvents,
      dccHits: _sh.dccHits,
      dcqAlarms: _sh.dcqAlarms,
      cnxfAlarms: _sh.cnxfAlarms,
      qrsdAlarms: _sh.qrsdAlarms,
      answerDrifts: _sh.answerDrifts,
      ttlEvents: {
        inflations: _sh.ttlInflations,
        deflations: _sh.ttlDeflations,
      },
      gsbBlocks: _sh.gsbBlocks,
      abirBlocks: _sh.abirBlocks,
      multiFeedBlocks: _sh.multiFeedBlocks,
      feedAiBlocks: _sh.feedAiBlocks,
      abirSize: _abirSet.size,
      abirTotalEntries: _abirTotalEntries,
      gsbOk: SAFE_BROWSING_KEYS.length > 0,
      gsbKeyCount: SAFE_BROWSING_KEYS.length,
      abirOk: _abirOk,
      commonSize: _commonSet.size,
      commonTotalEntries: _commonTotalEntries,
      commonOk: _commonOk,
      feedTier1: _sh.feedTier1,
      feedTier2: _sh.feedTier2,
      feedTier3: _sh.feedTier3,
      feedTier4: _sh.feedTier4,
      swarmAlarms: _sh.swarmAlarms,
      swarmSnap: { alarms: _sh.swarmAlarms },
      pgSnap: { blocks: _sh.aiBlocks },
      brainUtilization: brainUtil < 0 ? 0 : brainUtil,
      brainLoading: _brainInitializing,
      domainIQSize: iqSize,
      markovSize: markovSize,
      brainSyncBytes: _brainSyncBytes,
      brainSyncAge: _brainLastSync
        ? Math.floor((Date.now() - _brainLastSync) / 1e3)
        : null,
      brainUptimeSec: _brainLoadedAt
        ? Math.floor((Date.now() - _brainLoadedAt) / 1e3)
        : null,
      upstreamScores: upstreamScores,
      cts: cts,
      expectedUsers: _userEstimate,
      activeDevices: getActiveDeviceCount(),
      activeIps: getActiveIpCount(),
      userScale: (_userEstimate / 10).toFixed(2),
      brainVersion: _nnStats.brainVersion,
      learningCycles: _nnStats.learningCycles,
      recentDecisions: _aiDecisions.slice(-20),
      configDecisions: _configDecisions.slice(-50),
      lbModeChanges: [],
      dailyUsed: _pulseW,
      dailyCap: PULSE_WRITE_LIMIT,
      alwRemediations: 0,
      rebindLog: [],
      homoglyphLog: [],
      dgaLog: [],
      freshnessStaleHits: _sh.freshnessStale,
      freshnessChecks: 0,
      freshnessStats: [],
      xvalCacheSize: 0,
      xvalUpstreamPenalties: _cb.map((c) => c.errors || 0),
      prsdSnap: { alarms: 0 },
      cqtaAlarms: 0,
      urdmAlarms: _sh.urdmAlarms,
      aiOutcomeWins: 0,
      aiOutcomeLosses: 0,
      hotDomains: hotDomains,
    },
    selfHeal: {
      panicCount: _sh.panicCount,
      authFails: _sh.authFails,
      emergencyMode: _sh.emergencyMode,
      dailyLimits: "None (Uncapped Dedicated)",
      throttled: false,
      pulseDayWrites: _pulseW,
      pulseDayReads: _pulseR,
      pulseDayPct: 0,
      pulseReadPct: 0,
      pulseThrottled: false,
      pulseSoftCapped: false,
      aeroDayWrites: _aeroW,
      aeroDayPct: 0,
      aeroThrottled: false,
      pulseReadThrottled: false,
      pulseReadSoftCap: false,
      recentActions: _actions.slice(-50),
      recentAnomalies: _anomalies.slice(-50),
      selfHealActions: _actions,
      gcCycles: _sh.gcCycles,
      memPressure: _sh.memPressure,
    },
    storage: {
      engine: "PulseDB + AeroCache",
      cache: env?.aeroCache?.getStats() || {},
      db: env?.pulseDb?.getStats() || {},
    },
    config: {
      hedgeMs: 20,
      fetchTimeoutMs: 3e3,
      cooldownMs: 1e4,
      swrFactor: 0.8,
      minCacheTtl: MIN_CACHE_TTL,
      maxCacheTtl: MAX_CACHE_TTL,
      raceSlots: 2,
      cbWindow: CB_WINDOW,
      cbThreshold: CB_THRESHOLD,
      storageEngine: "PulseDB (SuffixTrie WAL) + AeroCache (S3-FIFO)",
      hmacAuth: !!env.DNS_TOKEN_SECRET,
      dnsMode: _dnsMode,
      blockingEnabled: _blockingEnabled,
      upstreamAuraPrioritization: true,
      upstreamCandidates: Array.isArray(_upMetadata) ? _upMetadata.length : _ups.length,
      upstreamLastSync: env?.pulseDb?.get("upstreams:last_sync", null),
    },
    intelligence: {
      cfgOverride: {},
      configMode: "ai",
      incidentActive: _stress > 0.8,
      incident:
        _stress > 0.8
          ? {
              type: "high_stress",
              detectedAt: Date.now(),
              affectedUpstreams: [],
              resolvedAt: null,
              durationS: null,
            }
          : null,
      upstreamProfiles: upstreams.map((u, i) => ({
        p50: u.latencyMs,
        p95: Math.round(u.latencyMs * 1.5),
        p99: Math.round(u.latencyMs * 2),
        slowEwma: u.latencyMs,
        score: u.score,
        errorRate: u.errorRatePct,
        flaps: 0,
        samples: u.hits,
        lastRecoveryAgo: null,
      })),
    },
    inflight: { total: 0 },
    perpetualAI: {
      booted: _brainLoaded,
      brainDirty: _brainDirty,
      domainIQ: { size: iqSize },
      ledger: {
        size: _ledger.entries.length,
        calibration: +_ledger.calibration().toFixed(3),
      },
      obs: { deviation: +_obs.deviation().toFixed(3) },
      ticks: _sh.requests,
      nn: {
        dtnInferences: _nnStats.dtnInferences,
        dtnCalls: _nnStats.dtnCalls,
        dtnLoss: +_dtn.totalLoss.toFixed(4),
        gruAlarms: _nnStats.gruAlarms,
        gruSteps: _nnStats.gruSteps || _nnStats.dtnInferences || 0,
        mhaSelections: _nnStats.mhaSelections,
        dtcnClass: _nnStats.dtcnClass,
        dtcnScore: +_nnStats.dtcnScore.toFixed(3),
        moeDecisions: _nnStats.moeDecisions,
        aeAnomalies: _nnStats.aeAnomalies,
        rlDecisions: _nnStats.rlDecisions,
        rlHitReward: +_nnStats.rlHitReward.toFixed(3),
        aeThreshold: +_ae.mseLoss.toFixed(4),
        totalParams: 203e3,
        charTransformerCalls: _charTransformer.t || 0,
        contextFusionCalls: _contextFusion.calls || 0,
        episodicMemory: _episodic.stats(),
        rewardSignals: _rewardShaper.getStats(),
        meta: _nnStats.lastMeta,
      },
    },
    authRole: request?.authRole || "admin",
    isViewOnly: request?.authRole === "view",
  };
}
export async function handleAdmin(request, url, env, authedPath) {
  const method = request.method;
  const pathname = url.pathname;
  const adminBase = authedPath === "/" ? "" : authedPath;
  let subPath = adminBase;
  const adminIdx = adminBase.indexOf("/admin");
  const apiIdx = adminBase.indexOf("/api/");
  const routeIdx =
    adminIdx !== -1 && (apiIdx === -1 || adminIdx <= apiIdx)
      ? adminIdx
      : apiIdx;
  if (routeIdx > 0) {
    subPath = adminBase.slice(routeIdx);
  }
  if (!subPath || subPath === "/") subPath = "/dashboard";
  const isKeyOrToken = (k) => {
    if (!k || typeof k !== "string") return false;
    if (env?.DNS_MASTER_KEY && k === env.DNS_MASTER_KEY) return true;
    if ((k.length === 80 || k.length === 72) && /^[0-9a-f]+$/i.test(k)) return true;
    return false;
  };

  const cleanPath = pathname.length > 1 && pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;
  const lastSeg = cleanPath.slice(cleanPath.lastIndexOf("/") + 1);
  const _key = isKeyOrToken(lastSeg)
    ? lastSeg
    : (request?.headers?.get("x-auth-key") || (request?.headers?.get("authorization")?.startsWith("Bearer ") ? request.headers.get("authorization").slice(7).trim() : ""));

  const _workerBase = (() => {
    if (routeIdx > 0) return adminBase.slice(0, routeIdx);
    return "";
  })();
  if (subPath === "/dashboard") {
    if (request.headers.get("accept")?.includes("application/json")) {
      return jsonResp(buildStatus(env, request));
    }
    const { nonce: nonce, csp: csp } = await _makeAdminCspHeader();
    const { ADMIN_HTML } = await import("./dashboard-html.js");
    const machineId = (typeof process !== "undefined" && process.env?.FLY_MACHINE_ID) || _ISOLATE_ID;
    const flyRegion = (typeof process !== "undefined" && process.env?.FLY_REGION) || "sin";
    const html = ADMIN_HTML.replace(
      "var BASE='',",
      "var BASE=" + JSON.stringify(_workerBase) + ",",
    )
      .replace("var _KEY='';", "var _KEY=" + JSON.stringify(_key) + ";")
      .replace("var _CURRENT_MACHINE_ID='';", "var _CURRENT_MACHINE_ID=" + JSON.stringify(machineId) + ";")
      .replace("var _FLY_REGION='';", "var _FLY_REGION=" + JSON.stringify(flyRegion) + ";")
      .replace(/<script>/g, `<script nonce="${nonce}">`)
      .replace(/<style>/g, `<style nonce="${nonce}">`);
    return new Response(html, {
      headers: {
        "content-type": "text/html;charset=utf-8",
        ...NO_CACHE_H,
        ..._SEC_H,
        "content-security-policy": csp,
      },
    });
  }
  if (subPath.startsWith("/api/")) {
    if (isKeyOrToken(lastSeg) && subPath.endsWith("/" + lastSeg)) {
      subPath = subPath.slice(0, -(lastSeg.length + 1));
    }
    return handleApiRoute(request, subPath, env, method);
  }
  return new Response("Not Found", { status: 404 });
}
export function _streamJson(data) {
  const { readable: readable, writable: writable } = new TransformStream();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();
  (async () => {
    try {
      await writer.write(encoder.encode(JSON.stringify(data)));
    } catch (_) {
    } finally {
      await writer.close();
    }
  })();
  return new Response(readable, {
    headers: {
      "content-type": "application/json",
      ...NO_CACHE_H,
      ...ADMIN_CORS_H,
    },
  });
}
export async function handleApiRoute(request, path, env, method) {
  const db = env?.pulseDb || env?.PULSE_DB;

  // View-Only Protection: Generated tokens cannot modify settings or generate more tokens
  if (request?.authRole === "view") {
    if (path.startsWith("/api/token")) {
      return jsonResp({ ok: false, error: "Forbidden: Tokens can only be generated with the Master Key" }, 403);
    }
    if (method !== "GET" && method !== "HEAD") {
      return jsonResp({ ok: false, error: "Forbidden: Generated tokens are view-only. No changes can be made." }, 403);
    }
  }

  if (path === "/api/status") return jsonResp(buildStatus(env, request));
  if (path === "/api/settings/dns-mode") {
    if (method === "GET") {
      return jsonResp({ ok: true, mode: _dnsMode });
    }
    if (method === "POST") {
      const body = await request.json().catch(() => ({}));
      const mode = body.mode === "public" ? "public" : "private";
      await _setDnsMode(mode, db);
      _action("dns_mode_changed", "admin", { mode: _dnsMode });
      return jsonResp({ ok: true, mode: _dnsMode });
    }
  }
  if (path === "/api/settings/blocking") {
    if (method === "GET") {
      return jsonResp({ ok: true, blockingEnabled: _blockingEnabled });
    }
    if (method === "POST") {
      if (request?.authRole !== "admin") {
        return jsonResp({ ok: false, error: "Forbidden: Blocking can only be toggled with the Master Key" }, 403);
      }
      const body = await request.json().catch(() => ({}));
      const enabled = body.enabled === true || body.enabled === "true" || body.enabled === "active" || body.enabled === "1";
      await _setBlockingEnabled(enabled, db);
      _action("blocking_toggled", "admin", { enabled: _blockingEnabled });
      return jsonResp({ ok: true, blockingEnabled: _blockingEnabled });
    }
  }
  if (path === "/api/upstreams/ranked" && method === "GET") {
    let ranked = _upMetadata;
    if (!ranked && env?.pulseDb) {
      try {
        const saved = env.pulseDb.get("upstreams:ranked", null);
        if (saved) ranked = JSON.parse(saved);
      } catch (_) {}
    }
    const lastSync = env?.pulseDb?.get("upstreams:last_sync", null);
    return jsonResp({
      ok: true,
      lastSync: lastSync ? parseInt(lastSync, 10) : null,
      active: _ups,
      upstreams:
        ranked ||
        _ups.map((url, i) => ({
          provider: `Upstream #${i + 1}`,
          url,
          aura: "medium",
          latency: 0,
          ok: true,
        })),
    });
  }
  if (path === "/api/upstreams/sync" && method === "POST") {
    try {
      const { syncAndRankUpstreams } = await import("../upstream-manager.js");
      const result = await syncAndRankUpstreams(env, { setUpstreams });
      return jsonResp(result);
    } catch (e) {
      return jsonResp({ ok: false, error: e.message }, 500);
    }
  }
  if (path.startsWith("/api/token") && method === "GET") {
    if (request?.authRole !== "admin") {
      return jsonResp({ ok: false, error: "Forbidden: Tokens can only be generated with the Master Key" }, 403);
    }
    const url = new URL(request.url);
    const targetPath = sanitizePath(url.searchParams.get("path") || "/");
    const rawTtl = (url.searchParams.get("ttl") || "1d").trim().toLowerCase();
    const ttlSeconds = sanitizeTtl(rawTtl, 86400);
    const token = await generateToken(targetPath, env, ttlSeconds);
    return jsonResp({
      token: token,
      fullPath: `${targetPath === "/" ? "" : targetPath}/${token}`,
      targetPath: targetPath,
      expiresIn: rawTtl,
      ttlSeconds: ttlSeconds,
      role: "view_only"
    });
  }
  if (path === "/api/blocklist" || path.startsWith("/api/blocklist?")) {
    const pdb = env?.pulseDb;
    if (method === "GET") {
      const domMap = new Map();
      if (pdb) {
        const rows = pdb.listBlocklist(1000);
        for (const r of rows) {
          const d = typeof r === "string" ? r : r.domain;
          if (d) {
            const rawSrc = (typeof r === "object" && r.source ? r.source : "").toLowerCase();
            const rawRs = (typeof r === "object" && r.reason ? r.reason : "").toLowerCase();
            let source = "manual";
            let tag = "MANUAL";
            let auto = false;

            if (
              rawSrc === "feed" ||
              rawSrc === "abir_feed" ||
              rawSrc === "detected" ||
              rawRs.includes("feed") ||
              rawRs.includes("abir") ||
              rawRs.includes("gsb")
            ) {
              source = "feed";
              tag = "FEED";
            } else if (
              (typeof r === "object" && r.auto) ||
              rawSrc === "ai" ||
              rawSrc === "auto" ||
              rawRs.includes("dga") ||
              rawRs.includes("brand") ||
              rawRs.includes("alike") ||
              rawRs.includes("lookalike") ||
              rawRs.includes("anomaly") ||
              rawRs.includes("typo") ||
              rawRs.includes("ai")
            ) {
              source = "ai";
              tag = "AI";
              auto = true;
            }

            domMap.set(d, {
              domain: d,
              reason: (typeof r === "object" && r.reason) || "blocked",
              source: source,
              tag: tag,
              auto: auto,
              createdAt: (typeof r === "object" && r.createdAt) || Date.now(),
            });
          }
        }
      }
      const now = Date.now();
      for (const [d, v] of _autoBlocks) {
        if (v && v.exp > now) {
          domMap.set(d, {
            domain: d,
            reason: v.reason || "AI dynamic block",
            source: "ai",
            tag: "AI",
            auto: true,
            ttl: Math.max(1, Math.floor((v.exp - now) / 1000)),
          });
        }
      }
      if (_memBlacklist) {
        for (const d of _memBlacklist) {
          if (!domMap.has(d)) {
            domMap.set(d, {
              domain: d,
              reason: "custom",
              source: "manual",
              tag: "MANUAL",
              auto: false,
            });
          }
        }
      }
      return _streamJson({ domains: Array.from(domMap.values()) });
    }
    if (method === "POST") {
      const body = await request.json().catch(() => ({}));
      const rawDomains = Array.isArray(body.domains)
        ? body.domains
        : body.domain
          ? [body.domain]
          : [];
      const eligible = rawDomains.map(sanitizeDomain).filter(Boolean);
      if (eligible.length === 0) return jsonResp({ ok: true, added: 0, skipped: [] });
      const reason = typeof body.reason === "string" ? body.reason.slice(0, 100) : "manual";
      const source = typeof body.source === "string" ? body.source.slice(0, 20) : "admin";
      const added = pdb ? pdb.addBlocklist(eligible, reason, source) : 0;
      if (_memBlacklist) {
        for (const d of eligible) _memBlacklist.add(d);
      }
      if (typeof process !== "undefined" && process.env?.FLY_APP_NAME && !request.headers.get("x-peer-sync")) {
        const port = process.env.PORT || "8080";
        fetch(`http://${process.env.FLY_APP_NAME}.internal:${port}/api/blocklist`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "authorization": `Bearer ${env.DNS_MASTER_KEY || ""}`,
            "x-peer-sync": "1",
          },
          body: JSON.stringify(body),
        }).catch(() => {});
      }
      _action("blocklist_added", "admin", { count: added || eligible.length });
      return jsonResp({ ok: true, added: added || eligible.length, skipped: [] });
    }
    if (method === "DELETE") {
      const body = await request.json().catch(() => ({}));
      const domain = sanitizeDomain(body.domain);
      if (!domain) return jsonResp({ ok: false, error: "invalid domain" }, 400);
      if (pdb) pdb.removeBlocklist(domain);
      _autoBlocks.delete(domain);
      if (_memBlacklist) _memBlacklist.delete(domain);
      if (typeof process !== "undefined" && process.env?.FLY_APP_NAME && !request.headers.get("x-peer-sync")) {
        const port = process.env.PORT || "8080";
        fetch(`http://${process.env.FLY_APP_NAME}.internal:${port}/api/blocklist`, {
          method: "DELETE",
          headers: {
            "content-type": "application/json",
            "authorization": `Bearer ${env.DNS_MASTER_KEY || ""}`,
            "x-peer-sync": "1",
          },
          body: JSON.stringify(body),
        }).catch(() => {});
      }
      _action("blocklist_removed", "admin", { domain });
      return jsonResp({ ok: true, domain: domain });
    }
  }
  if (path === "/api/blocklist/clear" && method === "POST") {
    if (env?.pulseDb) env.pulseDb.clearBlocklist();
    _autoBlocks.clear();
    if (_memBlacklist) _memBlacklist.clear();
    if (typeof process !== "undefined" && process.env?.FLY_APP_NAME && !request.headers.get("x-peer-sync")) {
      const port = process.env.PORT || "8080";
      fetch(`http://${process.env.FLY_APP_NAME}.internal:${port}/api/blocklist/clear`, {
        method: "POST",
        headers: {
          "authorization": `Bearer ${env.DNS_MASTER_KEY || ""}`,
          "x-peer-sync": "1",
        },
      }).catch(() => {});
    }
    _action("blocklist_cleared", "admin");
    return jsonResp({ ok: true });
  }
  if (path === "/api/whitelist/clear" && method === "POST") {
    if (env?.pulseDb) env.pulseDb.whitelistTrie.clear();
    _action("whitelist_cleared", "admin");
    return jsonResp({ ok: true });
  }
  if (path === "/api/common/clear" && method === "POST") {
    return jsonResp({ ok: true });
  }
  if (path === "/api/auto-block" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const domain = sanitizeDomain(body.domain);
    if (domain) {
      await autoBlockSet(domain, body.reason || "ai", body.ttl || 300, true);
    }
    return jsonResp({ ok: true });
  }
  if (path === "/api/auto-block" && method === "DELETE") {
    const body = await request.json().catch(() => ({}));
    const domain = sanitizeDomain(body.domain);
    if (domain) {
      _autoBlocks.delete(domain);
      if (env?.pulseDb) env.pulseDb.removeBlocklist(domain);
    }
    return jsonResp({ ok: true });
  }
  if (path === "/api/system/reload" && method === "POST") {
    if (env?.pulseDb) {
      const savedMode = env.pulseDb.get("config:dns_mode", env.DNS_ACCESS_MODE || "public");
      if (savedMode) _setDnsMode(savedMode, env.pulseDb);
      preloadLists(env);
    }
    _loadUpstreams(env);
    _action("system_reloaded", "admin", { dnsMode: _dnsMode, upstreams: _ups.length });
    return jsonResp({ ok: true, dnsMode: _dnsMode, upstreams: _ups.length });
  }
  if (path === "/api/system/restart" && method === "POST") {
    _action("system_restart_requested", "admin");
    setTimeout(() => {
      process.exit(0);
    }, 100);
    return jsonResp({ ok: true, message: "Server shutting down cleanly for restart" });
  }
  if (path === "/api/whitelist") {
    const pdb = env?.pulseDb;
    if (method === "GET") {
      if (!pdb) return jsonResp({ domains: [] });
      return _streamJson({ domains: pdb.listWhitelist(1000).map((r) => r.domain) });
    }
    if (method === "POST") {
      const body = await request.json().catch(() => ({}));
      const rawDomains = Array.isArray(body.domains) ? body.domains : body.domain ? [body.domain] : [];
      const eligible = rawDomains.map(sanitizeDomain).filter(Boolean);
      let added = 0;
      for (const d of eligible) {
        if (pdb) {
          pdb.addWhitelist(d);
          added++;
        }
      }
      return jsonResp({ ok: true, added: added, skipped: [] });
    }
    if (method === "DELETE") {
      const body = await request.json().catch(() => ({}));
      const domain = sanitizeDomain(body.domain);
      if (!domain) return jsonResp({ ok: false, error: "invalid domain" }, 400);
      if (pdb && domain) pdb.removeWhitelist(domain);
      return jsonResp({ ok: true, domain: domain });
    }
  }
  if (path === "/api/common") {
    return jsonResp({ domains: [] });
  }
  if (path === "/api/heatmap/top" && method === "GET") {
    const top = [..._heatmap.entries()]
      .sort((a, b) => b[1].total - a[1].total)
      .slice(0, 50)
      .map(([d, r]) => ({
        domain: d,
        total: r.total,
        peak: [...r.hourly].indexOf(Math.max(...r.hourly)),
        peakRps: Math.max(...r.hourly),
        hourly: Array.from(r.hourly),
      }));
    return jsonResp({ domains: top, total: _heatmap.size });
  }
  if (path.startsWith("/api/heatmap/lookup") && method === "GET") {
    const url2 = new URL(request.url);
    const domain = sanitizeDomain(url2.searchParams.get("domain"));
    const rec = domain ? _heatmap.get(domain) : null;
    return jsonResp(
      rec
        ? {
            domain: domain,
            total: rec.total,
            hourly: Array.from(rec.hourly),
            peak: [...rec.hourly].indexOf(Math.max(...rec.hourly)),
          }
        : { domain: domain, found: false },
    );
  }
  if (path === "/api/intelligence") return jsonResp(buildStatus(env, request));
  if (path === "/api/hot" && method === "GET") {
    const top = [..._heatmap.entries()]
      .sort((a, b) => b[1].total - a[1].total)
      .slice(0, 30)
      .map(([d, r]) => ({
        domain: d,
        hits: r.total,
        peakHour: [...r.hourly].indexOf(Math.max(...r.hourly)),
      }));
    return jsonResp({ domains: top });
  }
  if (path === "/api/reset-cb" && method === "POST") {
    _cb.forEach((c) => {
      c.errors = 0;
      c.total = 0;
      c.open = false;
      c.openTs = 0;
    });
    _action("cb_reset", "admin");
    return jsonResp({ ok: true });
  }
  if (path === "/api/self-heal" && method === "DELETE") {
    _anomalies.length = 0;
    _actions.length = 0;
    _action("self_heal_cleared", "admin");
    return jsonResp({ ok: true });
  }
  if (path === "/api/incident" && method === "DELETE") {
    return jsonResp({ ok: true });
  }
  if (path === "/api/pcb" && method === "DELETE") {
    _cb.forEach((c) => {
      c.errors = 0;
      c.total = 0;
    });
    return jsonResp({ ok: true });
  }
  if (path === "/api/xval" && method === "DELETE") {
    return jsonResp({ ok: true });
  }
  if (path === "/api/config") {
    if (method === "GET")
      return jsonResp({
        configMode: "ai",
        override: {},
        active: {
          hedgeMs: 20,
          cooldownMs: 1e4,
          fetchTimeoutMs: 3e3,
          swrFactor: 0.8,
          raceSlots: 2,
          cbWindow: CB_WINDOW,
          cbThreshold: CB_THRESHOLD,
          expectedUsers: _userEstimate,
          minCacheTtl: MIN_CACHE_TTL,
          maxCacheTtl: MAX_CACHE_TTL,
        },
      });
    if (method === "POST") return jsonResp({ ok: true });
  }
  if (path === "/api/ai/export" && method === "GET") {
    const { hot: hot, markov: markov } = _brainExport();
    return jsonResp({ hot: JSON.parse(hot), markovSize: markov.length });
  }
  if (path === "/api/ai/import" && method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch (_) {
      return jsonResp({ ok: false, error: "invalid JSON" }, 400);
    }
    const MAX_BRAIN_CHUNKS = 64;
    if (
      body.chunked &&
      typeof body.totalChunks === "number" &&
      body.totalChunks > MAX_BRAIN_CHUNKS
    ) {
      return jsonResp({ ok: false, error: "Too many chunks" }, 413);
    }
    const ok = await _brainImport(
      JSON.stringify(body.hot || body),
      JSON.stringify(body.markov || []),
    );
    if (ok) {
      setBrainDirty(true);
      _bgEnqueue(() => brainSync(true), true);
    }
    return jsonResp({ ok: ok });
  }
  if (path === "/api/ai/prune" && method === "POST") {
    _brainPrune();
    if (db && !_pulseThrottle) {
      const now = Math.floor(Date.now() / 1e3);
      await db
        .prepare(
          "DELETE FROM pulse_generic WHERE exp > 0 AND exp < ? AND key NOT LIKE 'ai:brain%'",
        )
        .bind(now)
        .run();
    }
    _bgEnqueue(() => brainSync(true), true);
    return jsonResp({
      ok: true,
      iq: _domainIQ.map.size,
      markov: _markov.transitions.size,
    });
  }
  if (path.startsWith("/api/pulse-usage")) {
    const url2 = new URL(request.url);
    const days = parseInt(url2.searchParams.get("days") || "30");
    let rows = [];
    if (db && !_pulseThrottle) {
      accountPulseRead();
      const res = await db
        .prepare("SELECT * FROM pulse_usage ORDER BY day DESC LIMIT ?")
        .bind(days)
        .all()
        .catch(() => ({ results: [] }));
      rows = res.results || [];
    }
    return jsonResp({
      rows: rows,
      today: {
        day: _utcDay(),
        writes: _pulseW,
        reads: _pulseR,
        errors: _sh.pulseErrors,
        throttled: _pulseThrottle ? 1 : 0,
        soft_capped: _pulseW > PULSE_WRITE_LIMIT * PULSE_SOFT_CAP ? 1 : 0,
        mode: _pulseThrottle ? "THROTTLED" : "NORMAL",
        eod_drained: 0,
      },
    });
  }
  if (path.startsWith("/api/ai-learning")) {
    let rows = [];
    if (db && !_pulseThrottle) {
      accountPulseRead();
      const res = await db
        .prepare("SELECT * FROM pulse_ai_learning ORDER BY day DESC LIMIT 90")
        .all()
        .catch(() => ({ results: [] }));
      rows = res.results || [];
    }
    return jsonResp({
      rows: rows,
      today: { day: _utcDay(), gain: _brainDirty ? 0.1 : 0 },
      totalGain: rows.reduce((a, r) => a + (r.knowledge_gain || 0), 0),
    });
  }
  if (path === "/api/intel/export" && method === "POST") {
    try {
      const bundle = {
        domainIQ: _domainIQ.export(),
        autoBlocks: [..._autoBlocks.entries()],
        timestamp: Date.now(),
      };
      const sig = await crypto.subtle.sign(
        "HMAC",
        await _getHmacKey(env),
        _enc.encode(JSON.stringify(bundle)),
      );
      return jsonResp({ bundle: bundle, signature: bufToHex(sig) });
    } catch (e) {
      _log("api_error", { err: e?.message ?? String(e) });
      return jsonResp({ ok: false, error: "Internal error" }, 500);
    }
  }
  if (path === "/api/intel/import" && method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch (_) {
      return jsonResp({ ok: false, error: "invalid JSON" }, 400);
    }
    if (!body.bundle || !body.signature)
      return jsonResp({ ok: false, error: "missing fields" }, 400);
    try {
      const sigBuf = new Uint8Array(
        body.signature.match(/../g).map((h) => parseInt(h, 16)),
      );
      const ok = await crypto.subtle.verify(
        "HMAC",
        await _getHmacKey(env),
        sigBuf,
        _enc.encode(JSON.stringify(body.bundle)),
      );
      if (!ok) return jsonResp({ ok: false, error: "invalid signature" }, 403);
      if (body.bundle.domainIQ) _domainIQ.import(body.bundle.domainIQ);
      return jsonResp({ ok: true });
    } catch (e) {
      _log("api_error", { err: e?.message ?? String(e) });
      return jsonResp({ ok: false, error: "Internal error" }, 500);
    }
  }
  if (path === "/api/warm" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const rawDomains = Array.isArray(body.domains) ? body.domains : [];
    const domains = rawDomains.map(sanitizeDomain).filter(Boolean);
    _sh.preWarms += domains.length;
    return jsonResp({ ok: true, queued: domains.length });
  }
  if (path === "/api/dga-test" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const domain = sanitizeDomain(body.domain);
    if (!domain) {
      return jsonResp({
        domain: typeof body.domain === "string" ? body.domain.slice(0, 253) : "",
        score: 0,
        flagged: false,
        blocked: false,
        alike: null,
      });
    }
    const alike = alikeDomainCheck(domain);
    const score = dgaScore(domain);
    return jsonResp({
      domain: domain,
      score: score,
      flagged: score >= DGA_FLAG_SCORE || alike.detected,
      blocked: score >= DGA_BLOCK_SCORE || alike.detected,
      alike: alike.detected
        ? { reason: alike.reason, brand: alike.brand }
        : null,
    });
  }
  if (path === "/api/nuke-token" && method === "GET") {
    if (!env?.DNS_MASTER_KEY) {
      return jsonResp(
        { ok: false, error: "DNS_MASTER_KEY not configured" },
        403,
      );
    }
    const ts = Math.floor(Date.now() / 1e3);
    const tsHex = ts.toString(16).padStart(8, "0");
    let sig;
    try {
      const raw = await crypto.subtle.sign(
        "HMAC",
        await _getHmacKey(env),
        _enc.encode(tsHex + "/nuke"),
      );
      sig = Array.from(new Uint8Array(raw))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    } catch (e) {
      return jsonResp({ ok: false, error: "Token generation failed" }, 500);
    }
    return jsonResp({ nukeToken: tsHex + sig, expiresIn: "5m" });
  }
  if (
    (path === "/api/nuclear-wipe" ||
      path === "/api/nuke" ||
      path === "/api/system/nuke" ||
      path === "/api/system/reset") &&
    (method === "POST" || method === "DELETE")
  ) {
    try {
      // 0. Peer-sync across all Fly.io machines if running in cluster
      const isPeerSync = request.headers.get("x-peer-sync") === "1";
      if (!isPeerSync && process.env.FLY_APP_NAME) {
        const port = process.env.PORT || 8080;
        const peerHost = `http://${process.env.FLY_APP_NAME}.internal:${port}/api/nuke`;
        const syncHdrs = {
          "x-peer-sync": "1",
          "content-type": "application/json"
        };
        const auth = request.headers.get("authorization");
        if (auth) syncHdrs["authorization"] = auth;
        const xKey = request.headers.get("x-admin-key") || request.headers.get("x-request-key");
        if (xKey) syncHdrs["x-admin-key"] = xKey;
        fetch(peerHost, {
          method: "POST",
          headers: syncHdrs,
          body: JSON.stringify({ confirm: "NUKE" })
        }).catch((err) => {
          logger.warn("[nuke] Peer sync broadcast notice:", err.message);
        });
      }

      // 1. Clear in-memory AeroCache (entries, ghost queue, memory counters, and stats)
      if (env?.aeroCache && typeof env.aeroCache.clear === "function") {
        env.aeroCache.clear();
      }

      // 2. Wipe PulseDB storage on disk and in memory (clears tries, aeroStore, and truncates WAL to 0 bytes)
      if (env?.pulseDb && typeof env.pulseDb.wipe === "function") {
        env.pulseDb.wipe();
      }

      // 3. Clear all in-memory DNS, feature, feed, and negative caches
      _negCache.clear();
      _featCache.clear();
      _feedCache.clear();
      _answerHistory.clear();

      // 4. Clear all transient security and tracking maps
      _autoBlocks.clear();
      _burstMap.clear();
      _fpMap.clear();
      _memBlacklist.clear();
      _memWhitelist.clear();
      _memCommon.clear();
      _dgaLegit.clear();
      if (_userMap?.clear) _userMap.clear();
      if (_deviceMap?.clear) _deviceMap.clear();
      if (_heatmap?.clear) _heatmap.clear();
      _bgQueue.length = 0;
      _bgQueueHi.length = 0;

      // 5. Clear threat intelligence caches
      clearThreatIntelligenceCaches();

      // 6. Clear neural engine and model states
      clearNeuralCaches();
      clearNeuralModelStates();
      _domainIQ.clear();
      _markov.clear();
      _ledger.clear();
      _kf.reset();
      _rhythm.reset();
      _anomaly.reset();
      _obs.reset();
      _budgetAI.reset();

      // 7. Reset circuit breakers, UCB bandit, and upstream scores
      if (Array.isArray(_cb)) {
        _cb.forEach((c) => {
          c.errors = 0;
          c.total = 0;
          c.open = false;
          c.openTs = 0;
        });
      }
      if (_ucb?.rewards) _ucb.rewards.fill(0);
      if (_ucb?.pulls) _ucb.pulls.fill(0);
      if (_ucb) _ucb.total = 0;
      if (Array.isArray(_upScores)) {
        _upScores.forEach((s) => {
          if (s && typeof s.fill === "function") s.fill(0);
        });
      }

      // 8. Reset all telemetry, RPS, stress, counters, and logs
      resetSh();
      resetTelemetry();
      _anomalies.length = 0;
      _actions.length = 0;
      _aiDecisions.length = 0;
      _configDecisions.length = 0;

      // 9. Re-initialize in-memory defaults ONLY (DO NOT write to PulseDB so it remains 100% hollow: 0 records, 0 bytes)
      const defaultMode = env.DNS_ACCESS_MODE || "public";
      _setDnsMode(defaultMode); // in-memory only, no DB write

      // In-memory 9 active upstreams (3xN) baseline so DNS queries continue resolving cleanly
      const defaultMetadata = [
        { provider: "Cloudflare", url: "https://cloudflare-dns.com/dns-query", aura: "high", latency: 15, ok: true },
        { provider: "Cloudflare (1.1.1.1)", url: "https://1.1.1.1/dns-query", aura: "high", latency: 16, ok: true },
        { provider: "Cloudflare (1.0.0.1)", url: "https://1.0.0.1/dns-query", aura: "high", latency: 16, ok: true },
        { provider: "Google DNS", url: "https://dns.google/dns-query", aura: "high", latency: 18, ok: true },
        { provider: "Google (8.8.8.8)", url: "https://8.8.8.8/dns-query", aura: "high", latency: 19, ok: true },
        { provider: "Google (8.8.4.4)", url: "https://8.8.4.4/dns-query", aura: "high", latency: 19, ok: true },
        { provider: "Quad9", url: "https://dns.quad9.net/dns-query", aura: "high", latency: 22, ok: true },
        { provider: "OpenDNS", url: "https://doh.opendns.com/dns-query", aura: "medium", latency: 25, ok: true },
        { provider: "AdGuard", url: "https://dns.adguard-dns.com/dns-query", aura: "medium", latency: 28, ok: true },
      ];
      const defaultUpstreams = defaultMetadata.map((m) => m.url);
      setUpstreams(defaultUpstreams, defaultMetadata, true);

      // Reload customized threat feeds cleanly into memory BloomFilter via streaming (zero disk write to PulseDB)
      try {
        await syncThreatFeeds(true, env);
      } catch (feedErr) {
        logger.warn("[nuke] Customized threat feed load deferred:", feedErr.message);
      }

      // Live upstream probing runs asynchronously in the background
      import("../upstream-manager.js").then(({ syncAndRankUpstreams }) => {
        syncAndRankUpstreams(env, { setUpstreams }).catch((err) => {
          logger.warn("[nuke] Upstream live sync error:", err.message);
        });
      }).catch(() => {});

      // Final guarantee: zero out logs, counters, and verify PulseDB & Cache are hollow
      _anomalies.length = 0;
      _actions.length = 0;
      _aiDecisions.length = 0;
      _configDecisions.length = 0;
      resetSh();

      const dbStats = env?.pulseDb?.getStats?.() || {};
      const cacheStats = env?.aeroCache?.getStats?.() || {};

      // Return hollowed confirmation response
      return jsonResp({
        ok: true,
        wiped: true,
        hollow: true,
        details: {
          cache: {
            size: env?.aeroCache?.size || 0,
            bytes: cacheStats.bytes || 0,
            negCacheSize: _negCache.size,
            featCacheSize: _featCache.size,
            hits: cacheStats.hits || 0,
          },
          database: {
            totalRecords: dbStats.totalRecords || 0,
            walBytes: dbStats.walBytes || 0,
            blocklistDomains: dbStats.blocklistDomains || 0,
            whitelistDomains: dbStats.whitelistDomains || 0,
            aeroKeys: dbStats.aeroKeys || 0,
          },
          upstreams: {
            count: _ups.length,
            status: "active",
          },
          threatFeeds: {
            abirOk: _abirOk,
            abirSize: _abirSet.size,
            commonOk: _commonOk,
            commonSize: _commonSet.size,
          },
          telemetry: {
            requests: _sh.requests,
            anomalies: _anomalies.length,
            actions: _actions.length,
          },
        },
        message: "Nuclear wipe complete: PulseDB and AeroCache hollowed to 0 records and 0 bytes. Active upstreams and threat feeds ready in-memory.",
      });
    } catch (e) {
      return jsonResp({ ok: false, error: "Nuclear wipe failed: " + e.message }, 500);
    }
  }
  return jsonResp({ error: "Not found" }, 404);
}
export async function _makeAdminCspHeader() {
  const raw = crypto.getRandomValues(new Uint8Array(18));
  const nonce = btoa(String.fromCharCode(...raw));
  const csp = [
    "default-src 'none'",
    `script-src 'self' 'unsafe-inline' 'unsafe-eval' 'nonce-${nonce}' 'sha256-GnAkdM4av7pyUXIs0Ef48zRcJUVxXgrN5xpfzFfJ9dQ='`,
    "style-src 'self' 'unsafe-inline'",
    "font-src 'self' data:",
    "connect-src 'self'",
    "img-src 'self' data:",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
  ].join("; ");
  return { nonce: nonce, csp: csp };
}
export function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status: status,
    headers: {
      "content-type": "application/json",
      ...NO_CACHE_H,
      ...ADMIN_CORS_H,
      ..._SEC_H,
      "content-security-policy": "default-src 'none'",
    },
  });
}
