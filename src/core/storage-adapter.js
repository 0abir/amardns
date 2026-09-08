// src/core/storage-adapter.js
// Aero and Pulse storage compatibility adapters, brain serialization, chunking, and persistence.

import {
  BRAIN_SYNC_INTERVAL, BRAIN_CHUNK_SIZE, IMPORT_CHUNK_CHARS,
  VERSION, FEED_CACHE_TTL, FEED_CACHE_MAX, AUTO_BLOCK_TTL,
  BRAIN_PRUNE_EVERY
} from "./constants.js";
import {
  _env, _sh, _ISOLATE_ID,
  _domainIQ, _markov, _anomalies,
  _actions, _aiDecisions, _kf, _rhythm, _anomaly, _ucb, _obs,
  _ledger, _budgetAI, _runtimeConfig, _listsPreloaded,
  setListsPreloaded, setBrainLastSync, setBrainSyncBytes,
  setBrainLoaded, setBrainLoadedAt, setBrainInitializing, setBrainSyncCount,
  _bgEnqueue, _dgaLegit, _autoBlocks, _ctx, _feedCache,
  _aeroW, _aeroR, _pulseW, _pulseR, _aeroThrottle, _pulseThrottle, _dayStr,
  _brainDirty, _brainLastSync, _brainSyncBytes, _brainLoadedAt, _brainLoaded, _brainInitializing, _brainSyncCount,
  incPulseW, incPulseR, incAeroW, incAeroR, setPulseThrottle, setAeroThrottle, resetStorageQuotas, setBrainDirty,
  _log, _stress, setStress, _userEstimate, _userSamples, setUserEstimate
} from "./state.js";
import {
  nnExport, nnImport, _nnStats, _episodic, _brainPrune
} from "./neural-engine.js";
import { preloadLists as _preloadLists } from "./threat-intelligence.js";
import { _aeroCanWrite } from "./telemetry.js";

export {
  _aeroW, _aeroR, _pulseW, _pulseR, _aeroThrottle, _pulseThrottle, _dayStr,
  _brainDirty, _brainLastSync, _brainSyncBytes, _brainLoadedAt, _brainLoaded, _brainInitializing, _brainSyncCount,
  resetStorageQuotas, setBrainDirty
};

export function accountAeroWrite() { incAeroW(); }
export function accountAeroRead() { incAeroR(); }
export function accountPulseRead() { incPulseR(); }
export function accountPulseWrite() { incPulseW(); }


export async function aeroGet(key, fallback = null) {
  const pdb = _env?.pulseDb;
  if (pdb && typeof pdb.get === "function") {
    incAeroR();
    return pdb.get(key, fallback);
  }
  const aero = _env?.DNS_AERO;
  if (!aero || _aeroThrottle) return fallback;
  try {
    incAeroR();
    const val = await aero.get(key, "json");
    return val !== null ? val : fallback;
  } catch (e) {
    if (e.message?.includes("limit") || e.message?.includes("quota"))
      setAeroThrottle(true);
    return fallback;
  }
}
export async function aeroPut(key, value, ttl = 3600) {
  const pdb = _env?.pulseDb;
  if (pdb && typeof pdb.set === "function") {
    pdb.set(key, value, ttl);
    incAeroW();
    return;
  }
  const aero = _env?.DNS_AERO;
  if (!aero || !_aeroCanWrite()) return;
  try {
    await aero.put(key, JSON.stringify(value), { expirationTtl: ttl });
    incAeroW();
  } catch (e) {
    if (e.message?.includes("limit") || e.message?.includes("quota"))
      setAeroThrottle(true);
    _sh.pulseErrors++;
  }
}
export async function pulseGet(key, fallback = null) {
  const pdb = _env?.pulseDb;
  if (pdb && typeof pdb.get === "function") {
    incPulseR();
    return pdb.get(key, fallback);
  }
  const db = _env?.PULSE_DB;
  if (!db || _pulseThrottle) return fallback;
  try {
    incPulseR();
    const row = await db
      .prepare(
        "SELECT value FROM pulse_generic WHERE key=? AND (exp=0 OR exp>?) LIMIT 1",
      )
      .bind(key, Math.floor(Date.now() / 1e3))
      .first();
    return row?.value ? JSON.parse(row.value) : fallback;
  } catch (e) {
    _sh.pulseErrors++;
    if (e.message?.includes("limit")) setPulseThrottle(true);
    return fallback;
  }
}
export async function pulsePut(key, value, ttlSeconds = 3600) {
  const pdb = _env?.pulseDb;
  if (pdb && typeof pdb.set === "function") {
    pdb.set(key, value, ttlSeconds);
    incPulseW();
    return;
  }
  const db = _env?.PULSE_DB;
  if (!db || _pulseThrottle || !_budgetAI.canWrite()) return;
  const exp = ttlSeconds > 0 ? Math.floor(Date.now() / 1e3) + ttlSeconds : 0;
  incPulseW();
  _budgetAI.track();
  try {
    await db
      .prepare("INSERT OR REPLACE INTO pulse_generic(key,value,exp) VALUES(?,?,?)")
      .bind(key, typeof value === "string" ? value : JSON.stringify(value), exp)
      .run();
  } catch (e) {
    _sh.pulseErrors++;
    if (e.message?.includes("limit")) setPulseThrottle(true);
  }
}
export async function pulseDel(key) {
  const pdb = _env?.pulseDb;
  if (pdb && typeof pdb.delete === "function") {
    pdb.delete(key);
    return;
  }
  const db = _env?.PULSE_DB;
  if (!db || _pulseThrottle) return;
  try {
    await db.prepare("DELETE FROM pulse_generic WHERE key=?").bind(key).run();
  } catch (_) {}
}
export function _brainExportParts() {
  const nn = nnExport();
  const markovArr = [..._markov.transitions.entries()]
    .sort((a, b) => b[1].size - a[1].size)
    .slice(0, 200)
    .map(([k, v]) => [
      k,
      [...v.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10),
    ]);
  const hotMeta = {
    v: VERSION,
    ts: Date.now(),
    kf: { x: _kf.x, P: _kf.P, Q: _kf.Q, R: _kf.R },
    ucb: {
      r: Array.from(_ucb.rewards),
      p: Array.from(_ucb.pulls),
      t: _ucb.total,
    },
    dgaLegit: [..._dgaLegit].slice(0, 200),
    ledger: _ledger.entries
      .slice(-30)
      .map((e) => ({
        ts: e.ts,
        t: e.type,
        d: e.domain,
        s: e.signal,
        a: e.action,
        c: e.conf,
        o: e.outcome,
      })),
    stress: _stress,
    userEst: _userEstimate,
    userSamples: _userSamples,
    nnStats: {
      learningCycles: _nnStats.learningCycles,
      brainVersion: _nnStats.brainVersion,
    },
  };
  const parts = {};
  parts["meta"] = JSON.stringify(hotMeta);
  parts["rhythm"] = JSON.stringify(_rhythm.export());
  for (const k of [
    "dtn",
    "emb",
    "mha",
    "gru",
    "dtcn",
    "ae",
    "moe",
    "rl",
    "meta_nn",
    "liquid",
    "spiking",
    "symbolic",
    "bnn",
    "contrastive",
    "forest",
    "gnn",
    "calibrator",
    "neuron",
    "transformer",
    "manifold",
    "contextFusion",
    "finalNeuron",
    "charTransformer",
  ])
    parts[`nn_${k}`] = JSON.stringify(nn[k === "meta_nn" ? "meta" : k] || {});
  parts["nn_stats"] = JSON.stringify(nn.stats);
  const iqArr = JSON.stringify(_domainIQ.export());
  _splitIntoChunks(parts, "iq", iqArr);
  const markovStr = JSON.stringify(markovArr);
  _splitIntoChunks(parts, "markov", markovStr);
  return parts;
}
export function _splitIntoChunks(parts, prefix, str) {
  if (str.length <= IMPORT_CHUNK_CHARS) {
    parts[prefix] = str;
    return;
  }
  const n = Math.min(5, Math.ceil(str.length / IMPORT_CHUNK_CHARS));
  const chunkSize = Math.ceil(str.length / n);
  for (let i = 0; i < n; i++)
    parts[`${prefix}_${i}`] = str.slice(i * chunkSize, (i + 1) * chunkSize);
  parts[`${prefix}_chunks`] = String(n);
}
export function _brainExport() {
  const parts = _brainExportParts();
  const markovChunks = parseInt(parts["markov_chunks"] || "1");
  let markovStr =
    parts["markov"] ||
    (() => {
      let s = "";
      for (let i = 0; i < markovChunks; i++) s += parts[`markov_${i}`] || "";
      return s;
    })();
  const iqChunks = parseInt(parts["iq_chunks"] || "1");
  let iqStr =
    parts["iq"] ||
    (() => {
      let s = "";
      for (let i = 0; i < iqChunks; i++) s += parts[`iq_${i}`] || "";
      return s;
    })();
  const nn = {};
  for (const k of [
    "dtn",
    "emb",
    "mha",
    "gru",
    "dtcn",
    "ae",
    "moe",
    "rl",
    "meta",
    "liquid",
    "spiking",
    "symbolic",
    "bnn",
    "contrastive",
    "forest",
    "gnn",
    "calibrator",
    "neuron",
    "transformer",
    "manifold",
    "contextFusion",
    "finalNeuron",
    "charTransformer",
  ])
    try {
      nn[k === "meta" ? "meta" : k] = JSON.parse(
        parts[`nn_${k === "meta" ? "meta_nn" : k}`] || "null",
      );
    } catch (_) {}
  nn.stats = JSON.parse(parts["nn_stats"] || "{}");
  const hotMeta = JSON.parse(parts["meta"] || "{}");
  const hot = {
    ...hotMeta,
    nn: nn,
    nnStats: {
      learningCycles: _nnStats.learningCycles,
      brainVersion: _nnStats.brainVersion,
    },
    rhythm: JSON.parse(parts["rhythm"] || "{}"),
    domainIQ: JSON.parse(iqStr || "[]"),
  };
  return { hot: JSON.stringify(hot), markov: markovStr };
}
export async function _brainImport(hotStr, markovStr) {
  try {
    const hot = JSON.parse(hotStr);
    if (hot.kf) Object.assign(_kf, hot.kf);
    if (hot.ucb) {
      _ucb.rewards.set(hot.ucb.r);
      _ucb.pulls.set(hot.ucb.p);
      _ucb.total = hot.ucb.t || 0;
    }
    if (hot.rhythm) _rhythm.import(hot.rhythm);
    if (hot.domainIQ) _domainIQ.import(hot.domainIQ);
    if (hot.dgaLegit) {
      for (const d of hot.dgaLegit) _dgaLegit.add(d);
    }
    if (hot.stress) setStress(hot.stress);
    if (hot.userEst) {
      setUserEstimate(hot.userEst, hot.userSamples || 0);
    }
    if (markovStr) {
      const markovArr = JSON.parse(markovStr);
      _markov.transitions.clear();
      for (const [k, v] of markovArr) {
        if (_markov.transitions.size >= _markov.MAX_DOMAINS) break;
        _markov.transitions.set(k, new Map(v));
      }
    }
    if (hot.nn) nnImport(hot.nn);
    if (hot.nnStats) {
      if (hot.nnStats.learningCycles)
        _nnStats.learningCycles = hot.nnStats.learningCycles;
      if (hot.nnStats.brainVersion)
        _nnStats.brainVersion = hot.nnStats.brainVersion;
    }
    _log("brain_imported", {
      v: hot.v,
      iq: _domainIQ.map.size,
      markov: _markov.transitions.size,
    });
    return true;
  } catch (e) {
    _log("brain_import_error", { err: e.message });
    return false;
  }
}
export async function _brainImportParts(aero) {
  try {
    const get = async (k) => {
      try {
        const v = await aeroGetChunked(aero, `ai:brain:${k}`);
        return v || "";
      } catch (_) {
        return "";
      }
    };
    const metaStr = await get("meta");
    if (!metaStr) return false;
    const hot = JSON.parse(metaStr);
    if (hot.kf) Object.assign(_kf, hot.kf);
    if (hot.ucb) {
      _ucb.rewards.set(hot.ucb.r);
      _ucb.pulls.set(hot.ucb.p);
      _ucb.total = hot.ucb.t || 0;
    }
    if (hot.dgaLegit) for (const d of hot.dgaLegit) _dgaLegit.add(d);
    if (hot.stress != null) setStress(hot.stress);
    if (hot.userEst) {
      setUserEstimate(hot.userEst, hot.userSamples || 0);
    }
    if (hot.nnStats) {
      if (hot.nnStats.learningCycles)
        _nnStats.learningCycles = hot.nnStats.learningCycles;
      if (hot.nnStats.brainVersion)
        _nnStats.brainVersion = hot.nnStats.brainVersion;
    }
    const rhythmStr = await get("rhythm");
    if (rhythmStr)
      try {
        _rhythm.import(JSON.parse(rhythmStr));
      } catch (_) {}
    const [iqChunksRaw, markovChunksRaw] = await Promise.all([
      get("iq_chunks"),
      get("markov_chunks"),
    ]);
    const iqChunks = parseInt(iqChunksRaw || "0", 10);
    const markovChunks = parseInt(markovChunksRaw || "0", 10);
    const [iqChunkParts, markovChunkParts, iqPlain, markovPlain] =
      await Promise.all([
        iqChunks > 0
          ? Promise.all(
              Array.from({ length: iqChunks }, (_, i) => get(`iq_${i}`)),
            )
          : Promise.resolve([]),
        markovChunks > 0
          ? Promise.all(
              Array.from({ length: markovChunks }, (_, i) =>
                get(`markov_${i}`),
              ),
            )
          : Promise.resolve([]),
        iqChunks === 0 ? get("iq") : Promise.resolve(""),
        markovChunks === 0 ? get("markov") : Promise.resolve(""),
      ]);
    const iqStr = iqChunks > 0 ? iqChunkParts.join("") : iqPlain;
    if (iqStr)
      try {
        _domainIQ.import(JSON.parse(iqStr));
      } catch (_) {}
    const markovStr =
      markovChunks > 0 ? markovChunkParts.join("") : markovPlain;
    if (markovStr) {
      try {
        const arr = JSON.parse(markovStr);
        _markov.transitions.clear();
        for (const [k, v] of arr) {
          if (_markov.transitions.size >= _markov.MAX_DOMAINS) break;
          _markov.transitions.set(k, new Map(v));
        }
      } catch (_) {}
    }
    const NN_IMPORT_KEYS = [
      "dtn",
      "emb",
      "mha",
      "gru",
      "dtcn",
      "ae",
      "moe",
      "rl",
      "meta",
      "liquid",
      "spiking",
      "symbolic",
      "bnn",
      "contrastive",
      "forest",
      "gnn",
      "calibrator",
      "neuron",
      "transformer",
      "manifold",
      "contextFusion",
      "finalNeuron",
      "charTransformer",
    ];
    const [nnResults, statsStr] = await Promise.all([
      Promise.all(
        NN_IMPORT_KEYS.map((k) => get(`nn_${k === "meta" ? "meta_nn" : k}`)),
      ),
      get("nn_stats"),
    ]);
    const nn = {};
    for (let i = 0; i < NN_IMPORT_KEYS.length; i++) {
      const s = nnResults[i];
      if (s)
        try {
          nn[NN_IMPORT_KEYS[i]] = JSON.parse(s);
        } catch (_) {}
    }
    if (statsStr)
      try {
        nn.stats = JSON.parse(statsStr);
      } catch (_) {}
    if (Object.keys(nn).length) nnImport(nn);
    _log("brain_imported_parts", {
      iq: _domainIQ.map.size,
      markov: _markov.transitions.size,
    });
    return true;
  } catch (e) {
    _log("brain_import_parts_error", { err: e.message });
    return false;
  }
}
export async function brainLoad(env) {
  if (_brainLoaded || _brainInitializing) return;
  setBrainInitializing(true);
  try {
    const db = env?.PULSE_DB;
    if (db && !_pulseThrottle) {
      try {
        const now = Math.floor(Date.now() / 1e3);
        const abRows = await db
          .prepare(
            "SELECT domain, reason, exp FROM pulse_autoblock WHERE exp=0 OR exp>? LIMIT 500",
          )
          .bind(now)
          .all()
          .catch(() => ({ results: [] }));
        for (const row of abRows.results || []) {
          _autoBlocks.set(row.domain, {
            exp: row.exp || now + AUTO_BLOCK_TTL,
            reason: row.reason || "ai",
            auto: true,
          });
        }
      } catch (_) {}
    }
    let pulseLoaded = false;
    if (db && !_pulseThrottle) {
      const hot = await pulseGet("ai:brain:hot", null);
      if (hot) {
        let markovRaw = await pulseGet("ai:brain:markov", null);
        if (!markovRaw) {
          const nChunks = parseInt(
            await pulseGet("ai:brain:markov_chunks", "0"),
            10,
          );
          if (nChunks > 0) {
            const rawChunks = await Promise.all(
              Array.from({ length: nChunks }, (_, i) =>
                pulseGet(`ai:brain:markov_${i}`, ""),
              ),
            );
            markovRaw = rawChunks
              .map((v) => (typeof v === "string" ? v : JSON.stringify(v)))
              .join("");
          }
        }
        const markovStr = markovRaw
          ? typeof markovRaw === "string"
            ? markovRaw
            : JSON.stringify(markovRaw)
          : "[]";
        await _brainImport(
          typeof hot === "string" ? hot : JSON.stringify(hot),
          markovStr,
        );
        const NN_KEYS = [
          "dtn",
          "emb",
          "mha",
          "gru",
          "dtcn",
          "ae",
          "moe",
          "rl",
          "meta_nn",
          "liquid",
          "spiking",
          "symbolic",
          "bnn",
          "contrastive",
          "forest",
          "gnn",
          "calibrator",
          "neuron",
          "transformer",
          "manifold",
          "contextFusion",
          "finalNeuron",
          "charTransformer",
        ];
        const [nnResults, statsStr, rhythmStr, iqChunksStr] = await Promise.all(
          [
            Promise.all(NN_KEYS.map((k) => pulseGet("ai:brain:nn_" + k, null))),
            pulseGet("ai:brain:nn_stats", null),
            pulseGet("ai:brain:rhythm", null),
            pulseGet("ai:brain:iq_chunks", null),
          ],
        );
        const nn = {};
        for (let i = 0; i < NN_KEYS.length; i++) {
          const k = NN_KEYS[i],
            s = nnResults[i];
          if (s)
            try {
              nn[k === "meta_nn" ? "meta" : k] =
                typeof s === "string" ? JSON.parse(s) : s;
            } catch (_) {}
        }
        if (statsStr)
          try {
            nn.stats =
              typeof statsStr === "string" ? JSON.parse(statsStr) : statsStr;
          } catch (_) {}
        if (Object.keys(nn).length) nnImport(nn);
        if (rhythmStr)
          try {
            _rhythm.import(
              typeof rhythmStr === "string" ? JSON.parse(rhythmStr) : rhythmStr,
            );
          } catch (_) {}
        if (iqChunksStr) {
          const n = parseInt(iqChunksStr, 10);
          if (!isNaN(n) && n > 0) {
            const iqParts = await Promise.all(
              Array.from({ length: n }, (_, i) =>
                pulseGet("ai:brain:iq_" + i, ""),
              ),
            );
            const iq = iqParts.join("");
            if (iq)
              try {
                _domainIQ.import(JSON.parse(iq));
              } catch (_) {}
          }
        } else {
          const iqStr = await pulseGet("ai:brain:iq", null);
          if (iqStr)
            try {
              _domainIQ.import(
                typeof iqStr === "string" ? JSON.parse(iqStr) : iqStr,
              );
            } catch (_) {}
        }
        pulseLoaded = true;
        if (!_brainLoadedAt) setBrainLoadedAt(Date.now());
        if (_brainSyncBytes === 0) {
          const _loadParts = _brainExportParts();
          setBrainSyncBytes(
            Object.values(_loadParts).reduce((a, s) => a + s.length, 0),
          );
        }
        _log("brain_loaded_pulse", {
          iq: _domainIQ.map.size,
          markov: _markov.transitions.size,
          bytes: _brainSyncBytes,
        });
      }
    }
    if (!pulseLoaded) {
      const aero = env?.DNS_AERO;
      if (aero && !_aeroThrottle) {
        try {
          const metaProbe = await aero.get("ai:brain:meta", "text");
          if (metaProbe && metaProbe !== "1") {
            await _brainImportParts(aero);
          }
        } catch (_) {}
      }
      if (!pulseLoaded) {
        const hot = await pulseGet("ai:brain:hot", null);
        if (hot) {
          let markovRaw2 = await pulseGet("ai:brain:markov", null);
          if (!markovRaw2) {
            const nChunks2 = parseInt(
              await pulseGet("ai:brain:markov_chunks", "0"),
              10,
            );
            if (nChunks2 > 0) {
              const rawChunks2 = await Promise.all(
                Array.from({ length: nChunks2 }, (_, i) =>
                  pulseGet(`ai:brain:markov_${i}`, ""),
                ),
              );
              markovRaw2 = rawChunks2
                .map((v) => (typeof v === "string" ? v : JSON.stringify(v)))
                .join("");
            }
          }
          const markovStr2 = markovRaw2
            ? typeof markovRaw2 === "string"
              ? markovRaw2
              : JSON.stringify(markovRaw2)
            : "[]";
          await _brainImport(
            typeof hot === "string" ? hot : JSON.stringify(hot),
            markovStr2,
          );
        }
      }
    }
    _ctx?.waitUntil(_episodic.load());
    if (!_listsPreloaded && (env?.pulseDb || env?.PULSE_DB)) {
      await _preloadLists(env).catch(() => {});
    }
    setBrainLoaded(true);
    setBrainLastSync(Date.now());
  } catch (e) {
    _log("brain_load_error", { err: e.message });
  } finally {
    setBrainInitializing(false);
  }
}
export function _feedCacheGet(domain) {
  const e = _feedCache.get(domain);
  if (!e) return null;
  if (Date.now() - e.ts > FEED_CACHE_TTL) {
    _feedCache.delete(domain);
    return null;
  }
  _feedCache.delete(domain);
  _feedCache.set(domain, e);
  return e;
}
export function _feedCacheSet(domain, blocked, source) {
  _feedCache.delete(domain);
  if (_feedCache.size >= FEED_CACHE_MAX)
    _feedCache.delete(_feedCache.keys().next().value);
  _feedCache.set(domain, { blocked: blocked, source: source, ts: Date.now() });
}

export async function aeroGetChunked(aero, key) {
  if (!aero) return null;
  try {
    const manifest = await aero.get(`${key}:__n`, "text");
    if (manifest) {
      const n = parseInt(manifest, 10);
      if (isNaN(n) || n < 1) return null;
      const parts = await Promise.all(
        Array.from({ length: n }, (_, i) => aero.get(`${key}:__c${i}`, "text")),
      );
      return parts.join("") || null;
    }
    return await aero.get(key, "text");
  } catch (_) {
    return null;
  }
}
export async function brainSync(force = false) {
  const now = Date.now();
  if (!force && now - _brainLastSync < BRAIN_SYNC_INTERVAL) return;
  if (!force && !_brainDirty) return;
  if (_pulseThrottle && _aeroThrottle) {
    _log("brain_sync_skipped_throttled", { pulse: _pulseThrottle, aero: _aeroThrottle });
    return;
  }
  const db = _env?.pulseDb || _env?.PULSE_DB;
  if (!_listsPreloaded && db) _bgEnqueue(() => _preloadLists(_env), true);
  if (!force && !_budgetAI.canWrite(true)) return;
  setBrainLastSync(now);
  setBrainDirty(false);
  setBrainSyncCount(_brainSyncCount + 1);
  if (_brainSyncCount % BRAIN_PRUNE_EVERY === 0) _brainPrune();
  const parts = _brainExportParts();
  setBrainSyncBytes(Object.values(parts).reduce((a, s) => a + s.length, 0));
  if (_brainSyncBytes > 9e5) {
    _log("brain_size_warn", {
      bytes: _brainSyncBytes,
      note: "approaching Pulse 1MB row limit — consider manual prune",
    });
  }
  _bgEnqueue(async () => {
    try {
      if (!_pulseThrottle && _budgetAI.canWrite(true)) {
        const metaVal = parts["meta"] || "";
        if (metaVal) {
          _budgetAI.track();
          await pulsePut("ai:brain:hot", metaVal, 0).catch(() => {});
        }
        const statsVal = parts["nn_stats"] || "";
        if (statsVal && statsVal.length < 2e4 && _budgetAI.canWrite(true)) {
          _budgetAI.track();
          await pulsePut("ai:brain:nn_stats", statsVal, 0).catch(() => {});
        }
        const markovPlain = parts["markov"] || "";
        const markovChunkCount = parseInt(parts["markov_chunks"] || "0", 10);
        if (markovPlain && _budgetAI.canWrite(true)) {
          _budgetAI.track();
          await pulsePut("ai:brain:markov", markovPlain, 0).catch(() => {});
        } else if (markovChunkCount > 0) {
          if (_budgetAI.canWrite(true)) {
            _budgetAI.track();
            await pulsePut(
              "ai:brain:markov_chunks",
              String(markovChunkCount),
              0,
            ).catch(() => {});
          }
          await Promise.all(
            Array.from({ length: markovChunkCount }, async (_, i) => {
              const chunk = parts[`markov_${i}`] || "";
              if (chunk && _budgetAI.canWrite(true)) {
                _budgetAI.track();
                await pulsePut(`ai:brain:markov_${i}`, chunk, 0).catch(() => {});
              }
            }),
          );
        }
        const NN_SYNC_KEYS = [
          "dtn",
          "emb",
          "mha",
          "gru",
          "dtcn",
          "ae",
          "moe",
          "rl",
          "meta_nn",
          "liquid",
          "spiking",
          "symbolic",
          "bnn",
          "contrastive",
          "forest",
          "gnn",
          "calibrator",
          "neuron",
          "transformer",
          "manifold",
          "contextFusion",
          "finalNeuron",
          "charTransformer",
        ];
        await Promise.all(
          NN_SYNC_KEYS.map(async (k) => {
            const val = parts["nn_" + k];
            if (val && val.length < 5e4 && _budgetAI.canWrite(true)) {
              _budgetAI.track();
              await pulsePut("ai:brain:nn_" + k, val, 0).catch(() => {});
            }
          }),
        );
        const rhythmVal = parts["rhythm"] || "";
        if (rhythmVal && _budgetAI.canWrite(true)) {
          _budgetAI.track();
          await pulsePut("ai:brain:rhythm", rhythmVal, 0).catch(() => {});
        }
        const iqChunks = parts["iq_chunks"] || "";
        const iqWrites = [];
        if (iqChunks && _budgetAI.canWrite(true)) {
          _budgetAI.track();
          iqWrites.push(
            pulsePut("ai:brain:iq_chunks", iqChunks, 0).catch(() => {}),
          );
        }
        for (let i = 0; i < 5; i++) {
          const iqPart = parts["iq_" + i];
          if (iqPart && _budgetAI.canWrite(true)) {
            _budgetAI.track();
            iqWrites.push(pulsePut("ai:brain:iq_" + i, iqPart, 0).catch(() => {}));
          }
        }
        const iqPlain = parts["iq"] || "";
        if (iqPlain && _budgetAI.canWrite(true)) {
          _budgetAI.track();
          iqWrites.push(pulsePut("ai:brain:iq", iqPlain, 0).catch(() => {}));
        }
        await Promise.all(iqWrites);
        const aero = _env?.DNS_AERO;
        if (aero && !_aeroThrottle && _aeroCanWrite()) {
          try {
            await aero.put("ai:brain:probe", "1", { expirationTtl: 172800 });
            incAeroW();
          } catch (_) {}
        }
      }
      _log("brain_synced", {
        parts: Object.keys(parts).length,
        bytes: _brainSyncBytes,
        store: "pulse-primary",
      });
    } catch (e) {
      _log("brain_sync_error", { err: e.message });
    }
  }, false);
}
