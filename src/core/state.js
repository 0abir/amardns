// src/core/state.js
// Global runtime state, telemetry containers, queues, and caches.

import {
  BG_CONCURRENCY, FEED_CACHE_MAX, PULSE_WRITE_LIMIT
} from "./constants.js";
import logger from "../logger.js";

// Context & Environment
export let _env = null;
export function setEnv(e) { _env = e; }
export let _ctx = null;
export function setCtx(c) { _ctx = c; }
export let SAFE_BROWSING_KEYS = [];
export function setSafeBrowsingKeys(k) { SAFE_BROWSING_KEYS = k; }

export let _dnsMode =
  typeof process !== "undefined" && process.env?.DNS_ACCESS_MODE === "public"
    ? "public"
    : "private";

export function _setDnsMode(mode, db) {
  const m = mode === "public" ? "public" : "private";
  _dnsMode = m;
  const pdb = _env?.pulseDb || db;
  if (pdb && typeof pdb.set === "function") {
    try {
      pdb.set("config:dns_mode", m);
    } catch (e) {
      logger.error("Failed to persist dns_mode:", e.message);
    }
  }
  logger.debug(`[settings] DNS access mode set to: ${m.toUpperCase()}`);
  return _dnsMode;
}
export function getDnsMode() { return _dnsMode; }

export let _blockingEnabled =
  typeof process !== "undefined" && process.env?.BLOCKING_ENABLED === "false"
    ? false
    : true;

export function _setBlockingEnabled(enabled, db) {
  _blockingEnabled = enabled === true || enabled === "true" || enabled === "active" || enabled === "1";
  const pdb = _env?.pulseDb || db;
  if (pdb && typeof pdb.set === "function") {
    try {
      pdb.set("config:blocking_enabled", _blockingEnabled ? "true" : "false");
    } catch (e) {
      logger.error("Failed to persist blocking_enabled:", e.message);
    }
  }
  logger.debug(`[settings] Threat & Ad blocking set to: ${_blockingEnabled ? "ACTIVE" : "DEACTIVATED (PASSTHROUGH)"}`);
  return _blockingEnabled;
}
export function getBlockingEnabled() { return _blockingEnabled; }

// Background Queues & Worker
export const _featCache = new Map();
export const _bgQueue = [];
export const _bgQueueHi = [];
export const BG_MAX_QUEUE = 2e3;
export let _bgRunning = false;
export function setBgRunning(r) { _bgRunning = r; }
export let _bgSlots = 0;
export function setBgSlots(s) { _bgSlots = s; }
export let _lastLbMode = "BALANCED";
export function setLastLbMode(m) { _lastLbMode = m; }

export async function _bgRun() {
  if (_bgRunning) return;
  _bgRunning = true;
  try {
    while (_bgQueueHi.length || _bgQueue.length) {
      const src = _bgQueueHi.length ? _bgQueueHi : _bgQueue;
      const available = BG_CONCURRENCY - _bgSlots;
      if (available <= 0) {
        await new Promise((r) => setTimeout(r, 0));
        continue;
      }
      const batch = src.splice(0, Math.min(available, src.length));
      _bgSlots += batch.length;
      await Promise.all(
        batch.map(async (job) => {
          try {
            await job();
          } catch (e) {
            _log("bg_job_error", { err: e?.message ?? String(e) });
          } finally {
            _bgSlots--;
          }
        }),
      );
    }
  } catch (e) {
    _log("bg_run_fatal", { err: e?.message ?? String(e) });
  } finally {
    _bgRunning = false;
    _bgSlots = 0;
  }
}
export function _bgEnqueue(job, hi = false) {
  const ring = hi ? _bgQueueHi : _bgQueue;
  if (ring.length >= BG_MAX_QUEUE) {
    ring.shift();
    _log("bg_queue_overflow", { hi: hi, len: ring.length });
  }
  ring.push(job);
  _ctx?.waitUntil(_bgRun());
}

// Feed caches and sets
export const _feedCache = new Map();
export const _memBlacklist = new Set();
export const _memWhitelist = new Set();
export const _memCommon = new Set();
export let _listsPreloaded = false;
export function setListsPreloaded(b) { _listsPreloaded = b; }

export let BRANDS_LIST = [
  "paypal",
  "google",
  "apple",
  "microsoft",
  "amazon",
  "facebook",
  "instagram",
  "twitter",
  "netflix",
  "chase",
  "bankofamerica",
  "wellsfargo",
  "citibank",
  "coinbase",
  "binance",
  "metamask",
  "openai",
  "anthropic",
];
export function setBrandsList(b) { BRANDS_LIST = b; }

// Runtime configuration & dynamic user-agent
export let _runtimeConfig = {
  cbThreshold: 0.45,
  burstThreshold: 60,
  maxCacheTtl: 3600,
  hedgeMs: 20,
  fetchTimeoutMs: 3e3,
  lbFloodRps: 200,
  lbFloodStress: 0.7,
  lbFastRps: 5,
  lbFastStress: 0.3,
  userAgentMode: "old_acceptable",
};
export let _memoUA = null;
export let _memoUAExp = 0;
export const _rndData = () => {
  const now = Date.now();
  const CYCLE_MS_UA = 28 * 24 * 60 * 60 * 1e3;
  if (_memoUA && now < _memoUAExp && now >= _memoUAExp - CYCLE_MS_UA)
    return _memoUA;
  const ANCHOR_DATE = new Date("2026-04-01").getTime();
  const ANCHOR_CHROME = 147;
  const CYCLE_MS = 28 * 24 * 60 * 60 * 1e3;
  const elapsed = now - ANCHOR_DATE;
  const cyclesSince = Math.max(0, Math.floor(elapsed / CYCLE_MS));
  const c = ANCHOR_CHROME + cyclesSince;
  const dayInCycle =
    elapsed >= 0 ? (elapsed % CYCLE_MS) / (24 * 60 * 60 * 1e3) : 0;
  const currentMax = dayInCycle < 7 ? c - 1 : c;
  const inRollout = dayInCycle >= 0 && dayInCycle < 7;
  const allowOld = _runtimeConfig.userAgentMode === "old_acceptable";
  const wantOld = (inRollout || allowOld) && Math.random() < 0.3;
  const verBase = wantOld ? currentMax - 1 : currentMax;
  const ver = verBase + (Math.random() < 0.45 ? 0 : -1);
  const FF_ANCHOR = 149;
  const ffBase = FF_ANCHOR + cyclesSince;
  const fv = Math.max(
    FF_ANCHOR,
    (wantOld ? ffBase - 1 : ffBase) + (Math.random() < 0.5 ? 0 : -1),
  );
  const ANCHOR_EDGE = 146;
  const edgeBase = ANCHOR_EDGE + cyclesSince;
  const edgeVer = Math.max(
    ANCHOR_EDGE,
    (wantOld ? edgeBase - 1 : edgeBase) + (Math.random() < 0.5 ? 0 : -1),
  );
  const androidVer = Math.random() < 0.55 ? 15 : 14;
  const androidTokens = [
    "K",
    "SM-S928B",
    "Pixel 9",
    "Pixel 8",
    "SM-A556B",
    "23049PCD8G",
  ];
  const androidDevice =
    androidTokens[Math.floor(Math.random() * androidTokens.length)];
  const chromeOsWeighted = [
    "Windows NT 10.0; Win64; x64",
    "Windows NT 10.0; Win64; x64",
    "Windows NT 10.0; Win64; x64",
    "Macintosh; Intel Mac OS X 10_15_7",
    "Macintosh; Intel Mac OS X 10_15_7",
    `Linux; Android ${androidVer}; ${androidDevice}`,
    "X11; Linux x86_64",
  ];
  const firefoxOsWeighted = [
    "Windows NT 10.0; Win64; x64",
    "Windows NT 10.0; Win64; x64",
    "Macintosh; Intel Mac OS X 10_15_7",
    `Android ${androidVer}; Mobile`,
    "X11; Linux x86_64",
  ];
  const isFirefox = Math.random() < 0.22;
  const isEdge = !isFirefox && Math.random() < 0.12;
  let ua = "";
  if (isFirefox) {
    const fos =
      firefoxOsWeighted[Math.floor(Math.random() * firefoxOsWeighted.length)];
    ua = fos.startsWith("Android")
      ? `Mozilla/5.0 (${fos}; rv:${fv}.0) Gecko/${fv}.0 Firefox/${fv}.0`
      : `Mozilla/5.0 (${fos}; rv:${fv}.0) Gecko/20100101 Firefox/${fv}.0`;
  } else {
    const os =
      chromeOsWeighted[Math.floor(Math.random() * chromeOsWeighted.length)];
    const mobile = os.includes("Android") ? " Mobile" : "";
    const base = `Mozilla/5.0 (${os}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${ver}.0.0.0${mobile} Safari/537.36`;
    ua =
      isEdge && !os.includes("Android") && !os.includes("X11")
        ? base + ` Edg/${edgeVer}.0.0.0`
        : base;
  }
  _memoUA = ua;
  const _msPerDay = 24 * 60 * 60 * 1e3;
  const _cycleMs = 28 * _msPerDay;
  const _elapsed = now - new Date("2026-04-01").getTime();
  const _dayInC = _elapsed >= 0 ? (_elapsed % _cycleMs) / _msPerDay : 0;
  const _msUntilNextBoundary =
    _dayInC < 1 ? (1 - _dayInC) * _msPerDay : _cycleMs - (_elapsed % _cycleMs);
  _memoUAExp = now + Math.max(6e4, _msUntilNextBoundary);
  return ua;
};
export let _ISOLATE_ID = null;
export let _aeroW = 0,
  _aeroR = 0,
  _pulseW = 0,
  _pulseR = 0;
export let _aeroThrottle = false,
  _pulseThrottle = false;
export let _dayStr = "";
export let _aeroBucket = 10;
export const AERO_BUCKET_CAP = 10;
export const AERO_REFILL_PER_MIN = 1;
export let _aeroBucketTs = 0;
export const _negCache = new Map();
export const _autoBlocks = new Map();
export const _burstMap = new Map();
export const _fpMap = new Map();
export { _ups, _upScores, _cb, _upMetadata } from "./dns-protocol.js";
export const _sh = {
  requests: 0,
  cacheHits: 0,
  cacheMisses: 0,
  negHits: 0,
  burstEvents: 0,
  dgaBlocked: 0,
  repBlocks: 0,
  autoBlocks: 0,
  rebindBlocks: 0,
  xvalDisagree: 0,
  alikeBlocks: 0,
  nxAlarms: 0,
  crlBlocks: 0,
  fpEvents: 0,
  swarmAlarms: 0,
  aiBlocks: 0,
  gsbBlocks: 0,
  abirBlocks: 0,
  multiFeedBlocks: 0,
  feedAiBlocks: 0,
  feedTier1: 0,
  feedTier2: 0,
  feedTier3: 0,
  feedTier4: 0,
  piggybacks: 0,
  preWarms: 0,
  panicCount: 0,
  memPressure: false,
  emergencyMode: false,
  pulseErrors: 0,
  authFails: 0,
  gcCycles: 0,
  answerDrifts: 0,
  ttlInflations: 0,
  ttlDeflations: 0,
  freshnessStale: 0,
  pcbEvents: 0,
  dccHits: 0,
  urdmAlarms: 0,
  dcqAlarms: 0,
  cnxfAlarms: 0,
  qrsdAlarms: 0,
};
export function resetSh() {
  for (const k of Object.keys(_sh)) {
    if (typeof _sh[k] === "number") _sh[k] = 0;
    else if (typeof _sh[k] === "boolean") _sh[k] = false;
  }
}
export const _anomalies = [];
export function _log(type, data = {}) {
  _anomalies.push({ t: Date.now(), type: type, ...data });
  if (_anomalies.length > 300) _anomalies.splice(0, 100);
  _obs?.observe?.(type);
}
export const _actions = [];
export const _aiDecisions = [];
export const _configDecisions = [];
export const _kf = {
  x: 1,
  P: 1e3,
  Q: 10,
  R: 50,
  loaded: false,
  reset() {
    this.x = 1;
    this.P = 1e3;
    this.Q = 10;
    this.R = 50;
    this.loaded = false;
  },
  update(obs) {
    this.P += this.Q;
    const inn = obs - this.x;
    this.Q = Math.min(500, 0.5 * Math.abs(inn)) + 5;
    const r = this.R * (1 + 5 * _anomaly.score);
    const k = this.P / (this.P + r);
    this.x = this.x + k * inn;
    this.P *= 1 - k;
    return Math.max(1, Math.round(this.x));
  },
};
export const _rhythm = {
  slots: Array.from({ length: 7 }, () => new Float32Array(24)),
  counts: Array.from({ length: 7 }, () => new Uint16Array(24)),
  reset() {
    for (let i = 0; i < 7; i++) {
      this.slots[i].fill(0);
      this.counts[i].fill(0);
    }
  },
  record(rps) {
    const d = new Date(),
      dow = d.getUTCDay(),
      h = d.getUTCHours();
    const c = this.counts[dow][h];
    this.slots[dow][h] =
      c < 5
        ? (this.slots[dow][h] * c + rps) / (c + 1)
        : 0.08 * rps + 0.92 * this.slots[dow][h];
    if (c < 65535) this.counts[dow][h]++;
  },
  expected(dow, h) {
    if (this.counts[dow][h] < 3) return 0;
    let sum = 0,
      w = 0;
    for (let dd = -1; dd <= 1; dd++)
      for (let dh = -1; dh <= 1; dh++) {
        const wt = (dd === 0 ? 2 : 1) * (dh === 0 ? 2 : 1);
        const v = this.slots[(dow + dd + 7) % 7][(h + dh + 24) % 24];
        if (v > 0) {
          sum += wt * v;
          w += wt;
        }
      }
    return w > 0 ? sum / w : 0;
  },
  anomalyFactor(rps) {
    const d = new Date();
    const exp = this.expected(d.getUTCDay(), d.getUTCHours());
    if (exp < 0.1) return 1;
    return Math.min(3, Math.max(0.1, rps / exp));
  },
  export() {
    return {
      s: this.slots.map((a) => Array.from(a)),
      c: this.counts.map((a) => Array.from(a)),
    };
  },
  import(d) {
    if (!d?.s || !d?.c) return;
    for (let i = 0; i < 7; i++) {
      if (d.s[i]) this.slots[i].set(d.s[i].slice(0, 24));
      if (d.c[i]) this.counts[i].set(d.c[i].slice(0, 24));
    }
  },
};
export const _anomaly = {
  n: 0,
  meanC: 0,
  M2C: 0,
  stdC: 0,
  meanD: 0,
  M2D: 0,
  stdD: 0,
  prev: 0,
  score: 0,
  reset() {
    this.n = 0;
    this.meanC = 0;
    this.M2C = 0;
    this.stdC = 0;
    this.meanD = 0;
    this.M2D = 0;
    this.stdD = 0;
    this.prev = 0;
    this.score = 0;
  },
  update(obs) {
    const delta = obs - this.prev;
    this.prev = obs;
    this.n++;
    const a = obs - this.meanC;
    this.meanC += a / this.n;
    this.M2C += a * (obs - this.meanC);
    this.stdC = this.n > 1 ? Math.sqrt(this.M2C / (this.n - 1)) : 0;
    const b = delta - this.meanD;
    this.meanD += b / this.n;
    this.M2D += b * (delta - this.meanD);
    this.stdD = this.n > 1 ? Math.sqrt(this.M2D / (this.n - 1)) : 0;
    if (this.n > 10) {
      const zC = this.stdC > 0 ? (obs - this.meanC) / this.stdC : 0;
      const zD = this.stdD > 0 ? (delta - this.meanD) / this.stdD : 0;
      this.score = Math.min(1, 1 - Math.exp(-(zC ** 2 + zD ** 2) / 2));
    }
  },
};
export const DOMAIN_IQ_MAX = 2e3;
export let _iqDecayTs = 0;
export let _userEstTs = 0;
export const _domainIQ = {
  map: new Map(),
  see(domain, outcome) {
    if (!domain || domain.length > 128) return;
    const d = domain.toLowerCase().replace(/\.$/, "");
    let rec = this.map.get(d);
    if (!rec) {
      if (this.map.size >= DOMAIN_IQ_MAX) this._evict();
      rec = {
        score: 100,
        hits: 0,
        bad: 0,
        nxHits: 0,
        blocked: 0,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        flags: 0,
      };
      this.map.set(d, rec);
    }
    rec.lastSeen = Date.now();
    rec.hits++;
    switch (outcome) {
      case "good":
        rec.score = Math.min(200, rec.score * 1.001 + 0.5);
        break;
      case "nx":
        rec.nxHits++;
        rec.score = Math.max(10, rec.score - 2);
        break;
      case "blocked":
        rec.blocked++;
        rec.bad++;
        rec.score = Math.max(5, rec.score - 15);
        break;
      case "dga":
        rec.bad++;
        rec.flags |= 1;
        rec.score = Math.max(5, rec.score - 25);
        break;
      case "burst":
        rec.bad++;
        rec.score = Math.max(10, rec.score - 8);
        break;
    }
    _brainDirty = true;
  },
  riskScore(domain) {
    const rec = this.map.get(domain?.toLowerCase().replace(/\.$/, "") ?? "");
    if (!rec || rec.hits < 3) return 50;
    const base = 100 - rec.score;
    const nxBoost =
      rec.hits > 0 ? Math.min(30, (rec.nxHits / rec.hits) * 100) : 0;
    return Math.min(
      100,
      Math.max(0, base + nxBoost + rec.blocked * 10 + (rec.flags & 1 ? 25 : 0)),
    );
  },
  decay() {
    for (const [, rec] of this.map) {
      const ageH = (Date.now() - rec.lastSeen) / 36e5;
      if (ageH > 24)
        rec.score = Math.max(20, rec.score * 0.9985 ** (ageH / 24));
    }
  },
  _evict() {
    let worst = null,
      wScore = Infinity;
    for (const [k, v] of this.map) {
      const s = v.score - (Date.now() - v.lastSeen) / 864e5;
      if (s < wScore) {
        wScore = s;
        worst = k;
      }
    }
    if (worst) this.map.delete(worst);
  },
  export() {
    return [...this.map.entries()]
      .sort((a, b) => b[1].hits - a[1].hits)
      .slice(0, 500)
      .map(([k, v]) => [
        k,
        v.score,
        v.hits,
        v.bad,
        v.blocked,
        v.flags,
        v.firstSeen,
      ]);
  },
  clear() {
    this.map.clear();
  },
  import(data) {
    if (!Array.isArray(data)) return;
    for (const [k, score, hits, bad, blocked, flags, firstSeen] of data)
      this.map.set(k, {
        score: score || 100,
        hits: hits || 0,
        bad: bad || 0,
        nxHits: 0,
        blocked: blocked || 0,
        firstSeen: firstSeen || Date.now(),
        lastSeen: Date.now(),
        flags: flags || 0,
      });
  },
};
export const _markov = {
  transitions: new Map(),
  history: new Map(),
  MAX_DOMAINS: 1e3,
  PREFETCH_THRESHOLD: 0.4,
  clear() {
    this.transitions.clear();
    this.history.clear();
  },
  track(clientIp, domain) {
    if (!clientIp || !domain || domain.length > 64) return;
    const prev = this.history.get(clientIp);
    const now = Date.now();
    this.history.set(clientIp, { d: domain, ts: now });
    if (this.history.size > 2e3)
      this.history.delete(this.history.keys().next().value);
    if (prev && prev.d !== domain && now - prev.ts < 2e3) {
      let t = this.transitions.get(prev.d);
      if (!t) {
        if (this.transitions.size >= this.MAX_DOMAINS)
          this.transitions.delete(this.transitions.keys().next().value);
        t = new Map();
        this.transitions.set(prev.d, t);
      }
      t.set(domain, (t.get(domain) || 0) + 1);
      if (t.size > 20) {
        const [oldest] = [...t.entries()].sort((a, b) => a[1] - b[1]);
        t.delete(oldest[0]);
      }
      _brainDirty = true;
    }
  },
  predict(domain) {
    const t = this.transitions.get(domain);
    if (!t || t.size === 0) return null;
    let total = 0,
      best = null,
      bestN = 0;
    for (const [d, n] of t) {
      total += n;
      if (n > bestN) {
        bestN = n;
        best = d;
      }
    }
    return bestN / total >= this.PREFETCH_THRESHOLD ? best : null;
  },
};
export const _dgaLegit = new Set();
export const _ucb = {
  rewards: new Float32Array(8),
  pulls: new Uint32Array(8),
  total: 0,
  select(n) {
    this.total++;
    let best = -1,
      bestVal = -Infinity;
    for (let i = 0; i < n; i++) {
      const exploit = this.pulls[i] > 0 ? this.rewards[i] / this.pulls[i] : 0;
      const explore =
        this.pulls[i] > 0
          ? Math.sqrt((2 * Math.log(this.total)) / this.pulls[i])
          : 10;
      const val = exploit + explore;
      if (val > bestVal) {
        bestVal = val;
        best = i;
      }
    }
    return best;
  },
  reward(i, r) {
    this.pulls[i]++;
    this.rewards[i] += (r - this.rewards[i]) / this.pulls[i];
  },
};
export let _brainDirty = false;
export let _brainLastSync = 0;
export let _brainSyncBytes = 0;
export let _brainLoadedAt = 0;
export let _brainLoaded = false;
export let _brainInitializing = false;
export let _stressHistory = new Float32Array(10);
export let _rpsHistory = new Float64Array(60);
export let _userMap = new Map();
export let _deviceMap = new Map();
export let _userRing = new Float32Array(20);
export {
  _stress, setStress, _stressIdx,
  _rpsSmooth, _rpsPeak, _rpsIdx, _rpsTotal,
  _userWinStart, _userRingIdx, _userSamples, _userRingFull,
  _userEwmaFast, _userEwmaSlow, _userPeak,
  _userEstimate, _userModeAuto, setUserEstimate, setUserModeAuto
} from "./telemetry.js";
export const HEATMAP_MAX = 2e3;
export const _heatmap = new Map();
export let _heatmapFlushTs = 0;
export const _obs = {
  ewma: new Map(),
  hourly: new Map(),
  hourStart: 0,
  reset() {
    this.ewma.clear();
    this.hourly.clear();
    this.hourStart = 0;
  },
  observe(type, n = 1) {
    const now = Date.now();
    if (now - this.hourStart > 36e5) {
      for (const [k, v] of this.hourly)
        this.ewma.set(k, 0.15 * v + 0.85 * (this.ewma.get(k) || 0));
      this.hourly.clear();
      this.hourStart = now;
    }
    this.hourly.set(type, (this.hourly.get(type) || 0) + n);
  },
  deviation() {
    const scores = [];
    for (const [k, ewma] of this.ewma) {
      const cur = this.hourly.get(k) || 0;
      if (ewma > 0) scores.push(Math.min(1, Math.abs(cur - ewma) / (ewma + 1)));
    }
    return scores.length
      ? scores.reduce((a, b) => a + b, 0) / scores.length
      : 0;
  },
};
export const _answerHistory = new Map();
export const LEDGER_MAX = 200;
export const _ledger = {
  entries: [],
  clear() {
    this.entries.length = 0;
  },
  record(type, domain, signal, action, conf = 0.5) {
    this.entries.push({
      ts: Date.now(),
      type: type,
      domain: domain?.slice(0, 64) || "",
      signal: signal,
      action: action,
      conf: conf,
      outcome: null,
    });
    if (this.entries.length > LEDGER_MAX) this.entries.shift();
  },
  calibration() {
    const closed = this.entries.filter((e) => e.outcome != null);
    if (closed.length < 10) return 1;
    const correct = closed.filter(
      (e) =>
        (e.outcome === "confirmed_threat" && e.conf >= 0.5) ||
        (e.outcome === "false_positive" && e.conf < 0.5),
    ).length;
    return correct / closed.length;
  },
};
export const _budgetAI = {
  used: 0,
  limit: PULSE_WRITE_LIMIT,
  hourlyBurn: new Float32Array(24),
  learnedBurn: new Float32Array(24),
  learnedBurnN: new Uint16Array(24),
  govMult: 1,
  govLoosen: 0,
  reset() {
    this.used = 0;
    this.hourlyBurn.fill(0);
    this.learnedBurn.fill(0);
    this.learnedBurnN.fill(0);
    this.govMult = 1;
    this.govLoosen = 0;
  },
  track(n = 1) {
    this.used += n;
    this.hourlyBurn[new Date().getUTCHours()] += n;
  },
  canWrite(isLearning = false) {
    if (this.used >= this.limit) return false;
    const progress = (new Date().getUTCHours() + 1) / 24;
    const target = this.limit * progress * (isLearning ? 0.4 : 0.85);
    return this.used < target * this.govMult;
  },
  governorTick() {
    const h = new Date().getUTCHours();
    const progress = (h + 1) / 24;
    const ratio = this.used / (this.limit * progress || 1);
    if (ratio > 1.2) {
      this.govMult = Math.max(0.2, this.govMult * 0.6);
      this.govLoosen = 0;
    } else if (ratio > 0.9) {
      this.govMult = Math.max(0.4, this.govMult * 0.85);
      this.govLoosen = 0;
    } else if (ratio < 0.65) {
      this.govLoosen++;
      if (this.govLoosen >= 2) this.govMult = Math.min(1.5, this.govMult * 1.1);
    } else {
      this.govMult = this.govMult * 0.97 + 0.03;
      this.govLoosen = 0;
    }
  },
};
export const _enc = new TextEncoder();
export const _hmacCache = new WeakMap();
export function setIsolateId(id) { _ISOLATE_ID = id; }
export function setBrainDirty(b) { _brainDirty = b; }
export function setBrainLastSync(t) { _brainLastSync = t; }
export function setBrainSyncBytes(b) { _brainSyncBytes = b; }
export function setBrainLoaded(b) { _brainLoaded = b; }
export function setBrainLoadedAt(t) { _brainLoadedAt = t; }
export function setBrainInitializing(b) { _brainInitializing = b; }
export let _workerId = null;
export function setWorkerId(id) { _workerId = id; }
export let _workerStartTs = 0;
export function setWorkerStartTs(ts) { _workerStartTs = ts; }
export let _brainSyncCount = 0;
export function setBrainSyncCount(c) { _brainSyncCount = c; }
