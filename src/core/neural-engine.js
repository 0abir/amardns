// src/core/neural-engine.js
// Neural AI Threat Engine: Feature extraction, attention routing, 20-model threat ensemble, dynamic TTL, and online learning.

import {
  _BG_SET1,
  _RE_CONSONANT_RUN, FEAT_CACHE_MAX,
  AERO_WRITE_LIMIT, PULSE_WRITE_LIMIT, CB_THRESHOLD, DGA_FLAG_SCORE, DGA_BLOCK_SCORE, DOMAIN_IQ_MAX,
  BRAIN_PRUNE_EVERY
} from "./constants.js";
import {
  _featCache, BRANDS_LIST, _env, _bgEnqueue,
  _aeroThrottle, _domainIQ, _markov, _runtimeConfig, _sh, _rhythm, _budgetAI,
  _rpsHistory, _anomaly, _cb, _dgaLegit, _ucb, _ups, setBrainDirty,
  _pulseThrottle, _pulseW, _aeroW
} from "./state.js";
import {
  _softmax, _clip, _sigmoid, _relu,
  _makeLayerNorm, _heInit, _makeDense, _zeros, _randn, _glorot, _ones, _gelu
} from "./neural-math.js";
import {
  _lazy, _dtn, _moe, _gru, _ae, _spiking, _liquid, _mha,
  _bnn, _contrastive, _neuron, _gnn, _forest, _calibrator,
  _meta, _dtcn, _symbolic, _embNet, _finalNeuron, _rl
} from "./neural-models.js";
import {
  _aeroCanWrite, _aeroAccountWrite, _log, _aiDecision,
  _adaptiveConfigTick, _updateUserEstimate, _memCheck, _stress, _rpsSmooth
} from "./telemetry.js";

let _iqDecayTs = 0;
let _userEstTs = 0;


export function _feat40Raw(
  domain,
  clientIp,
  rps,
  iqScore,
  markovConf,
  burstFlag,
  latencyMs,
  ttl,
) {
  const parts = domain.split(".");
  const label = (
    parts.length >= 2 ? parts[parts.length - 2] : ""
  ).toLowerCase();
  const tld = parts[parts.length - 1] || "";
  const subDepth = Math.max(0, parts.length - 2);
  const freq = {};
  for (const c of label) freq[c] = (freq[c] || 0) + 1;
  let ent = 0;
  for (const c in freq) {
    const p = freq[c] / label.length;
    ent -= p * Math.log2(p + 1e-9);
  }
  const dl = label.length;
  let vowels = 0;
  let digits = 0;
  let hyphens = 0;
  for (let i = 0; i < dl; i++) {
    const code = label.charCodeAt(i);
    if (code >= 48 && code <= 57) digits++;
    else if (code === 45) hyphens++;
    else if (code === 97 || code === 101 || code === 105 || code === 111 || code === 117) vowels++;
  }
  const cruns = (label.match(_RE_CONSONANT_RUN) || []).length;
  const dots = parts.length - 1;
  let bgH = 0,
    bgT = 0;
  for (let i = 0; i < label.length - 1; i++) {
    bgT++;
    if (_BG_SET1.has(label[i] + label[i + 1])) bgH++;
  }
  const now = new Date();
  const h = now.getUTCHours();
  const dow = now.getUTCDay();
  const embVec = _embNet.embed(label);
  if (!_embNet._brandEmbs)
    _embNet._brandEmbs = BRANDS_LIST.map((b) => ({
      brand: b,
      emb: _embNet.embed(b),
    }));
  let bestBrandSim = 0;
  for (const { emb: emb } of _embNet._brandEmbs) {
    let s = 0;
    for (let i = 0; i < 24; i++) s += embVec[i] * emb[i];
    if (s > bestBrandSim) bestBrandSim = s;
  }
  const f32stub = new Float32Array(32);
  f32stub[0] = Math.min(ent / 4, 1);
  f32stub[5] = Math.min(dl / 30, 1);
  const contrScore = _contrastive.score(f32stub);
  const gnnScore = _gnn.propagate(domain);
  return new Float32Array([
    Math.min(ent / 4, 1),
    dl > 0 ? vowels / dl : 0,
    dl > 0 ? digits / dl : 0,
    bgT > 0 ? bgH / bgT : 0,
    Math.min(cruns / 3, 1),
    Math.min(dl / 30, 1),
    Math.min(hyphens / 3, 1),
    /[^\x00-\x7f]/.test(domain) ? 1 : 0,
    Math.min((label.match(/\d{4,}/g) || []).length / 2, 1),
    Math.min(subDepth / 6, 1),
    Math.sin((2 * Math.PI * h) / 24),
    Math.cos((2 * Math.PI * h) / 24),
    Math.sin((2 * Math.PI * dow) / 7),
    Math.cos((2 * Math.PI * dow) / 7),
    Math.min(rps / 100, 1),
    iqScore / 100,
    markovConf,
    burstFlag ? 1 : 0,
    bestBrandSim,
    tld === "com" ? 1 : 0,
    tld === "net" ? 1 : 0,
    tld === "org" ? 1 : 0,
    dl > 20 && digits > 0 ? 1 : 0,
    Math.min(dots / 5, 1),
    embVec[0],
    embVec[1],
    embVec[2],
    embVec[3],
    embVec[4],
    embVec[5],
    embVec[6],
    embVec[7],
    embVec[8],
    latencyMs ? Math.min(latencyMs / 3e3, 1) : 0,
    ttl ? Math.min(ttl / 3600, 1) : 0,
    contrScore,
    gnnScore,
    Math.min((digits + cruns) / 5, 1),
    ent > 3.5 ? 1 : 0,
    dl < 5 ? 1 : 0,
  ]);
}
export function _feat40(d, ip, r, iq, m, b, l, t) {
  const k = `${d}:${iq}:${m}:${b}:${l}:${t}`;
  if (_featCache.has(k)) {
    const v = _featCache.get(k);
    _featCache.delete(k);
    _featCache.set(k, v);
    return v;
  }
  const f = _feat40Raw(d, ip, r, iq, m, b, l, t);
  if (_featCache.size >= FEAT_CACHE_MAX)
    _featCache.delete(_featCache.keys().next().value);
  _featCache.set(k, f);
  return f;
}
export function _buildUpstreamFeats(ups, ucb, cb) {
  const n = ups.length;
  const feats = new Float32Array(n * 4);
  for (let i = 0; i < n; i++) {
    const pulls = ucb.pulls[i] || 0;
    const exploit = pulls > 0 ? ucb.rewards[i] / pulls : 0.5;
    const explore =
      pulls > 0 ? Math.sqrt((2 * Math.log(ucb.total + 1)) / pulls) : 1;
    const cbOpen = cb[i] && cb[i].open ? 1 : 0;
    const errRate = cb[i] && cb[i].total > 0 ? cb[i].errors / cb[i].total : 0;
    feats[i * 4 + 0] = exploit;
    feats[i * 4 + 1] = Math.min(1, explore);
    feats[i * 4 + 2] = cbOpen;
    feats[i * 4 + 3] = errRate;
  }
  return feats;
}
export const _transformer = _lazy(() => ({
  heads: 4,
  dim: 32,
  WQ: _heInit(32, 32),
  WK: _heInit(32, 32),
  WV: _heInit(32, 32),
  Wout: _heInit(32, 32),
  LN: _makeLayerNorm(32),
  forward(x32) {
    const q = new Float32Array(32),
      k = new Float32Array(32),
      v = new Float32Array(32);
    for (let j = 0; j < 32; j++) {
      for (let i = 0; i < 32; i++) {
        q[j] += this.WQ[j * 32 + i] * x32[i];
        k[j] += this.WK[j * 32 + i] * x32[i];
        v[j] += this.WV[j * 32 + i] * x32[i];
      }
    }
    const scores = new Float32Array(32);
    for (let i = 0; i < 32; i++) scores[i] = (q[i] * k[i]) / Math.sqrt(8);
    const attn = _softmax(Array.from(scores));
    const out = new Float32Array(32);
    for (let i = 0; i < 32; i++) out[i] = attn[i] * v[i];
    const residual = new Float32Array(32);
    for (let i = 0; i < 32; i++) residual[i] = _relu(out[i] + x32[i]);
    return this.LN.fwd(residual);
  },
  export() {
    return {
      WQ: Array.from(this.WQ),
      WK: Array.from(this.WK),
      WV: Array.from(this.WV),
      Wout: Array.from(this.Wout),
    };
  },
  import(d) {
    if (d.WQ) this.WQ.set(d.WQ);
    if (d.WK) this.WK.set(d.WK);
    if (d.WV) this.WV.set(d.WV);
    if (d.Wout) this.Wout.set(d.Wout);
  },
}));
export const _manifold = _lazy(() => ({
  L1: _makeDense(17, 32, "gelu"),
  L2: _makeDense(32, 16, "swish"),
  L3: _makeDense(16, 1, "sig"),
  lr: 1e-4,
  fuse(scores17) {
    const h1 = this.L1.fwd(scores17);
    const h2 = this.L2.fwd(h1);
    return this.L3.fwd(h2)[0];
  },
  train(scores17, label) {
    const out = this.fuse(scores17);
    const dL = new Float32Array([out - label]);
    const d2 = this.L3.bwd(dL, this.lr);
    const gOne = this.L2.bwd(d2, this.lr);
    this.L1.bwd(gOne, this.lr);
  },
  export() {
    return { L1: this.L1.export(), L2: this.L2.export(), L3: this.L3.export() };
  },
  import(d) {
    if (d.L1) this.L1.import(d.L1);
    if (d.L2) this.L2.import(d.L2);
    if (d.L3) this.L3.import(d.L3);
  },
}));
export const _nnStats = {
  learningCycles: 0,
  brainVersion: "1.0.0",
  dtnInferences: 0,
  dtnBlocks: 0,
  dtnCalls: 0,
  gruAlarms: 0,
  gruSteps: 0,
  mhaSelections: 0,
  dtcnClass: "normal",
  dtcnScore: 0,
  moeDecisions: { phishing: 0, dga: 0, c2: 0, tunnel: 0 },
  aeAnomalies: 0,
  rlDecisions: 0,
  rlHitReward: 0,
  liquidCalls: 0,
  liquidStability: 0,
  spikeCount: 0,
  symbolicDecisions: 0,
  manifoldInferences: 0,
  transformerReflex: 0,
  bnnUncertainty: 0,
  bnnCalls: 0,
  neuronCalls: 0,
  contrastiveCalls: 0,
  gnnCalls: 0,
  forestCalls: 0,
  calibratorCalls: 0,
  metaCalls: 0,
  embUpdates: 0,
  finalInferences: 0,
  lastMeta: { lrScale: 1, cacheTtlMult: 1, cbThreshAdj: 0, stressResponse: 0 },
  totalParams: 168400,
};
export const _charTransformer = _lazy(() => {
  const VOCAB = 128;
  const DIM = 32;
  const HEADS = 4;
  const HEAD_DIM = DIM / HEADS;
  const FFN_DIM = 64;
  const N_LAYERS = 4;
  const MAX_SEQ = 66;
  const E = _heInit(VOCAB, DIM);
  const cls = _randn(DIM, 0.02);
  const pos = _randn(MAX_SEQ * DIM, 0.01);
  const layers = Array.from({ length: N_LAYERS }, (_, l) => ({
    WQ: _glorot(DIM, DIM),
    WK: _glorot(DIM, DIM),
    WV: _glorot(DIM, DIM),
    WO: _glorot(DIM, DIM),
    mWQ: _zeros(DIM * DIM),
    vWQ: _zeros(DIM * DIM),
    mWK: _zeros(DIM * DIM),
    vWK: _zeros(DIM * DIM),
    mWV: _zeros(DIM * DIM),
    vWV: _zeros(DIM * DIM),
    mWO: _zeros(DIM * DIM),
    vWO: _zeros(DIM * DIM),
    W1: _heInit(DIM, FFN_DIM),
    b1: _zeros(FFN_DIM),
    W2: _heInit(FFN_DIM, DIM),
    b2: _zeros(DIM),
    mW1: _zeros(DIM * FFN_DIM),
    vW1: _zeros(DIM * FFN_DIM),
    mW2: _zeros(FFN_DIM * DIM),
    vW2: _zeros(FFN_DIM * DIM),
    ln1_g: _ones(DIM),
    ln1_b: _zeros(DIM),
    ln2_g: _ones(DIM),
    ln2_b: _zeros(DIM),
  }));
  const mE = _zeros(VOCAB * DIM),
    vE = _zeros(VOCAB * DIM);
  let t = 0;
  const LR = 2e-4;
  const BETA1 = 0.9,
    BETA2 = 0.999,
    EPS = 1e-8;
  function layerNorm(x, g, b) {
    const n = x.length;
    let mean = 0;
    for (let i = 0; i < n; i++) mean += x[i];
    mean /= n;
    let v = 0;
    for (let i = 0; i < n; i++) v += (x[i] - mean) ** 2;
    v = Math.sqrt(v / n + 1e-5);
    const out = new Float32Array(n);
    for (let i = 0; i < n; i++) out[i] = (g[i] * (x[i] - mean)) / v + b[i];
    return out;
  }
  function matmul(x, W, inDim, outDim) {
    const out = new Float32Array(outDim);
    for (let j = 0; j < outDim; j++) {
      let s = 0;
      for (let i = 0; i < inDim; i++) s += x[i] * W[j * inDim + i];
      out[j] = s;
    }
    return out;
  }
  function tokenize(domain) {
    const parts = domain.toLowerCase().replace(/\.$/, "").split(".");
    const raw = parts
      .slice(-3)
      .join(".")
      .slice(0, MAX_SEQ - 1);
    const seq = [];
    seq.push(new Float32Array(cls));
    for (let i = 0; i < raw.length; i++) {
      const id = Math.min(raw.charCodeAt(i), 127);
      const emb = new Float32Array(DIM);
      for (let d = 0; d < DIM; d++) emb[d] = E[id * DIM + d];
      seq.push(emb);
    }
    for (let s = 0; s < seq.length; s++) {
      const p = pos.slice(s * DIM, (s + 1) * DIM);
      for (let d = 0; d < DIM; d++) seq[s][d] += p[d];
    }
    return seq;
  }
  function forwardLayer(seq, layer) {
    const S = seq.length;
    const out = [];
    const Qs = seq.map((x) => matmul(x, layer.WQ, DIM, DIM));
    const Ks = seq.map((x) => matmul(x, layer.WK, DIM, DIM));
    const Vs = seq.map((x) => matmul(x, layer.WV, DIM, DIM));
    for (let s = 0; s < S; s++) {
      const headConcat = new Float32Array(DIM);
      for (let h = 0; h < HEADS; h++) {
        const hOff = h * HEAD_DIM;
        const scores = new Float32Array(S);
        for (let k = 0; k < S; k++) {
          let dot = 0;
          for (let d = 0; d < HEAD_DIM; d++)
            dot += Qs[s][hOff + d] * Ks[k][hOff + d];
          scores[k] = dot / Math.sqrt(HEAD_DIM);
        }
        const attn = _softmax(Array.from(scores));
        for (let d = 0; d < HEAD_DIM; d++) {
          let ctx = 0;
          for (let k = 0; k < S; k++) ctx += attn[k] * Vs[k][hOff + d];
          headConcat[hOff + d] = ctx;
        }
      }
      const attnOut = matmul(headConcat, layer.WO, DIM, DIM);
      const res1 = new Float32Array(DIM);
      for (let d = 0; d < DIM; d++) res1[d] = seq[s][d] + attnOut[d];
      const ln1 = layerNorm(res1, layer.ln1_g, layer.ln1_b);
      const ffn1 = new Float32Array(FFN_DIM);
      for (let j = 0; j < FFN_DIM; j++) {
        let s2 = layer.b1[j];
        for (let i = 0; i < DIM; i++) s2 += layer.W1[j * DIM + i] * ln1[i];
        ffn1[j] = _gelu(s2);
      }
      const ffn2 = new Float32Array(DIM);
      for (let j = 0; j < DIM; j++) {
        let s2 = layer.b2[j];
        for (let i = 0; i < FFN_DIM; i++)
          s2 += layer.W2[j * FFN_DIM + i] * ffn1[i];
        ffn2[j] = s2;
      }
      const res2 = new Float32Array(DIM);
      for (let d = 0; d < DIM; d++) res2[d] = ln1[d] + ffn2[d];
      out.push(layerNorm(res2, layer.ln2_g, layer.ln2_b));
    }
    return out;
  }
  function encode(domain) {
    if (!domain || domain.length < 2) return _zeros(DIM);
    let seq = tokenize(domain);
    for (const layer of layers) seq = forwardLayer(seq, layer);
    const out = new Float32Array(DIM);
    for (let d = 0; d < DIM; d++) out[d] = seq[0][d];
    return out;
  }
  function adamUpdate(param, grad, m, v, lr) {
    t++;
    const bc1 = 1 - BETA1 ** t,
      bc2 = 1 - BETA2 ** t;
    for (let i = 0; i < param.length; i++) {
      const g = _clip(grad[i], -1, 1);
      m[i] = BETA1 * m[i] + (1 - BETA1) * g;
      v[i] = BETA2 * v[i] + (1 - BETA2) * g * g;
      param[i] -= (lr * (m[i] / bc1)) / (Math.sqrt(v[i] / bc2) + EPS);
    }
  }
  function backward(domain, dCLS) {
    if (!domain || !dCLS) return;
    const raw = domain
      .toLowerCase()
      .replace(/\.$/, "")
      .split(".")
      .slice(-3)
      .join(".")
      .slice(0, MAX_SEQ - 1);
    const scale = 1 / Math.max(1, raw.length);
    for (let i = 0; i < raw.length; i++) {
      const id = Math.min(raw.charCodeAt(i), 127);
      for (let d = 0; d < DIM; d++) {
        const g = dCLS[d] * scale;
        mE[id * DIM + d] = BETA1 * mE[id * DIM + d] + (1 - BETA1) * g;
        vE[id * DIM + d] = BETA2 * vE[id * DIM + d] + (1 - BETA2) * g * g;
        const bc1 = 1 - BETA1 ** Math.max(1, t),
          bc2 = 1 - BETA2 ** Math.max(1, t);
        E[id * DIM + d] -=
          (LR * (mE[id * DIM + d] / bc1)) /
          (Math.sqrt(vE[id * DIM + d] / bc2) + EPS);
      }
    }
    const layer = layers[N_LAYERS - 1];
    const dW2 = new Float32Array(FFN_DIM * DIM);
    for (let j = 0; j < DIM; j++)
      for (let i = 0; i < FFN_DIM; i++) dW2[j * FFN_DIM + i] = dCLS[j] * 0.1;
    adamUpdate(layer.W2, dW2, layer.mW2, layer.vW2, LR);
  }
  function exportWeights() {
    const r = (v) => +v.toFixed(5);
    return {
      E: Array.from(E).map(r),
      cls: Array.from(cls).map(r),
      pos: Array.from(pos).map(r),
      layers: layers.map((l) => ({
        WQ: Array.from(l.WQ).map(r),
        WK: Array.from(l.WK).map(r),
        WV: Array.from(l.WV).map(r),
        WO: Array.from(l.WO).map(r),
        W1: Array.from(l.W1).map(r),
        b1: Array.from(l.b1).map(r),
        W2: Array.from(l.W2).map(r),
        b2: Array.from(l.b2).map(r),
        ln1_g: Array.from(l.ln1_g).map(r),
        ln1_b: Array.from(l.ln1_b).map(r),
        ln2_g: Array.from(l.ln2_g).map(r),
        ln2_b: Array.from(l.ln2_b).map(r),
      })),
      t: t,
    };
  }
  function importWeights(d) {
    if (!d) return;
    if (d.E && d.E.length === E.length) E.set(d.E);
    if (d.cls && d.cls.length === cls.length) cls.set(d.cls);
    if (d.pos && d.pos.length === pos.length) pos.set(d.pos);
    if (d.layers)
      d.layers.forEach((ld, i) => {
        if (!layers[i]) return;
        const l = layers[i];
        if (ld.WQ) l.WQ.set(ld.WQ);
        if (ld.WK) l.WK.set(ld.WK);
        if (ld.WV) l.WV.set(ld.WV);
        if (ld.WO) l.WO.set(ld.WO);
        if (ld.W1) l.W1.set(ld.W1);
        if (ld.b1) l.b1.set(ld.b1);
        if (ld.W2) l.W2.set(ld.W2);
        if (ld.b2) l.b2.set(ld.b2);
        if (ld.ln1_g) l.ln1_g.set(ld.ln1_g);
        if (ld.ln1_b) l.ln1_b.set(ld.ln1_b);
        if (ld.ln2_g) l.ln2_g.set(ld.ln2_g);
        if (ld.ln2_b) l.ln2_b.set(ld.ln2_b);
      });
    if (d.t) t = d.t;
  }
  return {
    encode: encode,
    backward: backward,
    exportWeights: exportWeights,
    importWeights: importWeights,
    get t() {
      return t;
    },
  };
});
export const _episodic = (() => {
  const CAPACITY = 500;
  const K_NEAREST = 8;
  const PERSIST_EVERY = 50;
  const OUTCOME_SCORES = { good: 0, nx: 0.3, burst: 0.5, dga: 0.9, blocked: 1 };
  let buffer = [];
  let addCount = 0;
  let _dirty = false;
  function remember(domain, emb, outcome) {
    if (!emb) return;
    buffer.push({
      emb: new Float32Array(emb),
      outcome: outcome,
      domain: domain.slice(0, 64),
      ts: Date.now(),
    });
    if (buffer.length > CAPACITY) buffer.shift();
    addCount++;
    _dirty = true;
    if (addCount % PERSIST_EVERY === 0) _persistAsync();
  }
  function recall(emb) {
    if (!emb || buffer.length === 0) {
      return {
        contextVec: new Float32Array(8),
        threatRatio: 0.5,
        seenBefore: false,
      };
    }
    const norm = (v) => {
      let s = 0;
      for (let i = 0; i < v.length; i++) s += v[i] * v[i];
      return Math.sqrt(s) + 1e-8;
    };
    const qNorm = norm(emb);
    const scored = buffer.map((ev, idx) => {
      let dot = 0;
      const eNorm = norm(ev.emb);
      for (let i = 0; i < 32; i++) dot += emb[i] * ev.emb[i];
      const sim = dot / (qNorm * eNorm);
      return { sim: sim, outcome: ev.outcome, ts: ev.ts, idx: idx };
    });
    scored.sort((a, b) => b.sim - a.sim);
    const topK = scored.slice(0, K_NEAREST);
    const ctx = new Float32Array(8);
    let threatSum = 0,
      totalSim = 0,
      recentCount = 0;
    const now = Date.now();
    for (const ev of topK) {
      const w = Math.max(0, ev.sim);
      const ts = OUTCOME_SCORES[ev.outcome] ?? 0.5;
      const recency = Math.exp(-(now - ev.ts) / 36e5);
      threatSum += ts * w;
      totalSim += w;
      if (ev.sim > 0.9) recentCount++;
      ctx[0] += w * ts;
      ctx[1] += w * recency;
      ctx[2] += w * (ts > 0.5 ? 1 : 0);
      ctx[3] += w * (ts < 0.2 ? 1 : 0);
    }
    if (totalSim > 0) {
      ctx[0] /= totalSim;
      ctx[1] /= totalSim;
      ctx[2] = Math.min(1, ctx[2] / K_NEAREST);
      ctx[3] = Math.min(1, ctx[3] / K_NEAREST);
    }
    ctx[4] = Math.min(1, recentCount / K_NEAREST);
    ctx[5] = totalSim > 0 ? threatSum / totalSim : 0.5;
    ctx[6] = topK.length > 0 ? topK[0].sim : 0;
    ctx[7] = Math.min(1, buffer.length / CAPACITY);
    const threatRatio = totalSim > 0 ? threatSum / totalSim : 0.5;
    const seenBefore = topK.length > 0 && topK[0].sim > 0.85;
    return {
      contextVec: ctx,
      threatRatio: threatRatio,
      seenBefore: seenBefore,
    };
  }
  function _persistAsync() {
    if (!_dirty) return;
    _dirty = false;
    const aero = _env?.DNS_AERO;
    if (!aero || _aeroThrottle) return;
    const toSave = buffer
      .slice(-200)
      .map((ev) => ({
        e: Array.from(ev.emb).map((v) => +v.toFixed(4)),
        o: ev.outcome,
        d: ev.domain,
        t: ev.ts,
      }));
    _bgEnqueue(async () => {
      if (_aeroThrottle || !_aeroCanWrite()) return;
      try {
        await _env.DNS_AERO.put("ai:episodic", JSON.stringify(toSave), {
          expirationTtl: 86400,
        });
        _aeroAccountWrite();
      } catch (_) {}
    });
  }
  async function load() {
    const aero = _env?.DNS_AERO;
    if (!aero) return;
    try {
      const raw = await aero.get("ai:episodic", "text");
      if (!raw) return;
      const saved = JSON.parse(raw);
      for (const ev of saved) {
        if (!ev.e || ev.e.length !== 32) continue;
        buffer.push({
          emb: new Float32Array(ev.e),
          outcome: ev.o || "good",
          domain: ev.d || "",
          ts: ev.t || Date.now(),
        });
      }
      if (buffer.length > CAPACITY) buffer = buffer.slice(-CAPACITY);
    } catch (_) {}
  }
  function clear() {
    buffer = [];
    addCount = 0;
    _dirty = false;
  }
  function stats() {
    return { size: buffer.length, capacity: CAPACITY, addCount: addCount };
  }
  return { remember: remember, recall: recall, load: load, stats: stats, clear: clear };
})();
export const _rewardShaper = (() => {
  const SIGNAL_LOG = [];
  const MAX_LOG = 200;
  let totalSignals = 0;
  function signal(domain, outcome, context = {}) {
    if (!domain) return;
    totalSignals++;
    const isThreaten = outcome === "confirmed_threat" ? 1 : 0;
    const isClean =
      outcome === "confirmed_clean" || outcome === "false_positive";
    const emb = _charTransformer.encode(domain);
    const dCLS = new Float32Array(32);
    for (let i = 0; i < 32; i++)
      dCLS[i] = isThreaten ? emb[i] * 0.1 : -emb[i] * 0.05;
    _charTransformer.backward(domain, dCLS);
    const epOutcome = isThreaten ? "blocked" : "good";
    _episodic.remember(domain, emb, epOutcome);
    for (let rep = 0; rep < 3; rep++) {
      nnLearn(
        domain,
        null,
        _rpsSmooth,
        _domainIQ.riskScore(domain),
        _markov.predict(domain) ? 1 : 0,
        false,
        isThreaten ? "blocked" : "good",
        undefined,
        undefined,
      );
    }
    const rawScore = _dtn._a6 || 0.5;
    _calibrator.update(rawScore, isThreaten);
    SIGNAL_LOG.push({
      ts: Date.now(),
      domain: domain,
      outcome: outcome,
      source: context.source || "admin",
    });
    if (SIGNAL_LOG.length > MAX_LOG) SIGNAL_LOG.shift();
    setBrainDirty(true);
    _log("reward_signal", {
      domain: domain,
      outcome: outcome,
      totalSignals: totalSignals,
    });
  }
  function getLog() {
    return SIGNAL_LOG.slice(-50);
  }
  function getStats() {
    return { totalSignals: totalSignals, logSize: SIGNAL_LOG.length };
  }
  function clear() {
    SIGNAL_LOG.length = 0;
    totalSignals = 0;
  }
  return { signal: signal, getLog: getLog, getStats: getStats, clear: clear };
})();
export const _contextFusion = _lazy(() => ({
  L1: _makeDense(32, 48, "gelu"),
  L2: _makeDense(48, 24, "mish"),
  L3: _makeDense(24, 1, "sig"),
  lr: 15e-5,
  calls: 0,
  fwd(scores20, episodicCtx8, charSummary4) {
    const inp = new Float32Array(32);
    for (let i = 0; i < 20; i++) inp[i] = scores20[i] || 0;
    for (let i = 0; i < 8; i++) inp[20 + i] = episodicCtx8[i] || 0;
    for (let i = 0; i < 4; i++) inp[28 + i] = charSummary4[i] || 0;
    const h1 = this.L1.fwd(inp);
    const h2 = this.L2.fwd(h1);
    this.calls++;
    return this.L3.fwd(h2)[0];
  },
  train(scores20, episodicCtx8, charSummary4, label) {
    const inp = new Float32Array(32);
    for (let i = 0; i < 20; i++) inp[i] = scores20[i] || 0;
    for (let i = 0; i < 8; i++) inp[20 + i] = episodicCtx8[i] || 0;
    for (let i = 0; i < 4; i++) inp[28 + i] = charSummary4[i] || 0;
    const h1 = this.L1.fwd(inp);
    const h2 = this.L2.fwd(h1);
    const out = this.L3.fwd(h2)[0];
    const dL = new Float32Array(1);
    dL[0] = out - label;
    const d2 = this.L3.bwd(dL, this.lr);
    const gOne = this.L2.bwd(d2, this.lr);
    this.L1.bwd(gOne, this.lr);
    this.calls++;
  },
  export() {
    return {
      L1: this.L1.export(),
      L2: this.L2.export(),
      L3: this.L3.export(),
      calls: this.calls,
    };
  },
  import(d) {
    if (!d) return;
    if (d.L1) this.L1.import(d.L1);
    if (d.L2) this.L2.import(d.L2);
    if (d.L3) this.L3.import(d.L3);
    if (d.calls) this.calls = d.calls;
  },
}));
export function _charSummary4(charEmb32) {
  if (!charEmb32) return new Float32Array(4);
  let mean = 0,
    mx = -Infinity,
    mn = Infinity;
  for (let i = 0; i < 32; i++) {
    mean += charEmb32[i];
    if (charEmb32[i] > mx) mx = charEmb32[i];
    if (charEmb32[i] < mn) mn = charEmb32[i];
  }
  mean /= 32;
  let std = 0;
  for (let i = 0; i < 32; i++) std += (charEmb32[i] - mean) ** 2;
  std = Math.sqrt(std / 32);
  return new Float32Array([
    _sigmoid(mean * 4),
    Math.min(1, std * 2),
    _sigmoid(mx * 3),
    _sigmoid(mn * 3),
  ]);
}
export function nnThreatScore(domain, clientIp, rps, iqScore, markovConf, burstFlag) {
  const f40 = _feat40(
    domain,
    clientIp,
    rps,
    iqScore,
    markovConf,
    burstFlag,
    0,
    0,
  );
  const f32_raw = f40.slice(0, 32);
  const charEmb = _charTransformer.encode(domain);
  const f32 = _transformer.forward(f32_raw);
  _nnStats.transformerReflex++;
  const {
    contextVec: _epCtx,
    threatRatio: _epThreat,
    seenBefore: _epSeen,
  } = _episodic.recall(charEmb);
  const liquidIn = new Float32Array([f40[0], f40[14], f40[15], f40[17]]);
  const liqOut = _liquid.step(liquidIn);
  _nnStats.liquidCalls++;
  _nnStats.liquidStability = 0.99 * _nnStats.liquidStability + 0.01 * liqOut[0];
  const spikes =
    _stress < 0.8 ? _spiking.step(f40.slice(0, 16)) : new Float32Array(32);
  _nnStats.spikeCount = _spiking.spikes;
  const reasons = _symbolic.reason(f40);
  if (reasons) _nnStats.symbolicDecisions++;
  const dtnP = _dtn.fwd(f32);
  _nnStats.dtnInferences++;
  const f24 = f40.slice(0, 24);
  const moeResult = _moe.fwd(f24);
  if (moeResult.score > 0.5)
    _nnStats.moeDecisions[moeResult.expert] =
      (_nnStats.moeDecisions[moeResult.expert] || 0) + 1;
  const gruIn = new Float32Array(8);
  gruIn[0] = f40[0];
  gruIn[1] = f40[2];
  gruIn[2] = f40[9];
  gruIn[3] = f40[14];
  gruIn[4] = f40[15];
  gruIn[5] = f40[17];
  gruIn[6] = f40[18];
  gruIn[7] = f40[22];
  const gruScore = _gru.step(clientIp || "0.0.0.0", gruIn);
  _nnStats.gruSteps = (_nnStats.gruSteps || 0) + 1;
  if (gruScore > 0.7) _nnStats.gruAlarms++;
  const dtcnResult = _dtcn.forward(_rpsHistory);
  const aeResult = _ae.fwd(f32);
  if (aeResult.anomaly) _nnStats.aeAnomalies++;
  const bnnResult = _bnn.predict(f32);
  const forestScore = _forest.predict(f32);
  const metaOut = _meta.forward(gruIn);
  const neuronScore = _neuron.fwd(f24);
  _nnStats.lastMeta = metaOut;
  _nnStats.neuronCalls++;
  _nnStats.contrastiveCalls++;
  _nnStats.gnnCalls++;
  _nnStats.forestCalls++;
  const scores20 = new Float32Array([
    dtnP,
    moeResult.score,
    gruScore,
    dtcnResult.score,
    aeResult.mse,
    bnnResult.mean,
    f40[35] || 0,
    f40[36] || 0,
    forestScore,
    metaOut.stressResponse,
    neuronScore,
    liqOut[0],
    liqOut[1],
    bnnResult.confidence,
    _spiking.spikes / 100,
    _transformer.forward(f32_raw)[0],
    reasons ? 1 : 0,
    _rl.cacheHitReward + 0.5,
    _mha.posBias[0] + 0.5,
    _calibrator.calibrate(dtnP),
  ]);
  const fused = _finalNeuron.fwd(scores20);
  _nnStats.finalInferences++;
  _nnStats.manifoldInferences++;
  const charSum4 = _charSummary4(charEmb);
  const fusedCtx = _contextFusion.fwd(scores20, _epCtx, charSum4);
  const blended = fusedCtx * 0.4 + fused * 0.6;
  const calibrated = _calibrator.calibrate(blended);
  _episodic.remember(domain, charEmb, blended > 0.5 ? "blocked" : "good");
  _nnStats.calibratorCalls++;
  const _finalScore = Math.min(100, Math.round(calibrated * 100));
  if (_finalScore >= DGA_FLAG_SCORE) {
    _aiDecision(_finalScore >= DGA_BLOCK_SCORE ? "nn_block" : "nn_flag", {
      score: _finalScore,
      dtn: +dtnP.toFixed(3),
      moe: moeResult.expert,
      gru: +gruScore.toFixed(3),
      reasons: reasons || "",
    });
  }
  return { score: _finalScore, reason: reasons };
}
export function nnSelectUpstream(n) {
  if (n === 0) return 0;
  const feats = _buildUpstreamFeats(_ups, _ucb, _cb);
  const idx = _mha.select(feats, n);
  _nnStats.mhaSelections++;
  return idx;
}
export function nnCacheTTL(
  domain,
  clientIp,
  rps,
  iqScore,
  markovConf,
  upLatency,
  ttlHint,
) {
  const h = new Date().getUTCHours(),
    dow = new Date().getUTCDay();
  const state16 = new Float32Array([
    Math.min(rps / 100, 1),
    iqScore / 100,
    markovConf,
    Math.sin((2 * Math.PI * h) / 24),
    Math.cos((2 * Math.PI * h) / 24),
    Math.sin((2 * Math.PI * dow) / 7),
    Math.cos((2 * Math.PI * dow) / 7),
    Math.min(upLatency / 3e3, 1),
    ttlHint ? Math.min(ttlHint / 3600, 1) : 0.5,
    _stress,
    _nnStats.dtcnScore,
    _nnStats.bnnUncertainty,
    Math.min(_rpsSmooth / 100, 1),
    _anomaly.score,
    _pulseW / PULSE_WRITE_LIMIT,
    _aeroW / AERO_WRITE_LIMIT,
  ]);
  const ttl = _rl.act(state16);
  _nnStats.rlDecisions++;
  return ttl;
}
export function nnCacheSignal(hit) {
  _rl.reward(hit);
  _nnStats.rlHitReward = _rl.cacheHitReward;
}
export function _incrementBrainVersion(v) {
  const parts = v.split(".");
  const padding = parts[0].length;
  const p = parts.map((n) => parseInt(n, 10));
  const max = Math.pow(10, padding) - 1;
  p[2]++;
  if (p[2] > max) {
    p[2] = 0;
    p[1]++;
  }
  if (p[1] > max) {
    p[1] = 0;
    p[0]++;
  }
  let newPadding = padding;
  if (p[0] > max) {
    newPadding++;
  }
  return p.map((n) => n.toString().padStart(newPadding, "0")).join(".");
}
export function nnLearn(
  domain,
  clientIp,
  rps,
  iqScore,
  markovConf,
  burstFlag,
  outcome,
  upIdx,
  latencyMs,
) {
  const isThreaten = outcome !== "good" ? 1 : 0;
  const isClean = outcome === "good";
  const f40 = _feat40(
    domain,
    clientIp,
    rps,
    iqScore,
    markovConf,
    burstFlag,
    latencyMs || 0,
    0,
  );
  const f32 = f40.slice(0, 32);
  const f24 = f40.slice(0, 24);
  _dtn.fwd(f32);
  const dIn = _dtn.bwd(isThreaten);
  _nnStats.dtnCalls++;
  _moe.fwd(f24);
  _moe.bwd(isThreaten);
  const aeRes = _ae.fwd(f32);
  _ae.train(isClean);
  _bnn.train(f32, isThreaten);
  _contrastive.train(f32, isClean);
  _forest.train(f32, isThreaten);
  _gnn.train(domain, isThreaten);
  const neuronScore = _neuron.fwd(f24);
  _neuron.train(f24, isThreaten);
  if (dIn && dIn.length >= 32) {
    const fullGrad = new Float32Array(24);
    for (let i = 0; i < 8; i++) fullGrad[i] = dIn[24 + i];
    _embNet.updateEmbedding(domain, fullGrad);
    _nnStats.embUpdates++;
  }
  const liquidIn = new Float32Array([f40[0], f40[14], f40[15], f40[17]]);
  const liqOut = _liquid.step(liquidIn);
  const gruIn = new Float32Array(8);
  gruIn[0] = f40[0];
  gruIn[1] = f40[2];
  gruIn[2] = f40[9];
  gruIn[3] = f40[14];
  gruIn[4] = f40[15];
  gruIn[5] = f40[17];
  gruIn[6] = f40[18];
  gruIn[7] = f40[22];
  const gruScore = _gru.step(clientIp || "0.0.0.0", gruIn);
  _nnStats.gruSteps = (_nnStats.gruSteps || 0) + 1;
  const bnnResult = _bnn.predict(f32);
  const forestScore = _forest.predict(f32);
  const dtcnResult = _dtcn.forward(_rpsHistory);
  const metaOut = _meta.forward(gruIn);
  const moeScore = _moe._lastGateW
    ? _moe._lastGateW.reduce((s, w, i) => s + w * _moe._lastExpertOut[i], 0)
    : 0;
  const scores20 = new Float32Array([
    _dtn._a6 || 0,
    moeScore,
    gruScore,
    dtcnResult.score,
    aeRes.mse,
    bnnResult.mean,
    f40[35] || 0,
    f40[36] || 0,
    forestScore,
    metaOut.stressResponse,
    neuronScore,
    liqOut[0],
    liqOut[1],
    bnnResult.confidence,
    _spiking.spikes / 100,
    _transformer.forward(f32)[0],
    isThreaten ? 1 : 0,
    _rl.cacheHitReward + 0.5,
    _mha.posBias[0] + 0.5,
    _calibrator.calibrate(_dtn._a6 || 0),
  ]);
  _finalNeuron.train(scores20, isThreaten);
  _manifold.train(scores20.slice(0, 17), isThreaten);
  const charEmbL = _charTransformer.encode(domain);
  const { contextVec: epCtxL } = _episodic.recall(charEmbL);
  const charSum4L = _charSummary4(charEmbL);
  _contextFusion.train(scores20, epCtxL, charSum4L, isThreaten);
  const dCLS = new Float32Array(32);
  for (let i = 0; i < 32; i++)
    dCLS[i] = (isThreaten - 0.5) * charEmbL[i] * 0.05;
  _charTransformer.backward(domain, dCLS);
  _episodic.remember(domain, charEmbL, outcome || "good");
  _nnStats.learningCycles++;
  if (_nnStats.learningCycles % 10 === 0) {
    _nnStats.brainVersion = _incrementBrainVersion(_nnStats.brainVersion);
  }
  if (clientIp) {
    const prev = _markov.history.get(clientIp);
    if (prev && prev.d && prev.d !== domain) _gnn.addEdge(domain, prev.d);
  }
  if (upIdx !== undefined && latencyMs !== undefined)
    _mha.reward(upIdx, latencyMs, _ups.length);
  const isThrottled = _pulseThrottle || _aeroThrottle;
  if (_nnStats.dtnCalls % 30 === 0) {
    const x8 = new Float32Array([
      _stress,
      _pulseW / PULSE_WRITE_LIMIT,
      _aeroW / AERO_WRITE_LIMIT,
      Math.min(_rpsSmooth / 100, 1),
      _anomaly.score,
      _domainIQ.map.size / DOMAIN_IQ_MAX,
      Math.min(_dtn.totalLoss, 1),
      _dtcn._lastScore,
    ]);
    const metaOut = _meta.forward(x8);
    _nnStats.lastMeta = metaOut;
    _nnStats.metaCalls++;
    const lrS = metaOut.lrScale;
    _dtn.lr = _clip(_dtn.lr * lrS, 5e-6, 0.01);
    _moe.lr = _clip(_moe.lr * lrS, 1e-5, 0.005);
    _ae.lr = _clip(_ae.lr * lrS, 1e-5, 0.003);
    _bnn.lr = _clip(_bnn.lr * lrS, 1e-5, 0.005);
    _rl.lr = _clip(_rl.lr * lrS, 1e-6, 0.002);
    _runtimeConfig.maxCacheTtl = Math.round(300 * metaOut.cacheTtlMult + 300);
    _runtimeConfig.cbThreshold = Math.max(
      0.2,
      Math.min(0.75, CB_THRESHOLD + metaOut.cbThreshAdj),
    );
  }
  _meta.train(_stress, isThrottled, _dtn.totalLoss);
  if (outcome !== undefined) {
    const rawScore = _dtn._a6 || 0;
    _calibrator.update(rawScore, isThreaten);
  }
}
export function nnExport() {
  return {
    dtn: _dtn.export(),
    emb: _embNet.export(),
    mha: _mha.export(),
    gru: _gru.export(),
    dtcn: _dtcn.export(),
    ae: _ae.export(),
    moe: _moe.export(),
    rl: _rl.export(),
    meta: _meta.export(),
    liquid: _liquid.export(),
    spiking: _spiking.export(),
    symbolic: _symbolic.export(),
    transformer: _transformer.export(),
    manifold: _manifold.export(),
    bnn: _bnn.export(),
    contrastive: _contrastive.export(),
    forest: _forest.export(),
    gnn: _gnn.export(),
    calibrator: _calibrator.export(),
    neuron: _neuron.export(),
    finalNeuron: _finalNeuron.export(),
    charTransformer: _charTransformer.exportWeights(),
    contextFusion: _contextFusion.export(),
    episodicStats: _episodic.stats(),
    rewardStats: _rewardShaper.getStats(),
    stats: _nnStats,
  };
}
export function nnImport(d) {
  if (!d) return;
  if (d.dtn) _dtn.import(d.dtn);
  if (d.emb) _embNet.import(d.emb);
  if (d.mha) _mha.import(d.mha);
  if (d.gru) _gru.import(d.gru);
  if (d.dtcn) _dtcn.import(d.dtcn);
  if (d.ae) _ae.import(d.ae);
  if (d.moe) _moe.import(d.moe);
  if (d.rl) _rl.import(d.rl);
  if (d.meta) _meta.import(d.meta);
  if (d.bnn) _bnn.import(d.bnn);
  if (d.contrastive) _contrastive.import(d.contrastive);
  if (d.forest) _forest.import(d.forest);
  if (d.gnn) _gnn.import(d.gnn);
  if (d.calibrator) _calibrator.import(d.calibrator);
  if (d.liquid) _liquid.import(d.liquid);
  if (d.spiking) _spiking.import(d.spiking);
  if (d.symbolic) _symbolic.import(d.symbolic);
  if (d.transformer) _transformer.import(d.transformer);
  if (d.manifold) _manifold.import(d.manifold);
  if (d.neuron) _neuron.import(d.neuron);
  if (d.finalNeuron) _finalNeuron.import(d.finalNeuron);
  if (d.charTransformer) _charTransformer.importWeights(d.charTransformer);
  if (d.contextFusion) _contextFusion.import(d.contextFusion);
  if (d.stats) {
    Object.assign(_nnStats, d.stats);
    if (d.stats.learningCycles !== undefined)
      _nnStats.learningCycles = d.stats.learningCycles;
    if (d.stats.brainVersion !== undefined)
      _nnStats.brainVersion = d.stats.brainVersion;
  }
}
let _brainSyncCount = 0;
export function _brainPrune() {
  const now = Date.now();
  const iqCutoff = now - 7 * 864e5;
  let iqEvicted = 0;
  for (const [k, v] of _domainIQ.map) {
    if (v.lastSeen < iqCutoff && v.hits < 5) {
      _domainIQ.map.delete(k);
      iqEvicted++;
    }
  }
  let markovEvicted = 0;
  for (const [k, v] of _markov.transitions) {
    for (const [d, n] of v) {
      if (n < 2) {
        v.delete(d);
        markovEvicted++;
      }
    }
    if (v.size === 0) _markov.transitions.delete(k);
  }
  for (const tree of _forest.trees) {
    if (tree.rules.length >= _forest.MAX_DEPTH) {
      tree.rules = tree.rules.filter((r) => r.depth < 3);
    }
  }
  const referenced = new Set();
  for (const nbSet of _gnn.edges.values())
    for (const nb of nbSet) referenced.add(nb);
  let gnnEvicted = 0;
  for (const [k] of _gnn.nodes) {
    if (!referenced.has(k) && !_gnn.edges.has(k)) {
      _gnn.nodes.delete(k);
      gnnEvicted++;
    }
  }
  _contrastive._cache = [];
  if (_dgaLegit.size > 200) {
    const iter = _dgaLegit.values();
    for (let i = 0; i < _dgaLegit.size - 200; i++)
      _dgaLegit.delete(iter.next().value);
  }
  setBrainDirty(true);
  _log("brain_pruned", {
    iq: _domainIQ.map.size,
    iqEvicted: iqEvicted,
    markov: _markov.transitions.size,
    markovEvicted: markovEvicted,
    gnnEvicted: gnnEvicted,
  });
}
const _hotCache = new Map();
const HOT_CACHE_TTL = 3e5;
const HOT_CACHE_MAX = 4e3;
export function _hotGet(key) {
  const entry = _hotCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.exp) {
    _hotCache.delete(key);
    return null;
  }
  _hotCache.delete(key);
  _hotCache.set(key, entry);
  return entry.val;
}
export function _hotPut(key, val) {
  _hotCache.delete(key);
  if (_hotCache.size >= HOT_CACHE_MAX)
    _hotCache.delete(_hotCache.keys().next().value);
  _hotCache.set(key, { val: val, exp: Date.now() + HOT_CACHE_TTL });
}

export function clearNeuralCaches() {
  _hotCache.clear();
  if (_episodic?.clear) _episodic.clear();
  if (_rewardShaper?.clear) _rewardShaper.clear();
  _nnStats.learningCycles = 0;
  _nnStats.brainVersion = "1.0.0";
  _nnStats.dtnInferences = 0;
  _nnStats.dtnBlocks = 0;
  _nnStats.dtnCalls = 0;
  _nnStats.gruAlarms = 0;
  _nnStats.mhaSelections = 0;
  _nnStats.dtcnClass = "normal";
  _nnStats.dtcnScore = 0;
  _nnStats.moeDecisions = { phishing: 0, dga: 0, c2: 0, tunnel: 0 };
  _nnStats.aeAnomalies = 0;
  _nnStats.rlDecisions = 0;
  _nnStats.rlHitReward = 0;
  _nnStats.liquidCalls = 0;
  _nnStats.liquidStability = 0;
  _nnStats.spikeCount = 0;
  _nnStats.symbolicDecisions = 0;
  _nnStats.manifoldInferences = 0;
  _nnStats.transformerReflex = 0;
  _nnStats.bnnUncertainty = 0;
  _nnStats.bnnCalls = 0;
  _nnStats.neuronCalls = 0;
  _nnStats.contrastiveCalls = 0;
  _nnStats.gnnCalls = 0;
  _nnStats.forestCalls = 0;
  _nnStats.calibratorCalls = 0;
  _nnStats.metaCalls = 0;
  _nnStats.embUpdates = 0;
  _nnStats.finalInferences = 0;
  _nnStats.lastMeta = { lrScale: 1, cacheTtlMult: 1, cbThreshAdj: 0, stressResponse: 0 };
}

export function _perpetualLearnTick(domain, rcode, rps, outcome, upIdx, latencyMs) {
  const _now2 = Date.now();
  _rhythm.record(rps);
  _budgetAI.governorTick();
  _adaptiveConfigTick();
  setBrainDirty(true);
  const _learnEvery = _stress > 0.7 ? 5 : _stress > 0.4 ? 3 : 1;
  if (_sh.requests % _learnEvery === 0) {
    nnLearn(
      domain,
      null,
      rps,
      _domainIQ.riskScore(domain),
      _markov.predict(domain) ? 1 : 0,
      false,
      outcome || "good",
      upIdx,
      latencyMs,
    );
  }
  if (_nnStats.learningCycles > 0 && _nnStats.learningCycles % 50 === 0) {
    _aiDecision("brain_tick", {
      cycles: _nnStats.learningCycles,
      version: _nnStats.brainVersion,
      loss: +_dtn.totalLoss.toFixed(4),
      iq: _domainIQ.map.size,
    });
  }
  const _now = Date.now();
  if (_now - _iqDecayTs > 6e4) {
    _iqDecayTs = _now;
    _domainIQ.decay();
  }
  if (_now2 - _userEstTs > 3e4) {
    _userEstTs = _now2;
    _updateUserEstimate();
  }
  if (_sh.requests % 500 === 0) _memCheck();
}

