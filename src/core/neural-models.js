// src/core/neural-models.js
// 20-Model Ensemble Neural Network Architectures (DTN, MoE, GRU, Autoencoder, SNN, Liquid, MHA).

import {
  _makeDense, _makeBN, _makeLayerNorm,
  _heInit, _glorot, _zeros, _ones, _randn,
  _relu, _lrelu, _sigmoid, _tanh, _swish, _gelu, _mish, _softmax, _clip, _norm2
} from "./neural-math.js";

export function _lazy(initFn) {
  let _inst = null;
  return new Proxy(initFn, {
    get: (t, p) => {
      if (!_inst) _inst = initFn();
      return _inst[p];
    },
    set: (t, p, v) => {
      if (!_inst) _inst = initFn();
      _inst[p] = v;
      return true;
    },
  });
}
export const _dtn = _lazy(() => ({
  L1: _makeDense(32, 128, "gelu"),
  BN1: _makeBN(128),
  L2: _makeDense(128, 64, "mish"),
  BN2: _makeBN(64),
  L3: _makeDense(64, 64, "gelu"),
  BN3: _makeBN(64),
  L4: _makeDense(64, 32, "mish"),
  BN4: _makeBN(32),
  L5: _makeDense(32, 16, "gelu"),
  BN5: _makeBN(16),
  L6: _makeDense(16, 1, "sig"),
  Rp1: _makeDense(32, 64, "linear"),
  Rp2: _makeDense(64, 32, "linear"),
  lr: 8e-4,
  calls: 0,
  totalLoss: 0,
  _a1: null,
  _a2: null,
  _a3: null,
  _a4: null,
  _a5: null,
  _a6: null,
  fwd(x32) {
    const z1 = this.L1.fwd(x32);
    this._a1 = this.BN1.fwd(z1);
    const z2 = this.L2.fwd(this._a1);
    const bn2 = this.BN2.fwd(z2);
    const r1 = this.Rp1.fwd(x32);
    this._a2 = new Float32Array(64);
    for (let i = 0; i < 64; i++) this._a2[i] = _relu(bn2[i] + r1[i]);
    const z3 = this.L3.fwd(this._a2);
    this._a3 = this.BN3.fwd(z3);
    const z4 = this.L4.fwd(this._a3);
    const bn4 = this.BN4.fwd(z4);
    const r2 = this.Rp2.fwd(this._a2);
    this._a4 = new Float32Array(32);
    for (let i = 0; i < 32; i++) this._a4[i] = _relu(bn4[i] + r2[i]);
    const z5 = this.L5.fwd(this._a4);
    this._a5 = this.BN5.fwd(z5);
    this._a6 = this.L6.fwd(this._a5)[0];
    return this._a6;
  },
  bwd(label) {
    const p = this._a6,
      eps = 1e-7;
    const dL5 = new Float32Array(1);
    dL5[0] = p - label;
    const d5 = this.L6.bwd(dL5, this.lr);
    const d5bn = this.BN5.bwd(d5, this.lr * 8);
    const d4 = this.L5.bwd(d5bn, this.lr);
    const d4pre = new Float32Array(32);
    for (let i = 0; i < 32; i++) d4pre[i] = this._a4[i] > 0 ? d4[i] : 0;
    const d4bn = this.BN4.bwd(d4pre, this.lr * 8);
    const d3 = this.L4.bwd(d4bn, this.lr);
    this.Rp2.bwd(d4pre, this.lr);
    const d2 = this.L3.bwd(d3, this.lr);
    const d2bn = this.BN3.bwd(d2, this.lr * 8);
    const gOne = this.L2.bwd(d2bn, this.lr);
    const gOnePre = new Float32Array(64);
    for (let i = 0; i < 64; i++) gOnePre[i] = this._a2[i] > 0 ? gOne[i] : 0;
    const gOneBn = this.BN2.bwd(gOnePre, this.lr * 8);
    const dIn = this.L1.bwd(gOneBn, this.lr);
    this.Rp1.bwd(gOnePre, this.lr);
    this.calls++;
    const bce = -(
      label * Math.log(p + eps) +
      (1 - label) * Math.log(1 - p + eps)
    );
    this.totalLoss = 0.997 * this.totalLoss + 0.003 * bce;
    return dIn;
  },
  export() {
    return {
      L1: this.L1.export(),
      BN1: this.BN1.export(),
      L2: this.L2.export(),
      BN2: this.BN2.export(),
      L3: this.L3.export(),
      BN3: this.BN3.export(),
      L4: this.L4.export(),
      BN4: this.BN4.export(),
      L5: this.L5.export(),
      BN5: this.BN5.export(),
      L6: this.L6.export(),
      R1: this.Rp1.export(),
      R2: this.Rp2.export(),
      calls: this.calls,
      loss: this.totalLoss,
    };
  },
  import(d) {
    if (!d) return;
    ["L1", "L2", "L3", "L4", "L5", "L6"].forEach((k) => {
      if (d[k]) this[k].import(d[k]);
    });
    ["BN1", "BN2", "BN3", "BN4", "BN5"].forEach((k) => {
      if (d[k]) this[k].import(d[k]);
    });
    if (d.R1) this.Rp1.import(d.R1);
    if (d.R2) this.Rp2.import(d.R2);
    if (d.calls) this.calls = d.calls;
    if (d.loss) this.totalLoss = d.loss;
  },
}));
export const _embNet = _lazy(() => ({
  VOCAB: 256,
  DIM: 24,
  E: _heInit(256, 24),
  mE: _zeros(256 * 24),
  vE: _zeros(256 * 24),
  tE: 0,
  lr: 3e-4,
  _brandEmbs: null,
  _bigramHash(a, b) {
    return (((a.charCodeAt(0) & 15) << 4) | (b.charCodeAt(0) & 15)) & 255;
  },
  embed(domain) {
    const d = domain.toLowerCase().replace(/[^a-z0-9]/g, "");
    const vec = _zeros(this.DIM);
    if (d.length < 2) return vec;
    let count = 0;
    for (let i = 0; i < d.length - 1; i++) {
      const idx = this._bigramHash(d[i], d[i + 1]);
      for (let k = 0; k < this.DIM; k++) vec[k] += this.E[idx * this.DIM + k];
      count++;
    }
    if (count > 0) {
      for (let k = 0; k < this.DIM; k++) vec[k] /= count;
    }
    const n = _norm2(vec);
    for (let k = 0; k < this.DIM; k++) vec[k] /= n;
    return vec;
  },
  updateEmbedding(domain, grad24) {
    const d = domain.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (d.length < 2) return;
    const indices = new Set();
    for (let i = 0; i < d.length - 1; i++)
      indices.add(this._bigramHash(d[i], d[i + 1]));
    this.tE++;
    const bc1 = 1 - 0.9 ** this.tE,
      bc2 = 1 - 0.999 ** this.tE;
    for (const idx of indices) {
      for (let k = 0; k < this.DIM; k++) {
        const g = _clip(grad24[k] / indices.size, -0.5, 0.5);
        const p = idx * this.DIM + k;
        this.mE[p] = 0.9 * this.mE[p] + (1 - 0.9) * g;
        this.vE[p] = 0.999 * this.vE[p] + (1 - 0.999) * g * g;
        this.E[p] -=
          (this.lr * (this.mE[p] / bc1)) / (Math.sqrt(this.vE[p] / bc2) + 1e-8);
      }
    }
    this._brandEmbs = null;
  },
  export() {
    return { E: Array.from(this.E).map((v) => +v.toFixed(5)) };
  },
  import(d) {
    if (!d) return;
    if (d.E && d.E.length === this.E.length) this.E.set(d.E);
    this._brandEmbs = null;
  },
}));
export const _mha = _lazy(() => ({
  HEADS: 4,
  DIM: 16,
  INF: 8,
  WQ: _glorot(8, 16),
  WK: _glorot(8, 16),
  WV: _glorot(8, 16),
  Wout: _glorot(64, 16),
  Wscore: _glorot(16, 1),
  posBias: _randn(8, 0.01),
  mWout: _zeros(64 * 16),
  vWout: _zeros(64 * 16),
  t: 0,
  lr: 3e-4,
  calls: 0,
  _lastAttn: null,
  _lastF: null,
  select(feats, n) {
    if (n === 0) return 0;
    const h = new Date().getUTCHours();
    const dow = new Date().getUTCDay();
    const hsin = Math.sin((2 * Math.PI * h) / 24),
      hcos = Math.cos((2 * Math.PI * h) / 24);
    const dsin = Math.sin((2 * Math.PI * dow) / 7),
      dcos = Math.cos((2 * Math.PI * dow) / 7);
    const F = [];
    for (let i = 0; i < n; i++) {
      const f = feats.slice
        ? Array.from(feats.slice(i * 4, (i + 1) * 4))
        : [
            feats[i * 4] || 0,
            feats[i * 4 + 1] || 0,
            feats[i * 4 + 2] || 0,
            feats[i * 4 + 3] || 0,
          ];
      F.push(
        new Float32Array([
          f[0] || 0,
          f[1] || 0,
          f[2] || 0,
          f[3] || 0,
          hsin,
          hcos,
          dsin,
          dcos,
        ]),
      );
    }
    this._lastF = F;
    const headOutputs = [];
    for (let h2 = 0; h2 < this.HEADS; h2++) {
      const avgF = _zeros(8);
      for (let i = 0; i < n; i++)
        for (let k = 0; k < 8; k++) avgF[k] += F[i][k] / n;
      const q = new Float32Array(this.DIM);
      for (let j = 0; j < this.DIM; j++) {
        let s = 0;
        for (let k = 0; k < 8; k++)
          s += this.WQ[h2 * 8 * 4 + (j % 16) + k] * (avgF[k] || 0);
        q[j] = s;
      }
      const attnScores = new Float32Array(n);
      const Vs = [];
      for (let i = 0; i < n; i++) {
        const keyVec = new Float32Array(this.DIM),
          vv = new Float32Array(this.DIM);
        for (let j = 0; j < this.DIM; j++) {
          let sk = 0,
            sv = 0;
          for (let l = 0; l < 8; l++) {
            sk += this.WK[h2 * 8 * 4 + (j % 16) + l] * (F[i][l] || 0);
            sv += this.WV[h2 * 8 * 4 + (j % 16) + l] * (F[i][l] || 0);
          }
          keyVec[j] = sk;
          vv[j] = sv;
        }
        let qk = 0;
        for (let j = 0; j < this.DIM; j++) qk += q[j] * keyVec[j];
        attnScores[i] = qk / Math.sqrt(this.DIM) + (this.posBias[i] || 0);
        Vs.push(vv);
      }
      const attnW = _softmax(Array.from(attnScores));
      const ctx = _zeros(this.DIM);
      for (let i = 0; i < n; i++)
        for (let j = 0; j < this.DIM; j++) ctx[j] += attnW[i] * Vs[i][j];
      headOutputs.push({ ctx: ctx, attnW: attnW });
    }
    this._lastAttn = headOutputs;
    const concat = new Float32Array(64);
    for (let h2 = 0; h2 < this.HEADS; h2++)
      for (let j = 0; j < this.DIM; j++)
        concat[h2 * this.DIM + j] = headOutputs[h2].ctx[j];
    const out = new Float32Array(this.DIM);
    for (let j = 0; j < this.DIM; j++) {
      let s = 0;
      for (let k = 0; k < 64; k++) s += this.Wout[j * 64 + k] * concat[k];
      out[j] = _relu(s);
    }
    const scores = new Float32Array(n);
    for (let i = 0; i < n; i++) {
      let s = 0;
      for (let j = 0; j < this.DIM; j++)
        s += this.Wscore[j] * (F[i][j % 8] || 0) * out[j];
      scores[i] = s;
    }
    let best = 0;
    for (let i = 1; i < n; i++) if (scores[i] > scores[best]) best = i;
    this.calls++;
    return best;
  },
  reward(idx, latencyMs, n) {
    if (n === 0) return;
    const r = Math.max(0, 1 - latencyMs / 3e3);
    if (idx < 8)
      this.posBias[idx] = 0.95 * this.posBias[idx] + 0.05 * (r - 0.5) * 0.1;
    this.t++;
  },
  export() {
    const r = (v) => +v.toFixed(5);
    return {
      WQ: Array.from(this.WQ).map(r),
      WK: Array.from(this.WK).map(r),
      WV: Array.from(this.WV).map(r),
      Wout: Array.from(this.Wout).map(r),
      Ws: Array.from(this.Wscore).map(r),
      pb: Array.from(this.posBias).map(r),
      calls: this.calls,
    };
  },
  import(d) {
    if (!d) return;
    if (d.WQ) this.WQ.set(d.WQ);
    if (d.WK) this.WK.set(d.WK);
    if (d.WV) this.WV.set(d.WV);
    if (d.Wout && d.Wout.length === this.Wout.length) this.Wout.set(d.Wout);
    if (d.Ws) this.Wscore.set(d.Ws);
    if (d.pb) this.posBias.set(d.pb);
    if (d.calls) this.calls = d.calls;
  },
}));
export const _gru = _lazy(() => ({
  H: 48,
  X: 8,
  Wzf: _heInit(32, 24),
  bzf: _zeros(24),
  Wrf: _heInit(32, 24),
  brf: _zeros(24),
  Whf: _heInit(32, 24),
  bhf: _zeros(24),
  Wzb: _heInit(32, 24),
  bzb: _zeros(24),
  Wrb: _heInit(32, 24),
  brb: _zeros(24),
  Whb: _heInit(32, 24),
  bhb: _zeros(24),
  Wread: _heInit(48, 1),
  bread: _zeros(1),
  LN: _makeLayerNorm(48),
  t: 0,
  lr: 0.001,
  states: new Map(),
  history: new Map(),
  MAX: 2e3,
  _get(ip) {
    if (!this.states.has(ip)) {
      if (this.states.size >= this.MAX)
        this.states.delete(this.states.keys().next().value);
      this.states.set(ip, { fwd: _zeros(24), bwd: _zeros(24), buf: [] });
    }
    return this.states.get(ip);
  },
  _gruStep(x8, h, Wz, bz, Wr, br, Wh, bh) {
    const xh = new Float32Array(32);
    for (let i = 0; i < 8; i++) xh[i] = x8[i];
    for (let i = 0; i < 24; i++) xh[8 + i] = h[i];
    const z = new Float32Array(24);
    for (let j = 0; j < 24; j++) {
      let s = bz[j];
      for (let i = 0; i < 32; i++) s += Wz[j * 32 + i] * xh[i];
      z[j] = _sigmoid(s);
    }
    const r = new Float32Array(24);
    for (let j = 0; j < 24; j++) {
      let s = br[j];
      for (let i = 0; i < 32; i++) s += Wr[j * 32 + i] * xh[i];
      r[j] = _sigmoid(s);
    }
    const xhr = new Float32Array(32);
    for (let i = 0; i < 8; i++) xhr[i] = x8[i];
    for (let i = 0; i < 24; i++) xhr[8 + i] = r[i] * h[i];
    const hn = new Float32Array(24);
    for (let j = 0; j < 24; j++) {
      let s = bh[j];
      for (let i = 0; i < 32; i++) s += Wh[j * 32 + i] * xhr[i];
      hn[j] = _tanh(s);
    }
    const newH = new Float32Array(24);
    for (let j = 0; j < 24; j++) newH[j] = (1 - z[j]) * h[j] + z[j] * hn[j];
    return newH;
  },
  step(ip, x8) {
    const state = this._get(ip);
    state.fwd = this._gruStep(
      x8,
      state.fwd,
      this.Wzf,
      this.bzf,
      this.Wrf,
      this.brf,
      this.Whf,
      this.bhf,
    );
    state.buf.push(Array.from(x8));
    if (state.buf.length > 8) state.buf.shift();
    let hb = state.bwd;
    for (let i = state.buf.length - 1; i >= 0; i--) {
      hb = this._gruStep(
        new Float32Array(state.buf[i]),
        hb,
        this.Wzb,
        this.bzb,
        this.Wrb,
        this.brb,
        this.Whb,
        this.bhb,
      );
    }
    state.bwd = hb;
    const combined = new Float32Array(48);
    for (let i = 0; i < 24; i++) {
      combined[i] = state.fwd[i];
      combined[24 + i] = state.bwd[i];
    }
    const normed = this.LN.fwd(combined);
    let logit = this.bread[0];
    for (let i = 0; i < 48; i++) logit += this.Wread[i] * normed[i];
    return _sigmoid(logit);
  },
  export() {
    const r = (v) => +v.toFixed(5);
    return {
      Wzf: Array.from(this.Wzf).map(r),
      Wrf: Array.from(this.Wrf).map(r),
      Whf: Array.from(this.Whf).map(r),
      Wzb: Array.from(this.Wzb).map(r),
      Wrb: Array.from(this.Wrb).map(r),
      Whb: Array.from(this.Whb).map(r),
      Wr: Array.from(this.Wread).map(r),
      br: Array.from(this.bread).map(r),
    };
  },
  import(d) {
    if (!d) return;
    ["Wzf", "Wrf", "Whf", "Wzb", "Wrb", "Whb"].forEach((k) => {
      if (d[k] && d[k].length === this[k].length) this[k].set(d[k]);
    });
    if (d.Wr && d.Wr.length === this.Wread.length) this.Wread.set(d.Wr);
    if (d.br && d.br.length === this.bread.length) this.bread.set(d.br);
  },
}));
export const _dtcn = _lazy(() => ({
  K1: _heInit(4, 16),
  K2: _heInit(64, 16),
  K3: _heInit(64, 16),
  K4: _heInit(64, 16),
  b1: _zeros(16),
  b2: _zeros(16),
  b3: _zeros(16),
  b4: _zeros(16),
  Wfc: _glorot(16, 6),
  bfc: _zeros(6),
  t: 0,
  lr: 0.001,
  _lastScore: 0,
  _lastLogits: null,
  _conv1d(input, kernel, bias, nFilters, dilation, nIn) {
    const inLen = input[0].length;
    const out = Array.from({ length: nFilters }, () => new Float32Array(inLen));
    for (let f = 0; f < nFilters; f++) {
      for (let t = 0; t < inLen; t++) {
        let s = bias[f];
        for (let k = 0; k < 4; k++) {
          const tIn = t - k * dilation;
          if (tIn >= 0) {
            for (let c = 0; c < nIn; c++)
              s += kernel[(f * nIn + c) * 4 + k] * (input[c][tIn] || 0);
          }
        }
        out[f][t] = _lrelu(s);
      }
    }
    return out;
  },
  _addResidual(a, b, nFilters) {
    const out = Array.from(
      { length: nFilters },
      () => new Float32Array(a[0].length),
    );
    for (let f = 0; f < nFilters; f++)
      for (let t = 0; t < a[0].length; t++)
        out[f][t] = _lrelu(a[f][t] + (b[f] ? b[f][t] : 0));
    return out;
  },
  forward(rpsRing60) {
    let mx = 0;
    for (let i = 0; i < 60; i++) if (rpsRing60[i] > mx) mx = rpsRing60[i];
    const x = new Float32Array(60);
    for (let i = 0; i < 60; i++) x[i] = mx > 0 ? rpsRing60[i] / mx : 0;
    const fm1 = this._conv1d([x], this.K1, this.b1, 16, 1, 1);
    const fm2 = this._conv1d(fm1, this.K2, this.b2, 16, 2, 16);
    const fm2r = this._addResidual(fm2, fm1, 16);
    const fm3 = this._conv1d(fm2r, this.K3, this.b3, 16, 4, 16);
    const fm3r = this._addResidual(fm3, fm2r, 16);
    const fm4 = this._conv1d(fm3r, this.K4, this.b4, 16, 8, 16);
    const fm4r = this._addResidual(fm4, fm3r, 16);
    const pooled = new Float32Array(16);
    for (let f = 0; f < 16; f++) {
      let s = 0;
      for (let t = 0; t < 60; t++) s += fm4r[f][t];
      pooled[f] = s / 60;
    }
    const logits = new Float32Array(6);
    for (let j = 0; j < 6; j++) {
      let s = this.bfc[j];
      for (let i = 0; i < 16; i++) s += this.Wfc[j * 16 + i] * pooled[i];
      logits[j] = s;
    }
    const probs = _softmax(Array.from(logits));
    this._lastLogits = probs;
    this._lastScore = 1 - probs[0];
    return {
      score: this._lastScore,
      class: ["normal", "spike", "beacon", "flood", "tunnel", "scan"][
        probs.indexOf(Math.max(...probs))
      ],
      probs: probs,
    };
  },
  export() {
    const r = (v) => +v.toFixed(5);
    return {
      K1: Array.from(this.K1).map(r),
      b1: Array.from(this.b1).map(r),
      K2: Array.from(this.K2).map(r),
      b2: Array.from(this.b2).map(r),
      K3: Array.from(this.K3).map(r),
      b3: Array.from(this.b3).map(r),
      K4: Array.from(this.K4).map(r),
      b4: Array.from(this.b4).map(r),
      Wfc: Array.from(this.Wfc).map(r),
      bfc: Array.from(this.bfc).map(r),
    };
  },
  import(d) {
    if (!d) return;
    ["K1", "b1", "K2", "b2", "K3", "b3", "K4", "b4", "Wfc", "bfc"].forEach(
      (k) => {
        if (d[k] && d[k].length === this[k].length) this[k].set(d[k]);
      },
    );
  },
}));
export const _ae = _lazy(() => ({
  Enc1: _makeDense(32, 32, "lrelu"),
  Enc2: _makeDense(32, 16, "lrelu"),
  EncMu: _makeDense(16, 8, "linear"),
  EncLv: _makeDense(16, 8, "linear"),
  Dec1: _makeDense(8, 16, "lrelu"),
  Dec2: _makeDense(16, 32, "lrelu"),
  Dec3: _makeDense(32, 32, "linear"),
  lr: 2e-4,
  calls: 0,
  mseLoss: 0,
  klLoss: 0,
  threshold: 0.15,
  _lastRecon: null,
  _lastInput: null,
  _lastMu: null,
  _lastLv: null,
  _lastZ: null,
  fwd(x32) {
    this._lastInput = x32;
    const h1 = this.Enc1.fwd(x32);
    const h2 = this.Enc2.fwd(h1);
    const mu = this.EncMu.fwd(h2);
    const lv = this.EncLv.fwd(h2);
    const z = new Float32Array(8);
    for (let i = 0; i < 8; i++) {
      const eps = (Math.random() + Math.random() - 1) * 0.7071;
      z[i] = mu[i] + Math.exp(0.5 * _clip(lv[i], -4, 4)) * eps;
    }
    this._lastMu = mu;
    this._lastLv = lv;
    this._lastZ = z;
    const decA = this.Dec1.fwd(z);
    const d2 = this.Dec2.fwd(decA);
    const recon = this.Dec3.fwd(d2);
    this._lastRecon = recon;
    let mse = 0;
    for (let i = 0; i < 32; i++) mse += (recon[i] - x32[i]) ** 2;
    mse /= 32;
    let kl = 0;
    for (let i = 0; i < 8; i++)
      kl -=
        0.5 *
        (1 + _clip(lv[i], -4, 4) - mu[i] ** 2 - Math.exp(_clip(lv[i], -4, 4)));
    kl /= 8;
    const elbo = mse + 0.01 * kl;
    return {
      recon: recon,
      mse: mse,
      kl: kl,
      elbo: elbo,
      anomaly: elbo > this.threshold,
    };
  },
  train(isClean) {
    if (!this._lastRecon || !isClean) return;
    this.calls++;
    const dRecon = new Float32Array(32);
    let mse = 0;
    for (let i = 0; i < 32; i++) {
      const e = this._lastRecon[i] - this._lastInput[i];
      dRecon[i] = (2 * e) / 32;
      mse += (e * e) / 32;
    }
    let kl = 0;
    for (let i = 0; i < 8; i++)
      kl -=
        0.5 *
        (1 +
          _clip(this._lastLv[i], -4, 4) -
          this._lastMu[i] ** 2 -
          Math.exp(_clip(this._lastLv[i], -4, 4)));
    kl /= 8;
    this.mseLoss = 0.997 * this.mseLoss + 0.003 * mse;
    this.klLoss = 0.997 * this.klLoss + 0.003 * kl;
    this.threshold = Math.max(0.05, this.mseLoss * 3 + this.klLoss * 0.1);
    const d2 = this.Dec3.bwd(dRecon, this.lr);
    const gDec = this.Dec2.bwd(d2, this.lr);
    const dz = this.Dec1.bwd(gDec, this.lr);
    const dMu = new Float32Array(8),
      dLv = new Float32Array(8);
    for (let i = 0; i < 8; i++) {
      dMu[i] = (0.01 * this._lastMu[i]) / 8;
      dLv[i] = (0.01 * 0.5 * (Math.exp(_clip(this._lastLv[i], -4, 4)) - 1)) / 8;
    }
    const dh2mu = this.EncMu.bwd(
      new Float32Array(8).map((_, i) => dz[i] + dMu[i]),
      this.lr,
    );
    const dh2lv = this.EncLv.bwd(dLv, this.lr);
    const dh2 = new Float32Array(16);
    for (let i = 0; i < 16; i++) dh2[i] = dh2mu[i] + dh2lv[i];
    const dh1 = this.Enc2.bwd(dh2, this.lr);
    this.Enc1.bwd(dh1, this.lr);
  },
  export() {
    return {
      E1: this.Enc1.export(),
      E2: this.Enc2.export(),
      EMu: this.EncMu.export(),
      ELv: this.EncLv.export(),
      Dec1: this.Dec1.export(),
      D2: this.Dec2.export(),
      D3: this.Dec3.export(),
      thr: this.threshold,
      mse: this.mseLoss,
      kl: this.klLoss,
      calls: this.calls,
    };
  },
  import(d) {
    if (!d) return;
    if (d.E1) this.Enc1.import(d.E1);
    if (d.E2) this.Enc2.import(d.E2);
    if (d.EMu) this.EncMu.import(d.EMu);
    if (d.ELv) this.EncLv.import(d.ELv);
    if (d.Dec1) this.Dec1.import(d.Dec1);
    if (d.D2) this.Dec2.import(d.D2);
    if (d.D3) this.Dec3.import(d.D3);
    if (d.thr) this.threshold = d.thr;
    if (d.mse) this.mseLoss = d.mse;
    if (d.kl) this.klLoss = d.kl;
    if (d.calls) this.calls = d.calls;
  },
}));
export const _moe = _lazy(() => ({
  experts: [
    {
      L1: _makeDense(24, 12, "swish"),
      L2: _makeDense(12, 1, "sig"),
      name: "phishing",
    },
    {
      L1: _makeDense(24, 12, "swish"),
      L2: _makeDense(12, 1, "sig"),
      name: "dga",
    },
    {
      L1: _makeDense(24, 12, "swish"),
      L2: _makeDense(12, 1, "sig"),
      name: "c2",
    },
    {
      L1: _makeDense(24, 12, "swish"),
      L2: _makeDense(12, 1, "sig"),
      name: "tunnel",
    },
  ],
  Gate: _makeDense(24, 4, "linear"),
  lr: 6e-4,
  calls: 0,
  _lastGateW: null,
  _lastExpertOut: null,
  _lastX: null,
  fwd(x24) {
    this._lastX = x24;
    const gLogits = this.Gate.fwd(x24);
    const gw = _softmax(Array.from(gLogits));
    this._lastGateW = gw;
    const eOut = this.experts.map((e) => {
      const h = e.L1.fwd(x24);
      return e.L2.fwd(h)[0];
    });
    this._lastExpertOut = eOut;
    let out = 0;
    for (let e = 0; e < 4; e++) out += gw[e] * eOut[e];
    const dom = gw.indexOf(Math.max(...gw));
    return { score: out, expert: this.experts[dom].name, gateW: gw };
  },
  bwd(label) {
    if (!this._lastGateW) return;
    let out = 0;
    for (let e = 0; e < 4; e++)
      out += this._lastGateW[e] * this._lastExpertOut[e];
    const dOut = out - label;
    for (let e = 0; e < 4; e++) {
      const dE = new Float32Array(1);
      dE[0] = dOut * this._lastGateW[e];
      const dH = this.experts[e].L2.bwd(dE, this.lr);
      this.experts[e].L1.bwd(dH, this.lr);
    }
    const dGate = new Float32Array(4);
    for (let e = 0; e < 4; e++)
      dGate[e] =
        dOut * this._lastExpertOut[e] + (this._lastGateW[e] - 0.25) * 0.05;
    this.Gate.bwd(dGate, this.lr);
    this.calls++;
  },
  export() {
    return {
      experts: this.experts.map((e) => ({
        L1: e.L1.export(),
        L2: e.L2.export(),
      })),
      Gate: this.Gate.export(),
      calls: this.calls,
    };
  },
  import(d) {
    if (!d) return;
    if (d.experts)
      d.experts.forEach((ed, i) => {
        if (this.experts[i]) {
          if (ed.L1) this.experts[i].L1.import(ed.L1);
          if (ed.L2) this.experts[i].L2.import(ed.L2);
        }
      });
    if (d.Gate) this.Gate.import(d.Gate);
    if (d.calls) this.calls = d.calls;
  },
}));
export const _rl = _lazy(() => ({
  TTLs: [10, 30, 300, 900, 1800, 3600, 7200],
  A1: _makeDense(16, 64, "relu"),
  A2: _makeDense(64, 32, "relu"),
  A3: _makeDense(32, 7, "linear"),
  V1: _makeDense(16, 64, "relu"),
  V2: _makeDense(64, 32, "relu"),
  V3: _makeDense(32, 1, "linear"),
  baseline: 0.5,
  lr: 1e-4,
  gamma: 0.99,
  calls: 0,
  cacheHitReward: 0,
  _lastLogProb: 0,
  _lastAction: 2,
  _lastState: null,
  _lastValue: 0,
  act(state16) {
    this._lastState = state16;
    const h1 = this.A1.fwd(state16);
    const h2 = this.A2.fwd(h1);
    const logits = this.A3.fwd(h2);
    const probs = _softmax(Array.from(logits));
    let action;
    if (Math.random() < 0.08) {
      action = Math.floor(Math.random() * 7);
    } else {
      action = probs.indexOf(Math.max(...probs));
    }
    this._lastAction = action;
    this._lastLogProb = Math.log(probs[action] + 1e-8);
    const v1 = this.V1.fwd(state16);
    const v2 = this.V2.fwd(v1);
    this._lastValue = this.V3.fwd(v2)[0];
    this.calls++;
    return this.TTLs[action];
  },
  reward(cacheHit) {
    if (!this._lastState) return;
    const r = cacheHit ? 1 : -0.05;
    this.cacheHitReward = 0.99 * this.cacheHitReward + 0.01 * r;
    const advantage = r - this._lastValue;
    this.baseline = 0.99 * this.baseline + 0.01 * r;
    const h1 = this.A1.fwd(this._lastState);
    const h2 = this.A2.fwd(h1);
    const logits = this.A3.fwd(h2);
    const probs = _softmax(Array.from(logits));
    const dLogits = new Float32Array(7);
    for (let i = 0; i < 7; i++)
      dLogits[i] =
        (probs[i] - (i === this._lastAction ? 1 : 0)) * -advantage * 0.005;
    const d2 = this.A3.bwd(dLogits, this.lr);
    const gOne = this.A2.bwd(d2, this.lr);
    this.A1.bwd(gOne, this.lr);
    const v1 = this.V1.fwd(this._lastState);
    const v2 = this.V2.fwd(v1);
    const vOut = this.V3.fwd(v2);
    const dV = new Float32Array(1);
    dV[0] = 2 * (vOut[0] - r) * 0.01;
    const dv2 = this.V3.bwd(dV, this.lr);
    const dv1 = this.V2.bwd(dv2, this.lr);
    this.V1.bwd(dv1, this.lr);
  },
  export() {
    return {
      A1: this.A1.export(),
      A2: this.A2.export(),
      A3: this.A3.export(),
      V1: this.V1.export(),
      V2: this.V2.export(),
      V3: this.V3.export(),
      baseline: this.baseline,
      calls: this.calls,
      hr: this.cacheHitReward,
    };
  },
  import(d) {
    if (!d) return;
    ["A1", "A2", "A3", "V1", "V2", "V3"].forEach((k) => {
      if (d[k]) this[k].import(d[k]);
    });
    if (d.baseline) this.baseline = d.baseline;
    if (d.calls) this.calls = d.calls;
    if (d.hr) this.cacheHitReward = d.hr;
  },
}));
export const _meta = _lazy(() => ({
  Wf: _heInit(24, 16),
  bf: _zeros(16),
  Wi: _heInit(24, 16),
  bi: _zeros(16),
  Wo: _heInit(24, 16),
  bo: _zeros(16),
  Wg: _heInit(24, 16),
  bg: _zeros(16),
  Wout: _heInit(16, 4),
  bout: _zeros(4),
  h: _zeros(16),
  c: _zeros(16),
  lr: 3e-4,
  calls: 0,
  forward(x8) {
    const xh = new Float32Array(24);
    for (let i = 0; i < 8; i++) xh[i] = x8[i];
    for (let i = 0; i < 16; i++) xh[8 + i] = this.h[i];
    const f = new Float32Array(16);
    for (let j = 0; j < 16; j++) {
      let s = this.bf[j];
      for (let i = 0; i < 24; i++) s += this.Wf[j * 24 + i] * xh[i];
      f[j] = _sigmoid(s);
    }
    const inp = new Float32Array(16);
    for (let j = 0; j < 16; j++) {
      let s = this.bi[j];
      for (let i = 0; i < 24; i++) s += this.Wi[j * 24 + i] * xh[i];
      inp[j] = _sigmoid(s);
    }
    const o = new Float32Array(16);
    for (let j = 0; j < 16; j++) {
      let s = this.bo[j];
      for (let i = 0; i < 24; i++) s += this.Wo[j * 24 + i] * xh[i];
      o[j] = _sigmoid(s);
    }
    const g = new Float32Array(16);
    for (let j = 0; j < 16; j++) {
      let s = this.bg[j];
      for (let i = 0; i < 24; i++) s += this.Wg[j * 24 + i] * xh[i];
      g[j] = _tanh(s);
    }
    const newC = new Float32Array(16);
    for (let j = 0; j < 16; j++) newC[j] = f[j] * this.c[j] + inp[j] * g[j];
    const newH = new Float32Array(16);
    for (let j = 0; j < 16; j++) newH[j] = o[j] * _tanh(newC[j]);
    this.c = newC;
    this.h = newH;
    const out = new Float32Array(4);
    for (let j = 0; j < 4; j++) {
      let s = this.bout[j];
      for (let i = 0; i < 16; i++) s += this.Wout[j * 16 + i] * newH[i];
      out[j] = _sigmoid(s);
    }
    this.calls++;
    return {
      lrScale: 0.5 + out[0],
      cacheTtlMult: 0.5 + out[1] * 1.5,
      cbThreshAdj: out[2] * 0.4 - 0.2,
      stressResponse: out[3],
    };
  },
  train(stress, throttle, loss) {
    const x8 = new Float32Array([
      stress,
      throttle ? 1 : 0,
      Math.min(loss, 1),
      0,
      0,
      0,
      0,
      0,
    ]);
    this.forward(x8);
  },
  export() {
    return {
      Wf: Array.from(this.Wf),
      Wi: Array.from(this.Wi),
      Wo: Array.from(this.Wo),
      Wg: Array.from(this.Wg),
      Wout: Array.from(this.Wout),
      h: Array.from(this.h),
      c: Array.from(this.c),
      calls: this.calls,
    };
  },
  import(d) {
    if (!d) return;
    ["Wf", "Wi", "Wo", "Wg", "Wout"].forEach((k) => {
      if (d[k] && d[k].length === this[k].length) this[k].set(d[k]);
    });
    if (d.h && d.h.length === 16) this.h = new Float32Array(d.h);
    if (d.c && d.c.length === 16) this.c = new Float32Array(d.c);
    if (d.calls) this.calls = d.calls;
  },
}));
export const _neuron = _lazy(() => ({
  L1: _makeDense(24, 64, "gelu"),
  L2: _makeDense(64, 32, "mish"),
  L3: _makeDense(32, 1, "sig"),
  lr: 5e-4,
  calls: 0,
  fwd(x24) {
    const h1 = this.L1.fwd(x24);
    const h2 = this.L2.fwd(h1);
    this.calls++;
    return this.L3.fwd(h2)[0];
  },
  train(x24, label) {
    const h1 = this.L1.fwd(x24);
    const h2 = this.L2.fwd(h1);
    const out = this.L3.fwd(h2);
    const dL = new Float32Array(1);
    dL[0] = out[0] - label;
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
export const _finalNeuron = _lazy(() => ({
  L1: _makeDense(20, 32, "gelu"),
  L2: _makeDense(32, 16, "mish"),
  L3: _makeDense(16, 1, "sig"),
  lr: 2e-4,
  calls: 0,
  fwd(scores20) {
    const h1 = this.L1.fwd(scores20);
    const h2 = this.L2.fwd(h1);
    this.calls++;
    return this.L3.fwd(h2)[0];
  },
  train(scores20, label) {
    const h1 = this.L1.fwd(scores20);
    const h2 = this.L2.fwd(h1);
    const out = this.L3.fwd(h2);
    const dL = new Float32Array(1);
    dL[0] = out[0] - label;
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
export const _bnn = _lazy(() => ({
  L1: _makeDense(32, 16, "relu"),
  L2: _makeDense(16, 8, "relu"),
  L3: _makeDense(8, 1, "sig"),
  lr: 0.001,
  calls: 0,
  DROP: 0.15,
  SAMPLES: 5,
  _fwdDrop(x32) {
    const h1 = this.L1.fwd(x32);
    const h1d = new Float32Array(16);
    for (let i = 0; i < 16; i++)
      h1d[i] = Math.random() > this.DROP ? h1[i] / (1 - this.DROP) : 0;
    const h2 = this.L2.fwd(h1d);
    const h2d = new Float32Array(8);
    for (let i = 0; i < 8; i++)
      h2d[i] = Math.random() > this.DROP ? h2[i] / (1 - this.DROP) : 0;
    return this.L3.fwd(h2d)[0];
  },
  predict(x32) {
    const samples = [];
    for (let s = 0; s < this.SAMPLES; s++) samples.push(this._fwdDrop(x32));
    const mean = samples.reduce((a, b) => a + b, 0) / this.SAMPLES;
    let variance = 0;
    for (const s of samples) variance += (s - mean) ** 2;
    variance /= this.SAMPLES;
    this.calls++;
    return {
      mean: mean,
      variance: variance,
      std: Math.sqrt(variance),
      confidence: 1 - Math.sqrt(variance) * 2,
    };
  },
  train(x32, label) {
    const p = this.L1.fwd(x32);
    const p2 = this.L2.fwd(p);
    const out = this.L3.fwd(p2)[0];
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
export const _contrastive = _lazy(() => ({
  Proj1: _makeDense(32, 16, "relu"),
  Proj2: _makeDense(16, 8, "linear"),
  lr: 5e-4,
  temp: 0.07,
  calls: 0,
  _cache: [],
  MAX_CACHE: 20,
  project(x32) {
    const h = this.Proj1.fwd(x32);
    const z = this.Proj2.fwd(h);
    const n = _norm2(z);
    return z.map((v) => v / n);
  },
  similarity(z1, z2) {
    let s = 0;
    for (let i = 0; i < 8; i++) s += z1[i] * z2[i];
    return s;
  },
  train(x32, isClean) {
    const z = this.project(x32);
    this._cache.push({ z: Array.from(z), clean: isClean });
    if (this._cache.length > this.MAX_CACHE) this._cache.shift();
    if (this._cache.length < 4) return;
    const pos = this._cache.filter((e) => e.clean === isClean && e.z !== z);
    if (!pos.length) return;
    const posZ = new Float32Array(
      pos[Math.floor(Math.random() * pos.length)].z,
    );
    const posS = this.similarity(z, posZ);
    let negSum = 0;
    for (const neg of this._cache.filter((e) => e.clean !== isClean)) {
      negSum += Math.exp(
        this.similarity(z, new Float32Array(neg.z)) / this.temp,
      );
    }
    const posExp = Math.exp(posS / this.temp);
    const loss = -Math.log(posExp / (posExp + negSum + 1e-8));
    const dZ = new Float32Array(8);
    for (let i = 0; i < 8; i++) {
      dZ[i] = (posZ[i] - z[i]) * (-loss * 0.01);
    }
    const dH = this.Proj2.bwd(dZ, this.lr);
    this.Proj1.bwd(dH, this.lr);
    this.calls++;
  },
  score(x32) {
    const z = this.project(x32);
    let cleanSim = 0,
      malSim = 0,
      cn = 0,
      mn = 0;
    for (const e of this._cache) {
      const s = this.similarity(z, new Float32Array(e.z));
      if (e.clean) {
        cleanSim += s;
        cn++;
      } else {
        malSim += s;
        mn++;
      }
    }
    if (!cn && !mn) return 0.5;
    const cAvg = cn > 0 ? cleanSim / cn : -1;
    const mAvg = mn > 0 ? malSim / mn : -1;
    return _sigmoid((mAvg - cAvg) * 5);
  },
  export() {
    return {
      P1: this.Proj1.export(),
      P2: this.Proj2.export(),
      calls: this.calls,
    };
  },
  import(d) {
    if (!d) return;
    if (d.P1) this.Proj1.import(d.P1);
    if (d.P2) this.Proj2.import(d.P2);
    if (d.calls) this.calls = d.calls;
  },
}));
export const _forest = _lazy(() => ({
  trees: [],
  N_TREES: 8,
  MAX_DEPTH: 6,
  calls: 0,
  _makeTree() {
    return { rules: [], counts: { good: 0, bad: 0 } };
  },
  _addRule(tree, feat, thresh, dir, depth) {
    if (depth > this.MAX_DEPTH) return;
    tree.rules.push({ f: feat, t: thresh, d: dir, depth: depth });
  },
  _updateTree(tree, x32, label) {
    tree.counts[label > 0.5 ? "bad" : "good"]++;
    for (const rule of tree.rules) {
      const v = x32[rule.f] || 0;
      rule.t = rule.t * 0.999 + v * 0.001;
    }
    if (tree.rules.length < this.MAX_DEPTH && Math.random() < 0.01) {
      const feat = Math.floor(Math.random() * 32);
      const thresh = (x32[feat] || 0) * 0.5 + 0.25;
      this._addRule(
        tree,
        feat,
        thresh,
        label > 0.5 ? 1 : -1,
        tree.rules.length,
      );
    }
  },
  _predictTree(tree, x32) {
    let score = 0.5;
    for (const rule of tree.rules) {
      const v = x32[rule.f] || 0;
      if (rule.d > 0 && v > rule.t) score += 0.05;
      else if (rule.d < 0 && v <= rule.t) score -= 0.03;
    }
    const total = tree.counts.good + tree.counts.bad + 1;
    const prior = tree.counts.bad / total;
    return _clip(score * 0.7 + prior * 0.3, 0, 1);
  },
  predict(x32) {
    if (!this.trees.length) return 0.5;
    let sum = 0;
    for (const tree of this.trees) sum += this._predictTree(tree, x32);
    this.calls++;
    return sum / this.trees.length;
  },
  train(x32, label) {
    while (this.trees.length < this.N_TREES) {
      const t = this._makeTree();
      for (let i = 0; i < 3; i++) {
        const feat = Math.floor(Math.random() * 32);
        this._addRule(t, feat, 0.5, label > 0.5 ? 1 : -1, i);
      }
      this.trees.push(t);
    }
    for (const tree of this.trees) this._updateTree(tree, x32, label);
  },
  export() {
    return { trees: this.trees, calls: this.calls };
  },
  import(d) {
    if (!d) return;
    if (d.trees && Array.isArray(d.trees)) this.trees = d.trees;
    if (d.calls) this.calls = d.calls;
  },
}));
export const _gnn = _lazy(() => ({
  WMsg: _makeDense(16, 8, "relu"),
  WUpd: _makeDense(16, 8, "relu"),
  WRead: _makeDense(8, 1, "sig"),
  nodes: new Map(),
  edges: new Map(),
  MAX_NODES: 1500,
  MAX_EDGES_PER_NODE: 16,
  lr: 0.001,
  calls: 0,
  _getNode(domain) {
    if (!this.nodes.has(domain)) {
      if (this.nodes.size >= this.MAX_NODES) {
        this.nodes.delete(this.nodes.keys().next().value);
        this.edges.delete(this.edges.keys().next().value);
      }
      this.nodes.set(domain, _randn(8, 0.1));
      this.edges.set(domain, new Set());
    }
    return this.nodes.get(domain);
  },
  addEdge(domA, domB) {
    const eA = this.edges.get(domA) || new Set();
    const eB = this.edges.get(domB) || new Set();
    if (eA.size < this.MAX_EDGES_PER_NODE) eA.add(domB);
    if (eB.size < this.MAX_EDGES_PER_NODE) eB.add(domA);
    this.edges.set(domA, eA);
    this.edges.set(domB, eB);
    this._getNode(domA);
    this._getNode(domB);
  },
  propagate(domain) {
    const hv = this._getNode(domain);
    const neighbors = this.edges.get(domain) || new Set();
    if (!neighbors.size) {
      return this.WRead.fwd(hv)[0];
    }
    const aggr = _zeros(8);
    for (const nb of neighbors) {
      const hu = this._getNode(nb);
      const concat = new Float32Array(16);
      for (let i = 0; i < 8; i++) {
        concat[i] = hv[i];
        concat[8 + i] = hu[i];
      }
      const msg = this.WMsg.fwd(concat);
      for (let i = 0; i < 8; i++) aggr[i] += msg[i];
    }
    for (let i = 0; i < 8; i++) aggr[i] /= neighbors.size;
    const upd_in = new Float32Array(16);
    for (let i = 0; i < 8; i++) {
      upd_in[i] = hv[i];
      upd_in[8 + i] = aggr[i];
    }
    const newH = this.WUpd.fwd(upd_in);
    const updated = new Float32Array(8);
    for (let i = 0; i < 8; i++) updated[i] = 0.9 * hv[i] + 0.1 * newH[i];
    this.nodes.set(domain, updated);
    const score = this.WRead.fwd(updated)[0];
    this.calls++;
    return score;
  },
  train(domain, isThreaten) {
    const hv = this._getNode(domain);
    const score = this.WRead.fwd(hv)[0];
    const dL = new Float32Array(1);
    dL[0] = score - isThreaten;
    const dH = this.WRead.bwd(dL, this.lr);
    for (let i = 0; i < 8; i++) hv[i] -= this.lr * dH[i];
  },
  export() {
    const nodes = [];
    for (const [k, v] of this.nodes) nodes.push([k, Array.from(v)]);
    return {
      WMsg: this.WMsg.export(),
      WUpd: this.WUpd.export(),
      WRead: this.WRead.export(),
      nodes: nodes.slice(0, 200),
      calls: this.calls,
    };
  },
  import(d) {
    if (!d) return;
    if (d.WMsg) this.WMsg.import(d.WMsg);
    if (d.WUpd) this.WUpd.import(d.WUpd);
    if (d.WRead) this.WRead.import(d.WRead);
    if (d.nodes) {
      for (const [k, v] of d.nodes) {
        this.nodes.set(k, new Float32Array(v));
        if (!this.edges.has(k)) this.edges.set(k, new Set());
      }
    }
    if (d.calls) this.calls = d.calls;
  },
}));
export const _calibrator = _lazy(() => ({
  a: 1,
  b: 0,
  lr: 0.01,
  knots: new Float32Array(10).fill(0.5),
  knotX: new Float32Array([
    0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95,
  ]),
  calls: 0,
  calibrate(rawScore) {
    const platt = _sigmoid(this.a * rawScore + this.b);
    let lo = 0,
      hi = 9;
    for (let i = 0; i < 9; i++)
      if (rawScore >= this.knotX[i] && rawScore < this.knotX[i + 1]) {
        lo = i;
        hi = i + 1;
        break;
      }
    const t =
      (rawScore - this.knotX[lo]) / (this.knotX[hi] - this.knotX[lo] + 1e-8);
    const iso = this.knots[lo] * (1 - t) + this.knots[hi] * t;
    this.calls++;
    return _clip(iso * 0.6 + platt * 0.4, 0.01, 0.99);
  },
  update(rawScore, trueLabel) {
    const pred = _sigmoid(this.a * rawScore + this.b);
    const err = pred - trueLabel;
    this.a -= this.lr * err * rawScore;
    this.b -= this.lr * err;
    let best = 0,
      bestD = Infinity;
    for (let i = 0; i < 10; i++) {
      const d = Math.abs(rawScore - this.knotX[i]);
      if (d < bestD) {
        bestD = d;
        best = i;
      }
    }
    this.knots[best] = 0.95 * this.knots[best] + 0.05 * trueLabel;
    for (let i = 1; i < 10; i++)
      if (this.knots[i] < this.knots[i - 1]) this.knots[i] = this.knots[i - 1];
  },
  export() {
    return {
      a: this.a,
      b: this.b,
      knots: Array.from(this.knots),
      calls: this.calls,
    };
  },
  import(d) {
    if (!d) return;
    if (d.a != null) this.a = d.a;
    if (d.b != null) this.b = d.b;
    if (d.knots && d.knots.length === 10) this.knots.set(d.knots);
    if (d.calls) this.calls = d.calls;
  },
}));
export const _liquid = _lazy(() => ({
  units: 32,
  inputs: 4,
  h: new Float32Array(32),
  Win: _heInit(4, 32),
  Wrec: _heInit(32, 32),
  Wout: _heInit(32, 2),
  tau: new Float32Array(32).fill(1),
  lr: 5e-4,
  calls: 0,
  _ode(h, x) {
    const dh = new Float32Array(32);
    for (let j = 0; j < 32; j++) {
      let s = 0;
      for (let i = 0; i < 4; i++) s += this.Win[j * 4 + i] * x[i];
      for (let i = 0; i < 32; i++) s += this.Wrec[j * 32 + i] * h[i];
      dh[j] = (-h[j] + _tanh(s)) / (this.tau[j] + 1e-6);
    }
    return dh;
  },
  step(x4, dt = 0.1) {
    const k1 = this._ode(this.h, x4);
    const h2 = new Float32Array(32).map((v, i) => this.h[i] + k1[i] * dt * 0.5);
    const k2 = this._ode(h2, x4);
    const h3 = new Float32Array(32).map((v, i) => this.h[i] + k2[i] * dt * 0.5);
    const k3 = this._ode(h3, x4);
    const h4 = new Float32Array(32).map((v, i) => this.h[i] + k3[i] * dt);
    const k4 = this._ode(h4, x4);
    for (let i = 0; i < 32; i++)
      this.h[i] += (dt / 6) * (k1[i] + 2 * k2[i] + 2 * k3[i] + k4[i]);
    const out = new Float32Array(2);
    for (let j = 0; j < 2; j++) {
      let s = 0;
      for (let i = 0; i < 32; i++) s += this.Wout[j * 32 + i] * this.h[i];
      out[j] = _sigmoid(s);
    }
    this.calls++;
    return out;
  },
  export() {
    return {
      Win: Array.from(this.Win),
      Wrec: Array.from(this.Wrec),
      Wout: Array.from(this.Wout),
      h: Array.from(this.h),
      tau: Array.from(this.tau),
      calls: this.calls,
    };
  },
  import(d) {
    if (!d) return;
    if (d.Win) this.Win.set(d.Win);
    if (d.Wrec) this.Wrec.set(d.Wrec);
    if (d.Wout) this.Wout.set(d.Wout);
    if (d.h) this.h.set(d.h);
    if (d.tau) this.tau.set(d.tau);
    if (d.calls) this.calls = d.calls;
  },
}));
export const _spiking = _lazy(() => ({
  units: 32,
  v: new Float32Array(32),
  thr: new Float32Array(32).fill(1),
  trace: new Float32Array(32),
  W: _heInit(16, 32),
  decay: 0.9,
  calls: 0,
  spikes: 0,
  _lastX: new Float32Array(16),
  step(x16) {
    let delta = 0;
    for (let i = 0; i < 16; i++) delta += Math.abs(x16[i] - this._lastX[i]);
    if (delta < 0.01 && this.calls > 0) return new Float32Array(32);
    this._lastX.set(x16);
    const s = new Float32Array(32);
    for (let j = 0; j < 32; j++) {
      let input = 0;
      for (let i = 0; i < 16; i++) input += this.W[j * 16 + i] * x16[i];
      this.v[j] = this.v[j] * this.decay + input;
      if (this.v[j] > this.thr[j]) {
        s[j] = 1;
        this.v[j] = 0;
        this.trace[j] = 1;
        this.spikes++;
      } else {
        this.trace[j] *= 0.95;
      }
    }
    this.calls++;
    return s;
  },
  export() {
    return {
      W: Array.from(this.W),
      thr: Array.from(this.thr),
      calls: this.calls,
    };
  },
  import(d) {
    if (!d) return;
    if (d.W) this.W.set(d.W);
    if (d.thr) this.thr.set(d.thr);
    if (d.calls) this.calls = d.calls;
  },
}));
export const _symbolic = {
  rules: [
    {
      id: "r1",
      cond: (f) => f[0] > 0.75,
      msg: "High-Entropy Entropy/DGA signature detected",
    },
    {
      id: "r2",
      cond: (f) => f[5] > 0.8,
      msg: "Suspiciously long cryptographic label",
    },
    {
      id: "r3",
      cond: (f) => f[14] > 0.85,
      msg: "Anomalous burst request rate",
    },
    {
      id: "r4",
      cond: (f) => f[17] > 0.6,
      msg: "Behavioral rhythm matches C2 beaconing",
    },
    {
      id: "r5",
      cond: (f) => f[38] > 0.7,
      msg: "Neural mismatch in character distribution",
    },
  ],
  calls: 0,
  reason(f40) {
    this.calls++;
    const active = this.rules.filter((r) => r.cond(f40));
    if (!active.length) return null;
    return active.map((r) => r.msg).join(" + ");
  },
  export() {
    return { calls: this.calls };
  },
  import(d) {
    if (d && d.calls) this.calls = d.calls;
  },
};

export function clearNeuralModelStates() {
  if (_gru?.states?.clear) _gru.states.clear();
  if (_gru?.history?.clear) _gru.history.clear();
  if (_gnn?.nodes?.clear) _gnn.nodes.clear();
  if (_gnn?.edges?.clear) _gnn.edges.clear();
  if (_gnn) _gnn.calls = 0;
  if (_contrastive?._cache) _contrastive._cache.length = 0;
  if (_spiking) {
    if (_spiking.v?.fill) _spiking.v.fill(0);
    if (_spiking.trace?.fill) _spiking.trace.fill(0);
    if (_spiking._lastX?.fill) _spiking._lastX.fill(0);
    _spiking.calls = 0;
    _spiking.spikes = 0;
  }
  if (_rl) {
    _rl.calls = 0;
    _rl.cacheHitReward = 0;
    _rl._lastState = null;
    _rl._lastValue = 0;
  }
}
