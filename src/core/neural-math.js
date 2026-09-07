// src/core/neural-math.js
// Math primitives, activations, candidate generators, and neural layer factories.

import { LEET_MAP } from "./constants.js";

export function deLeet(s) {
  return s.replace(/[013456789@$!]/g, (c) => LEET_MAP[c] || c);
}
export function _getCandidates(domain) {
  const d = domain.toLowerCase().replace(/\.$/, "");
  const parts = d.split(".");
  if (parts.length < 2) return [d];
  const res = [d, "*." + d];
  for (let i = 1; i < parts.length - 1; i++) {
    const p = parts.slice(i).join(".");
    res.push(p);
    res.push("*." + p);
  }
  return Array.from(new Set(res));
}

export const _relu = (x) => (x > 0 ? x : 0);
export const _lrelu = (x) => (x > 0 ? x : 0.01 * x);
export const _sigmoid = (x) => 1 / (1 + Math.exp(-Math.max(-20, Math.min(20, x))));
export const _tanh = (x) => {
  const e = Math.exp(-2 * Math.max(-20, Math.min(20, x)));
  return (1 - e) / (1 + e);
};
export const _swish = (x) => x * _sigmoid(x);
export const _gelu = (x) =>
  0.5 * x * (1 + _tanh(0.7978845608 * (x + 0.044715 * x * x * x)));
export const _mish = (x) =>
  x * _tanh(Math.log(1 + Math.exp(Math.max(-20, Math.min(20, x)))));
export function _softmax(a) {
  let m = a[0];
  for (let i = 1; i < a.length; i++) if (a[i] > m) m = a[i];
  let s = 0;
  const e = new Float32Array(a.length);
  for (let i = 0; i < a.length; i++) {
    e[i] = Math.exp(a[i] - m);
    s += e[i];
  }
  for (let i = 0; i < a.length; i++) e[i] /= s;
  return e;
}
export function _clip(x, lo, hi) {
  return Math.max(lo, Math.min(hi, x));
}
export function _norm2(v) {
  let s = 0;
  for (let i = 0; i < v.length; i++) s += v[i] * v[i];
  return Math.sqrt(s) + 1e-8;
}
export function _heInit(fan_in, fan_out) {
  const w = new Float32Array(fan_in * fan_out);
  const s = Math.sqrt(2 / fan_in);
  for (let i = 0; i < w.length; i++) w[i] = (Math.random() * 2 - 1) * s;
  return w;
}
export function _glorot(fan_in, fan_out) {
  const w = new Float32Array(fan_in * fan_out);
  const s = Math.sqrt(6 / (fan_in + fan_out));
  for (let i = 0; i < w.length; i++) w[i] = (Math.random() * 2 - 1) * s;
  return w;
}
export function _zeros(n) {
  return new Float32Array(n);
}
export function _ones(n) {
  const a = new Float32Array(n);
  a.fill(1);
  return a;
}
export function _randn(n, scale = 0.01) {
  const a = new Float32Array(n);
  for (let i = 0; i < n; i++) a[i] = (Math.random() * 2 - 1) * scale;
  return a;
}
export function _makeDense(fanIn, fanOut, act = "relu") {
  return {
    W: _heInit(fanIn, fanOut),
    b: _zeros(fanOut),
    mW: null,
    vW: null,
    mb: null,
    vb: null,
    t: 0,
    act: act,
    fanIn: fanIn,
    fanOut: fanOut,
    _in: null,
    _z: null,
    _out: null,
    fwd(x) {
      this._in = x;
      const z = new Float32Array(this.fanOut);
      for (let j = 0; j < this.fanOut; j++) {
        let s = this.b[j];
        const off = j * this.fanIn;
        for (let i = 0; i < this.fanIn; i++) s += this.W[off + i] * x[i];
        z[j] = s;
      }
      this._z = z;
      const out = new Float32Array(this.fanOut);
      const a = this.act;
      for (let j = 0; j < this.fanOut; j++) {
        const val = z[j];
        out[j] =
          a === "relu"
            ? _relu(val)
            : a === "lrelu"
              ? _lrelu(val)
              : a === "swish"
                ? _swish(val)
                : a === "gelu"
                  ? _gelu(val)
                  : a === "mish"
                    ? _mish(val)
                    : a === "tanh"
                      ? _tanh(val)
                      : a === "sig"
                        ? _sigmoid(val)
                        : val;
      }
      this._out = out;
      return out;
    },
    bwd(dOut, lr = 0.001, wd = 1e-4) {
      if (!this.mW) {
        this.mW = _zeros(this.fanIn * this.fanOut);
        this.vW = _zeros(this.fanIn * this.fanOut);
        this.mb = _zeros(this.fanOut);
        this.vb = _zeros(this.fanOut);
      }
      this.t++;
      const beta1 = 0.9,
        beta2 = 0.999,
        eps = 1e-8;
      const bc1 = 1 - beta1 ** this.t,
        bc2 = 1 - beta2 ** this.t;
      const dZ = new Float32Array(this.fanOut);
      for (let j = 0; j < this.fanOut; j++) {
        const z = this._z[j],
          a2 = this._out[j],
          a = this.act;
        dZ[j] =
          dOut[j] *
          (a === "relu"
            ? z > 0
              ? 1
              : 0
            : a === "lrelu"
              ? z > 0
                ? 1
                : 0.01
              : a === "swish"
                ? _sigmoid(z) + z * _sigmoid(z) * (1 - _sigmoid(z))
                : a === "gelu"
                  ? 0.5 *
                      (1 + _tanh(0.7978845608 * (z + 0.044715 * z * z * z))) +
                    z *
                      0.5 *
                      (1 -
                        _tanh(0.7978845608 * (z + 0.044715 * z * z * z)) ** 2) *
                      0.7978845608 *
                      (1 + 3 * 0.044715 * z * z)
                  : a === "mish"
                    ? _tanh(Math.log(1 + Math.exp(Math.max(-20, z)))) +
                      z *
                        (1 -
                          _tanh(Math.log(1 + Math.exp(Math.max(-20, z)))) **
                            2) *
                        _sigmoid(z)
                    : a === "tanh"
                      ? 1 - a2 * a2
                      : a === "sig"
                        ? a2 * (1 - a2)
                        : 1);
      }
      const dIn = new Float32Array(this.fanIn);
      for (let i = 0; i < this.fanIn; i++)
        for (let j = 0; j < this.fanOut; j++)
          dIn[i] += dZ[j] * this.W[j * this.fanIn + i];
      for (let j = 0; j < this.fanOut; j++) {
        for (let i = 0; i < this.fanIn; i++) {
          const k = j * this.fanIn + i;
          const g = _clip(dZ[j] * this._in[i], -1, 1) + wd * this.W[k];
          this.mW[k] = beta1 * this.mW[k] + (1 - beta1) * g;
          this.vW[k] = beta2 * this.vW[k] + (1 - beta2) * g * g;
          this.W[k] -=
            (lr * (this.mW[k] / bc1)) / (Math.sqrt(this.vW[k] / bc2) + eps);
        }
        const gb = _clip(dZ[j], -1, 1);
        this.mb[j] = beta1 * this.mb[j] + (1 - beta1) * gb;
        this.vb[j] = beta2 * this.vb[j] + (1 - beta2) * gb * gb;
        this.b[j] -=
          (lr * (this.mb[j] / bc1)) / (Math.sqrt(this.vb[j] / bc2) + eps);
      }
      return dIn;
    },
    export() {
      const r = (v) => +v.toFixed(5);
      const res = {
        W: Array.from(this.W).map(r),
        b: Array.from(this.b).map(r),
      };
      if (this.mW) {
        res.mW = Array.from(this.mW).map(r);
        res.vW = Array.from(this.vW).map(r);
        res.mb = Array.from(this.mb).map(r);
        res.vb = Array.from(this.vb).map(r);
        res.t = this.t;
      }
      return res;
    },
    import(d) {
      if (!d) return;
      if (d.W && d.W.length === this.W.length) this.W.set(d.W);
      if (d.b && d.b.length === this.b.length) this.b.set(d.b);
      if (d.mW) {
        this.mW = new Float32Array(d.mW);
        this.vW = new Float32Array(d.vW);
        this.mb = new Float32Array(d.mb);
        this.vb = new Float32Array(d.vb);
        this.t = d.t || 0;
      }
    },
  };
}
export function _makeBN(dim) {
  return {
    gamma: _ones(dim),
    beta: _zeros(dim),
    runMean: _zeros(dim),
    runVar: _ones(dim),
    eps: 1e-5,
    momentum: 0.1,
    dim: dim,
    _xhat: null,
    _in: null,
    fwd(x) {
      this._in = x;
      for (let i = 0; i < this.dim; i++) {
        this.runMean[i] =
          this.runMean[i] * (1 - this.momentum) + x[i] * this.momentum;
        const diff = x[i] - this.runMean[i];
        this.runVar[i] =
          this.runVar[i] * (1 - this.momentum) + diff * diff * this.momentum;
      }
      const xhat = new Float32Array(this.dim);
      const out = new Float32Array(this.dim);
      for (let i = 0; i < this.dim; i++) {
        xhat[i] =
          (x[i] - this.runMean[i]) / Math.sqrt(this.runVar[i] + this.eps);
        out[i] = this.gamma[i] * xhat[i] + this.beta[i];
      }
      this._xhat = xhat;
      return out;
    },
    bwd(dOut, lr = 0.001) {
      const dIn = new Float32Array(this.dim);
      for (let i = 0; i < this.dim; i++) {
        this.gamma[i] -= lr * _clip(dOut[i] * this._xhat[i], -1, 1);
        this.beta[i] -= lr * _clip(dOut[i], -1, 1);
        dIn[i] =
          (dOut[i] * this.gamma[i]) / Math.sqrt(this.runVar[i] + this.eps);
      }
      return dIn;
    },
    export() {
      return {
        g: Array.from(this.gamma).map((v) => +v.toFixed(5)),
        b: Array.from(this.beta).map((v) => +v.toFixed(5)),
        rm: Array.from(this.runMean).map((v) => +v.toFixed(5)),
        rv: Array.from(this.runVar).map((v) => +v.toFixed(5)),
      };
    },
    import(d) {
      if (!d) return;
      if (d.g) this.gamma.set(d.g);
      if (d.b) this.beta.set(d.b);
      if (d.rm) this.runMean.set(d.rm);
      if (d.rv) this.runVar.set(d.rv);
    },
  };
}
export function _makeLayerNorm(dim) {
  return {
    gamma: _ones(dim),
    beta: _zeros(dim),
    eps: 1e-5,
    dim: dim,
    fwd(x) {
      let mean = 0;
      for (let i = 0; i < dim; i++) mean += x[i];
      mean /= dim;
      let variance = 0;
      for (let i = 0; i < dim; i++) variance += (x[i] - mean) ** 2;
      variance /= dim;
      const std = Math.sqrt(variance + this.eps);
      const out = new Float32Array(dim);
      for (let i = 0; i < dim; i++)
        out[i] = (this.gamma[i] * (x[i] - mean)) / std + this.beta[i];
      return out;
    },
    export() {
      return {
        g: Array.from(this.gamma).map((v) => +v.toFixed(5)),
        b: Array.from(this.beta).map((v) => +v.toFixed(5)),
      };
    },
    import(d) {
      if (!d) return;
      if (d.g) this.gamma.set(d.g);
      if (d.b) this.beta.set(d.b);
    },
  };
}
