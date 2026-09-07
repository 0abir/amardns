// src/core/bloom-filter.js
// High-performance Fowler-Noll-Vo based Bloom Filter for fast domain set membership checks.

export class BloomFilter {
  constructor(capacity, fpr = 1e-4) {
    if (!capacity || capacity < 1) capacity = 1;
    this.n = capacity;
    const logFpr = Math.log(fpr);
    const ln2sq = Math.LN2 * Math.LN2;
    this.m = Math.ceil((-capacity * logFpr) / ln2sq);
    this.k = Math.max(1, Math.round((this.m / capacity) * Math.LN2));
    this.bits = new Uint32Array(Math.ceil(this.m / 32));
    this._size = 0;
    this._lastStr = null;
    this._lastH1 = 0;
    this._lastH2 = 0;
  }
  get size() {
    return this._size;
  }
  _hash(s) {
    if (s === this._lastStr) return [this._lastH1, this._lastH2];
    let h1 = 2166136261,
      h2 = 3735928559;
    for (let i = 0; i < s.length; i++) {
      const ch = s.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 16777619);
      h2 = Math.imul(h2 ^ ch, 1540483477);
    }
    h1 >>>= 0;
    h2 >>>= 0;
    this._lastStr = s;
    this._lastH1 = h1;
    this._lastH2 = h2;
    return [h1, h2];
  }
  add(s) {
    const [h1, h2] = this._hash(s);
    const m = this.m;
    for (let i = 0; i < this.k; i++) {
      const h = (h1 + i * h2) % m;
      this.bits[h >>> 5] |= 1 << (h & 31);
    }
    this._size++;
  }
  has(s) {
    if (!s) return false;
    const [h1, h2] = this._hash(s);
    const m = this.m,
      bits = this.bits;
    for (let i = 0; i < this.k; i++) {
      const h = (h1 + i * h2) % m;
      if (!(bits[h >>> 5] & (1 << (h & 31)))) return false;
    }
    return true;
  }
  clear() {
    this.bits.fill(0);
    this._size = 0;
    this._lastStr = null;
  }
  delete(_s) {}
}
