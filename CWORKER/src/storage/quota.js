// CWORKER/src/storage/quota.js
// Strict daily quota and cap guardian for Cloudflare KV, D1, and R2 operations.
// Zero reliance on environment variables; uses hardcoded canonical limits with graceful rollover.

import { CONFIG } from '../config.js';

export class QuotaGuardian {
  constructor(customCaps = {}) {
    this.kvWriteCap = parseInt(customCaps.DAILY_KV_WRITE_CAP || CONFIG.DAILY_KV_WRITE_CAP, 10);
    this.kvReadCap = parseInt(customCaps.DAILY_KV_READ_CAP || CONFIG.DAILY_KV_READ_CAP, 10);
    this.d1WriteCap = parseInt(customCaps.DAILY_D1_WRITE_CAP || CONFIG.DAILY_D1_WRITE_CAP, 10);
    this.d1ReadCap = parseInt(customCaps.DAILY_D1_READ_CAP || CONFIG.DAILY_D1_READ_CAP, 10);

    this.currentDate = this.getUtcDateKey();
    this.counters = {
      kvWrites: 0,
      kvReads: 0,
      d1Writes: 0,
      d1Reads: 0,
      r2Writes: 0,
      r2Reads: 0,
      rejectedWrites: 0,
      rejectedReads: 0
    };
  }

  getUtcDateKey() {
    return new Date().toISOString().slice(0, 10); // "YYYY-MM-DD"
  }

  checkDayRollover() {
    const today = this.getUtcDateKey();
    if (this.currentDate !== today) {
      this.currentDate = today;
      this.counters = {
        kvWrites: 0,
        kvReads: 0,
        d1Writes: 0,
        d1Reads: 0,
        r2Writes: 0,
        r2Reads: 0,
        rejectedWrites: 0,
        rejectedReads: 0
      };
    }
  }

  canKvWrite() {
    this.checkDayRollover();
    if (this.counters.kvWrites >= this.kvWriteCap) {
      this.counters.rejectedWrites++;
      return false;
    }
    return true;
  }

  recordKvWrite() {
    this.checkDayRollover();
    this.counters.kvWrites++;
  }

  canKvRead() {
    this.checkDayRollover();
    if (this.counters.kvReads >= this.kvReadCap) {
      this.counters.rejectedReads++;
      return false;
    }
    return true;
  }

  recordKvRead() {
    this.checkDayRollover();
    this.counters.kvReads++;
  }

  canD1Write() {
    this.checkDayRollover();
    if (this.counters.d1Writes >= this.d1WriteCap) {
      this.counters.rejectedWrites++;
      return false;
    }
    return true;
  }

  recordD1Write() {
    this.checkDayRollover();
    this.counters.d1Writes++;
  }

  canD1Read() {
    this.checkDayRollover();
    if (this.counters.d1Reads >= this.d1ReadCap) {
      this.counters.rejectedReads++;
      return false;
    }
    return true;
  }

  recordD1Read() {
    this.checkDayRollover();
    this.counters.d1Reads++;
  }

  getUsage() {
    this.checkDayRollover();
    return {
      date: this.currentDate,
      kv: {
        writes: this.counters.kvWrites,
        writeCap: this.kvWriteCap,
        writesRemaining: Math.max(0, this.kvWriteCap - this.counters.kvWrites),
        reads: this.counters.kvReads,
        readCap: this.kvReadCap,
        readsRemaining: Math.max(0, this.kvReadCap - this.counters.kvReads)
      },
      d1: {
        writes: this.counters.d1Writes,
        writeCap: this.d1WriteCap,
        writesRemaining: Math.max(0, this.d1WriteCap - this.counters.d1Writes),
        reads: this.counters.d1Reads,
        readCap: this.d1ReadCap,
        readsRemaining: Math.max(0, this.d1ReadCap - this.counters.d1Reads)
      },
      rejectedOperations: {
        writes: this.counters.rejectedWrites,
        reads: this.counters.rejectedReads
      }
    };
  }
}
