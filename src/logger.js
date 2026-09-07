// src/logger.js
// Centralized, zero-dependency logger with log-level suppression for production.

const LEVELS = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
  silent: 4,
};

function resolveLogLevel() {
  const envLevel = (process.env.LOG_LEVEL || "").trim().toLowerCase();
  if (envLevel in LEVELS) {
    return LEVELS[envLevel];
  }
  // In production default to "warn" (suppressing debug & info chatter)
  return process.env.NODE_ENV === "production" ? LEVELS.warn : LEVELS.info;
}

let activeLevel = resolveLogLevel();

export const logger = {
  LEVELS,
  get level() {
    return activeLevel;
  },
  setLevel(levelName) {
    const key = String(levelName).trim().toLowerCase();
    if (key in LEVELS) {
      activeLevel = LEVELS[key];
    }
  },
  debug(...args) {
    if (activeLevel <= LEVELS.debug) {
      console.log(...args);
    }
  },
  info(...args) {
    if (activeLevel <= LEVELS.info) {
      console.log(...args);
    }
  },
  warn(...args) {
    if (activeLevel <= LEVELS.warn) {
      console.warn(...args);
    }
  },
  error(...args) {
    if (activeLevel <= LEVELS.error) {
      console.error(...args);
    }
  },
  /**
   * Essential operational and lifecycle events (listening host/port, graceful shutdown)
   * that must always be printed unless explicitly silenced via LOG_LEVEL=silent.
   */
  system(...args) {
    if (activeLevel < LEVELS.silent) {
      console.log(...args);
    }
  },
};

export default logger;
