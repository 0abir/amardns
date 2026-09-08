// src/cron.js
import cron from "node-cron";
import logger from "./logger.js";

function stripQuotes(str) {
  if (!str) return str;
  const s = String(str).trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1).trim();
  }
  return s;
}

export function startCron(worker, env) {
  const schedule = stripQuotes(process.env.CRON_SCHEDULE) || "*/5 * * * *";
  // Continuously rank all upstreams in the background simultaneously (default: every 5 mins)
  const upstreamSchedule = stripQuotes(process.env.UPSTREAM_CRON) || "*/5 * * * *";
  const ctx = {
    waitUntil: (p) =>
      Promise.resolve(p).catch((e) => logger.error("cron waitUntil error:", e)),
  };

  // 1. Initial boot check: load persisted upstreams, then immediately trigger background simultaneous ranker
  import("./upstream-manager.js").then(({ loadPersistedUpstreams, syncAndRankUpstreams }) => {
    loadPersistedUpstreams(env, worker);
    if (process.env.AUTO_UPSTREAM_SYNC !== "false") {
      setTimeout(() => {
        syncAndRankUpstreams(env, worker).catch((err) => {
          logger.warn("[cron] Initial background upstream ranking deferred:", err.message);
        });
      }, 1000).unref();
    }
  }).catch((err) => logger.error("[cron] Failed to load upstream-manager:", err));

  // 2. Continuous Upstream DNS Sync & Simultaneous Aura Ranker (every 5 mins)
  const upstreamTask = cron.schedule(upstreamSchedule, () => {
    logger.info("[cron] Running background upstream DNS simultaneous probing & aura ranking...");
    import("./upstream-manager.js").then(({ syncAndRankUpstreams }) => {
      syncAndRankUpstreams(env, worker).catch((err) => {
        logger.error("[cron] Simultaneous upstream sync failed:", err.message);
      });
    }).catch((err) => logger.error("[cron] Simultaneous upstream sync error:", err));
  });

  // 3. Main scheduled worker cron (every 5 mins by default)
  const cronTask = cron.schedule(schedule, () => {
    worker
      .scheduled({ cron: schedule }, env, ctx)
      .catch((err) => logger.error("scheduled() error:", err));

    // Check PulseDB compaction
    if (env.pulseDb && typeof env.pulseDb.shouldCompact === "function") {
      if (env.pulseDb.shouldCompact()) {
        env.pulseDb.compact();
      }
    }

    // Periodic GC reclaim during maintenance cycle
    if (typeof global.gc === "function") {
      try { global.gc(); } catch (_) {}
    }
  });

  // 4. Active Cleaning Rotation Micro-Sweeper & Proactive Memory Guard (every 30 seconds):
  // - Proactively purges expired DNS wire cache entries and expired Aero store keys
  // - Monitors heap memory; triggers deep sweep if approaching budget to prevent OOM
  const sweepInterval = setInterval(() => {
    if (env.aeroCache && typeof env.aeroCache.sweep === "function") {
      env.aeroCache.sweep(1000);
    }
    if (env.pulseDb && typeof env.pulseDb.sweepExpiredAero === "function") {
      env.pulseDb.sweepExpiredAero(200);
    }

    const mem = process.memoryUsage();
    if (mem.heapUsed > 60 * 1024 * 1024) {
      logger.warn(`[memory-guard] Elevated heap (${(mem.heapUsed / 1048576).toFixed(1)}MB), executing deep sweep`);
      if (env.aeroCache) env.aeroCache.sweep(5000);
      if (typeof global.gc === "function") {
        try { global.gc(); } catch (_) {}
      }
    }
  }, 30000);
  sweepInterval.unref(); // don't prevent clean process shutdown

  logger.info(`[cron] scheduled: "${schedule}" + daily: "${upstreamSchedule}" (upstream sync) + 30s cleaning rotation & memory guard`);

  return {
    stop: () => {
      try {
        cronTask.stop();
        upstreamTask.stop();
        clearInterval(sweepInterval);
      } catch (e) {
        logger.error("cron stop error:", e.message);
      }
    },
  };
}
