// src/cron.js
import cron from "node-cron";
import logger from "./logger.js";

export function startCron(worker, env) {
  const schedule = process.env.CRON_SCHEDULE || "*/5 * * * *";
  // Pull upstream DNS list once weekly (default: Sunday at 03:00 UTC)
  const weeklySchedule = process.env.UPSTREAM_CRON || "0 3 * * 0";
  const ctx = {
    waitUntil: (p) =>
      Promise.resolve(p).catch((e) => logger.error("cron waitUntil error:", e)),
  };

  // 1. Initial boot check: load persisted upstreams or trigger initial sync asynchronously
  import("./upstream-manager.js").then(({ loadPersistedUpstreams, syncAndRankUpstreams }) => {
    const initStatus = loadPersistedUpstreams(env, worker);
    if (initStatus.shouldSync && process.env.AUTO_UPSTREAM_SYNC !== "false") {
      setImmediate(() => {
        syncAndRankUpstreams(env, worker).catch((err) => {
          logger.warn("[cron] Initial upstream sync deferred/failed:", err.message);
        });
      });
    }
  }).catch((err) => logger.error("[cron] Failed to load upstream-manager:", err));

  // 2. Weekly Upstream DNS Sync & Aura Ranker
  const weeklyTask = cron.schedule(weeklySchedule, () => {
    logger.info("[cron] Running weekly upstream DNS synchronization & aura ranking...");
    import("./upstream-manager.js").then(({ syncAndRankUpstreams }) => {
      syncAndRankUpstreams(env, worker).catch((err) => {
        logger.error("[cron] Weekly upstream sync failed:", err.message);
      });
    }).catch((err) => logger.error("[cron] Weekly upstream sync error:", err));
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
  });

  // 4. Active Cleaning Rotation Micro-Sweeper & Proactive Memory Guard (every 30 seconds):
  // - Proactively purges expired DNS wire cache entries and expired KV store keys
  // - Monitors heap memory; triggers deep sweep if approaching budget to prevent OOM
  const sweepInterval = setInterval(() => {
    if (env.aeroCache && typeof env.aeroCache.sweep === "function") {
      env.aeroCache.sweep(1000);
    }
    if (env.pulseDb && typeof env.pulseDb.sweepExpiredKV === "function") {
      env.pulseDb.sweepExpiredKV(200);
    }

    const mem = process.memoryUsage();
    if (mem.heapUsed > 140 * 1024 * 1024) {
      logger.warn(`[memory-guard] Elevated heap (${(mem.heapUsed / 1048576).toFixed(1)}MB), executing deep sweep`);
      if (env.aeroCache) env.aeroCache.sweep(5000);
      if (typeof global.gc === "function") global.gc();
    }
  }, 30000);
  sweepInterval.unref(); // don't prevent clean process shutdown

  logger.info(`[cron] scheduled: "${schedule}" + weekly: "${weeklySchedule}" (upstream sync) + 30s cleaning rotation & memory guard`);

  return {
    stop: () => {
      try {
        cronTask.stop();
        weeklyTask.stop();
        clearInterval(sweepInterval);
      } catch (e) {
        logger.error("cron stop error:", e.message);
      }
    },
  };
}
