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
  // Upstream DNS sync & aura ranker runs strictly once a day at GMT+6, Dhaka
  const upstreamSchedule = stripQuotes(process.env.UPSTREAM_CRON) || "0 0 * * *";
  const upstreamTz = stripQuotes(process.env.UPSTREAM_TZ) || "Asia/Dhaka";
  const ctx = {
    waitUntil: (p) =>
      Promise.resolve(p).catch((e) => logger.error("cron waitUntil error:", e)),
  };

  // 1. Initial boot check: load persisted upstreams from PulseDB.
  // If upstreams are already persisted and valid (< 24h old), avoid probe requests on boot.
  // Only sync if missing or expired (> 24h).
  import("./upstream-manager.js").then(({ loadPersistedUpstreams, syncAndRankUpstreams }) => {
    const { shouldSync, loaded } = loadPersistedUpstreams(env, worker);
    if (shouldSync && process.env.AUTO_UPSTREAM_SYNC !== "false") {
      setTimeout(() => {
        syncAndRankUpstreams(env, worker, { forcePull: true }).catch((err) => {
          logger.warn("[cron] Initial upstream ranking deferred:", err.message);
        });
      }, 1000).unref();
    } else if (loaded) {
      logger.info("[cron] Upstreams loaded from PulseDB; frequent background ranking disabled (scheduled once daily at GMT+6, Dhaka).");
    }
  }).catch((err) => logger.error("[cron] Failed to load upstream-manager:", err));

  // 2. Upstream DNS Sync & Aura Ranker — strictly once a day at GMT+6, Dhaka
  const upstreamTask = cron.schedule(
    upstreamSchedule,
    () => {
      logger.info(`[cron] Running daily upstream DNS pull & rank (schedule: "${upstreamSchedule}", tz: "${upstreamTz}")...`);
      import("./upstream-manager.js").then(({ syncAndRankUpstreams }) => {
        syncAndRankUpstreams(env, worker, { forcePull: true }).catch((err) => {
          logger.error("[cron] Daily upstream sync failed:", err.message);
        });
      }).catch((err) => logger.error("[cron] Daily upstream sync error:", err));
    },
    { timezone: upstreamTz }
  );

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

  logger.info(`[cron] scheduled: "${schedule}" + daily upstream: "${upstreamSchedule}" (${upstreamTz}) + 30s cleaning rotation & memory guard`);

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
