// @ts-nocheck
// CWORKER/src/index.js
// Standalone Cloudflare Worker entrypoint for AmarDNS Edge Security Resolver.

import { RulesEngine } from './dns/rules.js';
import { EdgeCache } from './dns/cache.js';
import { StorageManager } from './storage/store.js';
import { UpstreamResolver } from './dns/resolver.js';
import { AppRouter } from './api/router.js';

let globalContext = null;

function getOrCreateContext(env, ctx = null) {
  if (!globalContext) {
    const rules = new RulesEngine();
    rules.initDefaults();

    const cache = new EdgeCache(env);
    const store = new StorageManager(env);
    const resolver = new UpstreamResolver(env);

    const appContext = {
      rules,
      cache,
      store,
      resolver
    };

    const router = new AppRouter(appContext);
    globalContext = { ...appContext, router };

    // Initial warm-up tasks (non-blocking background initialization)
    const initTasks = async () => {
      try {
        await store.initDb();
        const loadedRules = await store.loadCustomRules();
        if (Array.isArray(loadedRules)) {
          for (const r of loadedRules) {
            rules.addRule(r.domain, r.type, r.isWildcard);
          }
        }
      } catch (e) {}

      // Autonomous threat feed and whitelist Bloom filter sync
      try {
        await rules.syncFeeds(store);
      } catch (e) {}

      // Autonomous background upstream probing & ranking
      try {
        await resolver.syncAndRank();
      } catch (e) {}
    };

    if (ctx && typeof ctx.waitUntil === 'function') {
      ctx.waitUntil(initTasks());
    } else {
      initTasks().catch(() => {});
    }
  }
  return globalContext;
}

export default {
  /**
   * Main HTTP Fetch Handler
   */
  async fetch(request, env, ctx) {
    try {
      const context = getOrCreateContext(env, ctx);
      return await context.router.handle(request, env, ctx);
    } catch (err) {
      return new Response(JSON.stringify({
        error: 'Internal Server Error',
        message: err.message,
        timestamp: Date.now()
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },

  /**
   * Scheduled Cron Handler (Runs at 00:00 UTC daily)
   */
  async scheduled(event, env, ctx) {
    const context = getOrCreateContext(env, ctx);
    ctx.waitUntil((async () => {
      try {
        context.cache.flush();

        const rules = await context.store.loadCustomRules();
        if (Array.isArray(rules)) {
          for (const r of rules) {
            context.rules.addRule(r.domain, r.type, r.isWildcard);
          }
        }

        await context.rules.syncFeeds(context.store);
        await context.resolver.syncAndRank();
      } catch (e) {
        // Scheduled task failure recovery
      }
    })());
  }
};
