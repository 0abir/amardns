// CWORKER/src/api/router.js
// Main HTTP router handling DoH (RFC 8484 / JSON), REST API endpoints, and Dashboard UI.
// All application configuration, keys, and quotas are canonical and hardcoded via CONFIG.

import { parseDnsQuery, buildBlockedResponse, buildServFailResponse, wireToDohJson, qtypeToNumber, qtypeToString } from '../dns/codec.js';
import { renderDashboardHtml, renderLoginHtml } from '../ui/dashboard.js';
import { CONFIG } from '../config.js';

export class AppRouter {
  constructor(appContext) {
    this.ctx = appContext;
    this.totalQueries = 0;
    this.blockedQueries = 0;
  }

  async handle(request, env, executionCtx) {
    // Dynamic binding sync: auto-detect any newly attached KV/D1/R2 on every invocation
    if (this.ctx && this.ctx.store && env) {
      this.ctx.store.updateEnv(env);
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // 1. CORS Preflight
    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, DELETE',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key, accept',
          'Access-Control-Max-Age': '86400'
        }
      });
    }

    // 2. Health check
    if (path === '/health') {
      return new Response(JSON.stringify({
        ok: true,
        status: 'healthy',
        storage: this.ctx.store.getStorageInfo(),
        colo: request.cf?.colo || 'edge',
        timestamp: Date.now()
      }), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    // 3. DoH RFC 8484 wireformat endpoint: /dns-query
    if (path === '/dns-query') {
      return await this.handleDohWire(request, env, executionCtx);
    }

    // 4. DoH JSON format endpoint: /resolve
    if (path === '/resolve') {
      return await this.handleDohJson(request, env, executionCtx);
    }

    // 5. REST API: /api/status
    if (path === '/api/status') {
      return this.handleApiStatus(request, env);
    }

    // 6. REST API: /api/rules
    if (path === '/api/rules') {
      return await this.handleApiRules(request, env);
    }

    // 7. REST API: /api/logs
    if (path === '/api/logs') {
      if (method === 'DELETE' || url.searchParams.get('action') === 'clear') {
        if (!this.checkAuth(request, env)) {
          return new Response(JSON.stringify({ error: 'Unauthorized: Master Key Required' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
          });
        }
        this.ctx.store.clearLogs();
        return new Response(JSON.stringify({ ok: true, message: 'Logs cleared' }), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      }

      const status = url.searchParams.get('status');
      const qtype = url.searchParams.get('qtype');
      const search = url.searchParams.get('search');
      const logs = this.ctx.store.getLogs({ status, qtype, search });

      return new Response(JSON.stringify(logs), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    // 8. REST API: /api/flush
    if (path === '/api/flush' && method === 'POST') {
      if (!this.checkAuth(request, env)) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
      }
      this.ctx.cache.flush();
      return new Response(JSON.stringify({ ok: true, message: 'Cache flushed' }), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    // 9. REST API: /api/upstreams/rank
    if (path === '/api/upstreams/rank' || path === '/api/upstreams/sync') {
      if (!this.checkAuth(request, env)) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
      }
      const res = await this.ctx.resolver.syncAndRank();
      return new Response(JSON.stringify({ ok: true, result: res, upstreams: this.ctx.resolver.getTelemetry() }), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    // 10. REST API: /api/feeds/sync
    if (path === '/api/feeds/sync') {
      if (!this.checkAuth(request, env)) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
      }
      const res = await this.ctx.rules.syncFeeds(this.ctx.store);
      return new Response(JSON.stringify({ ok: true, result: res, stats: this.ctx.rules.getStats() }), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    // 11. Dashboard UI / Auth Gate
    const masterKey = CONFIG.DNS_MASTER_KEY;
    const isDashboardPath = path === '/' || path === '/dashboard' || (masterKey && path === `/${masterKey}`);

    if (isDashboardPath) {
      const isAuthenticated = this.checkAuth(request, env);

      if (!isAuthenticated) {
        const loginHtml = renderLoginHtml(CONFIG.APP_NAME);
        return new Response(loginHtml, {
          status: 401,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-cache'
          }
        });
      }

      const stats = this.getStats();
      const quota = this.ctx.store.quota.getUsage();
      const storage = this.ctx.store.getStorageInfo();
      const upstreams = this.ctx.resolver.getTelemetry();
      const rules = Array.from(this.ctx.rules.customRules.values());
      const logs = this.ctx.store.getLogs();

      const html = renderDashboardHtml({
        appName: CONFIG.APP_NAME,
        masterKey,
        stats,
        quota,
        storage,
        upstreams,
        rules,
        logs
      });

      const headers = new Headers({
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-cache'
      });

      // Set auth cookie if ?key= was provided in URL
      const urlKey = url.searchParams.get('key');
      if (urlKey === masterKey) {
        headers.set('Set-Cookie', `amardns_auth=${encodeURIComponent(masterKey)}; Path=/; Max-Age=2592000; SameSite=Strict`);
      }

      return new Response(html, { status: 200, headers });
    }

    return new Response('Not Found', {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  async handleDohWire(request, env, executionCtx) {
    this.totalQueries++;
    const t0 = Date.now();
    let wireBuffer;

    try {
      if (request.method === 'GET') {
        const url = new URL(request.url);
        const dnsParam = url.searchParams.get('dns');
        if (!dnsParam) {
          return new Response('Missing ?dns= parameter', { status: 400 });
        }
        const base64 = dnsParam.replace(/-/g, '+').replace(/_/g, '/');
        const binaryStr = atob(base64);
        wireBuffer = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) {
          wireBuffer[i] = binaryStr.charCodeAt(i);
        }
      } else if (request.method === 'POST') {
        const ab = await request.arrayBuffer();
        wireBuffer = new Uint8Array(ab);
      } else {
        return new Response('Method Not Allowed', { status: 405 });
      }

      const query = parseDnsQuery(wireBuffer);
      const ruleResult = this.ctx.rules.evaluate(query.domain);

      // 1. Threat Blocking
      if (ruleResult.action === 'BLOCK') {
        this.blockedQueries++;
        const blockAction = CONFIG.BLOCK_ACTION || 'ZERO_IP';
        const blockedPacket = buildBlockedResponse(query, blockAction);

        this.ctx.store.recordQueryLog({
          domain: query.domain,
          qtype: qtypeToString(query.qtype),
          clientIp: request.headers.get('cf-connecting-ip') || 'anonymous',
          status: 'BLOCKED',
          reason: ruleResult.reason,
          latencyMs: Date.now() - t0,
          timestamp: Date.now()
        }, executionCtx);

        return new Response(blockedPacket, {
          headers: {
            'Content-Type': 'application/dns-message',
            'Cache-Control': 'public, max-age=300',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      // 2. Cache Lookup
      const cacheKey = `wire:${query.domain}:${query.qtype}`;
      const cached = await this.ctx.cache.get(cacheKey, request);
      if (cached && cached.data instanceof Uint8Array) {
        const resBuf = new Uint8Array(cached.data);
        new DataView(resBuf.buffer).setUint16(0, query.id);

        this.ctx.store.recordQueryLog({
          domain: query.domain,
          qtype: qtypeToString(query.qtype),
          clientIp: request.headers.get('cf-connecting-ip') || 'anonymous',
          status: 'ALLOWED',
          reason: 'cache_hit',
          latencyMs: Date.now() - t0,
          timestamp: Date.now()
        }, executionCtx);

        return new Response(resBuf, {
          headers: {
            'Content-Type': 'application/dns-message',
            'Cache-Control': `public, max-age=${cached.ttl}`,
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      // 3. Upstream Resolution
      const upstreamRes = await this.ctx.resolver.resolveWire(wireBuffer, query.domain, query.qtype);

      await this.ctx.cache.put(cacheKey, upstreamRes.raw, 300, request, executionCtx);

      this.ctx.store.recordQueryLog({
        domain: query.domain,
        qtype: qtypeToString(query.qtype),
        clientIp: request.headers.get('cf-connecting-ip') || 'anonymous',
        status: 'ALLOWED',
        reason: `upstream:${upstreamRes.provider}`,
        latencyMs: Date.now() - t0,
        timestamp: Date.now()
      }, executionCtx);

      return new Response(upstreamRes.raw, {
        headers: {
          'Content-Type': 'application/dns-message',
          'Cache-Control': 'public, max-age=300',
          'Access-Control-Allow-Origin': '*'
        }
      });
    } catch (err) {
      const servfail = buildServFailResponse(0);
      return new Response(servfail, {
        status: 200,
        headers: { 'Content-Type': 'application/dns-message', 'Access-Control-Allow-Origin': '*' }
      });
    }
  }

  async handleDohJson(request, env, executionCtx) {
    this.totalQueries++;
    const t0 = Date.now();
    const url = new URL(request.url);
    const domain = (url.searchParams.get('name') || '').trim();
    const typeParam = url.searchParams.get('type') || '1';
    const qtype = qtypeToNumber(typeParam);

    if (!domain) {
      return new Response(JSON.stringify({ Status: 2, Comment: 'Missing ?name= parameter' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    const ruleResult = this.ctx.rules.evaluate(domain);

    // 1. Threat Blocking
    if (ruleResult.action === 'BLOCK') {
      this.blockedQueries++;
      const isA = qtype === 1;
      const isAAAA = qtype === 28;

      const answer = (isA || isAAAA) ? [{
        name: `${domain.replace(/\.+$/, '')}.`,
        type: qtype,
        TTL: 300,
        data: isA ? '0.0.0.0' : '::'
      }] : undefined;

      const blockedJson = {
        Status: CONFIG.BLOCK_ACTION === 'NXDOMAIN' ? 3 : 0,
        TC: false,
        RD: true,
        RA: true,
        AD: false,
        CD: false,
        Question: [{ name: `${domain.replace(/\.+$/, '')}.`, type: qtype }],
        Answer: answer,
        Comment: `Blocked by rule: ${ruleResult.reason}`
      };

      this.ctx.store.recordQueryLog({
        domain,
        qtype: qtypeToString(qtype),
        clientIp: request.headers.get('cf-connecting-ip') || 'anonymous',
        status: 'BLOCKED',
        reason: ruleResult.reason,
        latencyMs: Date.now() - t0,
        timestamp: Date.now()
      }, executionCtx);

      return new Response(JSON.stringify(blockedJson), {
        headers: {
          'Content-Type': 'application/dns-json',
          'Cache-Control': 'public, max-age=300',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    // 2. Cache Lookup
    const cacheKey = `json:${domain}:${qtype}`;
    const cached = await this.ctx.cache.get(cacheKey, request);
    if (cached && typeof cached.data === 'object') {
      this.ctx.store.recordQueryLog({
        domain,
        qtype: qtypeToString(qtype),
        clientIp: request.headers.get('cf-connecting-ip') || 'anonymous',
        status: 'ALLOWED',
        reason: 'cache_hit',
        latencyMs: Date.now() - t0,
        timestamp: Date.now()
      }, executionCtx);

      return new Response(JSON.stringify(cached.data), {
        headers: {
          'Content-Type': 'application/dns-json',
          'Cache-Control': `public, max-age=${cached.ttl}`,
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    // 3. Upstream Query
    try {
      const syntheticQuery = parseDnsQuery(this.createSyntheticWireQuery(domain, qtype));
      const upstreamRes = await this.ctx.resolver.resolveWire(syntheticQuery.raw, domain, qtype);
      const jsonRes = wireToDohJson(upstreamRes.raw);

      await this.ctx.cache.put(cacheKey, jsonRes, 300, request, executionCtx);

      this.ctx.store.recordQueryLog({
        domain,
        qtype: qtypeToString(qtype),
        clientIp: request.headers.get('cf-connecting-ip') || 'anonymous',
        status: 'ALLOWED',
        reason: `upstream:${upstreamRes.provider}`,
        latencyMs: Date.now() - t0,
        timestamp: Date.now()
      }, executionCtx);

      return new Response(JSON.stringify(jsonRes), {
        headers: {
          'Content-Type': 'application/dns-json',
          'Cache-Control': 'public, max-age=300',
          'Access-Control-Allow-Origin': '*'
        }
      });
    } catch (err) {
      return new Response(JSON.stringify({
        Status: 2,
        Comment: `Resolution error: ${err.message}`
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/dns-json', 'Access-Control-Allow-Origin': '*' }
      });
    }
  }

  createSyntheticWireQuery(domain, qtype) {
    const labels = domain.replace(/\.+$/, '').split('.');
    let length = 12;
    for (const label of labels) {
      length += 1 + new TextEncoder().encode(label).length;
    }
    length += 1 + 4; // root null byte + QTYPE (2) + QCLASS (2)

    const out = new Uint8Array(length);
    const view = new DataView(out.buffer);

    const qid = (Math.random() * 0xffff) >>> 0;
    view.setUint16(0, qid);
    view.setUint16(2, 0x0100); // Standard query with RD=1
    view.setUint16(4, 1);      // QDCOUNT=1

    let offset = 12;
    const encoder = new TextEncoder();
    for (const label of labels) {
      const encoded = encoder.encode(label);
      out[offset++] = encoded.length;
      out.set(encoded, offset);
      offset += encoded.length;
    }
    out[offset++] = 0; // null root

    view.setUint16(offset, qtype);
    view.setUint16(offset + 2, 1); // IN class

    return out;
  }

  handleApiStatus(request, env) {
    return new Response(JSON.stringify({
      appName: CONFIG.APP_NAME,
      stats: this.getStats(),
      quota: this.ctx.store.quota.getUsage(),
      storage: this.ctx.store.getStorageInfo(),
      upstreams: this.ctx.resolver.getTelemetry(),
      rules: this.ctx.rules.getStats(),
      customRules: Array.from(this.ctx.rules.customRules.values())
    }), {
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }

  async handleApiRules(request, env) {
    if (!this.checkAuth(request, env)) {
      return new Response(JSON.stringify({ error: 'Unauthorized: Master Key Required' }), { status: 401 });
    }

    if (request.method === 'GET') {
      return new Response(JSON.stringify(Array.from(this.ctx.rules.customRules.values())), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    if (request.method === 'POST') {
      const body = await request.json();
      const { domain, type, isWildcard } = body;
      if (!domain || !type) {
        return new Response(JSON.stringify({ error: 'Missing domain or type' }), { status: 400 });
      }

      this.ctx.rules.addRule(domain, type, Boolean(isWildcard));
      await this.ctx.store.saveRule({ domain, type, isWildcard: Boolean(isWildcard), createdAt: Date.now() });

      return new Response(JSON.stringify({ ok: true, message: 'Rule saved' }), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    if (request.method === 'DELETE') {
      const url = new URL(request.url);
      const domain = url.searchParams.get('domain');
      if (!domain) {
        return new Response(JSON.stringify({ error: 'Missing ?domain= parameter' }), { status: 400 });
      }

      this.ctx.rules.removeRule(domain);
      await this.ctx.store.deleteRule(domain);

      return new Response(JSON.stringify({ ok: true, message: 'Rule deleted' }), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    return new Response('Method Not Allowed', { status: 405 });
  }

  checkAuth(request, env) {
    const masterKey = CONFIG.DNS_MASTER_KEY;
    if (!masterKey) return true;

    // 1. Check Authorization Bearer Header
    const authHeader = request.headers.get('authorization') || '';
    const token = authHeader.replace(/^Bearer\s+/i, '').trim();
    if (token === masterKey) return true;

    // 2. Check x-api-key or x-master-key Header
    const apiKeyHeader = request.headers.get('x-api-key') || request.headers.get('x-master-key') || '';
    if (apiKeyHeader === masterKey) return true;

    // 3. Check Cookie: amardns_auth=<masterKey>
    const cookieHeader = request.headers.get('cookie') || '';
    const match = cookieHeader.match(/amardns_auth=([^;]+)/);
    if (match && decodeURIComponent(match[1]) === masterKey) return true;

    // 4. Check Query Parameter: ?key=... or ?master_key=...
    const url = new URL(request.url);
    const keyParam = url.searchParams.get('key') || url.searchParams.get('master_key') || '';
    if (keyParam === masterKey) return true;

    // 5. Check Path Prefix: /<masterKey> or /<masterKey>/dashboard
    const cleanPath = url.pathname.replace(/^\/+|\/+$/g, '');
    if (cleanPath === masterKey || cleanPath === `${masterKey}/dashboard`) return true;

    return false;
  }

  getStats() {
    const cacheStats = this.ctx.cache.getStats();
    const blockRate = this.totalQueries > 0 ? ((this.blockedQueries / this.totalQueries) * 100).toFixed(1) + '%' : '0.0%';
    const ruleStats = this.ctx.rules.getStats();

    return {
      totalQueries: this.totalQueries,
      blockedQueries: this.blockedQueries,
      blockRate,
      cacheHitRate: cacheStats.hitRate,
      cacheHits: cacheStats.hits,
      cacheMisses: cacheStats.misses,
      rulesCount: ruleStats.customRulesCount,
      customRulesCount: ruleStats.customRulesCount,
      customBlockCount: ruleStats.customBlockCount,
      customAllowCount: ruleStats.customAllowCount,
      threatBloomCount: ruleStats.threatBloomCount,
      threatFeedEntries: ruleStats.threatFeedEntries,
      whitelistCount: ruleStats.whitelistCount,
      totalProtectedDomains: ruleStats.totalProtectedDomains,
      syncStatus: ruleStats.syncStatus,
      lastSyncTime: ruleStats.lastSyncTime,
      bloomFilter: ruleStats.bloomFilter
    };
  }
}
