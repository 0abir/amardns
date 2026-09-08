// src/core/threat-intelligence.js
// Threat feeds sync, Safe Browsing, lookalike brand spoofing, DGA scoring, behavioral heuristics, and list management.

import {
  VERSION, FEED_CACHE_TTL, FEED_CACHE_MAX, FEED_SYNC_INTERVAL, FEED_RETRY_INTERVAL,
  ABIR_FEED, ABIR_TOTAL_URL, COMMON_FEED, COMMON_TOTAL_URL, AUTO_BLOCK_TTL,
  AUTO_BLOCK_MAX, DGA_MIN_LEN, DGA_FLAG_SCORE, DGA_BLOCK_SCORE, DGA_SKIP_TLDS,
  PRIVATE_SUFFIXES, REBIND_PRIVATE, XV_PENALTY, TTL_DEVIATE_RATIO,
  TTL_DEFLATE_RATIO, TTL_PENALTY, BURST_WINDOW_MS, BURST_THRESHOLD,
  CB_WINDOW, CB_THRESHOLD, _BG_SET2, _RE_VOWELS, _RE_DIGITS, _RE_CONSONANT_RUN,
  GSB_CACHE_MAX
} from "./constants.js";
import {
  _feedCache, SAFE_BROWSING_KEYS, BRANDS_LIST,
  _autoBlocks, _burstMap, _fpMap, _answerHistory, _sh, _anomalies,
  _bgEnqueue, _env, _memBlacklist,
  _memWhitelist, _memCommon, _cb, _dnsMode, _setDnsMode,
  _blockingEnabled, _setBlockingEnabled, getBlockingEnabled,
  _dgaLegit, _markov, _domainIQ, _rhythm, _obs, _budgetAI, _runtimeConfig,
  _listsPreloaded, setListsPreloaded } from "./state.js";
import { _log, _action, _aiDecision, _getRps } from "./telemetry.js";
import { deLeet, _getCandidates } from "./neural-math.js";
import { aeroGet, aeroPut, _feedCacheGet, _feedCacheSet, _pulseThrottle, _pulseW } from "./storage-adapter.js";
import { BloomFilter } from "./bloom-filter.js";
import { NOT_BLOCKED } from "../storage/pulse-db.js";

export let _feedSyncing = false;
export let _feedLastSync = 0;
export let _abirTotalEntries = 500000;
export let _commonTotalEntries = 3000;
export let _abirLastSync = 0;
export let _commonLastSync = 0;
export let _abirSet = new BloomFilter(Math.ceil(_abirTotalEntries * 1.1));
export let _commonSet = new BloomFilter(Math.ceil(_commonTotalEntries * 1.1));
export let _whitelistExact = new Set();
export let _whitelistWildcards = new Set();
export let _abirOk = true;
export let _commonOk = true;

// Known legitimate root domains of major tech, cloud, CDN, and finance services.
// Subdomains and compound services of these domains are 100% immune to lookalike false positives.
export const KNOWN_LEGIT_DOMAINS = new Set([
  // Google
  "google.com", "googlesource.com", "googleapis.com", "googleusercontent.com",
  "googlevideo.com", "googleblog.com", "googlecode.com", "googlecommerce.com",
  "googleplay.com", "gstatic.com", "ggpht.com", "g.co", "goo.gl", "android.com",
  "chromium.org", "youtube.com", "ytimg.com", "youtu.be", "gmail.com",
  // Apple
  "apple.com", "icloud.com", "mzstatic.com", "aaplimg.com", "apple-dns.net",
  "apple-mapkit.com", "cdn-apple.com", "apple-cloudkit.com", "apple-livephotoskit.com",
  // Microsoft
  "microsoft.com", "live.com", "office.com", "office365.com", "windows.com",
  "microsoftonline.com", "msftconnecttest.com", "azure.com", "azureedge.net",
  "skype.com", "bing.com", "msn.com", "xbox.com", "github.com", "githubassets.com",
  "githubusercontent.com", "github.io",
  // Amazon
  "amazon.com", "amazonaws.com", "media-amazon.com", "primevideo.com", "a2z.com",
  "amazonpay.com", "cloudfront.net",
  // Meta
  "facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com", "whatsapp.com",
  "whatsapp.net", "meta.com",
  // Other major tech, finance, CDN & information
  "twitter.com", "x.com", "twimg.com", "netflix.com", "nflxvideo.net", "nflximg.net",
  "paypal.com", "paypalobjects.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
  "citibank.com", "citi.com", "coinbase.com", "binance.com", "openai.com", "anthropic.com",
  "cloudflare.com", "cloudflare-dns.com", "akamai.net", "akamaized.net", "fastly.net",
  "wikipedia.org", "wikimedia.org"
]);

export function isKnownLegitDomain(domain) {
  if (!domain) return false;
  let d = domain.toLowerCase();
  if (d.endsWith(".")) d = d.slice(0, -1);
  if (KNOWN_LEGIT_DOMAINS.has(d)) return true;
  for (const root of KNOWN_LEGIT_DOMAINS) {
    if (d.endsWith("." + root)) return true;
  }
  return false;
}

export async function syncThreatFeeds(force = false, env = null, options = {}) {
  const now = Date.now();
  const anyDue =
    force ||
    now - _abirLastSync > (_abirOk ? FEED_SYNC_INTERVAL : FEED_RETRY_INTERVAL) ||
    now - _commonLastSync > (_commonOk ? FEED_SYNC_INTERVAL : FEED_RETRY_INTERVAL);
  if (!anyDue) return;
  if (_feedSyncing) return;
  _feedSyncing = true;
  _feedLastSync = now;
  const timeoutMs = options.timeoutMs || 25000;

  function _normalizeBlocklistLine(raw) {
    let h = raw.trim().toLowerCase();
    if (!h) return null;
    const c = h[0];
    if (c === "#" || c === "!" || c === "@" || c === ";" || c === "/")
      return null;
    if (h.startsWith("@@")) return null;
    if (h.startsWith("[") || h.startsWith("$")) return null;
    if (h.startsWith("||")) h = h.slice(2);
    if (h.startsWith("|")) h = h.slice(1);
    if (h.startsWith("*.")) h = h.slice(2);
    if (h.startsWith("*")) h = h.slice(1);
    const dollarIdx = h.indexOf("$");
    if (dollarIdx > 0) h = h.slice(0, dollarIdx);
    if (h.endsWith("^")) h = h.slice(0, -1);
    if (h.startsWith("local=/")) h = h.slice(7);
    if (h.endsWith("/")) h = h.slice(0, -1);
    const spaceIdx = h.search(/\s/);
    if (spaceIdx > 0) {
      const ip = h.slice(0, spaceIdx);
      if (ip === "0.0.0.0" || ip === "127.0.0.1" || ip === "::1" || ip === "::")
        h = h.slice(spaceIdx).trim();
      else return null;
    }
    if (h.endsWith(".")) h = h.slice(0, -1);
    h = h.trim();
    if (
      !h ||
      !h.includes(".") ||
      h.includes(" ") ||
      h.includes("/") ||
      h.startsWith("-") ||
      h.length > 253
    )
      return null;
    if (/[^a-z0-9.*\-_]/.test(h)) return null;
    return h;
  }

  // Streaming blocklist: reads 64KB network chunks directly into 1.1MB BloomFilter
  // Yields event loop periodically so DNS resolution never lags
  async function streamBlocklist(url, capacity, timeout) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeout);
    try {
      const res = await fetch(url, { signal: ctrl.signal });
      clearTimeout(t);
      if (!res.ok) throw new Error("HTTP " + res.status);
      const filter = new BloomFilter(Math.ceil(capacity * 1.25));
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let residue = "";
      let totalProcessed = 0;
      let yieldCounter = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = residue + decoder.decode(value, { stream: true });
        const lines = chunk.split("\n");
        residue = lines.pop();
        for (let i = 0, n = lines.length; i < n; i++) {
          const d = _normalizeBlocklistLine(lines[i]);
          if (d) {
            filter.add(d);
            totalProcessed++;
            yieldCounter++;
            if (yieldCounter >= 15000) {
              yieldCounter = 0;
              await new Promise((r) => setImmediate(r));
            }
          }
        }
        if (totalProcessed > 1e6) break;
      }
      if (residue) {
        const d = _normalizeBlocklistLine(residue);
        if (d) filter.add(d);
      }
      return filter;
    } finally {
      clearTimeout(t);
    }
  }

  // Lightweight whitelist: parses exact & wildcard rules into memory sets (< 150KB)
  async function fetchWhitelistFeed(url, timeout) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeout);
    try {
      const res = await fetch(url, { signal: ctrl.signal });
      clearTimeout(t);
      if (!res.ok) throw new Error("HTTP " + res.status);
      const text = await res.text();
      const lines = text.split("\n");
      const exact = new Set();
      const wild = new Set();
      const filter = new BloomFilter(Math.ceil(lines.length * 1.5));
      for (let i = 0; i < lines.length; i++) {
        let line = lines[i].trim().toLowerCase();
        if (!line || line.startsWith("#") || line.startsWith("!")) continue;
        let isWild = false;
        if (line.startsWith("*.")) {
          isWild = true;
          line = line.slice(2);
        } else if (line.startsWith("*")) {
          isWild = true;
          line = line.slice(1);
        }
        if (!line || !line.includes(".") || line.startsWith("-")) continue;
        if (isWild) {
          wild.add(line);
        } else {
          exact.add(line);
        }
        filter.add(line);
      }
      return { exact, wild, filter };
    } finally {
      clearTimeout(t);
    }
  }

  try {
    const [rTotal, rCommonTotal] = await Promise.allSettled([
      fetch(ABIR_TOTAL_URL, { signal: AbortSignal.timeout(timeoutMs) }).then(async (r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        const txt = (await r.text()).trim();
        const n = parseInt(txt.replace(/_/g, ""), 10);
        if (!isNaN(n) && n > 0) {
          _abirTotalEntries = n;
          _log("abir_total_fetched", { total: n });
        }
      }),
      fetch(COMMON_TOTAL_URL, { signal: AbortSignal.timeout(timeoutMs) }).then(async (r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        const txt = (await r.text()).trim();
        const n = parseInt(txt.replace(/_/g, ""), 10);
        if (!isNaN(n) && n > 0) {
          _commonTotalEntries = n;
          _log("common_total_fetched", { total: n });
        }
      }),
    ]);
    if (rTotal.status === "rejected") {
      _log("abir_total_fail", {
        err: rTotal.reason?.message || String(rTotal.reason),
      });
    }
    if (rCommonTotal.status === "rejected") {
      _log("common_total_fail", {
        err: rCommonTotal.reason?.message || String(rCommonTotal.reason),
      });
    }

    const [rAbir, rCommon] = await Promise.allSettled([
      (async () => {
        _abirLastSync = now;
        const capacity = _abirTotalEntries || 5e5;
        const filter = await streamBlocklist(ABIR_FEED, capacity, timeoutMs);
        if (filter.size > 0) {
          _abirSet = filter;
          _abirOk = true;
        }
        _log("abir_sync", { domains: filter.size });
      })(),
      (async () => {
        _commonLastSync = now;
        const result = await fetchWhitelistFeed(COMMON_FEED, timeoutMs);
        if (result.exact.size > 0 || result.wild.size > 0) {
          _whitelistExact = result.exact;
          _whitelistWildcards = result.wild;
          _commonSet = result.filter;
          _commonOk = true;
        }
        _log("common_sync", { exact: result.exact.size, wildcards: result.wild.size });
      })(),
    ]);

    if (rAbir.status === "rejected") {
      _abirOk = false;
      _log("abir_sync_fail", {
        err: rAbir.reason?.message || String(rAbir.reason),
      });
    }
    if (rCommon.status === "rejected") {
      _commonOk = false;
      _log("common_sync_fail", {
        err: rCommon.reason?.message || String(rCommon.reason),
      });
    }
    _feedCache.clear();
  } finally {
    _feedSyncing = false;
  }
}
export async function checkThreatFeeds(domain) {
  if (!domain) return { blocked: false, isCommon: false };
  const cleanDomain = domain
    .replace(/^https?:\/\//, "")
    .replace(/\.$/, "")
    .toLowerCase()
    .split("/")[0];
  if (!cleanDomain) return { blocked: false, isCommon: false };
  const cached = _feedCacheGet(cleanDomain);
  if (cached) return cached;
  const candidates = _getCandidates(cleanDomain);
  const _bfCandidates = candidates.filter((c) => !c.startsWith("*"));
  let abirHit = false;
  const abirOk = _abirOk && _abirSet.size > 0;
  if (abirOk) {
    for (const c of _bfCandidates) {
      if (_abirSet.has(c)) { abirHit = true; break; }
    }
  }

  let commonHit = false;
  const commonOk = _commonOk && _commonSet.size > 0;
  if (commonOk) {
    for (const c of _bfCandidates) {
      if (_commonSet.has(c)) { commonHit = true; break; }
    }
  }

  let gsb = { hit: false, ok: false, matches: undefined };
  if (SAFE_BROWSING_KEYS.length) {
    try {
      const r = await checkGoogleSafeBrowsing(cleanDomain);
      gsb = {
        hit: !r.apiFailure && r.threat,
        ok: !r.apiFailure,
        matches: r.matches,
      };
    } catch (_) {}
  }

  const blockedBy = [abirHit ? "abir" : null, gsb.hit ? "gsb" : null].filter(
    Boolean,
  );
  if (blockedBy.length > 0) {
    const source = blockedBy.join("+");
    const r = {
      blocked: true,
      isCommon: false,
      source: source,
      tier: 1,
      abir: abirHit,
      gsb: gsb.hit,
      gsbMatches: gsb.matches,
    };
    _feedCacheSet(cleanDomain, true, source);
    return r;
  }
  const isCommon = commonHit;
  const feedsChecked = [
    abirOk ? "abir" : null,
    gsb.ok ? "gsb" : null,
    commonOk ? "common" : null,
  ].filter(Boolean);
  if (feedsChecked.length > 0) {
    const src = feedsChecked.join("+");
    const res = { blocked: false, isCommon: isCommon, source: src, tier: 1 };
    _feedCacheSet(cleanDomain, false, src);
    return res;
  }
  const { nnThreatScore } = await import("./neural-engine.js");
  const { score: nnScore, reason: nnReason } = nnThreatScore(
    cleanDomain,
    null,
    0,
    _domainIQ.riskScore(cleanDomain),
    _markov.predict(cleanDomain) ? 1 : 0,
    false,
  );
  const hScore = dgaScore(cleanDomain);
  const aiBlocked = nnScore >= DGA_BLOCK_SCORE && hScore >= DGA_BLOCK_SCORE;
  const r = {
    blocked: aiBlocked,
    isCommon: false,
    source: "ai_fallback",
    tier: 2,
    nnScore: nnScore,
    nnReason: nnReason,
    hScore: hScore,
  };
  _feedCacheSet(cleanDomain, aiBlocked, "ai_fallback");
  return r;
}
const AERO_CHUNK_BYTES = 1e4;
export const _gsbCache = new Map();

export function _gsbCacheGet(domain) {
  const entry = _gsbCache.get(domain);
  if (!entry) return null;
  if (Date.now() > entry.exp) {
    _gsbCache.delete(domain);
    return null;
  }
  return entry.val;
}
export function _gsbCachePut(domain, val, ttl) {
  _gsbCache.delete(domain);
  if (_gsbCache.size >= GSB_CACHE_MAX)
    _gsbCache.delete(_gsbCache.keys().next().value);
  _gsbCache.set(domain, { val: val, exp: Date.now() + ttl });
}
export async function checkGoogleSafeBrowsing(domain) {
  if (!SAFE_BROWSING_KEYS.length || !domain) return { threat: false };
  const cleanDomain = domain
    .replace(/^https?:\/\//, "")
    .replace(/\.$/, "")
    .toLowerCase()
    .split("/")[0];
  if (!cleanDomain) return { threat: false };
  const cached = _gsbCacheGet(cleanDomain);
  if (cached) return cached;
  let lastErr = null;
  for (const key of SAFE_BROWSING_KEYS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4e3);
    try {
      const url = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`;
      const req = {
        client: { clientId: "amar-dns", clientVersion: VERSION },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [
            { url: `http://${cleanDomain}/` },
            { url: `https://${cleanDomain}/` },
          ],
        },
      };
      const res = await fetch(url, {
        method: "POST",
        body: JSON.stringify(req),
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (res.status === 429 || res.status === 403) {
        lastErr = `Key ${key.slice(0, 6)}... failed with status ${res.status}`;
        continue;
      }
      if (!res.ok) {
        lastErr = `HTTP ${res.status}`;
        continue;
      }
      const data = await res.json();
      if (data.matches && data.matches.length > 0) {
        const result = { threat: true, matches: data.matches };
        _gsbCachePut(cleanDomain, result, GSB_CACHE_THREAT_TTL);
        return result;
      }
      const clean = { threat: false };
      _gsbCachePut(cleanDomain, clean, GSB_CACHE_CLEAN_TTL);
      return clean;
    } catch (e) {
      clearTimeout(timer);
      lastErr = e.name === "AbortError" ? "timeout" : e.message;
      continue;
    }
  }
  return { threat: false, apiFailure: true, error: lastErr };
}
export async function autoBlockSet(domain, reason, ttl = AUTO_BLOCK_TTL, isPeerSync = false) {
  const pdb = _env?.pulseDb;
  const db = pdb || _env?.PULSE_DB;
  const isSafe = isKnownLegitDomain(domain) || checkWhitelist(domain, db) || checkCommon(domain, db);
  if (isSafe) {
    _log("auto_block_skipped_safe", { domain: domain, reason: reason });
    return;
  }
  if (_autoBlocks.size >= AUTO_BLOCK_MAX) {
    const now = Date.now() / 1e3;
    for (const [k, v] of _autoBlocks) if (v.exp < now) _autoBlocks.delete(k);
    if (_autoBlocks.size >= AUTO_BLOCK_MAX) {
      const oldest = [..._autoBlocks.entries()].sort(
        (a, b) => a[1].exp - b[1].exp,
      )[0];
      if (oldest) _autoBlocks.delete(oldest[0]);
    }
  }
  const exp = Math.floor(Date.now() / 1e3) + ttl;
  _autoBlocks.set(domain, { exp: exp, reason: reason, auto: true, source: "ai", tag: "AI" });
  if (pdb && typeof pdb.addBlocklist === "function") {
    pdb.addBlocklist(domain, reason, "auto");
  }
  if (!isPeerSync && typeof process !== "undefined" && process.env?.FLY_APP_NAME) {
    const port = process.env.PORT || "8080";
    fetch(`http://${process.env.FLY_APP_NAME}.internal:${port}/api/auto-block`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "authorization": `Bearer ${_env?.DNS_MASTER_KEY || ""}`,
        "x-peer-sync": "1",
      },
      body: JSON.stringify({ domain, reason, ttl }),
    }).catch(() => {});
  }
  if (_env?.PULSE_DB && !_pulseThrottle && _budgetAI.canWrite(false)) {
    const domainSnap = domain,
      reasonSnap = reason,
      expSnap = exp;
    _bgEnqueue(async () => {
      if (_pulseThrottle || !_budgetAI.canWrite(false)) return;
      _pulseW++;
      _budgetAI.track();
      try {
        await _env.PULSE_DB
          .prepare(
            "INSERT OR REPLACE INTO pulse_autoblock(domain,reason,created_at,exp) VALUES(?,?,?,?)",
          )
          .bind(domainSnap, reasonSnap, Math.floor(Date.now() / 1e3), expSnap)
          .run();
      } catch (e) {
        _log("autoblock_db_error", { domain: domainSnap, err: e.message });
      }
    }, false);
  }
}
export function _levenshtein(s1, s2) {
  const m = s1.length,
    n = s2.length;
  let prev = new Uint16Array(n + 1);
  let curr = new Uint16Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      curr[j] =
        s1[i - 1] === s2[j - 1]
          ? prev[j - 1]
          : 1 + Math.min(prev[j - 1], prev[j], curr[j - 1]);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}
export function alikeDomainCheck(domain, db = null) {
  if (!domain) return { detected: false };
  let d = domain.toLowerCase();
  if (d.endsWith(".")) d = d.slice(0, -1);

  // 1. Mandatory Whitelist & Known Legit Domains immunity
  if (isKnownLegitDomain(d)) return { detected: false };
  const pdb = _env?.pulseDb || db;
  if (checkWhitelist(d, pdb)) return { detected: false };

  const parts = d.split(".");
  if (parts.length < 2) return { detected: false };
  const label = parts[parts.length - 2];

  // 2. Homoglyph Script Mixing Check (e.g. Latin + Cyrillic/Greek in the same label)
  const hasLatin = /[a-z]/.test(label);
  const hasCyrillic = /[\u0400-\u04ff]/.test(label);
  const hasGreek = /[\u0370-\u03ff]/.test(label);
  if ((hasCyrillic || hasGreek) && hasLatin) {
    return { detected: true, reason: "script_mix_lookalike" };
  }

  const normalized = label.replace(/[^a-z0-9]/g, "");
  const deLeeted = deLeet(label).replace(/[^a-z0-9]/g, "");

  const PHISH_KEYWORDS = [
    "-login", "-signin", "-verify", "-verification", "-security", "-secure",
    "-account", "-billing", "-support", "-auth", "-portal", "-update"
  ];

  for (const brand of BRANDS_LIST) {
    // 3. Leet lookalike: exact brand matches when leet substitutions are reversed
    // e.g. "paypa1" -> deLeet is "paypal", but normalized is "paypa1"
    if (deLeeted === brand && normalized !== brand) {
      return { detected: true, reason: "typosquatting", brand: brand };
    }

    // 4. Typosquatting: edit distance of 1 on 2-level domains (e.g. paypall.com, gogle.com)
    if (parts.length <= 2 && Math.abs(normalized.length - brand.length) <= 1) {
      const dist = _levenshtein(normalized, brand);
      if (dist === 1 && normalized !== brand) {
        return { detected: true, reason: "typosquatting", brand: brand };
      }
    }

    // 5. De-leeted typosquatting
    if (parts.length <= 2 && Math.abs(deLeeted.length - brand.length) <= 1 && normalized !== deLeeted) {
      const dist = _levenshtein(deLeeted, brand);
      if (dist === 1 && deLeeted !== brand) {
        return { detected: true, reason: "typosquatting", brand: brand };
      }
    }

    // 6. Phishing compound domain with suspicious action keywords (e.g. paypal-login-verify.com)
    for (const kw of PHISH_KEYWORDS) {
      if (label.includes(brand + kw) || label.includes(kw.slice(1) + "-" + brand)) {
        return { detected: true, reason: "brand_impersonation", brand: brand };
      }
    }
  }

  return { detected: false };
}
export function dgaScore(domain) {
  if (!domain) return 0;
  if (isKnownLegitDomain(domain) || checkWhitelist(domain, _env?.pulseDb)) return 0;
  const parts = domain.split(".");
  if (parts.length < 2) return 100;
  const label = parts[parts.length - 2];
  const tld = parts[parts.length - 1];
  if (label.length < DGA_MIN_LEN || DGA_SKIP_TLDS.has(tld)) return 0;
  const candidates = _getCandidates(domain);
  for (const c of candidates) if (_dgaLegit.has(c)) return 0;
  const lbl = label.toLowerCase();
  let vowels = 0;
  let digitCount = 0;
  for (let i = 0; i < lbl.length; i++) {
    const code = lbl.charCodeAt(i);
    if (code >= 48 && code <= 57) digitCount++;
    else if (code === 97 || code === 101 || code === 105 || code === 111 || code === 117) vowels++;
  }
  const vowelRatio = vowels / lbl.length;
  if (lbl.length <= 7 && vowelRatio < 0.35) return 0;
  let score = 0;
  score += Math.min(20, digitCount * 6);
  let bgHits = 0,
    total = 0;
  for (let i = 0; i < lbl.length - 1; i++) {
    total++;
    if (_BG_SET2.has(lbl[i] + lbl[i + 1])) bgHits++;
  }
  const bigramRatio = total > 0 ? bgHits / total : 0;
  score += (1 - bigramRatio) * 35;
  const freq = {};
  for (const c of lbl) freq[c] = (freq[c] || 0) + 1;
  let entropy = 0;
  for (const c in freq) {
    const p = freq[c] / lbl.length;
    entropy -= p * Math.log2(p);
  }
  score += entropy > 4.2 ? 22 : entropy > 3.7 ? 10 : 0;
  score += vowelRatio < 0.12 ? 18 : vowelRatio < 0.22 ? 8 : 0;
  const consonantRuns = (lbl.match(_RE_CONSONANT_RUN) || []).length;
  score += consonantRuns * 10;
  const numericCluster = (lbl.match(/\d{4,}/g) || []).length;
  score += numericCluster * 12;
  const mixedLongPenalty = lbl.length > 20 && digitCount > 0 ? 10 : 0;
  score += mixedLongPenalty;
  return Math.min(100, Math.round(score));
}
export function rebindCheck(domain, ips) {
  if (!ips || ips.length === 0) return false;
  for (const suf of PRIVATE_SUFFIXES) if (domain.endsWith(suf)) return false;
  for (const ip of ips) {
    for (const pat of REBIND_PRIVATE) if (pat.test(ip)) return true;
  }
  return false;
}
export function qtypeAbuseCheck(qtype) {
  if (qtype === 255) {
    _sh.repBlocks++;
    return "ANY_ABUSE";
  }
  if (qtype === 252 || qtype === 251) {
    _sh.repBlocks++;
    return "ZONE_TRANSFER";
  }
  return null;
}
export const _ttlHistory = new Map();
const _TTL_HISTORY_MAX = 5e3;
export function ttlCheck(domain, ttl) {
  let rec = _ttlHistory.get(domain);
  if (!rec) {
    if (_ttlHistory.size >= _TTL_HISTORY_MAX)
      _ttlHistory.delete(_ttlHistory.keys().next().value);
    _ttlHistory.set(domain, { median: ttl, samples: 1, sum: ttl });
    return null;
  }
  if (rec.samples < 5) {
    rec.sum += ttl;
    rec.samples++;
    rec.median = rec.sum / rec.samples;
    return null;
  }
  rec.sum += ttl;
  rec.samples++;
  rec.median = rec.sum / rec.samples;
  if (ttl > rec.median * TTL_DEVIATE_RATIO) {
    _sh.ttlInflations++;
    return "TTL_INFLATION";
  }
  if (ttl < rec.median * TTL_DEFLATE_RATIO) {
    _sh.ttlDeflations++;
    return "TTL_DEFLATION";
  }
  return null;
}
const _ANSWER_HISTORY_MAX = 5e3;
export function answerDriftCheck(domain, ips) {
  if (!ips || ips.length === 0) return false;
  let prev = _answerHistory.get(domain);
  if (!prev) {
    if (_answerHistory.size >= _ANSWER_HISTORY_MAX)
      _answerHistory.delete(_answerHistory.keys().next().value);
    _answerHistory.set(domain, new Set(ips));
    return false;
  }
  const newIps = new Set(ips);
  let addedCount = 0,
    removedCount = 0;
  for (const ip of newIps) if (!prev.has(ip)) addedCount++;
  for (const ip of prev) if (!newIps.has(ip)) removedCount++;
  if (addedCount + removedCount > 2 && prev.size > 0) {
    _sh.answerDrifts++;
    for (const ip of ips) prev.add(ip);
    if (prev.size > 32) {
      const toRemove = [...prev].slice(0, prev.size - 16);
      toRemove.forEach((ip) => prev.delete(ip));
    }
    return true;
  }
  for (const ip of ips) prev.add(ip);
  return false;
}
const _BURST_MAP_MAX = 1e4;
const _FP_MAP_MAX = 5e3;
export function burstCheck(clientIp) {
  const now = Date.now();
  const win = _burstMap.get(clientIp);
  if (!win) {
    if (_burstMap.size >= _BURST_MAP_MAX)
      _burstMap.delete(_burstMap.keys().next().value);
    _burstMap.set(clientIp, { count: 1, start: now });
    return false;
  }
  if (now - win.start > BURST_WINDOW_MS) {
    win.count = 1;
    win.start = now;
    return false;
  }
  win.count++;
  if (win.count > _runtimeConfig.burstThreshold) {
    _sh.burstEvents++;
    _domainIQ.see(clientIp, "burst");
    return true;
  }
  return false;
}
const FP_SCAN_UNIQ = 30,
  FP_ENTROPY_THR = 3.8,
  FP_FLOOD_COUNT = 150;
export function fpCheck(clientIp, domain, rps) {
  let fp = _fpMap.get(clientIp);
  if (!fp) {
    if (_fpMap.size >= _FP_MAP_MAX) _fpMap.delete(_fpMap.keys().next().value);
    fp = {
      uniqDomains: new Set(),
      queries: 0,
      firstSeen: Date.now(),
      flagged: null,
    };
    _fpMap.set(clientIp, fp);
  }
  fp.queries++;
  fp.uniqDomains.add(domain);
  if (fp.uniqDomains.size > FP_SCAN_UNIQ && !fp.flagged) {
    fp.flagged = "DNS_SCAN";
    _sh.fpEvents++;
  } else if (fp.queries > FP_FLOOD_COUNT && !fp.flagged) {
    fp.flagged = "QUERY_STRESS";
    _sh.fpEvents++;
  }
  const freq = {};
  for (const c of domain) freq[c] = (freq[c] || 0) + 1;
  let entropy = 0;
  for (const c in freq) {
    const p = freq[c] / domain.length;
    entropy -= p * Math.log2(p);
  }
  if (entropy > FP_ENTROPY_THR && !fp.flagged && rps > 5) {
    fp.flagged = "DNS_TUNNEL_SUSPECT";
    _sh.fpEvents++;
  }
  return fp.flagged;
}
export const _swarmMap = new Map();
export function swarmCheck(domain, clientIp) {
  const clients = _swarmMap.get(domain) || new Set();
  clients.add(clientIp);
  _swarmMap.set(domain, clients);
  if (_swarmMap.size > 5e3) _swarmMap.delete(_swarmMap.keys().next().value);
  if (clients.size > 20) {
    _sh.swarmAlarms++;
    return true;
  }
  return false;
}
export const _clientNX = new Map();
const _CLIENT_NX_MAX = 8e3;
export function clientNxCheck(clientIp, rcode) {
  if (rcode !== 3) return false;
  let rec = _clientNX.get(clientIp);
  if (!rec) {
    if (_clientNX.size >= _CLIENT_NX_MAX)
      _clientNX.delete(_clientNX.keys().next().value);
    rec = { nx: 0, total: 0, windowStart: Date.now() };
    _clientNX.set(clientIp, rec);
  }
  const now = Date.now();
  if (now - rec.windowStart > 6e4) {
    rec.nx = 0;
    rec.total = 0;
    rec.windowStart = now;
  }
  rec.nx++;
  rec.total++;
  const rate = rec.total > 10 ? rec.nx / rec.total : 0;
  if (rate > 0.6) {
    _sh.cnxfAlarms++;
    return true;
  }
  return false;
}
export async function aiThreatAugment(domain, baseScore) {
  let boost = 0;
  const iq = _domainIQ.riskScore(domain);
  if (iq > 50) boost += (iq - 50) * 0.3;
  const dev = _obs.deviation();
  if (dev > 0.35) boost += 5;
  const rhythmFactor = _rhythm.anomalyFactor(_getRps());
  if (rhythmFactor > 2) boost += 8;
  const rep = await aeroGet(`ai:rep:${domain}`, null);
  if (rep?.score < 30) boost += 15;
  return Math.min(100, Math.max(0, baseScore + boost));
}
const DCC_PATTERNS = {
  miner: /mine|crypto|coin|monero|xmr|pool|hash|worker/i,
  c2: /c2|command|control|beacon|stager|exfil|payload|inject/i,
  tracker: /track|pixel|analytic|telemetr|beacon|spy|sniff|collect/i,
  malware: /malware|botnet|zombie|dropper|loader|ransomware/i,
  phishing: /login|signin|verify|account|secure|update|alert|confirm/i,
};
export function dccClassify(domain) {
  for (const [cat, pat] of Object.entries(DCC_PATTERNS))
    if (pat.test(domain)) return cat;
  return null;
}
export const _cacheTimings = new Map();
const _CACHE_TIMINGS_MAX = 5e3;
export function poisonGuardCheck(domain, latencyMs) {
  let prev = _cacheTimings.get(domain);
  if (!prev) {
    if (_cacheTimings.size >= _CACHE_TIMINGS_MAX)
      _cacheTimings.delete(_cacheTimings.keys().next().value);
    _cacheTimings.set(domain, { ewma: latencyMs, n: 1 });
    return false;
  }
  prev.n++;
  const suspiciouslyFast = prev.ewma > 50 && latencyMs < prev.ewma * 0.1;
  prev.ewma = 0.2 * latencyMs + 0.8 * prev.ewma;
  if (suspiciouslyFast) {
    _sh.aiBlocks++;
    return true;
  }
  return false;
}
export function multiQuestionCheck(questionCount) {
  return questionCount > 1;
}
export function cbCheck(upIdx, success) {
  if (!_cb[upIdx]) _cb[upIdx] = { errors: 0, total: 0, open: false, openTs: 0 };
  const cb = _cb[upIdx];
  if (success !== null) {
    cb.total++;
    if (!success) cb.errors++;
  }
  if (cb.total > 50) {
    cb.errors = Math.floor(cb.errors * 0.5);
    cb.total = Math.floor(cb.total * 0.5);
  }
  const rate = cb.total > 5 ? cb.errors / cb.total : 0;
  if (rate > _runtimeConfig.cbThreshold && !cb.open) {
    cb.open = true;
    cb.openTs = Date.now();
    _log("cb_opened", { upstream: upIdx, errorRate: rate.toFixed(2) });
  }
  if (cb.open && Date.now() - cb.openTs > 3e4) {
    cb.open = false;
    cb.errors = 0;
    cb.total = 0;
    _log("cb_closed", { upstream: upIdx });
  }
  return cb.open;
}

export function preloadLists(env) {
  const pdb = env?.pulseDb;
  if (!pdb) return;
  const savedMode = pdb.get("config:dns_mode", env.DNS_ACCESS_MODE || "private");
  if (savedMode) _setDnsMode(savedMode, pdb);
  const savedBlocking = pdb.get("config:blocking_enabled", env.BLOCKING_ENABLED ?? "true");
  if (savedBlocking !== null && savedBlocking !== undefined) {
    _setBlockingEnabled(savedBlocking === "true" || savedBlocking === true, pdb);
  }
  setListsPreloaded(true);
}
export function checkBlocklist(domain, db) {
  if (!_blockingEnabled || !domain) return NOT_BLOCKED;
  let d = domain.toLowerCase();
  if (d.endsWith(".")) d = d.slice(0, -1);
  const pdb = _env?.pulseDb || db;

  // RULE 1: Whitelist & Known Legit Domains ALWAYS prioritize! If in whitelist, PASS!
  if (isKnownLegitDomain(d) || checkWhitelist(d, pdb)) {
    return NOT_BLOCKED;
  }

  // 2. Manually added admin blocklist from PulseDB
  if (pdb) {
    const res = pdb.checkBlocklist(d);
    if (res.blocked) return res;
  }

  // RULE 2: Blocklist feed matching (exact or wildcard)
  if (_abirOk && _abirSet && _abirSet.size > 0) {
    let hit = _abirSet.has(d);
    if (!hit) {
      const parts = d.split(".");
      for (let i = 1; i < parts.length - 1; i++) {
        const suffix = parts.slice(i).join(".");
        if (_abirSet.has(suffix)) {
          hit = true;
          break;
        }
      }
    }
    if (hit) {
      // RULE 3: Only display in blocked section those that have been DETECTED!
      if (pdb && pdb.blocklistTrie && pdb.blocklistTrie.size < 1000 && !pdb.blocklistTrie.check(d).matched) {
        pdb.blocklistTrie.add(d, "threat_feed_abir", "feed", Date.now());
        if (typeof process !== "undefined" && process.env?.FLY_APP_NAME) {
          const port = process.env.PORT || "8080";
          fetch(`http://${process.env.FLY_APP_NAME}.internal:${port}/api/blocklist`, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "authorization": `Bearer ${_env?.DNS_MASTER_KEY || ""}`,
              "x-peer-sync": "1",
            },
            body: JSON.stringify({ domains: [d], reason: "threat_feed_abir", source: "feed" }),
          }).catch(() => {});
        }
      }
      return { blocked: true, reason: "threat_feed_abir", source: "abir_feed" };
    }
  }

  return NOT_BLOCKED;
}
export function checkExistsAnywhere(domain, db) {
  let d = domain.toLowerCase();
  if (d.endsWith(".")) d = d.slice(0, -1);
  if (checkWhitelist(d, db)) return "whitelist";
  const bl = checkBlocklist(d, db);
  if (bl.blocked) return "blocklist";
  if (checkCommon(d, db)) return "common";
  return null;
}
export function checkWhitelist(domain, db) {
  if (!domain) return false;
  let d = domain.toLowerCase();
  if (d.endsWith(".")) d = d.slice(0, -1);
  const pdb = _env?.pulseDb || db;

  // 1. Manually added admin whitelist from PulseDB
  if (pdb && pdb.whitelistTrie && pdb.whitelistTrie.check(d).matched) {
    return true;
  }

  // 2. Customized Whitelist exact match
  if (_commonOk && _whitelistExact.has(d)) {
    if (pdb && pdb.whitelistTrie && pdb.whitelistTrie.size < 1000 && !pdb.whitelistTrie.check(d).matched) {
      pdb.whitelistTrie.add(d, "custom_whitelist", "detected", Date.now());
    }
    return true;
  }

  // 3. Customized Whitelist wildcard match (e.g. *.adguard.com matches sub.adguard.com)
  if (_commonOk && _whitelistWildcards.size > 0) {
    const parts = d.split(".");
    for (let i = 1; i < parts.length - 1; i++) {
      const parent = parts.slice(i).join(".");
      if (_whitelistWildcards.has(parent)) {
        if (pdb && pdb.whitelistTrie && pdb.whitelistTrie.size < 1000 && !pdb.whitelistTrie.check(d).matched) {
          pdb.whitelistTrie.add(d, "whitelist_wildcard", "detected", Date.now());
        }
        return true;
      }
    }
  }

  // 4. BloomFilter fallback check
  if (_commonOk && _commonSet && _commonSet.size > 0) {
    const candidates = _getCandidates(d);
    for (let i = 0; i < candidates.length; i++) {
      const c = candidates[i];
      if (!c.startsWith("*") && _commonSet.has(c)) {
        if (pdb && pdb.whitelistTrie && pdb.whitelistTrie.size < 1000 && !pdb.whitelistTrie.check(d).matched) {
          pdb.whitelistTrie.add(d, "custom_whitelist", "detected", Date.now());
        }
        return true;
      }
    }
  }

  return false;
}
export function checkCommon(domain, db) {
  return false;
}

export function clearThreatIntelligenceCaches() {
  _gsbCache.clear();
  _ttlHistory.clear();
  _swarmMap.clear();
  _clientNX.clear();
  _cacheTimings.clear();
}
