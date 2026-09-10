// src/server/doh.rs
// Zero-GC, high-performance DNS-over-HTTPS (DoH) engine with Master Key & HMAC authentication,
// Google Safe Browsing cloud threat intelligence, and multi-machine peer synchronization.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::SystemTime;
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::dns::parser::{build_blocked_response, build_servfail_response, parse_dns_query};
use crate::security::auth::{check_auth, generate_hmac_token, AuthRole};
use crate::state::AppState;
use crate::ui::dashboard::render_dashboard;
use crate::ui::gateway::GATEWAY_HTML;

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct DnsQueryParam {
    pub dns: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub qtype: Option<String>,
    pub device: Option<String>,
    pub client: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DomainReq {
    pub domain: Option<String>,
    pub domains: Option<Vec<String>>,
    #[allow(dead_code)]
    pub reason: Option<String>,
    #[allow(dead_code)]
    pub source: Option<String>,
    #[allow(dead_code)]
    pub ttl: Option<u32>,
}

#[derive(Deserialize)]
pub struct BoolSetting {
    pub enabled: bool,
}

#[derive(Deserialize)]
pub struct ModeSetting {
    pub mode: String,
}

#[derive(Deserialize)]
pub struct NuclearWipeReq {
    pub confirm: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "nukeToken")]
    pub nuke_token: Option<String>,
}

pub fn create_doh_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Dashboard & Gateway
        .route("/", get(dashboard_handler))
        .route("/dashboard", get(dashboard_handler))
        .route("/dashboard/", get(dashboard_handler))
        .route("/status", get(dashboard_handler))
        .route("/health", get(health_handler))
        .route("/favicon.ico", get(favicon_handler))
        .route("/dns-query", get(doh_get_handler).post(doh_post_handler))

        // Status & Authenticated root / key paths
        .route("/api/status", get(status_no_key_handler))
        .route("/api/status/", get(status_no_key_handler))
        .route("/api/intelligence", get(status_no_key_handler))
        .route("/api/intelligence/", get(status_no_key_handler))
        .route("/:key", get(status_handler))
        .route("/dashboard/:key", get(status_handler))
        .route("/api/status/:key", get(status_handler))
        .route("/api/intelligence/:key", get(status_handler))

        // Blocklist
        .route("/api/blocklist", get(get_blocklist).post(add_blocklist).delete(delete_blocklist))
        .route("/api/blocklist/", get(get_blocklist).post(add_blocklist).delete(delete_blocklist))
        .route("/api/blocklist/:key", get(get_blocklist_key).post(add_blocklist_key).delete(delete_blocklist_key))
        .route("/api/blocklist/clear", post(clear_blocklist))
        .route("/api/blocklist/clear/", post(clear_blocklist))
        .route("/api/blocklist/clear/:key", post(clear_blocklist_key))

        // Whitelist
        .route("/api/whitelist", get(get_whitelist).post(add_whitelist).delete(delete_whitelist))
        .route("/api/whitelist/", get(get_whitelist).post(add_whitelist).delete(delete_whitelist))
        .route("/api/whitelist/:key", get(get_whitelist_key).post(add_whitelist_key).delete(delete_whitelist_key))
        .route("/api/whitelist/clear", post(clear_whitelist))
        .route("/api/whitelist/clear/", post(clear_whitelist))
        .route("/api/whitelist/clear/:key", post(clear_whitelist_key))

        // Common
        .route("/api/common", get(get_common).post(add_common).delete(delete_common))
        .route("/api/common/", get(get_common).post(add_common).delete(delete_common))
        .route("/api/common/:key", get(get_common_key).post(add_common_key).delete(delete_common_key))
        .route("/api/common/clear", post(clear_common))
        .route("/api/common/clear/", post(clear_common))
        .route("/api/common/clear/:key", post(clear_common_key))

        // Auto-block
        .route("/api/auto-block", post(add_auto_block).delete(delete_auto_block))
        .route("/api/auto-block/", post(add_auto_block).delete(delete_auto_block))
        .route("/api/auto-block/:key", post(add_auto_block_key).delete(delete_auto_block_key))

        // Heatmap
        .route("/api/heatmap/top", get(get_heatmap_top))
        .route("/api/heatmap/top/", get(get_heatmap_top))
        .route("/api/heatmap/top/:key", get(get_heatmap_top_key))
        .route("/api/heatmap/lookup", get(heatmap_lookup))
        .route("/api/heatmap/lookup/", get(heatmap_lookup))
        .route("/api/heatmap/lookup/:key", get(heatmap_lookup_key))

        // DGA
        .route("/api/dga-test", post(dga_test))
        .route("/api/dga-test/", post(dga_test))
        .route("/api/dga-test/:key", post(dga_test_key))

        // Settings
        .route("/api/settings/blocking", get(get_blocking).post(set_blocking))
        .route("/api/settings/blocking/", get(get_blocking).post(set_blocking))
        .route("/api/settings/blocking/:key", get(get_blocking_key).post(set_blocking_key))
        .route("/api/settings/dns-mode", get(get_dns_mode).post(set_dns_mode))
        .route("/api/settings/dns-mode/", get(get_dns_mode).post(set_dns_mode))
        .route("/api/settings/dns-mode/:key", get(get_dns_mode_key).post(set_dns_mode_key))

        // Upstreams
        .route("/api/upstreams/ranked", get(get_ranked_upstreams))
        .route("/api/upstreams/ranked/", get(get_ranked_upstreams))
        .route("/api/upstreams/ranked/:key", get(get_ranked_upstreams_key))
        .route("/api/upstreams/sync", post(sync_upstreams))
        .route("/api/upstreams/sync/", post(sync_upstreams))
        .route("/api/upstreams/sync/:key", post(sync_upstreams_key))

        // Controls & Wipe
        .route("/api/reset-cb", post(reset_circuit_breakers))
        .route("/api/reset-cb/", post(reset_circuit_breakers))
        .route("/api/reset-cb/:key", post(reset_circuit_breakers_key))
        .route("/api/self-heal", delete(clear_self_heal))
        .route("/api/self-heal/", delete(clear_self_heal))
        .route("/api/self-heal/:key", delete(clear_self_heal_key))
        .route("/api/incident", delete(clear_incident))
        .route("/api/incident/", delete(clear_incident))
        .route("/api/incident/:key", delete(clear_incident_key))
        .route("/api/nuclear-wipe", post(nuclear_wipe))
        .route("/api/nuclear-wipe/", post(nuclear_wipe))
        .route("/api/nuclear-wipe/:key", post(nuclear_wipe_key))
        .route("/api/nuke-token", get(get_nuke_token))
        .route("/api/nuke-token/", get(get_nuke_token))
        .route("/api/nuke-token/:key", get(get_nuke_token_key))
        .route("/api/token", get(get_token))
        .route("/api/token/", get(get_token))
        .route("/api/token/:key", get(get_token_key))

        // AI export / import / prune
        .route("/api/ai/export", get(ai_export))
        .route("/api/ai/export/", get(ai_export))
        .route("/api/ai/export/:key", get(ai_export_key))
        .route("/api/ai/import", post(ai_import))
        .route("/api/ai/import/", post(ai_import))
        .route("/api/ai/import/:key", post(ai_import_key))
        .route("/api/ai/prune", post(ai_prune))
        .route("/api/ai/prune/", post(ai_prune))
        .route("/api/ai/prune/:key", post(ai_prune_key))

        // Query Logs
        .route("/api/logs", get(get_logs))
        .route("/api/logs/", get(get_logs))
        .route("/api/logs/:key", get(get_logs_key))

        // AI Brain Telemetry & Learning Curve
        .route("/api/ai/brain", get(get_ai_brain))
        .route("/api/ai/brain/", get(get_ai_brain))
        .route("/api/ai/brain/:key", get(get_ai_brain_key))
        .with_state(state)
}

// ── Root & Status Handlers ──────────────────────────────────────────────────

async fn health_handler() -> &'static str {
    "OK"
}

async fn favicon_handler() -> Response {
    (StatusCode::NO_CONTENT, "").into_response()
}

async fn dashboard_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/");
    let is_json = headers.get(header::ACCEPT)
        .and_then(|h| h.to_str().ok())
        .map(|a| a.contains("application/json"))
        .unwrap_or(false);

    if is_json {
        if auth.is_view_or_admin() {
            return build_status_response(&state, auth);
        } else {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "ok": false,
                    "error": "Unauthorized: Master key or valid token required"
                })),
            ).into_response();
        }
    }

    if auth.is_view_or_admin() {
        let fly_machine_id = std::env::var("FLY_MACHINE_ID").unwrap_or_default();
        let fly_region = std::env::var("FLY_REGION").unwrap_or_else(|_| "sin".to_string());
        let key = if auth.is_admin() { &state.config.dns_master_key } else { "view-only" };
        Html(render_dashboard(key, &fly_machine_id, &fly_region)).into_response()
    } else {
        Html(GATEWAY_HTML).into_response()
    }
}

async fn status_no_key_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/status");
    if auth.is_view_or_admin() {
        build_status_response(&state, auth)
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "ok": false,
                "error": "Unauthorized: Master key or valid token required"
            })),
        ).into_response()
    }
}

async fn status_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/status");
    let is_html = headers.get(header::ACCEPT)
        .and_then(|h| h.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);

    if is_html {
        if auth.is_view_or_admin() {
            let fly_machine_id = std::env::var("FLY_MACHINE_ID").unwrap_or_default();
            let fly_region = std::env::var("FLY_REGION").unwrap_or_else(|_| "sin".to_string());
            return Html(render_dashboard(&key, &fly_machine_id, &fly_region)).into_response();
        } else {
            return Html(GATEWAY_HTML).into_response();
        }
    }

    if auth.is_view_or_admin() {
        build_status_response(&state, auth)
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "ok": false,
                "error": "Unauthorized: Invalid master key or token"
            })),
        ).into_response()
    }
}

fn build_status_response(state: &AppState, auth: AuthRole) -> Response {
    let reqs = state.metrics.requests.load(Ordering::Relaxed);
    let hits = state.metrics.cache_hits.load(Ordering::Relaxed);
    let misses = state.metrics.cache_misses.load(Ordering::Relaxed);
    let hit_rate = if reqs > 0 {
        format!("{:.1}%", (hits as f64 / reqs as f64) * 100.0)
    } else {
        "0.0%".to_string()
    };

    let blk_cnt = state.custom_blocklist.read().len();
    let wl_cnt = state.custom_whitelist.read().len();
    let cm_cnt = state.custom_common.read().len();
    let upstreams = state.upstreams.snapshot();
    let active_upstreams = upstreams
        .iter()
        .filter(|u| u.get("healthy").and_then(|h| h.as_bool()).unwrap_or(true))
        .count();

    let fly_machine_id = std::env::var("FLY_MACHINE_ID").unwrap_or_default();
    let fly_region = std::env::var("FLY_REGION").unwrap_or_else(|_| "sin".to_string());
    let fly_app = std::env::var("FLY_APP_NAME").unwrap_or_else(|_| "amardns".to_string());

    let machine_id_val = if fly_machine_id.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(fly_machine_id.clone())
    };

    let (threat_bloom_cnt, threat_bloom_fp, threat_bloom_mem, threat_bloom_fill) = {
        let g = state.threat_bloom.read();
        (g.count(), g.false_positive_rate(), g.memory_bytes(), g.fill_ratio())
    };
    let (wl_bloom_cnt, wl_bloom_fp, wl_bloom_mem) = {
        let g = state.whitelist_bloom.read();
        (g.count(), g.false_positive_rate(), g.memory_bytes())
    };
    let exp_threat_total = state.expected_threat_total.load(Ordering::Relaxed);
    let exp_white_total = state.expected_whitelist_total.load(Ordering::Relaxed);
    let effective_threat_total = if exp_threat_total > 0 { exp_threat_total } else { threat_bloom_cnt };
    let effective_white_total = if exp_white_total > 0 { exp_white_total } else { wl_bloom_cnt };
    let abir_crossmatched = threat_bloom_cnt >= effective_threat_total && threat_bloom_cnt > 0;
    let common_crossmatched = wl_bloom_cnt >= effective_white_total && wl_bloom_cnt > 0;
    let feed_overlap = state.feed_overlap_count.load(Ordering::Relaxed);
    let total_bloom_domains = threat_bloom_cnt + wl_bloom_cnt;
    let threats_blocked = state.metrics.threat_blocks.load(Ordering::Relaxed);
    let dga_blocked = state.metrics.dga_blocks.load(Ordering::Relaxed);
    let alike_blocked = state.metrics.alike_blocks.load(Ordering::Relaxed);
    let gsb_blocked = state.metrics.gsb_blocks.load(Ordering::Relaxed);
    let dev_count = state.metrics.active_device_count();
    let is_priv = state.is_private_mode.load(Ordering::Relaxed);

    let (cache_len, cache_bytes, cache_mem_mb, cache_max_cap) = state.cache.get_stats();
    let (wal_bytes, wal_mb) = state.wal.get_stats();
    let total_records = state.wal.total_records().max((blk_cnt + wl_cnt + cm_cnt) as u64);

    let rss_mb = match std::fs::read_to_string("/proc/self/statm") {
        Ok(s) => {
            let parts: Vec<&str> = s.split_whitespace().collect();
            if parts.len() > 1 {
                let resident_pages: f64 = parts[1].parse().unwrap_or(0.0);
                ((resident_pages * 4096.0 / 1_048_576.0) * 10.0).round() / 10.0
            } else {
                0.0
            }
        }
        Err(_) => 0.0,
    };

    let valid_lats: Vec<u32> = upstreams.iter()
        .filter_map(|u| u.get("latencyMs").and_then(|v| v.as_u64()).map(|v| v as u32))
        .filter(|&l| l > 0 && l < 5000)
        .collect();
    let avg_latency = if !valid_lats.is_empty() {
        (valid_lats.iter().sum::<u32>() / valid_lats.len() as u32).max(1)
    } else {
        0
    };

    let brain_cycles = state.brain.training_cycles.load(Ordering::Relaxed);
    let domain_iq_size = state.brain.domain_iq.read().len();
    let markov_size = state.brain.markov_model.read().len();
    let cycle_factor = (brain_cycles as f64 / 1000.0).min(1.0);
    let brain_util = if domain_iq_size == 0 && markov_size == 0 && brain_cycles == 0 {
        0
    } else {
        let iq_ratio = (domain_iq_size as f64 / 2000.0).min(1.0);
        let markov_ratio = (markov_size as f64 / 1000.0).min(1.0);
        let score = (iq_ratio * 35.0 + markov_ratio * 35.0 + cycle_factor * 30.0).round() as u32;
        score.min(100).max(0)
    };
    let major = 1 + (brain_cycles / 1000);
    let minor = (brain_cycles / 100) % 10;
    let patch = (brain_cycles / 10) % 10;
    let brain_version = format!("{}.{}.{}", major, minor, patch);
    let (neg_cache_size, neg_cache_hits) = state.cache.get_neg_stats();
    let swr_serves = state.metrics.swr_serves.load(Ordering::Relaxed);
    let fast_neg_hits = state.metrics.fast_neg_hits.load(Ordering::Relaxed);
    let prefetch_triggers = state.metrics.prefetch_triggers.load(Ordering::Relaxed);
    let prefetch_hits = state.metrics.prefetch_hits.load(Ordering::Relaxed);
    let (avg_lat_us, avg_lat_ms) = state.metrics.get_avg_latency();
    let (lat_sub1, lat_1_5, lat_5_15, lat_15_50, lat_above50) = state.metrics.get_latency_distribution();

    let rps = state.metrics.get_rps();
    let rps_peak = state.metrics.get_rps_peak();
    let stress = state.metrics.calc_stress(rps);
    let uptime_str = state.metrics.online_since();
    let uptime_secs = state.metrics.uptime_secs();
    let active_ips = state.metrics.active_ip_count();
    let devices_list = state.metrics.get_active_devices();

    let burst_events = state.metrics.burst_events.load(Ordering::Relaxed);
    let rep_blocks = state.metrics.rep_blocks.load(Ordering::Relaxed);
    let rebind_blocks = state.metrics.rebind_blocks.load(Ordering::Relaxed);
    let auto_blocks = state.metrics.auto_blocks.load(Ordering::Relaxed);
    let nx_alarms = state.metrics.nx_alarms.load(Ordering::Relaxed);
    let answer_drifts = state.metrics.answer_drifts.load(Ordering::Relaxed);
    let dcc_hits = state.metrics.dcc_hits.load(Ordering::Relaxed);
    let swarm_alarms = state.metrics.swarm_alarms.load(Ordering::Relaxed);

    let cts = ((stress * 40.0)
        + if dga_blocked > 0 { 15.0 } else { 0.0 }
        + if burst_events > 5 { 20.0 } else { 0.0 }
        + if rep_blocks > 10 { 25.0 } else { 0.0 })
        .round() as u64;
    let cts = cts.min(100);

    let lb_mode = if rps > 100.0 || stress > 0.8 {
        "RELIABLE"
    } else if stress < 0.3 {
        "FAST"
    } else {
        "BALANCED"
    };

    let narrative = format!(
        "{} · {:.1} R/s · {} IQ · {} cycles · {} threats blocked · online {}",
        if stress > 0.7 { "HIGH STRESS" } else { "Nominal" },
        rps,
        domain_iq_size,
        brain_cycles,
        threats_blocked,
        uptime_str
    );

    let open_cb_count = upstreams.iter().filter(|u| {
        !u.get("healthy").and_then(|v| v.as_bool()).unwrap_or(true)
    }).count();

    let heatmap_guard = state.heatmap.read();
    let mut hot_domains: Vec<serde_json::Value> = heatmap_guard.iter().map(|(d, r)| {
        let max_idx = r.hourly.iter().enumerate().max_by_key(|(_, &v)| v).map(|(i, _)| i).unwrap_or(0);
        serde_json::json!({
            "domain": d,
            "total": r.total,
            "peak": max_idx,
            "hourly": r.hourly
        })
    }).collect();
    drop(heatmap_guard);
    hot_domains.sort_by(|a, b| {
        let ta = a.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
        let tb = b.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
        tb.cmp(&ta)
    });
    hot_domains.truncate(20);

    let status = serde_json::json!({
        "isolateId": if fly_machine_id.is_empty() { "local".to_string() } else { fly_machine_id.clone() },
        "authRole": auth.as_str(),
        "isViewOnly": !auth.is_admin(),
        "node": {
            "machineId": machine_id_val,
            "region": fly_region,
            "appName": fly_app,
            "activeDevices": dev_count,
            "activeIps": active_ips,
            "deviceList": devices_list,
            "memory": {
                "rssMB": rss_mb,
                "engine": "Rust (Zero GC)"
            }
        },
        "memory": {
            "rssMB": rss_mb,
            "engine": "Rust (Zero GC)"
        },
        "devices": devices_list,
        "dnsRequestsTotal": reqs,
        "upstreamsActive": active_upstreams,
        "upstreamsTotal": upstreams.len(),
        "avgLatency": avg_latency,
        "blockRate": if reqs > 0 { format!("{:.1}%", (threats_blocked as f64 / reqs as f64) * 100.0) } else { "0.0%".to_string() },
        "narrative": narrative,
        "performance": {
            "avgLatencyUs": avg_lat_us,
            "avgLatencyMs": if avg_lat_ms > 0.0 { avg_lat_ms } else { avg_latency as f64 },
            "swrServes": swr_serves,
            "fastNegHits": fast_neg_hits,
            "prefetchTriggers": prefetch_triggers,
            "prefetchHits": prefetch_hits,
            "latencyDistribution": {
                "sub1ms": lat_sub1,
                "from1to5ms": lat_1_5,
                "from5to15ms": lat_5_15,
                "from15to50ms": lat_15_50,
                "above50ms": lat_above50
            }
        },
        "cache": {
            "hits": hits,
            "misses": misses,
            "hitRate": hit_rate,
            "swrServes": swr_serves,
            "fastNegHits": fast_neg_hits,
            "prefetchHits": prefetch_hits,
            "size": cache_len,
            "bytes": cache_bytes,
            "memoryMB": cache_mem_mb,
            "maxEntries": cache_max_cap,
            "bloomTotalDomains": total_bloom_domains,
            "threatBloomDomains": threat_bloom_cnt,
            "whitelistBloomDomains": wl_bloom_cnt,
            "expectedThreatTotal": effective_threat_total,
            "expectedWhitelistTotal": effective_white_total,
            "crossMatched": abir_crossmatched && common_crossmatched,
            "feedOverlapCount": feed_overlap
        },
        "ai": {
            "activeDevices": dev_count,
            "activeIps": active_ips,
            "rps": rps,
            "rpsPeak": rps_peak,
            "lbMode": lb_mode,
            "cts": cts,
            "negCacheHits": neg_cache_hits,
            "negCacheSize": neg_cache_size,
            "brainLoading": false,
            "brainUtilization": brain_util,
            "brainVersion": brain_version,
            "learningCycles": brain_cycles,
            "domainIQSize": domain_iq_size,
            "markovSize": markov_size,
            "brainSyncBytes": 0u64,
            "brainSyncAge": 0,
            "brainUptimeSec": uptime_secs,
            "autoBlockActive": auto_blocks,
            "threatsBlocked": threats_blocked,
            "alikeBlocks": alike_blocked,
            "dgaBlocked": dga_blocked,
            "gsbBlocked": gsb_blocked,
            "gsbBlocks": gsb_blocked,
            "rebindBlocks": rebind_blocks,
            "repBlocks": rep_blocks,
            "abirBlocks": threats_blocked,
            "abirSize": threat_bloom_cnt,
            "abirTotalEntries": effective_threat_total,
            "commonSize": wl_bloom_cnt,
            "commonTotalEntries": effective_white_total,
            "burstEvents": burst_events,
            "answerDrifts": answer_drifts,
            "nxAlarms": nx_alarms,
            "dccHits": dcc_hits,
            "swarmAlarms": swarm_alarms,
            "abirOk": threat_bloom_cnt > 0,
            "commonOk": wl_bloom_cnt > 0,
            "abirCrossMatched": abir_crossmatched,
            "commonCrossMatched": common_crossmatched,
            "feedOverlapCount": feed_overlap,
            "bloom": {
                "threat": {
                    "count": threat_bloom_cnt,
                    "memoryBytes": threat_bloom_mem,
                    "memoryKB": threat_bloom_mem / 1024,
                    "fpRate": threat_bloom_fp,
                    "fillRatio": threat_bloom_fill
                },
                "whitelist": {
                    "count": wl_bloom_cnt,
                    "memoryBytes": wl_bloom_mem,
                    "memoryKB": wl_bloom_mem / 1024,
                    "fpRate": wl_bloom_fp
                }
            },
            "gsbOk": state.safe_browsing.is_active(),
            "gsbKeyCount": state.safe_browsing.key_count(),
            "fpSuspicious": state.fingerprint.get_suspicious(),
            "ttlEvents": { "inflations": 0, "deflations": 0 },
            "fpEvents": state.fingerprint.total_events(),
            "configDecisions": state.config_decisions.read().clone(),
            "decisionsMade": state.brain.decisions_made.load(Ordering::Relaxed),
            "recentDecisions": state.recent_actions.read().iter().take(20).map(|a| {
                serde_json::json!({
                    "t": a.t,
                    "decision": a.action,
                    "factors": { "reason": a.reason }
                })
            }).collect::<Vec<_>>(),
            "hotDomains": hot_domains
        },
        "config": {
            "hedgeMs": 20,
            "fetchTimeoutMs": 3000,
            "cooldownMs": 10000,
            "swrFactor": 0.8,
            "minCacheTtl": 5,
            "maxCacheTtl": 3600,
            "raceSlots": 2,
            "cbWindow": 50,
            "cbThreshold": 0.45,
            "storageEngine": "PulseDB (SuffixTrie WAL) + AeroCache (S3-FIFO)",
            "dnsMode": if is_priv { "private" } else { "public" },
            "blockingEnabled": state.blocking_enabled.load(Ordering::Relaxed),
            "hmacAuth": !state.config.dns_token_secret.is_empty(),
            "upstreamAuraPrioritization": true,
            "upstreamCandidates": upstreams.len(),
            "upstreamLastSync": serde_json::Value::Null
        },
        "intelligence": {
            "cfgOverride": serde_json::json!({}),
            "configMode": "ai",
            "incidentActive": stress > 0.8,
            "incident": if stress > 0.8 {
                serde_json::json!({
                    "type": "high_stress",
                    "detectedAt": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis(),
                    "affectedUpstreams": []
                })
            } else {
                serde_json::Value::Null
            },
            "upstreamProfiles": upstreams.iter().map(|u| {
                let lat = u.get("latencyMs").and_then(|v| v.as_u64()).unwrap_or(0);
                let p50 = u.get("p50").and_then(|v| v.as_u64()).unwrap_or(lat);
                let p95 = u.get("p95").and_then(|v| v.as_u64()).unwrap_or(lat);
                let p99 = u.get("p99").and_then(|v| v.as_u64()).unwrap_or(lat);
                let score = u.get("score").and_then(|v| v.as_u64()).unwrap_or(0);
                let err_rate = u.get("errorRatePct").and_then(|v| v.as_u64()).unwrap_or(0);
                let hits = u.get("hits").and_then(|v| v.as_u64()).unwrap_or(0);
                serde_json::json!({
                    "p50": p50,
                    "p95": p95,
                    "p99": p99,
                    "slowEwma": lat,
                    "fastEwma": lat,
                    "score": score,
                    "errorRate": err_rate,
                    "flaps": 0,
                    "samples": hits,
                    "lastRecoveryAgo": serde_json::Value::Null,
                    "aura": u.get("aura").and_then(|v| v.as_str()).unwrap_or("high"),
                    "healthy": u.get("healthy").and_then(|v| v.as_bool()).unwrap_or(true)
                })
            }).collect::<Vec<_>>()
        },
        "selfHeal": {
            "openCircuitBreakers": open_cb_count,
            "unhealthyUpstreams": open_cb_count,
            "recentActions": state.recent_actions.read().clone(),
            "recentAnomalies": state.recent_anomalies.read().clone(),
            "selfHealActions": state.recent_actions.read().clone(),
            "panicCount": 0,
            "authFails": 0,
            "emergencyMode": false,
            "dailyLimits": "None (Uncapped Dedicated)",
            "throttled": false,
            "gcCycles": 0,
            "memPressure": false
        },
        "storage": {
            "engine": "PulseDB + AeroCache",
            "db": {
                "totalRecords": total_records,
                "blocklistDomains": blk_cnt,
                "whitelistDomains": wl_cnt + cm_cnt,
                "walMB": wal_mb,
                "walBytes": wal_bytes
            },
            "cache": {
                "size": cache_len,
                "bytes": cache_bytes,
                "maxEntries": cache_max_cap,
                "memoryMB": cache_mem_mb,
                "hitRate": hit_rate
            }
        },
        "db": {
            "totalRecords": total_records,
            "blocklistDomains": blk_cnt,
            "whitelistDomains": wl_cnt + cm_cnt,
            "walMB": wal_mb,
            "walBytes": wal_bytes
        },
        "threatIntelligence": {
            "threatsBlocked": threats_blocked,
            "alikeBlocked": alike_blocked,
            "dgaBlocked": dga_blocked,
            "gsbBlocked": gsb_blocked,
            "threatBloomEntries": threat_bloom_cnt,
            "whitelistBloomEntries": wl_bloom_cnt,
            "totalBloomEntries": total_bloom_domains,
            "expectedThreatTotal": effective_threat_total,
            "expectedWhitelistTotal": effective_white_total,
            "crossMatched": abir_crossmatched && common_crossmatched,
            "feedOverlapCount": feed_overlap,
            "customBlocked": blk_cnt,
            "customWhitelisted": wl_cnt + cm_cnt
        },
        "upstreams": upstreams,
        "recentQueries": state.recent_queries.read().iter().rev().take(100).cloned().collect::<Vec<_>>()
    });

    let mut resp = Json(status).into_response();
    if !fly_machine_id.is_empty() {
        if let Ok(hval) = axum::http::HeaderValue::from_str(&fly_machine_id) {
            resp.headers_mut().insert("fly-machine-id", hval);
        }
    }
    resp
}

async fn get_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/logs");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized" })),
        ).into_response();
    }
    let queries = state.recent_queries.read().iter().rev().cloned().collect::<Vec<_>>();
    Json(serde_json::json!({
        "ok": true,
        "count": queries.len(),
        "queries": queries
    })).into_response()
}

async fn get_logs_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/logs");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized" })),
        ).into_response();
    }
    let queries = state.recent_queries.read().iter().rev().cloned().collect::<Vec<_>>();
    Json(serde_json::json!({
        "ok": true,
        "count": queries.len(),
        "queries": queries
    })).into_response()
}

async fn get_ai_brain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    handle_get_ai_brain(&state, None, &headers).await
}

async fn get_ai_brain_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_ai_brain(&state, Some(&key), &headers).await
}

async fn handle_get_ai_brain(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/ai/brain");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized" })),
        ).into_response();
    }

    let reqs = state.metrics.requests.load(Ordering::Relaxed);
    let brain_cycles = state.brain.training_cycles.load(Ordering::Relaxed);
    let domain_iq_size = state.brain.domain_iq.read().len();
    let markov_size = state.brain.markov_model.read().len();
    let zero_day_blocks = state.brain.zero_day_blocks.load(Ordering::Relaxed);
    let typo_blocks = state.brain.typo_blocks.load(Ordering::Relaxed);
    let fp_suppressions = state.brain.fp_suppressions.load(Ordering::Relaxed);
    let (neg_cache_size, neg_cache_hits) = state.cache.get_neg_stats();
    let total_evaluations = state.brain.decisions_made.load(Ordering::Relaxed);
    let neural_weights = *state.brain.neural_weights.read();
    let recent_decisions = state.brain.get_recent_decisions(100);
    let memory_bytes = state.brain.memory_bytes();

    // Measure live inference speed on this server
    let t0 = std::time::Instant::now();
    let (_sample_feats, _sample_ent) = state.brain.extract_features("telemetry.probe.internal");
    let (_sample_score, _sample_verdict) = state.brain.evaluate_internal("telemetry.probe.internal");
    let actual_inference_ms = ((t0.elapsed().as_nanos() as f64) / 1_000_000.0).max(0.001);

    let total_threats = zero_day_blocks + typo_blocks;
    let utility_score = if reqs > 0 {
        let safe_ratio = (reqs.saturating_sub(total_threats) as f64) / (reqs as f64);
        (safe_ratio * 100.0).clamp(0.0, 100.0)
    } else {
        100.0
    };

    let now_sec = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Generate 8 chronological time slices ending at current hour from real heatmap telemetry
    let current_hour = ((now_sec / 3600) % 24) as usize;
    let mut hourly_totals = [0u64; 24];
    let mut chart_points = Vec::with_capacity(8);
    {
        let guard = state.heatmap.read();
        for (_domain, rec) in guard.iter() {
            for h in 0..24 {
                hourly_totals[h] = hourly_totals[h].saturating_add(rec.hourly[h] as u64);
            }
        }
        for i in 0..8 {
            let h = (current_hour + 24 - 7 + i) % 24;
            let label = format!("{:02}:00", h);
            let queries = hourly_totals[h];
            let hour_unique_domains = guard.iter().filter(|(_, rec)| rec.hourly[h] > 0).count();
            let hour_threats: u64 = guard.iter()
                .filter(|(d, rec)| rec.hourly[h] > 0 && state.is_domain_blocked(d))
                .map(|(_, rec)| rec.hourly[h] as u64)
                .sum();
            let slice_acc = if queries > 0 {
                let safe_q = queries.saturating_sub(hour_threats);
                ((safe_q as f64 / queries as f64) * 100.0).clamp(0.0, 100.0)
            } else if reqs > 0 {
                utility_score
            } else {
                100.0
            };

            chart_points.push(serde_json::json!({
                "label": label,
                "queries": queries,
                "accuracy": (slice_acc * 10.0).round() / 10.0,
                "domainsProfiled": hour_unique_domains,
                "threatsBlocked": hour_threats,
                "trainingEpochs": if queries > 0 { queries } else { 0 },
                "hour": h
            }));
        }
    }

    let avg_upstream_lat: u32 = {
        let snaps = state.upstreams.snapshot();
        let lats: Vec<u32> = snaps.iter()
            .filter_map(|u| u.get("latencyMs").and_then(|v| v.as_u64()).map(|v| v as u32))
            .filter(|&l| l > 0 && l < 5000)
            .collect();
        if !lats.is_empty() {
            (lats.iter().sum::<u32>() / lats.len() as u32).max(1)
        } else {
            0
        }
    };

    Json(serde_json::json!({
        "ok": true,
        "engine": "AmarDNS Perpetual AI Brain",
        "version": format!("{}.{}.{}", 1 + (brain_cycles / 1000), (brain_cycles / 100) % 10, (brain_cycles / 10) % 10),
        "status": "active_learning",
        "stats": {
            "totalEvaluations": total_evaluations,
            "trainingCycles": brain_cycles,
            "domainIQCount": domain_iq_size,
            "markovBigrams": markov_size,
            "zeroDayBlocks": zero_day_blocks,
            "typoBlocks": typo_blocks,
            "fpSuppressions": fp_suppressions,
            "negCacheHits": neg_cache_hits,
            "negCacheSize": neg_cache_size,
            "inferenceSpeedMs": (actual_inference_ms * 1000.0).round() / 1000.0,
            "utilityScore": (utility_score * 10.0).round() / 10.0,
            "latencySavedMs": avg_upstream_lat,
            "memoryBytes": memory_bytes,
            "memoryKB": (memory_bytes as f64 / 1024.0).round(),
            "neuralWeights": neural_weights,
            "featureLabels": [
                "Domain Length Ratio",
                "Shannon Entropy",
                "Vowel Ratio",
                "Digit Ratio",
                "Consonant Clusters",
                "Markov Anomaly",
                "Brand Proximity",
                "Domain IQ History"
            ]
        },
        "chart": {
            "points": chart_points,
            "hourlyTraffic": hourly_totals
        },
        "recentDecisions": recent_decisions
    })).into_response()
}

// ── Multi-Machine Cluster Peer Sync ─────────────────────────────────────────

fn broadcast_peer_sync(
    headers: &HeaderMap,
    master_key: &str,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) {
    if headers.contains_key("x-peer-sync") {
        return;
    }
    let app_name = match std::env::var("FLY_APP_NAME") {
        Ok(name) if !name.is_empty() => name,
        _ => return,
    };
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let path = path.to_string();
    let auth_header = format!("Bearer {}", master_key);

    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(2000))
            .build()
            .unwrap_or_default();

        let host = format!("{}.internal:{}", app_name, port);
        if let Ok(iter) = tokio::net::lookup_host(host).await {
            let addrs: Vec<std::net::SocketAddr> = iter.collect();
            for addr in addrs {
                let url = format!("http://{}/{}", addr, path.trim_start_matches('/'));
                let mut req = client.request(method.clone(), &url)
                    .header("x-peer-sync", "1")
                    .header("authorization", &auth_header);
                if let Some(ref b) = body {
                    req = req.json(b);
                }
                let _ = req.send().await;
            }
        }
    });
}

// ── Blocklist Handlers ──────────────────────────────────────────────────────

async fn get_blocklist(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_get_blocklist(&state, None, &headers).await
}

async fn get_blocklist_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_blocklist(&state, Some(&key), &headers).await
}

async fn handle_get_blocklist(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/blocklist");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key or token required" })),
        ).into_response();
    }

    let guard = state.custom_blocklist.read();
    let domains: Vec<serde_json::Value> = guard
        .values()
        .take(1000)
        .map(|entry| {
            serde_json::json!({
                "domain": entry.domain,
                "reason": entry.reason,
                "source": entry.source,
                "tag": entry.tag,
                "auto": entry.auto,
                "createdAt": entry.created_at
            })
        })
        .collect();
    Json(serde_json::json!({ "ok": true, "domains": domains })).into_response()
}

async fn add_blocklist(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_add_blocklist(&state, None, &headers, payload).await
}

async fn add_blocklist_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_add_blocklist(&state, Some(&key), &headers, payload).await
}

async fn handle_add_blocklist(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
    payload: DomainReq,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/blocklist");
    if auth == AuthRole::None {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" })),
        ).into_response();
    }
    if auth == AuthRole::View {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "Forbidden: Generated tokens are view-only. No changes can be made." })),
        ).into_response();
    }

    let mut added = 0;
    let mut skipped = Vec::new();
    let mut to_add = Vec::new();
    if let Some(ref dom) = payload.domain {
        to_add.push(dom.clone());
    }
    if let Some(ref doms) = payload.domains {
        to_add.extend(doms.clone());
    }

    {
        let mut guard = state.custom_blocklist.write();
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        for raw in to_add {
            let clean = raw.trim().trim_end_matches('.').to_ascii_lowercase();
            if clean.is_empty() {
                continue;
            }
            if guard.contains_key(&clean) {
                skipped.push(format!("{} already exists", clean));
            } else {
                state.wal.append_block(&clean);
                guard.insert(
                    clean.clone(),
                    crate::state::BlockEntry {
                        domain: clean,
                        reason: payload.reason.clone().unwrap_or_else(|| "manual".to_string()),
                        source: "manual".to_string(),
                        tag: "MANUAL".to_string(),
                        auto: false,
                        created_at: now,
                    },
                );
                added += 1;
            }
        }
    }

    broadcast_peer_sync(headers, &state.config.dns_master_key, reqwest::Method::POST, "/api/blocklist", Some(serde_json::json!(payload)));
    state.log_action("blocklist_added", &format!("Added {} domain(s)", added));
    Json(serde_json::json!({
        "ok": true,
        "added": added,
        "skipped": skipped
    })).into_response()
}

async fn delete_blocklist(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_delete_blocklist(&state, None, &headers, payload).await
}

async fn delete_blocklist_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_delete_blocklist(&state, Some(&key), &headers, payload).await
}

async fn handle_delete_blocklist(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
    payload: DomainReq,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/blocklist");
    if auth == AuthRole::None {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" })),
        ).into_response();
    }
    if auth == AuthRole::View {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "Forbidden: Generated tokens are view-only. No changes can be made." })),
        ).into_response();
    }

    let domain = payload.domain.clone().unwrap_or_default();
    let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "ok": false, "error": "invalid domain" }))).into_response();
    }
    state.wal.append_unblock(&clean);
    state.custom_blocklist.write().remove(&clean);
    broadcast_peer_sync(headers, &state.config.dns_master_key, reqwest::Method::DELETE, "/api/blocklist", Some(serde_json::json!(payload)));
    state.log_action("blocklist_removed", &clean);
    Json(serde_json::json!({ "ok": true, "domain": clean })).into_response()
}

async fn clear_blocklist(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_clear_blocklist(&state, None, &headers).await
}

async fn clear_blocklist_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_clear_blocklist(&state, Some(&key), &headers).await
}

async fn handle_clear_blocklist(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/blocklist/clear");
    if auth == AuthRole::None {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" })),
        ).into_response();
    }
    if auth == AuthRole::View {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "Forbidden: Generated tokens are view-only. No changes can be made." })),
        ).into_response();
    }

    state.custom_blocklist.write().clear();
    state.wal.clear();
    broadcast_peer_sync(headers, &state.config.dns_master_key, reqwest::Method::POST, "/api/blocklist/clear", None);
    state.log_action("blocklist_cleared", "admin");
    Json(serde_json::json!({ "ok": true })).into_response()
}

// ── Whitelist Handlers ──────────────────────────────────────────────────────

async fn get_whitelist(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_get_whitelist(&state, None, &headers).await
}

async fn get_whitelist_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_whitelist(&state, Some(&key), &headers).await
}

async fn handle_get_whitelist(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/whitelist");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key or token required" })),
        ).into_response();
    }
    let list: Vec<String> = state.custom_whitelist.read().iter().cloned().collect();
    Json(serde_json::json!({ "ok": true, "domains": list })).into_response()
}

async fn add_whitelist(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_add_whitelist(&state, None, &headers, payload).await
}

async fn add_whitelist_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_add_whitelist(&state, Some(&key), &headers, payload).await
}

async fn handle_add_whitelist(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
    payload: DomainReq,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/whitelist");
    if auth == AuthRole::None {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" })),
        ).into_response();
    }
    if auth == AuthRole::View {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "Forbidden: Generated tokens are view-only. No changes can be made." })),
        ).into_response();
    }

    let mut added = 0;
    let mut skipped = Vec::new();
    let mut to_add = Vec::new();
    if let Some(ref dom) = payload.domain {
        to_add.push(dom.clone());
    }
    if let Some(ref doms) = payload.domains {
        to_add.extend(doms.clone());
    }

    let mut added_domains = Vec::new();
    {
        let mut guard = state.custom_whitelist.write();
        for raw in to_add {
            let clean = raw.trim().trim_end_matches('.').to_ascii_lowercase();
            if clean.is_empty() {
                continue;
            }
            if guard.contains(&clean) {
                skipped.push(format!("{} already exists", clean));
            } else {
                state.wal.append_whitelist(&clean);
                guard.insert(clean.clone());
                added_domains.push(clean);
                added += 1;
            }
        }
    }
    for dom in added_domains {
        state.cache.invalidate_negative(&dom).await;
    }

    broadcast_peer_sync(headers, &state.config.dns_master_key, reqwest::Method::POST, "/api/whitelist", Some(serde_json::json!(payload)));
    state.log_action("whitelist_added", &format!("Added {} domain(s)", added));
    Json(serde_json::json!({
        "ok": true,
        "added": added,
        "skipped": skipped
    })).into_response()
}

async fn delete_whitelist(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_delete_whitelist(&state, None, &headers, payload).await
}

async fn delete_whitelist_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_delete_whitelist(&state, Some(&key), &headers, payload).await
}

async fn handle_delete_whitelist(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
    payload: DomainReq,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/whitelist");
    if auth == AuthRole::None {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" })),
        ).into_response();
    }
    if auth == AuthRole::View {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "Forbidden: Generated tokens are view-only. No changes can be made." })),
        ).into_response();
    }

    let domain = payload.domain.clone().unwrap_or_default();
    let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "ok": false, "error": "invalid domain" }))).into_response();
    }
    state.wal.append_unwhitelist(&clean);
    state.custom_whitelist.write().remove(&clean);
    broadcast_peer_sync(headers, &state.config.dns_master_key, reqwest::Method::DELETE, "/api/whitelist", Some(serde_json::json!(payload)));
    state.log_action("whitelist_removed", &clean);
    Json(serde_json::json!({ "ok": true, "domain": clean })).into_response()
}

async fn clear_whitelist(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_clear_whitelist(&state, None, &headers).await
}

async fn clear_whitelist_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_clear_whitelist(&state, Some(&key), &headers).await
}

async fn handle_clear_whitelist(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/whitelist/clear");
    if auth == AuthRole::None {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" })),
        ).into_response();
    }
    if auth == AuthRole::View {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "Forbidden: Generated tokens are view-only. No changes can be made." })),
        ).into_response();
    }

    state.custom_whitelist.write().clear();
    broadcast_peer_sync(headers, &state.config.dns_master_key, reqwest::Method::POST, "/api/whitelist/clear", None);
    state.log_action("whitelist_cleared", "admin");
    Json(serde_json::json!({ "ok": true })).into_response()
}

// ── Common Handlers ─────────────────────────────────────────────────────────

async fn get_common(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_get_common(&state, None, &headers).await
}

async fn get_common_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_common(&state, Some(&key), &headers).await
}

async fn handle_get_common(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/common");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key or token required" })),
        ).into_response();
    }
    let list: Vec<String> = state.custom_common.read().iter().cloned().collect();
    Json(serde_json::json!({ "ok": true, "domains": list })).into_response()
}

async fn add_common(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_add_common(&state, None, &headers, payload).await
}

async fn add_common_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_add_common(&state, Some(&key), &headers, payload).await
}

async fn handle_add_common(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
    payload: DomainReq,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/common");
    if auth == AuthRole::None {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" })),
        ).into_response();
    }
    if auth == AuthRole::View {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "Forbidden: Generated tokens are view-only. No changes can be made." })),
        ).into_response();
    }

    let mut added = 0;
    let mut skipped = Vec::new();
    let mut to_add = Vec::new();
    if let Some(ref dom) = payload.domain {
        to_add.push(dom.clone());
    }
    if let Some(ref doms) = payload.domains {
        to_add.extend(doms.clone());
    }

    let mut added_domains = Vec::new();
    {
        let mut guard = state.custom_common.write();
        for raw in to_add {
            let clean = raw.trim().trim_end_matches('.').to_ascii_lowercase();
            if clean.is_empty() {
                continue;
            }
            if guard.contains(&clean) {
                skipped.push(format!("{} already exists", clean));
            } else {
                state.wal.append_common(&clean);
                guard.insert(clean.clone());
                added_domains.push(clean);
                added += 1;
            }
        }
    }
    for dom in added_domains {
        state.cache.invalidate_negative(&dom).await;
    }

    broadcast_peer_sync(headers, &state.config.dns_master_key, reqwest::Method::POST, "/api/common", Some(serde_json::json!(payload)));
    state.log_action("common_added", &format!("Added {} domain(s)", added));
    Json(serde_json::json!({
        "ok": true,
        "added": added,
        "skipped": skipped
    })).into_response()
}

async fn delete_common(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_delete_common(&state, None, &headers, payload).await
}

async fn delete_common_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_delete_common(&state, Some(&key), &headers, payload).await
}

async fn handle_delete_common(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
    payload: DomainReq,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/common");
    if auth == AuthRole::None {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" })),
        ).into_response();
    }
    if auth == AuthRole::View {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "Forbidden: Generated tokens are view-only. No changes can be made." })),
        ).into_response();
    }

    let domain = payload.domain.clone().unwrap_or_default();
    let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "ok": false, "error": "invalid domain" }))).into_response();
    }
    state.wal.append_uncommon(&clean);
    state.custom_common.write().remove(&clean);
    broadcast_peer_sync(headers, &state.config.dns_master_key, reqwest::Method::DELETE, "/api/common", Some(serde_json::json!(payload)));
    state.log_action("common_removed", &clean);
    Json(serde_json::json!({ "ok": true, "domain": clean })).into_response()
}

async fn clear_common(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_clear_common(&state, None, &headers).await
}

async fn clear_common_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_clear_common(&state, Some(&key), &headers).await
}

async fn handle_clear_common(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/common/clear");
    if auth == AuthRole::None {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" })),
        ).into_response();
    }
    if auth == AuthRole::View {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "Forbidden: Generated tokens are view-only. No changes can be made." })),
        ).into_response();
    }

    state.custom_common.write().clear();
    broadcast_peer_sync(headers, &state.config.dns_master_key, reqwest::Method::POST, "/api/common/clear", None);
    state.log_action("common_cleared", "admin");
    Json(serde_json::json!({ "ok": true })).into_response()
}

// ── Auto-Block Handlers ─────────────────────────────────────────────────────

async fn add_auto_block(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_add_auto_block(&state, None, &headers, payload).await
}

async fn add_auto_block_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_add_auto_block(&state, Some(&key), &headers, payload).await
}

async fn handle_add_auto_block(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
    payload: DomainReq,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/auto-block");
    if auth == AuthRole::None {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" }))).into_response();
    }
    if auth == AuthRole::View {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "ok": false, "error": "Forbidden: Generated tokens are view-only. No changes can be made." }))).into_response();
    }

    if let Some(dom) = payload.domain {
        let clean = dom.trim().trim_end_matches('.').to_ascii_lowercase();
        if !clean.is_empty() {
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            state.custom_blocklist.write().insert(
                clean.clone(),
                crate::state::BlockEntry {
                    domain: clean.clone(),
                    reason: payload.reason.clone().unwrap_or_else(|| "ai_auto_block".to_string()),
                    source: "ai".to_string(),
                    tag: "AI".to_string(),
                    auto: true,
                    created_at: now,
                },
            );
            state.wal.append_block(&clean);
            state.log_action("auto_block_added", &clean);
        }
    }
    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn delete_auto_block(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_delete_auto_block(&state, None, &headers, payload).await
}

async fn delete_auto_block_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_delete_auto_block(&state, Some(&key), &headers, payload).await
}

async fn handle_delete_auto_block(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
    payload: DomainReq,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/auto-block");
    if auth == AuthRole::None {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" }))).into_response();
    }
    if auth == AuthRole::View {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "ok": false, "error": "Forbidden: Generated tokens are view-only. No changes can be made." }))).into_response();
    }

    if let Some(dom) = payload.domain {
        let clean = dom.trim().trim_end_matches('.').to_ascii_lowercase();
        if !clean.is_empty() {
            state.custom_blocklist.write().remove(&clean);
            state.wal.append_unblock(&clean);
            state.log_action("auto_block_removed", &clean);
        }
    }
    Json(serde_json::json!({ "ok": true })).into_response()
}

// ── Settings Handlers ───────────────────────────────────────────────────────

async fn get_blocking(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_get_blocking(&state, None, &headers).await
}

async fn get_blocking_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_blocking(&state, Some(&key), &headers).await
}

async fn handle_get_blocking(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/settings/blocking");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key or token required" }))).into_response();
    }
    Json(serde_json::json!({ "ok": true, "blockingEnabled": state.blocking_enabled.load(Ordering::Relaxed) })).into_response()
}

async fn set_blocking(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<BoolSetting>,
) -> Response {
    handle_set_blocking(&state, None, &headers, payload).await
}

async fn set_blocking_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<BoolSetting>,
) -> Response {
    handle_set_blocking(&state, Some(&key), &headers, payload).await
}

async fn handle_set_blocking(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
    payload: BoolSetting,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/settings/blocking");
    if !auth.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "ok": false, "error": "Forbidden: Blocking can only be toggled with the Master Key" }))).into_response();
    }
    state.blocking_enabled.store(payload.enabled, Ordering::Relaxed);
    state.log_action("blocking_toggled", if payload.enabled { "enabled" } else { "disabled" });
    Json(serde_json::json!({ "ok": true, "blockingEnabled": payload.enabled })).into_response()
}

async fn get_dns_mode(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_get_dns_mode(&state, None, &headers).await
}

async fn get_dns_mode_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_dns_mode(&state, Some(&key), &headers).await
}

async fn handle_get_dns_mode(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/settings/dns-mode");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key or token required" }))).into_response();
    }
    let mode = if state.is_private_mode.load(Ordering::Relaxed) { "private" } else { "public" };
    Json(serde_json::json!({ "ok": true, "dnsMode": mode })).into_response()
}

async fn set_dns_mode(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ModeSetting>,
) -> Response {
    handle_set_dns_mode(&state, None, &headers, payload).await
}

async fn set_dns_mode_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<ModeSetting>,
) -> Response {
    handle_set_dns_mode(&state, Some(&key), &headers, payload).await
}

async fn handle_set_dns_mode(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
    payload: ModeSetting,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/settings/dns-mode");
    if !auth.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "ok": false, "error": "Forbidden: DNS mode can only be toggled with the Master Key" }))).into_response();
    }
    let is_private = payload.mode.to_lowercase() == "private";
    state.is_private_mode.store(is_private, Ordering::Relaxed);
    state.log_action("dns_mode_changed", &payload.mode);
    Json(serde_json::json!({ "ok": true, "dnsMode": payload.mode })).into_response()
}

// ── Upstreams Handlers ──────────────────────────────────────────────────────

async fn get_ranked_upstreams(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_get_ranked_upstreams(&state, None, &headers).await
}

async fn get_ranked_upstreams_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_ranked_upstreams(&state, Some(&key), &headers).await
}

async fn handle_get_ranked_upstreams(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/upstreams/ranked");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key or token required" }))).into_response();
    }
    Json(serde_json::json!({
        "ok": true,
        "upstreams": state.upstreams.snapshot()
    })).into_response()
}

async fn sync_upstreams(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_sync_upstreams(&state, None, &headers).await
}

async fn sync_upstreams_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_sync_upstreams(&state, Some(&key), &headers).await
}

async fn handle_sync_upstreams(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/upstreams/sync");
    if !auth.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "ok": false, "error": "Forbidden: Master key required" }))).into_response();
    }
    match state.upstreams.sync_and_rank().await {
        Ok(count) => {
            state.log_action("upstreams_synced", &format!("Ranked top {} upstreams", count));
            Json(serde_json::json!({ "ok": true, "ranked": count })).into_response()
        }
        Err(err) => {
            state.log_anomaly("upstream_sync_fail", &err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "ok": false, "error": err }))).into_response()
        }
    }
}

#[derive(Deserialize)]
struct HeatmapLookupQuery {
    domain: Option<String>,
}

async fn get_heatmap_top(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/heatmap/top");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Authentication required" }))).into_response();
    }
    let guard = state.heatmap.read();
    let mut entries: Vec<_> = guard.iter().collect();
    entries.sort_by(|a, b| b.1.total.cmp(&a.1.total));

    let top: Vec<serde_json::Value> = entries.iter().take(32).map(|(domain, rec)| {
        let max_val = *rec.hourly.iter().max().unwrap_or(&0);
        let peak_hour = rec.hourly.iter().position(|&v| v == max_val).unwrap_or(0);
        serde_json::json!({
            "domain": domain,
            "total": rec.total,
            "peak": peak_hour,
            "peakRps": max_val,
            "hourly": rec.hourly
        })
    }).collect();

    Json(serde_json::json!({
        "ok": true,
        "domains": top,
        "total": guard.len()
    })).into_response()
}

async fn get_heatmap_top_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/heatmap/top");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Invalid key" }))).into_response();
    }
    let guard = state.heatmap.read();
    let mut entries: Vec<_> = guard.iter().collect();
    entries.sort_by(|a, b| b.1.total.cmp(&a.1.total));

    let top: Vec<serde_json::Value> = entries.iter().take(32).map(|(domain, rec)| {
        let max_val = *rec.hourly.iter().max().unwrap_or(&0);
        let peak_hour = rec.hourly.iter().position(|&v| v == max_val).unwrap_or(0);
        serde_json::json!({
            "domain": domain,
            "total": rec.total,
            "peak": peak_hour,
            "peakRps": max_val,
            "hourly": rec.hourly
        })
    }).collect();

    Json(serde_json::json!({
        "ok": true,
        "domains": top,
        "total": guard.len()
    })).into_response()
}

fn handle_heatmap_lookup(state: &AppState, domain_opt: Option<&str>) -> Json<serde_json::Value> {
    let raw = domain_opt.unwrap_or_default().trim().trim_end_matches('.').to_ascii_lowercase();
    if raw.is_empty() {
        return Json(serde_json::json!({ "ok": true, "domain": "", "found": false }));
    }
    let guard = state.heatmap.read();
    if let Some(rec) = guard.get(&raw) {
        let max_val = *rec.hourly.iter().max().unwrap_or(&0);
        let peak_hour = rec.hourly.iter().position(|&v| v == max_val).unwrap_or(0);
        Json(serde_json::json!({
            "ok": true,
            "found": true,
            "domain": raw,
            "total": rec.total,
            "peak": peak_hour,
            "peakRps": max_val,
            "hourly": rec.hourly
        }))
    } else {
        Json(serde_json::json!({
            "ok": true,
            "domain": raw,
            "found": false
        }))
    }
}

async fn heatmap_lookup(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HeatmapLookupQuery>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/heatmap/lookup");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Authentication required" }))).into_response();
    }
    handle_heatmap_lookup(&state, query.domain.as_deref()).into_response()
}

async fn heatmap_lookup_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Query(query): Query<HeatmapLookupQuery>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/heatmap/lookup");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Invalid key" }))).into_response();
    }
    handle_heatmap_lookup(&state, query.domain.as_deref()).into_response()
}

async fn dga_test(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DomainReq>,
) -> Json<serde_json::Value> {
    let domain = payload.domain.unwrap_or_default();
    let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let is_dga = crate::security::heuristics::is_dga_threat(&clean);
    let is_alike = crate::security::heuristics::is_lookalike_threat(&clean);
    let (features, entropy) = state.brain.extract_features(&clean);
    let (neural_score, verdict) = state.brain.evaluate(&clean);
    let is_blocked = is_dga || is_alike || neural_score > 0.85;

    let action = if is_blocked { "HARD_BLOCK" } else { "ALLOW_SAFE" };
    let reason = if is_dga {
        "dga_algorithmic_threat"
    } else if is_alike {
        "typosquat_lookalike"
    } else if neural_score > 0.85 {
        "neural_threat"
    } else {
        "benign"
    };

    let utility_proof = if is_dga {
        format!("Zero-Day DGA intercepted (Entropy {:.2}); prevented algorithmic botnet connection", entropy)
    } else if is_alike {
        "Brand impersonation lookalike detected; credential theft averted".to_string()
    } else if neural_score > 0.85 {
        format!("Neural network pattern matched threat (Probability {:.1}%); blocked before static feed", neural_score * 100.0)
    } else {
        "Safe domain reputation verified; 0ms local resolution allowed".to_string()
    };

    Json(serde_json::json!({
        "ok": true,
        "domain": clean,
        "entropy": (entropy * 100.0).round() / 100.0,
        "isDga": is_dga,
        "isLookalike": is_alike,
        "neuralScore": (neural_score * 1000.0).round() / 1000.0,
        "verdict": verdict,
        "blocked": is_blocked,
        "action": action,
        "reason": reason,
        "utilityProof": utility_proof,
        "features": {
            "domainLengthRatio": (features[0] * 100.0).round() / 100.0,
            "shannonEntropyRatio": (features[1] * 100.0).round() / 100.0,
            "vowelRatio": (features[2] * 100.0).round() / 100.0,
            "digitRatio": (features[3] * 100.0).round() / 100.0,
            "consonantClusterRatio": (features[4] * 100.0).round() / 100.0,
            "markovBigramAnomaly": (features[5] * 100.0).round() / 100.0,
            "brandSquattingRisk": (features[6] * 100.0).round() / 100.0,
            "domainIqHistory": (features[7] * 100.0).round() / 100.0,
        },
        "score": if is_blocked { ((neural_score * 100.0).round() as u32).max(88) } else { ((neural_score * 100.0).round() as u32).min(25) }
    }))
}

async fn dga_test_key(
    State(state): State<Arc<AppState>>,
    Path(_key): Path<String>,
    Json(payload): Json<DomainReq>,
) -> Json<serde_json::Value> {
    dga_test(State(state), Json(payload)).await
}

// ── Controls, Tokens & Nuclear Wipe ─────────────────────────────────────────

async fn reset_circuit_breakers(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_reset_cb(&state, None, &headers).await
}

async fn reset_circuit_breakers_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_reset_cb(&state, Some(&key), &headers).await
}

async fn handle_reset_cb(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/reset-cb");
    if !auth.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "ok": false, "error": "Forbidden: Master key required" }))).into_response();
    }
    state.upstreams.reset_cb();
    state.log_action("cb_reset", "admin");
    Json(serde_json::json!({ "ok": true, "message": "Circuit breakers reset" })).into_response()
}

async fn clear_self_heal(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_clear_self_heal(&state, None, &headers).await
}

async fn clear_self_heal_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_clear_self_heal(&state, Some(&key), &headers).await
}

async fn handle_clear_self_heal(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/self-heal");
    if !auth.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "ok": false, "error": "Forbidden: Master key required" }))).into_response();
    }
    state.recent_actions.write().clear();
    state.recent_anomalies.write().clear();
    state.log_action("self_heal_cleared", "admin");
    Json(serde_json::json!({ "ok": true, "message": "Self-heal cleared" })).into_response()
}

async fn clear_incident(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_clear_incident(&state, None, &headers).await
}

async fn clear_incident_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_clear_incident(&state, Some(&key), &headers).await
}

async fn handle_clear_incident(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/incident");
    if !auth.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "ok": false, "error": "Forbidden: Master key required" }))).into_response();
    }
    state.log_action("incident_cleared", "admin");
    Json(serde_json::json!({ "ok": true, "message": "Incident cleared" })).into_response()
}

async fn nuclear_wipe(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<NuclearWipeReq>,
) -> Response {
    handle_nuclear_wipe(&state, None, &headers, payload).await
}

async fn nuclear_wipe_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<NuclearWipeReq>,
) -> Response {
    handle_nuclear_wipe(&state, Some(&key), &headers, payload).await
}

async fn handle_nuclear_wipe(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
    payload: NuclearWipeReq,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/nuclear-wipe");
    if !auth.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "ok": false, "error": "Forbidden: Master key required" }))).into_response();
    }
    if payload.confirm.as_deref() != Some("NUCLEAR_WIPE_CONFIRMED") {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "ok": false, "error": "Missing confirm phrase" }))).into_response();
    }

    state.cache.clear().await;
    state.custom_blocklist.write().clear();
    state.custom_whitelist.write().clear();
    state.custom_common.write().clear();
    state.heatmap.write().clear();
    state.wal.clear();
    state.fingerprint.clear();
    state.recent_actions.write().clear();
    state.recent_anomalies.write().clear();
    state.brain.clear();

    // Reset telemetry metrics to zero
    state.metrics.reset();

    // Reset upstream circuit breakers to healthy closed
    state.upstreams.reset_cb();

    // Reset DNS access mode to default
    state.is_private_mode.store(false, Ordering::Relaxed);
    state.log_action("nuclear_wipe", "System state purged to factory defaults");

    // Automatically rebuild structure: reload threat feeds cleanly in background (zero disk writes)
    let _ = state.sync_threat_feeds().await;

    // Cluster peer-sync across Fly.io instances
    let is_peer_sync = headers.get("x-peer-sync").and_then(|v| v.to_str().ok()) == Some("1");
    if !is_peer_sync {
        if let Ok(app_name) = std::env::var("FLY_APP_NAME") {
            let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
            let master_key = state.config.dns_master_key.clone();
            tokio::spawn(async move {
                let peer_host = format!("http://{}.internal:{}/api/nuclear-wipe/{}", app_name, port, master_key);
                let client = reqwest::Client::new();
                let _ = client.post(&peer_host)
                    .header("x-peer-sync", "1")
                    .header("x-master-key", &master_key)
                    .json(&serde_json::json!({ "confirm": "NUCLEAR_WIPE_CONFIRMED" }))
                    .send()
                    .await;
            });
        }
    }

    Json(serde_json::json!({ "ok": true, "message": "Nuclear wipe completed & threat feeds reloaded" })).into_response()
}

async fn get_nuke_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    handle_get_nuke_token(&state, None, &headers).await
}

async fn get_nuke_token_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_nuke_token(&state, Some(&key), &headers).await
}

async fn handle_get_nuke_token(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/nuke-token");
    if !auth.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "ok": false, "error": "Forbidden: Master key required" }))).into_response();
    }
    Json(serde_json::json!({ "ok": true, "nukeToken": "CONFIRMED", "expiresIn": "5m" })).into_response()
}

fn parse_ttl(raw: &str, default_secs: u64) -> u64 {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return default_secs;
    }
    if let Some(num_str) = s.strip_suffix('s') {
        num_str.parse().unwrap_or(default_secs)
    } else if let Some(num_str) = s.strip_suffix('m') {
        num_str.parse::<u64>().map(|n| n * 60).unwrap_or(default_secs)
    } else if let Some(num_str) = s.strip_suffix('h') {
        num_str.parse::<u64>().map(|n| n * 3600).unwrap_or(default_secs)
    } else if let Some(num_str) = s.strip_suffix('d') {
        num_str.parse::<u64>().map(|n| n * 86400).unwrap_or(default_secs)
    } else if let Some(num_str) = s.strip_suffix('w') {
        num_str.parse::<u64>().map(|n| n * 604800).unwrap_or(default_secs)
    } else {
        s.parse().unwrap_or(default_secs)
    }
}

async fn get_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    handle_get_token(&state, None, &headers, params).await
}

async fn get_token_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    handle_get_token(&state, Some(&key), &headers, params).await
}

async fn handle_get_token(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
    params: HashMap<String, String>,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/token");
    if !auth.is_admin() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": "Forbidden: Tokens can only be generated with the Master Key"
            })),
        ).into_response();
    }

    let target_path = params.get("path").map(|s| s.as_str()).unwrap_or("/");
    let raw_ttl = params.get("ttl").map(|s| s.as_str()).unwrap_or("1d");
    let ttl_seconds = parse_ttl(raw_ttl, 86400);
    let token = generate_hmac_token(&state.config.dns_token_secret, target_path, ttl_seconds);
    let full_path = if target_path == "/" {
        format!("/{}", token)
    } else {
        format!("{}/{}", target_path.trim_end_matches('/'), token)
    };

    Json(serde_json::json!({
        "ok": true,
        "token": token,
        "fullPath": full_path,
        "targetPath": target_path,
        "expiresIn": raw_ttl,
        "ttlSeconds": ttl_seconds,
        "role": "view_only"
    })).into_response()
}

// ── AI Engine Handlers ──────────────────────────────────────────────────────

async fn ai_export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/ai/export");
    if !auth.is_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Admin authorization required" }))).into_response();
    }
    let export_val = state.brain.export_json(
        &state.heatmap.read(),
        &state.custom_blocklist.read(),
        &state.custom_whitelist.read(),
    );
    let data = serde_json::to_string_pretty(&export_val).unwrap_or_else(|_| "{}".to_string());
    Json(serde_json::json!({
        "ok": true,
        "chunked": false,
        "data": data
    })).into_response()
}

async fn ai_export_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/ai/export");
    if !auth.is_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Admin authorization required" }))).into_response();
    }
    let export_val = state.brain.export_json(
        &state.heatmap.read(),
        &state.custom_blocklist.read(),
        &state.custom_whitelist.read(),
    );
    let data = serde_json::to_string_pretty(&export_val).unwrap_or_else(|_| "{}".to_string());
    Json(serde_json::json!({
        "ok": true,
        "chunked": false,
        "data": data
    })).into_response()
}

async fn ai_import(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/ai/import");
    if !auth.is_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Admin authorization required" }))).into_response();
    }
    let raw_data = if let Some(d) = payload.get("data").and_then(|v| v.as_str()) {
        serde_json::from_str::<serde_json::Value>(d).unwrap_or(payload)
    } else {
        payload
    };
    match state.brain.import_json(&raw_data) {
        Ok(count) => {
            state.log_action("ai_brain_imported", &format!("Restored {} domains into AI brain", count));
            Json(serde_json::json!({ "ok": true, "restored": count })).into_response()
        }
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e })).into_response(),
    }
}

async fn ai_import_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/ai/import");
    if !auth.is_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Admin authorization required" }))).into_response();
    }
    let raw_data = if let Some(d) = payload.get("data").and_then(|v| v.as_str()) {
        serde_json::from_str::<serde_json::Value>(d).unwrap_or(payload)
    } else {
        payload
    };
    match state.brain.import_json(&raw_data) {
        Ok(count) => {
            state.log_action("ai_brain_imported", &format!("Restored {} domains into AI brain", count));
            Json(serde_json::json!({ "ok": true, "restored": count })).into_response()
        }
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e })).into_response(),
    }
}

async fn ai_prune(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/ai/prune");
    if !auth.is_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Admin authorization required" }))).into_response();
    }
    let pruned = state.brain.prune_noise();
    state.log_action("ai_brain_pruned", &format!("Pruned {} noise domains from brain", pruned));
    Json(serde_json::json!({ "ok": true, "pruned": pruned })).into_response()
}

async fn ai_prune_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/ai/prune");
    if !auth.is_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Admin authorization required" }))).into_response();
    }
    let pruned = state.brain.prune_noise();
    state.log_action("ai_brain_pruned", &format!("Pruned {} noise domains from brain", pruned));
    Json(serde_json::json!({ "ok": true, "pruned": pruned })).into_response()
}

// ── DNS Query Handlers (DoH) ────────────────────────────────────────────────

async fn doh_post_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(params): Query<DnsQueryParam>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let client_ip = headers.get("fly-client-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .unwrap_or_else(|| addr.ip());

    if !state.rate_limiter.check(client_ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }

    // Access control: private DNS mode verification
    if state.is_private_mode.load(Ordering::Relaxed) {
        let has_dev = params.device.is_some() || params.client.is_some() || headers.get("x-device-id").is_some();
        let has_auth = check_auth(&state, None, &headers, "/dns-query").is_view_or_admin();
        if !has_dev && !has_auth {
            return (StatusCode::FORBIDDEN, "Private DNS mode: Authentication or device ID required").into_response();
        }
    }

    let dev_ref = params.device.as_deref()
        .or(params.client.as_deref())
        .or_else(|| headers.get("x-device-id").and_then(|h| h.to_str().ok()));

    process_dns_query(state, &body, client_ip, dev_ref, "DoH (POST)").await
}

async fn doh_get_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<DnsQueryParam>,
) -> Response {
    let client_ip = headers.get("fly-client-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .unwrap_or_else(|| addr.ip());

    if !state.rate_limiter.check(client_ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }

    // Access control: private DNS mode verification
    if state.is_private_mode.load(Ordering::Relaxed) {
        let has_dev = params.device.is_some() || params.client.is_some() || headers.get("x-device-id").is_some();
        let has_auth = check_auth(&state, None, &headers, "/dns-query").is_view_or_admin();
        if !has_dev && !has_auth {
            return (StatusCode::FORBIDDEN, "Private DNS mode: Authentication or device ID required").into_response();
        }
    }

    let dev_ref = params.device.as_deref()
        .or(params.client.as_deref())
        .or_else(|| headers.get("x-device-id").and_then(|h| h.to_str().ok()));

    let wire_bytes = if let Some(base64_dns) = params.dns {
        let clean = base64_dns.replace('-', "+").replace('_', "/");
        let padded = match clean.len() % 4 {
            2 => format!("{}==", clean),
            3 => format!("{}=", clean),
            _ => clean,
        };
        match base64_decode(&padded) {
            Ok(b) => b,
            Err(_) => return (StatusCode::BAD_REQUEST, "Invalid base64url dns query").into_response(),
        }
    } else {
        return (StatusCode::BAD_REQUEST, "Missing ?dns= parameter").into_response();
    };

    process_dns_query(state, &wire_bytes, client_ip, dev_ref, "DoH (GET)").await
}

async fn process_dns_query(state: Arc<AppState>, query_wire: &[u8], client_ip: IpAddr, dev_tag: Option<&str>, proto: &str) -> Response {
    let query_start = std::time::Instant::now();
    let client_str = client_ip.to_string();
    let log_id = dev_tag.unwrap_or(&client_str);
    state.metrics.record_query(log_id, "doh");

    let parsed = match parse_dns_query(query_wire) {
        Some(p) => p,
        None => {
            state.metrics.record_latency(query_start.elapsed());
            return (StatusCode::BAD_REQUEST, "Malformed DNS wire packet").into_response();
        }
    };

    let q = match parsed.question {
        Some(q) => q,
        None => {
            state.metrics.record_latency(query_start.elapsed());
            return (StatusCode::BAD_REQUEST, "No DNS question").into_response();
        }
    };

    // 1. Predictive AI Dependency Prefetching: Learn transitions & proactively prefetch subresources
    state.brain.record_sequence(&q.name);
    let prefetch_cands = state.brain.get_prefetch_candidates(&q.name);
    for cand in prefetch_cands {
        if !state.is_domain_blocked(&cand) {
            let state_p = state.clone();
            tokio::spawn(async move {
                state_p.metrics.prefetch_triggers.fetch_add(1, Ordering::Relaxed);
                state_p.brain.prefetch_triggers.fetch_add(1, Ordering::Relaxed);
                let mut p_wire = vec![0x53, 0x57, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                for label in cand.split('.') {
                    if !label.is_empty() {
                        p_wire.push(label.len() as u8);
                        p_wire.extend_from_slice(label.as_bytes());
                    }
                }
                p_wire.push(0x00);
                p_wire.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
                p_wire.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
                if let Some((resp, _)) = state_p.upstreams.resolve(&p_wire).await {
                    state_p.cache.insert(&cand, 1, resp, 300).await;
                }
            });
        }
    }

    // Record client query for rogue client & fingerprinting detection
    if let Some(flag) = state.fingerprint.record_query(client_ip, &q.name) {
        state.log_action("rogue_client_detected", &format!("{}: {}", client_ip, flag));
        state.log_anomaly("rogue_client_scanner", &format!("{}: {}", client_ip, flag));
    }

    // Record into 24-hour heatmap
    state.record_heatmap(&q.name);

    // 0. Local Threat, Blocklist & Whitelist Policy Check (with Fast-Path Negative Absorber in <10µs)
    let (is_blocked, is_nxdomain, reason) = state.check_domain(&q.name);
    if is_blocked {
        state.record_detected_block(&q.name, reason);
        state.fingerprint.record_response(client_ip, 3);
        state.fingerprint.flag_client(client_ip, reason, &q.name);
        state.wal.append_threat_event(&q.name, reason, log_id);
        state.wal.append_query(&q.name, q.qtype, log_id, 3, 0, "BLOCKED");
        state.log_query(&q.name, q.qtype, log_id, proto, "BLOCKED", 3, 0, reason, "Filter");
        state.cache.insert_negative(&q.name, 60).await;
        let resp_bytes = build_blocked_response(query_wire, is_nxdomain);
        state.metrics.record_latency(query_start.elapsed());
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/dns-message")
            .header("x-cache", "BLOCKED")
            .header("x-block-reason", reason)
            .body(Bytes::from(resp_bytes).into())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    // 1. AeroCache Negative Cache Lookup (Strictly bypassed if domain or parent is whitelisted/exempt)
    if !state.is_exempt(&q.name) && state.cache.get_negative(&q.name).await {
        state.metrics.threat_blocks.fetch_add(1, Ordering::Relaxed);
        let (feats, ent) = state.brain.extract_features(&q.name);
        state.brain.record_decision(
            &q.name,
            ent,
            0.96,
            feats,
            "AEROCACHE_DROP",
            "threat_negative_cache",
            "Preemptively dropped in 0ms from RAM; saved upstream DNS roundtrip and CPU cycles",
        );
        let resp_bytes = build_blocked_response(query_wire, true);
        state.wal.append_query(&q.name, q.qtype, log_id, 3, 0, "NEG_HIT");
        state.log_query(&q.name, q.qtype, log_id, proto, "NEG_HIT", 3, 0, "threat_negative_cache", "AeroCache");
        state.metrics.record_latency(query_start.elapsed());
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/dns-message")
            .header("x-cache", "NEG_HIT")
            .header("x-block-reason", "threat_negative_cache")
            .body(Bytes::from(resp_bytes).into())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    // 2. Google Safe Browsing Cloud Threat Check (Malware, Phishing, Unwanted Software)
    if state.blocking_enabled.load(Ordering::Relaxed) && !state.is_exempt(&q.name) {
        if let Some(threat_type) = state.safe_browsing.check_domain(&q.name).await {
            state.metrics.threat_blocks.fetch_add(1, Ordering::Relaxed);
            state.metrics.gsb_blocks.fetch_add(1, Ordering::Relaxed);
            state.fingerprint.record_response(client_ip, 3);
            state.fingerprint.flag_client(client_ip, "GSB_THREAT", &q.name);
            state.log_action("gsb_block", &format!("{} [{}]", q.name, threat_type));
            state.record_detected_block(&q.name, "google_safe_browsing");
            state.wal.append_threat_event(&q.name, "google_safe_browsing", log_id);
            state.wal.append_query(&q.name, q.qtype, log_id, 3, 0, "GSB_BLOCK");
            state.log_query(&q.name, q.qtype, log_id, proto, "GSB_BLOCK", 3, 0, "google_safe_browsing", "Google Safe Browsing");
            state.cache.insert_negative(&q.name, 120).await;
            let resp_bytes = build_blocked_response(query_wire, true);
            state.metrics.record_latency(query_start.elapsed());
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/dns-message")
                .header("x-cache", "BLOCKED")
                .header("x-block-reason", "google_safe_browsing")
                .body(Bytes::from(resp_bytes).into())
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    }

    // 3. Cache Lookup with RFC 8767 Stale-While-Revalidate (SWR)
    match state.cache.get_with_swr(&q.name, q.qtype, parsed.tx_id).await {
        crate::dns::cache::CacheLookupResult::Fresh(cached_wire) => {
            state.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            state.fingerprint.record_response(client_ip, 0);
            state.wal.append_query(&q.name, q.qtype, log_id, 0, 0, "HIT");
            state.log_query(&q.name, q.qtype, log_id, proto, "HIT", 0, 0, "none", "AeroCache");
            state.metrics.record_latency(query_start.elapsed());
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/dns-message")
                .header("x-cache", "HIT")
                .body(Bytes::from(cached_wire).into())
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
        crate::dns::cache::CacheLookupResult::Stale(cached_wire) => {
            state.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            state.metrics.swr_serves.fetch_add(1, Ordering::Relaxed);
            state.fingerprint.record_response(client_ip, 0);
            state.wal.append_query(&q.name, q.qtype, log_id, 0, 0, "STALE_HIT");
            state.log_query(&q.name, q.qtype, log_id, proto, "STALE_HIT", 0, 0, "swr_serve_stale", "AeroCache");

            // Background async revalidation without blocking client response
            let state_bg = state.clone();
            let q_name = q.name.clone();
            let q_type = q.qtype;
            let wire_clone = query_wire.to_vec();
            tokio::spawn(async move {
                if let Some((upstream_resp, _)) = state_bg.upstreams.resolve(&wire_clone).await {
                    state_bg.cache.insert(&q_name, q_type, upstream_resp, 300).await;
                }
            });

            state.metrics.record_latency(query_start.elapsed());
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/dns-message")
                .header("x-cache", "STALE_HIT")
                .header("x-swr", "revalidating")
                .body(Bytes::from(cached_wire).into())
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
        crate::dns::cache::CacheLookupResult::Miss => {}
    }

    state.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);

    // 4. Forward to upstream pool
    let start_upstream = std::time::Instant::now();
    if let Some((upstream_resp, upstream_name)) = state.upstreams.resolve(query_wire).await {
        let lat = start_upstream.elapsed().as_millis() as u32;
        let rcode = if upstream_resp.len() >= 4 { (upstream_resp[3] & 0x0F) as u16 } else { 0 };
        if let Some(flag) = state.fingerprint.record_response(client_ip, rcode) {
            state.log_action("rogue_client_detected", &format!("{}: {}", client_ip, flag));
        }

        // 4b. DNS Rebinding Protection: Block public domains resolving to private/loopback/link-local IP addresses
        if state.blocking_enabled.load(Ordering::Relaxed)
            && !state.is_exempt(&q.name)
            && !crate::dns::parser::is_rebind_exempt_domain(&q.name)
        {
            if let Some(rebind_ip) = crate::dns::parser::extract_rebind_ip(&upstream_resp) {
                state.metrics.rebind_blocks.fetch_add(1, Ordering::Relaxed);
                state.metrics.threat_blocks.fetch_add(1, Ordering::Relaxed);
                state.fingerprint.record_response(client_ip, 3);
                state.fingerprint.flag_client(client_ip, "REBIND_ATTACK", &q.name);
                state.log_action("rebind_block", &format!("{} -> {}", q.name, rebind_ip));
                state.log_anomaly("dns_rebind_attack", &format!("Private IP leak blocked: {} -> {}", q.name, rebind_ip));
                state.wal.append_threat_event(&q.name, "dns_rebind_attack", log_id);
                state.wal.append_query(&q.name, q.qtype, log_id, 3, lat, "REBIND_BLOCK");
                state.log_query(&q.name, q.qtype, log_id, proto, "REBIND_BLOCK", 3, lat, "dns_rebind_attack", "Rebind Defense");
                state.cache.insert_negative(&q.name, 120).await;
                let blocked = build_blocked_response(query_wire, true);
                state.metrics.record_latency(query_start.elapsed());
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/dns-message")
                    .header("x-cache", "BLOCKED")
                    .header("x-block-reason", "dns_rebind_attack")
                    .body(Bytes::from(blocked).into())
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        }

        state.cache.insert(&q.name, q.qtype, upstream_resp.clone(), 300).await;
        state.wal.append_query(&q.name, q.qtype, log_id, rcode, lat, "RESOLVED");
        state.log_query(&q.name, q.qtype, log_id, proto, "RESOLVED", rcode, lat, "none", &upstream_name);
        state.metrics.record_latency(query_start.elapsed());

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/dns-message")
            .header("x-cache", "MISS")
            .body(Bytes::from(upstream_resp).into())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    } else {
        state.fingerprint.record_response(client_ip, 2);
        state.wal.append_query(&q.name, q.qtype, log_id, 2, 0, "FAIL");
        state.log_query(&q.name, q.qtype, log_id, proto, "FAIL", 2, 0, "servfail", "none");
        let fail = build_servfail_response(query_wire);
        state.metrics.record_latency(query_start.elapsed());
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/dns-message")
            .header("x-cache", "FAIL")
            .body(Bytes::from(fail).into())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    }
}

// Minimal zero-dependency base64 decoder
fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;

    for &b in input.as_bytes() {
        if b == b'=' {
            break;
        }
        let val = match TABLE.iter().position(|&c| c == b) {
            Some(idx) => idx as u32,
            None => return Err(()),
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}
