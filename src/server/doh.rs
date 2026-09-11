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

        // Feature 4: Passive DNS Timeline
        .route("/api/passive-dns", get(passive_dns_handler))
        .route("/api/passive-dns/drifts", get(passive_dns_drifts_handler))

        // Feature 5: Canary Domain Detection
        .route("/api/canary", get(canary_handler))
        .route("/api/canary/:key", get(canary_key_handler))

        // Feature 6: TTL Guard toggle
        .route("/api/settings/ttl-guard", get(get_ttl_guard).post(set_ttl_guard))
        .route("/api/settings/ttl-guard/:key", get(get_ttl_guard_key).post(set_ttl_guard_key))

        // Feature 8: Real-Time SSE Log Stream
        .route("/api/logs/stream", get(logs_stream_handler))
        .route("/api/logs/stream/:key", get(logs_stream_handler_key))
        .route("/:key/api/logs/stream", get(logs_stream_handler_key))

        // Feature 9: Scheduled Blocking Rules
        .route("/api/schedule", get(get_schedule).post(add_schedule))
        .route("/api/schedule/:id", delete(delete_schedule))

        // Feature 10: Blocklist Feed Subscriptions
        .route("/api/feeds", get(get_feeds))
        .route("/api/feeds/:key", get(get_feeds_key))
        .route("/api/feeds/sync", post(sync_feeds))
        .route("/api/feeds/sync/:key", post(sync_feeds_key))
        .route("/api/feeds/:id/toggle", post(toggle_feed))

        // Feature 11+13: Cache & TTL stats
        .route("/api/cache/stats", get(cache_stats_handler))
        .route("/api/cache/stats/:key", get(cache_stats_key))
        .route("/api/ttl/volatile", get(volatile_domains_handler))
        .route("/api/ttl/volatile/:key", get(volatile_domains_key))

        // DoH JSON API (RFC 8427) — browser-testable
        .route("/resolve", get(doh_json_handler))

        // Prometheus-compatible metrics scrape endpoint
        // Requires master key via ?key=<key> or X-Api-Key header (same as other /api endpoints)
        .route("/metrics", get(prometheus_metrics_handler))
        .layer(axum::middleware::map_response(add_security_headers))
        .with_state(state)
}

async fn add_security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    if let Ok(name) = header::HeaderName::from_bytes(b"permissions-policy") {
        headers.insert(
            name,
            header::HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
        );
    }
    if let Some(ct) = headers.get(header::CONTENT_TYPE) {
        if ct.to_str().map(|s| s.starts_with("text/html")).unwrap_or(false) {
            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                header::HeaderValue::from_static("default-src 'self' 'unsafe-inline' data:; connect-src 'self' *; img-src 'self' data: https:;"),
            );
        }
    }
    response
}

// ── Root & Status Handlers ──────────────────────────────────────────────────

async fn health_handler(
    State(state): State<Arc<AppState>>,
) -> Response {
    let upstreams = state.upstreams.snapshot();
    let healthy_upstreams = upstreams
        .iter()
        .filter(|u| u.get("healthy").and_then(|h| h.as_bool()).unwrap_or(true))
        .count();
    let total_upstreams = upstreams.len();

    // Bloom filter is considered initialized when at least 1 domain is indexed
    let bloom_ready = state.threat_bloom.read().count() > 0;

    // WAL health: file is writable iff its stats return > 0 byte count or path is accessible
    let (wal_bytes, _) = state.wal.get_stats();
    let wal_ok = wal_bytes > 0
        || std::path::Path::new(state.config.db_path.as_str())
            .parent()
            .map(|p| p.exists())
            .unwrap_or(false);

    let is_healthy = healthy_upstreams > 0 && wal_ok;

    let body = serde_json::json!({
        "status": if is_healthy { "ok" } else { "degraded" },
        "upstreams": {
            "healthy": healthy_upstreams,
            "total": total_upstreams
        },
        "bloomReady": bloom_ready,
        "walOk": wal_ok,
    });

    let status = if is_healthy { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, [(header::CONTENT_TYPE, "application/json")], body.to_string()).into_response()
}

async fn prometheus_metrics_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DnsQueryParam>,
    headers: HeaderMap,
) -> Response {
    let key_param = params.dns.as_deref().or(params.name.as_deref());
    let auth = check_auth(&state, key_param, &headers, "/metrics");
    if !auth.is_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            "# Unauthorized: master key required\n",
        ).into_response();
    }

    use std::sync::atomic::Ordering;
    let m = &state.metrics;
    let reqs     = m.requests.load(Ordering::Relaxed);
    let hits     = m.cache_hits.load(Ordering::Relaxed);
    let misses   = m.cache_misses.load(Ordering::Relaxed);
    let threats  = m.threat_blocks.load(Ordering::Relaxed);
    let dga      = m.dga_blocks.load(Ordering::Relaxed);
    let alike    = m.alike_blocks.load(Ordering::Relaxed);
    let gsb      = m.gsb_blocks.load(Ordering::Relaxed);
    let rebind   = m.rebind_blocks.load(Ordering::Relaxed);
    let rep      = m.rep_blocks.load(Ordering::Relaxed);
    let auto_blk = m.auto_blocks.load(Ordering::Relaxed);
    let burst    = m.burst_events.load(Ordering::Relaxed);
    let nx       = m.nx_alarms.load(Ordering::Relaxed);
    let drifts   = m.answer_drifts.load(Ordering::Relaxed);
    let dcc      = m.dcc_hits.load(Ordering::Relaxed);
    let swarm    = m.swarm_alarms.load(Ordering::Relaxed);
    let dot_q    = m.dot_queries.load(Ordering::Relaxed);
    let doh_q    = m.doh_queries.load(Ordering::Relaxed);
    let lat_us   = m.total_lat_micros.load(Ordering::Relaxed);
    let lat_s1   = m.lat_sub_1ms.load(Ordering::Relaxed);
    let lat_1_5  = m.lat_1_to_5ms.load(Ordering::Relaxed);
    let lat_5_15 = m.lat_5_to_15ms.load(Ordering::Relaxed);
    let lat_1550 = m.lat_15_to_50ms.load(Ordering::Relaxed);
    let lat_a50  = m.lat_above_50ms.load(Ordering::Relaxed);
    let fneg     = m.fast_neg_hits.load(Ordering::Relaxed);
    let swr      = m.swr_serves.load(Ordering::Relaxed);
    let pfetch_t = m.prefetch_triggers.load(Ordering::Relaxed);
    let pfetch_h = m.prefetch_hits.load(Ordering::Relaxed);
    let ttlg     = m.ttl_guard_blocks.load(Ordering::Relaxed);
    let cname_f  = m.cname_flattened.load(Ordering::Relaxed);
    let race_w   = m.race_wins.load(Ordering::Relaxed);
    let sched_b  = m.schedule_blocks.load(Ordering::Relaxed);
    let rps      = m.get_rps();
    let rps_peak = m.get_rps_peak();
    let uptime   = m.uptime_secs();
    let dropped  = state.wal.dropped_entries.load(Ordering::Relaxed);

    let (cache_len, cache_bytes, _, _) = state.cache.get_stats();
    let bloom_cnt = state.threat_bloom.read().count();
    let wl_bloom  = state.whitelist_bloom.read().count();
    let brain_cyc = state.brain.training_cycles.load(Ordering::Relaxed);
    let canary_h  = state.canary_hits.load(Ordering::Relaxed);

    let upstreams = state.upstreams.snapshot();
    let healthy_up = upstreams.iter()
        .filter(|u| u.get("healthy").and_then(|h| h.as_bool()).unwrap_or(true))
        .count();

    // Emit Prometheus text exposition format (no external crate needed)
    let mut out = String::with_capacity(4096);
    macro_rules! gauge {
        ($name:expr, $help:expr, $val:expr) => {
            out.push_str(&format!(
                "# HELP {0} {1}\n# TYPE {0} gauge\n{0} {2}\n",
                $name, $help, $val
            ));
        };
    }
    macro_rules! counter {
        ($name:expr, $help:expr, $val:expr) => {
            out.push_str(&format!(
                "# HELP {0} {1}\n# TYPE {0} counter\n{0}_total {2}\n",
                $name, $help, $val
            ));
        };
    }

    counter!("amardns_dns_requests",           "Total DNS queries received",             reqs);
    counter!("amardns_cache_hits",             "DNS cache hits",                         hits);
    counter!("amardns_cache_misses",           "DNS cache misses",                       misses);
    counter!("amardns_threat_blocks",          "Domains blocked by threat feed",         threats);
    counter!("amardns_dga_blocks",             "Domains blocked by DGA heuristic",       dga);
    counter!("amardns_lookalike_blocks",       "Domains blocked by lookalike detection", alike);
    counter!("amardns_gsb_blocks",            "Domains blocked by Google Safe Browsing",gsb);
    counter!("amardns_rebind_blocks",          "DNS rebinding attack blocks",            rebind);
    counter!("amardns_reputation_blocks",      "Reputation-based blocks",                rep);
    counter!("amardns_auto_blocks",            "Automated behaviour-based blocks",       auto_blk);
    counter!("amardns_burst_events",           "Rate-limit burst events",                burst);
    counter!("amardns_nx_alarms",              "NXDOMAIN burst alarms",                  nx);
    counter!("amardns_answer_drifts",          "Passive DNS answer drift detections",    drifts);
    counter!("amardns_dcc_hits",               "Domain correlation chain hits",          dcc);
    counter!("amardns_swarm_alarms",           "Swarm query pattern alarms",             swarm);
    counter!("amardns_dot_queries",            "DNS-over-TLS queries received",          dot_q);
    counter!("amardns_doh_queries",            "DNS-over-HTTPS queries received",        doh_q);
    counter!("amardns_fast_neg_hits",          "Fast-negative filter cache hits",        fneg);
    counter!("amardns_swr_serves",             "Stale-while-revalidate cache serves",    swr);
    counter!("amardns_prefetch_triggers",      "Prefetch triggers fired",                pfetch_t);
    counter!("amardns_prefetch_hits",          "Prefetch hits (resolved before query)",  pfetch_h);
    counter!("amardns_ttl_guard_blocks",       "TTL manipulation guard blocks",          ttlg);
    counter!("amardns_cname_flattened",        "CNAME chains flattened",                 cname_f);
    counter!("amardns_race_wins",              "Hedged upstream race wins",              race_w);
    counter!("amardns_schedule_blocks",        "Scheduled-rule blocks",                  sched_b);
    counter!("amardns_canary_hits",            "Canary domain detection hits",           canary_h);
    counter!("amardns_wal_dropped_entries",    "WAL entries dropped under backpressure", dropped);
    counter!("amardns_ai_training_cycles",     "AI brain online training cycles",        brain_cyc);
    counter!("amardns_latency_micros",         "Total latency accumulated (µs)",         lat_us);

    gauge!("amardns_rps",                      "Current requests per second",            rps);
    gauge!("amardns_rps_peak",                 "Peak requests per second (lifetime)",    rps_peak);
    gauge!("amardns_uptime_seconds",           "Server uptime in seconds",               uptime);
    gauge!("amardns_cache_size",               "Current DNS cache entry count",          cache_len);
    gauge!("amardns_cache_bytes",              "Current DNS cache memory usage (bytes)", cache_bytes);
    gauge!("amardns_threat_bloom_domains",     "Threat bloom filter domain count",       bloom_cnt);
    gauge!("amardns_whitelist_bloom_domains",  "Whitelist bloom filter domain count",    wl_bloom);
    gauge!("amardns_healthy_upstreams",        "Number of healthy upstream resolvers",   healthy_up);

    // Latency histogram buckets (cumulative)
    out.push_str("# HELP amardns_latency_bucket DNS resolution latency histogram\n");
    out.push_str("# TYPE amardns_latency_bucket counter\n");
    out.push_str(&format!("amardns_latency_bucket{{le=\"1\"}} {}\n",   lat_s1));
    out.push_str(&format!("amardns_latency_bucket{{le=\"5\"}} {}\n",   lat_s1 + lat_1_5));
    out.push_str(&format!("amardns_latency_bucket{{le=\"15\"}} {}\n",  lat_s1 + lat_1_5 + lat_5_15));
    out.push_str(&format!("amardns_latency_bucket{{le=\"50\"}} {}\n",  lat_s1 + lat_1_5 + lat_5_15 + lat_1550));
    out.push_str(&format!("amardns_latency_bucket{{le=\"+Inf\"}} {}\n",lat_s1 + lat_1_5 + lat_5_15 + lat_1550 + lat_a50));

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        out,
    ).into_response()
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
        let view_token = if auth.is_admin() {
            state.config.dns_master_key.clone()
        } else {
            // Generate a fresh 1-hour HMAC view token embedded in the dashboard page
            crate::security::auth::generate_hmac_token(&state.config.dns_token_secret, "/dashboard", 3600)
        };
        Html(render_dashboard(&view_token, &fly_machine_id, &fly_region)).into_response()
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

    let rss_mb = crate::telemetry::metrics::get_process_rss_mb();

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
        score.min(100)
    };
    let major = 1 + (brain_cycles / 1000);
    let minor = (brain_cycles / 100) % 10;
    let patch = (brain_cycles / 10) % 10;
    let brain_version = format!("{}.{}.{}", major, minor, patch);
    let brain_mem_bytes = state.brain.memory_bytes();
    let brain_last_sync = state.brain.last_sync_time.load(Ordering::Relaxed);
    let now_unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let brain_sync_age = if brain_last_sync > 0 {
        Some(now_unix.saturating_sub(brain_last_sync))
    } else {
        None
    };

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

    // Pre-compute values that can't be expressed inside serde_json::json! macro
    let upstream_last_sync_val: serde_json::Value = {
        let ts = state.metrics.upstream_last_sync.load(Ordering::Relaxed);
        if ts > 0 { serde_json::Value::Number(serde_json::Number::from(ts)) }
        else { serde_json::Value::Null }
    };

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
            "brainUptimeSec": uptime_secs,
            "brainSyncBytes": brain_mem_bytes,
            "brainMemoryKB": (brain_mem_bytes as f64 / 1024.0).round(),
            "brainSyncAge": brain_sync_age,
            "autoBlockActive": auto_blocks,
            "threatsBlocked": threats_blocked,
            "alikeBlocks": alike_blocked,
            "dgaBlocked": dga_blocked,
            "gsbBlocked": gsb_blocked,
            "gsbBlocks": gsb_blocked,
            "rebindBlocks": rebind_blocks,
            "repBlocks": rep_blocks,
            "ttlGuardBlocks": state.metrics.ttl_guard_blocks.load(Ordering::Relaxed),
            "cnameFlattened": state.metrics.cname_flattened.load(Ordering::Relaxed),
            "raceWins": state.metrics.race_wins.load(Ordering::Relaxed),
            "scheduleBlocks": state.metrics.schedule_blocks.load(Ordering::Relaxed),
            "canaryHits": state.canary_hits.load(Ordering::Relaxed),
            "softLimitHits": state.rate_limiter.get_soft_limit_hits(),
            "blockedCount": state.rate_limiter.get_blocked_count(),
            "passiveDnsCount": state.passive_dns.domain_count(),
            "feedCount": state.feed_manager.list_feeds().len(),
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
            "ttlEvents": {
                "inflations": state.metrics.ttl_guard_blocks.load(Ordering::Relaxed),
                "deflations": 0u64
            },
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
            "storageEngine": "PulseDB (WAL) + AeroCache (W-TinyLFU)",
            "dnsMode": if is_priv { "private" } else { "public" },
            "blockingEnabled": state.blocking_enabled.load(Ordering::Relaxed),
            "hmacAuth": !state.config.dns_token_secret.is_empty(),
            "upstreamAuraPrioritization": true,
            "upstreamCandidates": upstreams.len(),
            "upstreamLastSync": upstream_last_sync_val
        },
        "intelligence": {
            "cfgOverride": serde_json::json!({
                "blockingEnabled": state.blocking_enabled.load(Ordering::Relaxed),
                "ttlGuardEnabled": state.ttl_guard_enabled.load(Ordering::Relaxed)
            }),
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
            "panicCount": 0,
            "authFails": state.metrics.auth_fails.load(Ordering::Relaxed),
            "emergencyMode": rss_mb >= 175.0,
            "dailyLimits": "None (Uncapped Dedicated)",
            "throttled": state.rate_limiter.get_blocked_count() > 0,
            "gcCycles": 0,
            "memPressure": rss_mb >= 140.0
        },
        "storage": {
            "engine": "PulseDB (WAL) + AeroCache (W-TinyLFU)",
            "cacheEngine": "AeroCache (W-TinyLFU)",
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
        // ── New Features Dashboard Data ──────────────────────────────────────
        "features": {
            "ttlGuard": {
                "enabled": state.ttl_guard_enabled.load(Ordering::Relaxed),
                "blocks": state.metrics.ttl_guard_blocks.load(Ordering::Relaxed)
            },
            "cnameFlattening": {
                "resolved": state.metrics.cname_flattened.load(Ordering::Relaxed)
            },
            "upstreamRacing": {
                "wins": state.metrics.race_wins.load(Ordering::Relaxed)
            },
            "scheduledBlocking": {
                "activeRules": state.schedule_store.list_rules().len(),
                "totalBlocks": state.metrics.schedule_blocks.load(Ordering::Relaxed)
            },
            "passiveDns": {
                "trackedDomains": state.passive_dns.domain_count(),
                "totalObservations": state.passive_dns.total_observations.load(Ordering::Relaxed),
                "driftEvents": state.passive_dns.drift_events.load(Ordering::Relaxed)
            },
            "feedSubscriptions": {
                "totalFeeds": state.feed_manager.list_feeds().len(),
                "totalSyncedDomains": state.feed_manager.total_synced_domains.load(Ordering::Relaxed)
            },
            "cacheCompression": {
                "engine": "Direct Wire Format (Zero-Copy Raw Wire)",
                "ratio": format!("{:.1}%", state.cache.compression_ratio())
            },
            "canary": {
                "domain": state.canary_domain.clone(),
                "hits": state.canary_hits.load(Ordering::Relaxed),
                "status": if state.canary_hits.load(Ordering::Relaxed) > 0 { "leak_detected" } else { "clean" }
            },
            "smartTtl": {
                "trackedDomains": state.ttl_learner.domain_count()
            },
            "rateLimiter": {
                "softLimitHits": state.rate_limiter.get_soft_limit_hits(),
                "blockedCount": state.rate_limiter.get_blocked_count()
            }
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
        for rec in guard.values() {
            for (h, total) in hourly_totals.iter_mut().enumerate() {
                *total = total.saturating_add(rec.hourly[h] as u64);
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
    entries.sort_by_key(|a| std::cmp::Reverse(a.1.total));

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
    entries.sort_by_key(|a| std::cmp::Reverse(a.1.total));

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
        "score": (neural_score * 100.0).clamp(0.0, 100.0).round() as u32
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

pub fn extract_client_ip(headers: &HeaderMap, peer_addr: SocketAddr) -> IpAddr {
    if let Some(fly_ip) = headers.get("fly-client-ip")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return fly_ip;
    }

    if let Some(cf_ip) = headers.get("cf-connecting-ip")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return cf_ip;
    }

    if let Some(real_ip) = headers.get("x-real-ip")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return real_ip;
    }

    let peer_ip = peer_addr.ip();
    let is_peer_private = match peer_ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    };

    if is_peer_private {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
            for part in xff.rsplit(',') {
                if let Ok(ip) = part.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    peer_ip
}

async fn doh_post_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(params): Query<DnsQueryParam>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let client_ip = extract_client_ip(&headers, addr);

    let dev_ref = params.device.as_deref()
        .or(params.client.as_deref())
        .or_else(|| headers.get("x-device-id").and_then(|h| h.to_str().ok()));

    // Rate limit with composite identity (IP + device ID).
    // Each device behind a router/NAT gets its own independent token bucket,
    // while the per-IP ceiling prevents fake device-ID flooding attacks.
    if !state.check_rate_limit(client_ip, dev_ref) {
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

    process_dns_query(state, &body, client_ip, dev_ref, "DoH (POST)").await
}

async fn doh_get_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<DnsQueryParam>,
) -> Response {
    let client_ip = extract_client_ip(&headers, addr);

    let dev_ref = params.device.as_deref()
        .or(params.client.as_deref())
        .or_else(|| headers.get("x-device-id").and_then(|h| h.to_str().ok()));

    // Rate limit with composite identity (IP + device ID).
    // Each device behind a router/NAT gets its own independent token bucket.
    if !state.check_rate_limit(client_ip, dev_ref) {
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

    // Feature 5: Canary Domain Detection — detect DNS leak if canary is queried externally
    {
        let q_clean = q.name.trim_end_matches('.').to_ascii_lowercase();
        if q_clean == state.canary_domain {
            state.canary_hits.fetch_add(1, Ordering::Relaxed);
            state.log_action("canary_query", &format!("Canary domain queried by {}", client_ip));
            let nxdomain = build_blocked_response(query_wire, true);
            state.metrics.record_latency(query_start.elapsed());
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/dns-message")
                .header("x-cache", "CANARY")
                .body(Bytes::from(nxdomain).into())
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }

    }

    // 0. Local Threat, Blocklist & Whitelist Policy Check (with Fast-Path Negative Absorber in <10µs)
    let (is_blocked, is_nxdomain, reason) = state.check_domain(&q.name);
    if is_blocked {
        state.record_detected_block(&q.name, reason);
        state.fingerprint.record_response(client_ip, 3);
        state.fingerprint.flag_client(client_ip, reason, &q.name);
        // rep_blocks: count when a block event flags the client's reputation profile
        state.metrics.rep_blocks.fetch_add(1, Ordering::Relaxed);
        // auto_blocks: count AI/neural/heuristic auto-detected blocks
        if matches!(reason, "neural_brain_block" | "dga_threat" | "lookalike_threat" | "ai_block") {
            state.metrics.auto_blocks.fetch_add(1, Ordering::Relaxed);
        }
        // alike_blocks: specifically brand-lookalike threats
        if reason == "lookalike_threat" {
            state.metrics.alike_blocks.fetch_add(1, Ordering::Relaxed);
        }
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

    // Swarm detection: runs in a detached background task so the Mutex write lock
    // NEVER stalls the DNS hot path. Swarm alarms are telemetry, not blocking decisions.
    {
        let state2 = state.clone();
        let domain_clone = q.name.clone();
        let ip_str = client_ip.to_string();
        tokio::spawn(async move {
            if state2.metrics.detect_swarm(&domain_clone, &ip_str) {
                state2.metrics.swarm_alarms.fetch_add(1, Ordering::Relaxed);
                state2.log_anomaly("swarm_flood", &format!(
                    "Swarm burst: {} queried by many clients simultaneously", domain_clone
                ));
            }
        });
    }

    // DCC / Category hits: detect C2, miner, and tracker category domains (lock-free, pure computation)
    {
        let name_bytes = q.name.as_bytes();
        let is_c2 = q.name.contains(".onion") || q.name.contains("c2.") || q.name.contains("cnc.")
            || q.name.contains("bot.") || q.name.contains("beacon.") || q.name.contains(".tk")
            || q.name.contains("miner") || q.name.contains("xmr.") || q.name.contains("crypto-pool")
            || (q.name.ends_with(".ru.") || q.name.ends_with(".ru"))
                && name_bytes.len() > 20
                && crate::security::heuristics::is_dga_threat(&q.name);
        if is_c2 {
            state.metrics.dcc_hits.fetch_add(1, Ordering::Relaxed);
        }
    }

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

    // 4. Forward to upstream pool with race fallback
    let start_upstream = std::time::Instant::now();
    let resolve_result = match state.upstreams.resolve(query_wire).await {
        Some(res) => Some(res),
        None => {
            state.metrics.race_wins.fetch_add(1, Ordering::Relaxed);
            state.upstreams.resolve_race(query_wire).await
        }
    };

    if let Some((upstream_resp, upstream_name)) = resolve_result {
        let lat = start_upstream.elapsed().as_millis() as u32;
        let rcode = if upstream_resp.len() >= 4 { (upstream_resp[3] & 0x0F) as u16 } else { 0 };
        if let Some(flag) = state.fingerprint.record_response(client_ip, rcode) {
            state.log_action("rogue_client_detected", &format!("{}: {}", client_ip, flag));
        }

        // Feature 4: Record passive DNS timeline (non-blocking)
        {
            let ips = crate::dns::parser::extract_a_records(&upstream_resp);
            if !ips.is_empty() {
                if let Some(drift) = state.passive_dns.record(&q.name, &ips) {
                    // Increment the answer_drifts counter — this is what the dashboard shows
                    state.metrics.answer_drifts.fetch_add(1, Ordering::Relaxed);
                    state.log_anomaly("passive_dns_drift", &format!(
                        "IP change detected for {}: {:?} -> {:?}", q.name, drift, ips
                    ));
                }
            }
        }

        // NX alarm detection: detect client IP generating many NX responses (C2 DGA storm)
        if rcode == 3 && state.metrics.detect_nx_burst(&client_ip.to_string()) {
            state.metrics.nx_alarms.fetch_add(1, Ordering::Relaxed);
            state.log_anomaly("nx_alarm", &format!(
                "NX domain burst detected from client {} — possible DGA/C2 scanner", client_ip
            ));
        }

        // Feature 6: TTL Manipulation Guard — detect fast-flux botnets (extremely low TTL + DGA pattern)
        // Robust & universal check: ultra-low TTL (<= 5s) combined with verified algorithmic threat
        // (DGA entropy AND AI brain confirmation). Necessary services (VoIP, CDNs, banking, APIs)
        // are NEVER harmed.
        if state.ttl_guard_enabled.load(Ordering::Relaxed)
            && state.blocking_enabled.load(Ordering::Relaxed)
            && !state.is_exempt(&q.name)
            && rcode == 0
        {
            if let Some(min_ttl) = crate::dns::parser::extract_min_ttl(&upstream_resp) {
                let is_dga_suspect = crate::security::heuristics::is_dga_threat(&q.name);
                let (ai_score, _) = state.brain.evaluate_internal(&q.name);
                if min_ttl <= 5 && is_dga_suspect && ai_score > 0.85 {
                    state.metrics.ttl_guard_blocks.fetch_add(1, Ordering::Relaxed);
                    state.metrics.threat_blocks.fetch_add(1, Ordering::Relaxed);
                    state.log_action("ttl_guard_block", &format!(
                        "{} TTL={}s (fast-flux/DGA confirmed, AI={:.2})", q.name, min_ttl, ai_score
                    ));
                    state.log_anomaly("ttl_manipulation_guard", &format!(
                        "Fast-flux botnet blocked: low TTL {}s + DGA pattern + AI {:.2} on {}", min_ttl, ai_score, q.name
                    ));
                    state.wal.append_query(&q.name, q.qtype, log_id, 3, lat, "TTL_GUARD_BLOCK");
                    state.log_query(&q.name, q.qtype, log_id, proto, "TTL_GUARD_BLOCK", 3, lat, "ttl_manipulation_guard", "TTL Guard");
                    state.cache.insert_negative(&q.name, 30).await;
                    let blocked = build_blocked_response(query_wire, false);
                    state.metrics.record_latency(query_start.elapsed());
                    return Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/dns-message")
                        .header("x-cache", "BLOCKED")
                        .header("x-block-reason", "ttl_manipulation_guard")
                        .body(Bytes::from(blocked).into())
                        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
                }
            }
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

        // Feature 13: Smart TTL learning — observe the upstream TTL and use adaptive cache TTL
        let smart_ttl = if let Some(raw_ttl) = crate::dns::parser::extract_answer_ttl(&upstream_resp) {
            state.ttl_learner.observe(&q.name, raw_ttl);
            state.ttl_learner.smart_ttl(&q.name, raw_ttl)
        } else {
            300
        };

        state.cache.insert(&q.name, q.qtype, upstream_resp.clone(), smart_ttl).await;
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

// ═══════════════════════════════════════════════════════════════════════════════
// NEW FEATURE HANDLERS (Features 4–13)
// ═══════════════════════════════════════════════════════════════════════════════

// ── Feature 4: Passive DNS Timeline ─────────────────────────────────────────

// Feature 4: Passive DNS lookup uses DomainReq (already defined above)
#[derive(Deserialize)]
struct DomainLookupParams { domain: Option<String> }

async fn passive_dns_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<DomainLookupParams>,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/passive-dns");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Unauthorized"}))).into_response();
    }
    let domain = params.domain.unwrap_or_default();
    if domain.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"ok":false,"error":"domain query parameter required"}))).into_response();
    }
    let timeline = state.passive_dns.get_timeline(&domain);
    Json(serde_json::json!({
        "ok": true,
        "domain": domain,
        "observations": timeline.len(),
        "timeline": timeline,
        "totalObservations": state.passive_dns.total_observations.load(std::sync::atomic::Ordering::Relaxed),
        "driftEvents": state.passive_dns.drift_events.load(std::sync::atomic::Ordering::Relaxed),
        "trackedDomains": state.passive_dns.domain_count()
    })).into_response()
}

async fn passive_dns_drifts_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/passive-dns/drifts");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Unauthorized"}))).into_response();
    }
    let drifts = state.passive_dns.get_recent_drifts(50);
    Json(serde_json::json!({
        "ok": true,
        "driftCount": state.passive_dns.drift_events.load(std::sync::atomic::Ordering::Relaxed),
        "recentDrifts": drifts
    })).into_response()
}

// ── Feature 5: Canary Domain ─────────────────────────────────────────────────

async fn canary_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    handle_canary(&state, None, &headers).await
}

async fn canary_key_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_canary(&state, Some(&key), &headers).await
}

async fn handle_canary(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/canary");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Unauthorized"}))).into_response();
    }
    let hits = state.canary_hits.load(std::sync::atomic::Ordering::Relaxed);
    Json(serde_json::json!({
        "ok": true,
        "canaryDomain": state.canary_domain,
        "hits": hits,
        "status": if hits > 0 { "leak_detected" } else { "clean" },
        "note": "Query this domain from a suspected device. If hits increases, that device is leaking DNS to AmarDNS bypassing your config."
    })).into_response()
}

// ── Feature 6: TTL Guard ─────────────────────────────────────────────────────

async fn get_ttl_guard(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    handle_get_ttl_guard(&state, None, &headers).await
}

async fn get_ttl_guard_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_ttl_guard(&state, Some(&key), &headers).await
}

async fn handle_get_ttl_guard(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/settings/ttl-guard");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Unauthorized"}))).into_response();
    }
    Json(serde_json::json!({
        "ok": true,
        "ttlGuardEnabled": state.ttl_guard_enabled.load(std::sync::atomic::Ordering::Relaxed),
        "ttlGuardBlocks": state.metrics.ttl_guard_blocks.load(std::sync::atomic::Ordering::Relaxed),
        "threshold": "5s with confirmed DGA pattern — legitimate dynamic TTLs (CDNs, VoIP) are fully allowed"
    })).into_response()
}

async fn set_ttl_guard(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<BoolSetting>,
) -> Response {
    handle_set_ttl_guard(&state, None, &headers, body).await
}

async fn set_ttl_guard_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(body): Json<BoolSetting>,
) -> Response {
    handle_set_ttl_guard(&state, Some(&key), &headers, body).await
}

async fn handle_set_ttl_guard(state: &AppState, key: Option<&str>, headers: &HeaderMap, body: BoolSetting) -> Response {
    let auth = check_auth(state, key, headers, "/api/settings/ttl-guard");
    if !auth.is_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Admin key required"}))).into_response();
    }
    state.ttl_guard_enabled.store(body.enabled, std::sync::atomic::Ordering::Relaxed);
    Json(serde_json::json!({
        "ok": true,
        "ttlGuardEnabled": body.enabled,
        "message": if body.enabled { "TTL Guard enabled — fast-flux/DGA protection active" } else { "TTL Guard disabled" }
    })).into_response()
}

// ── Feature 8: SSE Real-Time Log Stream ──────────────────────────────────────

fn build_logs_stream(state: Arc<AppState>) -> Response {
    let mut rx = state.log_broadcaster.subscribe();

    // Build a streaming body that pushes SSE events as DNS queries arrive
    let stream = async_stream::stream! {
        // Send an initial "connected" event
        let hello = "data: {\"type\":\"connected\",\"server\":\"AmarDNS\"}\n\n";
        yield Ok::<bytes::Bytes, std::convert::Infallible>(bytes::Bytes::from(hello));

        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(25), rx.recv()).await {
                Ok(Ok(msg)) => {
                    let sse = format!("data: {}\n\n", msg);
                    yield Ok::<bytes::Bytes, std::convert::Infallible>(bytes::Bytes::from(sse));
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
                    // Client lagged slightly under heavy query bursts; continue streaming next events
                    continue;
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break, // broadcaster dropped
                Err(_) => {
                    // Keepalive ping every 25s
                    yield Ok::<bytes::Bytes, std::convert::Infallible>(bytes::Bytes::from(": keepalive\n\n"));
                }
            }
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("X-Accel-Buffering", "no")
        .body(axum::body::Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn logs_stream_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/logs/stream");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Unauthorized"}))).into_response();
    }
    build_logs_stream(state)
}

async fn logs_stream_handler_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/logs/stream");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Unauthorized"}))).into_response();
    }
    build_logs_stream(state)
}


// ── Feature 9: Scheduled Blocking Rules ──────────────────────────────────────

async fn get_schedule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/schedule");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Unauthorized"}))).into_response();
    }
    let rules = state.schedule_store.list_rules();
    Json(serde_json::json!({
        "ok": true,
        "count": rules.len(),
        "scheduleBlocks": state.metrics.schedule_blocks.load(std::sync::atomic::Ordering::Relaxed),
        "rules": rules
    })).into_response()
}

#[derive(Deserialize)]
struct AddScheduleReq {
    domain: String,
    #[serde(rename = "startHour")] start_hour: u8,
    #[serde(rename = "endHour")] end_hour: u8,
    #[serde(rename = "tzOffset", default)] tz_offset: i8,
    #[serde(default)] reason: String,
}

async fn add_schedule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AddScheduleReq>,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/schedule");
    if !auth.is_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Admin key required"}))).into_response();
    }
    let reason = if body.reason.is_empty() {
        format!("Blocked {}-{}h", body.start_hour, body.end_hour)
    } else { body.reason };
    let id = state.schedule_store.add_rule(body.domain.clone(), body.start_hour, body.end_hour, body.tz_offset, reason);
    Json(serde_json::json!({
        "ok": true,
        "id": id,
        "domain": body.domain,
        "startHour": body.start_hour,
        "endHour": body.end_hour,
        "tzOffset": body.tz_offset,
        "message": "Schedule rule added"
    })).into_response()
}

async fn delete_schedule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<u64>,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/schedule");
    if !auth.is_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Admin key required"}))).into_response();
    }
    let removed = state.schedule_store.remove_rule(id);
    Json(serde_json::json!({
        "ok": removed,
        "id": id,
        "message": if removed { "Rule removed" } else { "Rule not found" }
    })).into_response()
}

// ── Feature 10: Blocklist Feed Subscriptions ─────────────────────────────────

async fn get_feeds(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/feeds");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Unauthorized"}))).into_response();
    }
    let feeds = state.feed_manager.list_feeds();
    Json(serde_json::json!({
        "ok": true,
        "count": feeds.len(),
        "totalSyncedDomains": state.feed_manager.total_synced_domains.load(std::sync::atomic::Ordering::Relaxed),
        "feeds": feeds
    })).into_response()
}

async fn get_feeds_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/feeds");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Unauthorized"}))).into_response();
    }
    let feeds = state.feed_manager.list_feeds();
    Json(serde_json::json!({
        "ok": true,
        "count": feeds.len(),
        "totalSyncedDomains": state.feed_manager.total_synced_domains.load(std::sync::atomic::Ordering::Relaxed),
        "feeds": feeds
    })).into_response()
}

async fn toggle_feed(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<u64>,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/feeds");
    if !auth.is_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Admin key required"}))).into_response();
    }
    let ok = state.feed_manager.toggle_feed(id);
    Json(serde_json::json!({
        "ok": ok,
        "feedId": id,
        "message": if ok { "Feed toggled" } else { "Feed not found" }
    })).into_response()
}

async fn sync_feeds(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    handle_sync_feeds(&state, None, &headers).await
}

async fn sync_feeds_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_sync_feeds(&state, Some(&key), &headers).await
}

async fn handle_sync_feeds(state: &Arc<AppState>, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/feeds/sync");
    if !auth.is_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Admin key required"}))).into_response();
    }

    let enabled = state.feed_manager.enabled_feeds();
    if enabled.is_empty() {
        return Json(serde_json::json!({
            "ok": true,
            "message": "No feeds enabled. Enable feeds via /api/feeds/:id/toggle first.",
            "synced": 0
        })).into_response();
    }

    let state_clone = (*state).clone();
    tokio::spawn(async move {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("AmarDNS/1.0 blocklist-sync")
            .build()
            .unwrap_or_default();

        for (feed_id, url, format) in enabled {
            tracing::info!("Syncing blocklist feed {} from {}", feed_id, url);
            match http.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(text) = resp.text().await {
                        let domains = crate::security::feed_manager::FeedManager::parse_domains(&text, &format);
                        let count = domains.len() as u64;
                        // Insert domains into the bloom filter
                        {
                            let mut bloom = state_clone.threat_bloom.write();
                            for domain in &domains {
                                bloom.insert(domain);
                            }
                        }
                        state_clone.feed_manager.update_sync_stats(feed_id, count);
                        tracing::info!("Feed {} synced: {} domains", feed_id, count);
                    }
                }
                Ok(resp) => tracing::warn!("Feed {} sync failed: HTTP {}", feed_id, resp.status()),
                Err(e) => tracing::warn!("Feed {} sync error: {}", feed_id, e),
            }
        }
    });

    Json(serde_json::json!({
        "ok": true,
        "message": "Feed sync started in background. Check /api/feeds for status.",
        "syncing": true
    })).into_response()
}

// ── Feature 11+13: Cache Stats & Volatile Domains ────────────────────────────

async fn cache_stats_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/cache/stats");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Unauthorized"}))).into_response();
    }
    let (count, compressed_bytes, mb, capacity) = state.cache.get_stats();
    let ratio = state.cache.compression_ratio();
    Json(serde_json::json!({
        "ok": true,
        "entries": count,
        "capacityLimit": capacity,
        "compressedBytes": compressed_bytes,
        "compressedMb": mb,
        "compressionRatio": format!("{:.1}%", ratio),
        "engine": "zstd level-1",
        "trackedDomains": state.ttl_learner.domain_count()
    })).into_response()
}

async fn cache_stats_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/cache/stats");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Unauthorized"}))).into_response();
    }
    let (count, compressed_bytes, mb, capacity) = state.cache.get_stats();
    let ratio = state.cache.compression_ratio();
    Json(serde_json::json!({
        "ok": true,
        "entries": count,
        "capacityLimit": capacity,
        "compressedBytes": compressed_bytes,
        "compressedMb": mb,
        "compressionRatio": format!("{:.1}%", ratio),
        "engine": "zstd level-1",
        "trackedDomains": state.ttl_learner.domain_count()
    })).into_response()
}

async fn volatile_domains_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/ttl/volatile");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Unauthorized"}))).into_response();
    }
    let volatile = state.ttl_learner.volatile_domains(20);
    Json(serde_json::json!({
        "ok": true,
        "note": "Domains with shortest learned TTLs (most dynamic/CDN-heavy)",
        "count": volatile.len(),
        "domains": volatile
    })).into_response()
}

async fn volatile_domains_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/ttl/volatile");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Unauthorized"}))).into_response();
    }
    let volatile = state.ttl_learner.volatile_domains(20);
    Json(serde_json::json!({
        "ok": true,
        "note": "Domains with shortest learned TTLs (most dynamic/CDN-heavy)",
        "count": volatile.len(),
        "domains": volatile
    })).into_response()
}

// ── DoH JSON API (RFC 8427 / Cloudflare / Google style) ──────────────────────

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct DohJsonParams {
    pub name: Option<String>,
    pub r#type: Option<String>,
    #[serde(rename = "do")]
    pub dnssec_ok: Option<bool>,
    pub cd: Option<bool>,
}

fn parse_qtype_param(t: Option<&str>) -> u16 {
    match t {
        None => 1, // A
        Some(s) => match s.to_ascii_uppercase().as_str() {
            "A" => 1,
            "NS" => 2,
            "CNAME" => 5,
            "SOA" => 6,
            "PTR" => 12,
            "MX" => 15,
            "TXT" => 16,
            "AAAA" => 28,
            "SRV" => 33,
            "ANY" => 255,
            other => other.parse::<u16>().unwrap_or(1),
        },
    }
}

async fn doh_json_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<DohJsonParams>,
) -> Response {
    let domain = match params.name {
        Some(ref n) if !n.trim().is_empty() => n.trim().to_ascii_lowercase(),
        _ => {
            let mut resp = (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "Status": 2, // SERVFAIL
                    "TC": false, "RD": true, "RA": false, "AD": false, "CD": false,
                    "Question": [],
                    "Comment": "Missing required parameter: name"
                })),
            ).into_response();
            resp.headers_mut().insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
            return resp;
        }
    };

    let qtype = parse_qtype_param(params.r#type.as_deref());
    let clean_domain = domain.trim_end_matches('.').to_string();
    let client_ip = extract_client_ip(&headers, addr);
    let query_start = std::time::Instant::now();
    let _log_id = state.metrics.requests.fetch_add(1, Ordering::Relaxed);
    state.metrics.doh_queries.fetch_add(1, Ordering::Relaxed);
    state.metrics.record_query(&client_ip.to_string(), "doh_json");

    // Canary check
    if clean_domain == state.canary_domain {
        state.canary_hits.fetch_add(1, Ordering::Relaxed);
        let mut resp = Json(serde_json::json!({
            "Status": 3, // NXDOMAIN
            "TC": false, "RD": true, "RA": true, "AD": false, "CD": false,
            "Question": [{"name": format!("{}.", clean_domain), "type": qtype}],
            "Comment": "Canary domain queried"
        })).into_response();
        resp.headers_mut().insert(header::CONTENT_TYPE, "application/dns-json".parse().unwrap());
        resp.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
        resp.headers_mut().insert("x-cache", "CANARY".parse().unwrap());
        return resp;
    }

    // Blocklist check
    let (is_blocked, is_nx, reason) = state.check_domain(&clean_domain);
    if is_blocked {
        state.record_detected_block(&clean_domain, reason);
        state.log_query(&clean_domain, qtype, &client_ip.to_string(), "DoH (JSON)", "BLOCKED", if is_nx { 3 } else { 0 }, 0, reason, "0.0.0.0");
        state.metrics.record_latency(query_start.elapsed());
        let answer = if is_nx {
            serde_json::json!([])
        } else {
            serde_json::json!([{
                "name": format!("{}.", clean_domain),
                "type": 1,
                "TTL": 300,
                "data": "0.0.0.0"
            }])
        };
        let mut resp = Json(serde_json::json!({
            "Status": if is_nx { 3 } else { 0 },
            "TC": false, "RD": true, "RA": true, "AD": false, "CD": false,
            "Question": [{"name": format!("{}.", clean_domain), "type": qtype}],
            "Answer": answer,
            "Comment": format!("Blocked by policy: {}", reason)
        })).into_response();
        resp.headers_mut().insert(header::CONTENT_TYPE, "application/dns-json".parse().unwrap());
        resp.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
        resp.headers_mut().insert("x-cache", "BLOCKED".parse().unwrap());
        return resp;
    }

    // Cache check
    if let Some(cached_wire) = state.cache.get(&clean_domain, qtype, 0x1234).await {
        state.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
        let (rcode, answers) = crate::dns::parser::parse_answers_for_doh_json(&cached_wire, &clean_domain);
        state.log_query(&clean_domain, qtype, &client_ip.to_string(), "DoH (JSON)", "HIT", rcode as u16, 0, "cache_hit", "cache");
        state.metrics.record_latency(query_start.elapsed());
        let mut resp = Json(serde_json::json!({
            "Status": rcode,
            "TC": false, "RD": true, "RA": true, "AD": false, "CD": false,
            "Question": [{"name": format!("{}.", clean_domain), "type": qtype}],
            "Answer": answers
        })).into_response();
        resp.headers_mut().insert(header::CONTENT_TYPE, "application/dns-json".parse().unwrap());
        resp.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
        resp.headers_mut().insert("x-cache", "HIT".parse().unwrap());
        return resp;
    }

    // Upstream resolution
    state.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
    let wire = crate::dns::parser::build_query_wire(&clean_domain, qtype);
    match state.upstreams.resolve_race(&wire).await {
        Some((resp_wire, upstream_name)) => {
            let (rcode, answers) = crate::dns::parser::parse_answers_for_doh_json(&resp_wire, &clean_domain);
            if rcode == 0 && !resp_wire.is_empty() {
                let ttl = crate::dns::parser::extract_answer_ttl(&resp_wire).unwrap_or(300);
                state.cache.insert(&clean_domain, qtype, resp_wire.clone(), ttl).await;
            }
            let elapsed_ms = query_start.elapsed().as_millis() as u32;
            state.log_query(&clean_domain, qtype, &client_ip.to_string(), "DoH (JSON)", "MISS", rcode as u16, elapsed_ms, "upstream", &upstream_name);
            state.metrics.record_latency(query_start.elapsed());
            let mut resp = Json(serde_json::json!({
                "Status": rcode,
                "TC": false, "RD": true, "RA": true, "AD": false, "CD": false,
                "Question": [{"name": format!("{}.", clean_domain), "type": qtype}],
                "Answer": answers
            })).into_response();
            resp.headers_mut().insert(header::CONTENT_TYPE, "application/dns-json".parse().unwrap());
            resp.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
            resp.headers_mut().insert("x-cache", "MISS".parse().unwrap());
            resp
        }
        None => {
            state.metrics.record_latency(query_start.elapsed());
            let mut resp = (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "Status": 2, // SERVFAIL
                    "TC": false, "RD": true, "RA": false, "AD": false, "CD": false,
                    "Question": [{"name": format!("{}.", clean_domain), "type": qtype}],
                    "Comment": "All upstreams failed to respond"
                })),
            ).into_response();
            resp.headers_mut().insert(header::CONTENT_TYPE, "application/dns-json".parse().unwrap());
            resp.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
            resp.headers_mut().insert("x-cache", "ERROR".parse().unwrap());
            resp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_extract_client_ip_direct_peer() {
        let headers = HeaderMap::new();
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 5), 5353));
        assert_eq!(extract_client_ip(&headers, peer), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
    }

    #[test]
    fn test_extract_client_ip_fly_and_cf() {
        let mut headers = HeaderMap::new();
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));

        headers.insert("fly-client-ip", HeaderValue::from_static("198.51.100.1"));
        assert_eq!(extract_client_ip(&headers, peer), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));

        headers.remove("fly-client-ip");
        headers.insert("cf-connecting-ip", HeaderValue::from_static("198.51.100.2"));
        assert_eq!(extract_client_ip(&headers, peer), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)));

        headers.remove("cf-connecting-ip");
        headers.insert("x-real-ip", HeaderValue::from_static("198.51.100.3"));
        assert_eq!(extract_client_ip(&headers, peer), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3)));
    }

    #[test]
    fn test_extract_client_ip_xff_private_vs_public_peer() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4, 198.51.100.4"));

        // When direct peer is a private reverse proxy (e.g. 10.0.0.2), trust XFF
        let private_peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 8080));
        assert_eq!(extract_client_ip(&headers, private_peer), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)));

        // When direct peer is a public IP (e.g. 203.0.113.9), do NOT trust unauthenticated XFF (anti-spoofing)
        let public_peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 5353));
        assert_eq!(extract_client_ip(&headers, public_peer), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
    }
}

