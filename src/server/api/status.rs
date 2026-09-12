use std::sync::atomic::Ordering;
use std::sync::Arc;
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};

use super::DnsQueryParam;
use crate::security::auth::{check_auth, AuthRole};
use crate::state::AppState;
use crate::ui::dashboard::render_dashboard;
use crate::ui::gateway::GATEWAY_HTML;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(dashboard_handler))
        .route("/health", get(health_handler))
        .route("/favicon.ico", get(favicon_handler))
        .route("/api/status", get(status_no_key_handler))
        .route("/api/status/", get(status_no_key_handler))
        .route("/api/intelligence", get(status_no_key_handler))
        .route("/api/intelligence/", get(status_no_key_handler))
        .route("/:key", get(status_handler))
        .route("/api/status/:key", get(status_handler))
        .route("/api/intelligence/:key", get(status_handler))
        .route("/metrics", get(prometheus_metrics_handler))
}

pub async fn health_handler(
    State(state): State<Arc<AppState>>,
) -> Response {
    let upstreams = state.upstreams.snapshot();
    let healthy_upstreams = upstreams
        .iter()
        .filter(|u| u.get("healthy").and_then(|h| h.as_bool()).unwrap_or(true))
        .count();
    let total_upstreams = upstreams.len();

    let bloom_ready = state.threat_bloom.read().count() > 0;

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

pub async fn prometheus_metrics_handler(
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
    counter!("amardns_gsb_blocks",            "Domains blocked by Google Safe Browsing", gsb);
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

pub async fn favicon_handler() -> Response {
    (StatusCode::NO_CONTENT, "").into_response()
}

pub async fn dashboard_handler(
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
            crate::security::auth::generate_hmac_token(&state.config.dns_token_secret, "/dashboard", 3600)
        };
        Html(render_dashboard(&view_token, &fly_machine_id, &fly_region)).into_response()
    } else {
        Html(GATEWAY_HTML).into_response()
    }
}

pub async fn status_no_key_handler(
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

pub async fn status_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/status");
    let is_json = headers.get(header::ACCEPT)
        .and_then(|h| h.to_str().ok())
        .map(|a| a.starts_with("application/json") || a == "application/json")
        .unwrap_or(false);

    if !is_json {
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

pub fn build_status_response(state: &AppState, auth: AuthRole) -> Response {
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
            "feedOverlapCount": feed_overlap,
            "feedSyncInProgress": state.is_feed_syncing.load(Ordering::Relaxed),
            "isFeedSyncing": state.is_feed_syncing.load(Ordering::Relaxed)
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
            "isFeedSyncing": state.is_feed_syncing.load(Ordering::Relaxed),
            "feedSyncInProgress": state.is_feed_syncing.load(Ordering::Relaxed),
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
