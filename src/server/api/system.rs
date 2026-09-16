use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{BoolSetting, ModeSetting, NuclearWipeReq};
use crate::security::auth::{check_auth, generate_hmac_token};
use crate::state::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // Settings
        .route(
            "/api/settings/blocking",
            get(get_blocking).post(set_blocking),
        )
        .route(
            "/api/settings/blocking/",
            get(get_blocking).post(set_blocking),
        )
        .route(
            "/api/settings/blocking/:key",
            get(get_blocking_key).post(set_blocking_key),
        )
        .route(
            "/api/settings/dns-mode",
            get(get_dns_mode).post(set_dns_mode),
        )
        .route(
            "/api/settings/dns-mode/",
            get(get_dns_mode).post(set_dns_mode),
        )
        .route(
            "/api/settings/dns-mode/:key",
            get(get_dns_mode_key).post(set_dns_mode_key),
        )
        .route(
            "/api/settings/ttl-guard",
            get(get_ttl_guard).post(set_ttl_guard),
        )
        .route(
            "/api/settings/ttl-guard/:key",
            get(get_ttl_guard_key).post(set_ttl_guard_key),
        )
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
        // Query Logs
        .route("/api/logs", get(get_logs))
        .route("/api/logs/", get(get_logs))
        .route("/api/logs/:key", get(get_logs_key))
        // Passive DNS Timeline
        .route("/api/passive-dns", get(passive_dns_handler))
        .route("/api/passive-dns/", get(passive_dns_handler))
        .route("/api/passive-dns/:key", get(passive_dns_key_handler))
        .route("/api/passive-dns/drifts", get(passive_dns_drifts_handler))
        .route("/api/passive-dns/drifts/", get(passive_dns_drifts_handler))
        .route(
            "/api/passive-dns/drifts/:key",
            get(passive_dns_drifts_key_handler),
        )
        // Canary Domain Detection
        .route("/api/canary", get(canary_handler))
        .route("/api/canary/:key", get(canary_key_handler))
        // Real-Time SSE Log Stream
        .route("/api/logs/stream", get(logs_stream_handler))
        .route("/api/logs/stream/:key", get(logs_stream_handler_key))
        .route("/:key/api/logs/stream", get(logs_stream_handler_key))
        // Cache & TTL stats
        .route("/api/cache/stats", get(cache_stats_handler))
        .route("/api/cache/stats/:key", get(cache_stats_key))
        .route("/api/ttl/volatile", get(volatile_domains_handler))
        .route("/api/ttl/volatile/:key", get(volatile_domains_key))
        // Peer TLS Bundle Sync & ACME Coordination Lock
        .route("/internal/tls/bundle", get(get_tls_bundle))
        .route("/internal/tls/bundle/:key", get(get_tls_bundle_key))
        .route("/internal/acme/lock", post(acquire_acme_lock))
        .route("/internal/acme/lock/:key", post(acquire_acme_lock_key))
        .route("/internal/acme/unlock", post(release_acme_lock))
        .route("/internal/acme/unlock/:key", post(release_acme_lock_key))
}

// ── Query Logs ──────────────────────────────────────────────────────────────

pub async fn get_logs(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/logs");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized" })),
        )
            .into_response();
    }
    let queries = state
        .recent_queries
        .read()
        .iter()
        .rev()
        .cloned()
        .collect::<Vec<_>>();
    Json(serde_json::json!({
        "ok": true,
        "count": queries.len(),
        "queries": queries
    }))
    .into_response()
}

pub async fn get_logs_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/logs");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized" })),
        )
            .into_response();
    }
    let queries = state
        .recent_queries
        .read()
        .iter()
        .rev()
        .cloned()
        .collect::<Vec<_>>();
    Json(serde_json::json!({
        "ok": true,
        "count": queries.len(),
        "queries": queries
    }))
    .into_response()
}

// ── Settings Handlers ───────────────────────────────────────────────────────

pub async fn get_blocking(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_get_blocking(&state, None, &headers).await
}

pub async fn get_blocking_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_blocking(&state, Some(&key), &headers).await
}

pub async fn handle_get_blocking(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/settings/blocking");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key or token required" }))).into_response();
    }
    Json(serde_json::json!({ "ok": true, "blockingEnabled": state.blocking_enabled.load(Ordering::Relaxed) })).into_response()
}

pub async fn set_blocking(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<BoolSetting>,
) -> Response {
    handle_set_blocking(&state, None, &headers, payload).await
}

pub async fn set_blocking_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<BoolSetting>,
) -> Response {
    handle_set_blocking(&state, Some(&key), &headers, payload).await
}

pub async fn handle_set_blocking(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
    payload: BoolSetting,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/settings/blocking");
    if !auth.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "ok": false, "error": "Forbidden: Blocking can only be toggled with the Master Key" }))).into_response();
    }
    state
        .blocking_enabled
        .store(payload.enabled, Ordering::Relaxed);
    state.log_action(
        "blocking_toggled",
        if payload.enabled {
            "enabled"
        } else {
            "disabled"
        },
    );
    Json(serde_json::json!({ "ok": true, "blockingEnabled": payload.enabled })).into_response()
}

pub async fn get_dns_mode(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_get_dns_mode(&state, None, &headers).await
}

pub async fn get_dns_mode_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_dns_mode(&state, Some(&key), &headers).await
}

pub async fn handle_get_dns_mode(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/settings/dns-mode");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key or token required" }))).into_response();
    }
    let mode = if state.is_private_mode.load(Ordering::Relaxed) {
        "private"
    } else {
        "public"
    };
    Json(serde_json::json!({ "ok": true, "dnsMode": mode })).into_response()
}

pub async fn set_dns_mode(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ModeSetting>,
) -> Response {
    handle_set_dns_mode(&state, None, &headers, payload).await
}

pub async fn set_dns_mode_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<ModeSetting>,
) -> Response {
    handle_set_dns_mode(&state, Some(&key), &headers, payload).await
}

pub async fn handle_set_dns_mode(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
    payload: ModeSetting,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/settings/dns-mode");
    if !auth.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "ok": false, "error": "Forbidden: DNS mode can only be toggled with the Master Key" }))).into_response();
    }
    let clean_mode = match crate::security::sanitizer::sanitize_mode(&payload.mode) {
        Ok(m) => m,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": err })),
            )
                .into_response();
        }
    };
    let is_private = clean_mode == "private" || clean_mode == "strict";
    state.is_private_mode.store(is_private, Ordering::Relaxed);
    state.log_action("dns_mode_changed", &clean_mode);
    Json(serde_json::json!({ "ok": true, "dnsMode": clean_mode })).into_response()
}

// ── Upstreams Handlers ──────────────────────────────────────────────────────

pub async fn get_ranked_upstreams(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    handle_get_ranked_upstreams(&state, None, &headers).await
}

pub async fn get_ranked_upstreams_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_ranked_upstreams(&state, Some(&key), &headers).await
}

pub async fn handle_get_ranked_upstreams(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/upstreams/ranked");
    if !auth.is_view_or_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key or token required" }))).into_response();
    }
    Json(serde_json::json!({
        "ok": true,
        "upstreams": state.upstreams.snapshot()
    }))
    .into_response()
}

pub async fn sync_upstreams(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_sync_upstreams(&state, None, &headers).await
}

pub async fn sync_upstreams_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_sync_upstreams(&state, Some(&key), &headers).await
}

pub async fn handle_sync_upstreams(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/upstreams/sync");
    if !auth.is_admin() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "Forbidden: Master key required" })),
        )
            .into_response();
    }
    match state.upstreams.sync_and_rank().await {
        Ok(count) => {
            state.log_action(
                "upstreams_synced",
                &format!("Ranked top {} upstreams", count),
            );
            Json(serde_json::json!({ "ok": true, "ranked": count })).into_response()
        }
        Err(err) => {
            state.log_anomaly("upstream_sync_fail", &err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": err })),
            )
                .into_response()
        }
    }
}

// ── Controls, Tokens & Nuclear Wipe ─────────────────────────────────────────

pub async fn reset_circuit_breakers(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    handle_reset_cb(&state, None, &headers).await
}

pub async fn reset_circuit_breakers_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_reset_cb(&state, Some(&key), &headers).await
}

pub async fn handle_reset_cb(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/reset-cb");
    if !auth.is_admin() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "Forbidden: Master key required" })),
        )
            .into_response();
    }
    state.upstreams.reset_cb();
    state.log_action("cb_reset", "admin");
    Json(serde_json::json!({ "ok": true, "message": "Circuit breakers reset" })).into_response()
}

pub async fn clear_self_heal(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_clear_self_heal(&state, None, &headers).await
}

pub async fn clear_self_heal_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_clear_self_heal(&state, Some(&key), &headers).await
}

pub async fn handle_clear_self_heal(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/self-heal");
    if !auth.is_admin() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "Forbidden: Master key required" })),
        )
            .into_response();
    }
    state.recent_actions.write().clear();
    state.recent_anomalies.write().clear();
    state.log_action("self_heal_cleared", "admin");
    Json(serde_json::json!({ "ok": true, "message": "Self-heal cleared" })).into_response()
}

pub async fn clear_incident(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_clear_incident(&state, None, &headers).await
}

pub async fn clear_incident_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_clear_incident(&state, Some(&key), &headers).await
}

pub async fn handle_clear_incident(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/incident");
    if !auth.is_admin() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "Forbidden: Master key required" })),
        )
            .into_response();
    }
    state.log_action("incident_cleared", "admin");
    Json(serde_json::json!({ "ok": true, "message": "Incident cleared" })).into_response()
}

pub async fn nuclear_wipe(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<NuclearWipeReq>,
) -> Response {
    handle_nuclear_wipe(&state, None, &headers, payload).await
}

pub async fn nuclear_wipe_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<NuclearWipeReq>,
) -> Response {
    handle_nuclear_wipe(&state, Some(&key), &headers, payload).await
}

pub async fn handle_nuclear_wipe(
    state: &Arc<AppState>,
    key: Option<&str>,
    headers: &HeaderMap,
    payload: NuclearWipeReq,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/nuclear-wipe");
    if !auth.is_admin() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "Forbidden: Master key required" })),
        )
            .into_response();
    }
    if payload.confirm.as_deref() != Some("NUCLEAR_WIPE_CONFIRMED") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "Missing confirm phrase" })),
        )
            .into_response();
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

    // Automatically rebuild structure: spawn continuous background retry polling until threat feeds succeed
    state.trigger_background_feed_sync();

    // Cluster peer-sync across Fly.io instances
    let is_peer_sync = headers.get("x-peer-sync").and_then(|v| v.to_str().ok()) == Some("1");
    if !is_peer_sync {
        if let Ok(app_name) = std::env::var("FLY_APP_NAME") {
            let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
            let master_key = state.config.dns_master_key.clone();
            tokio::spawn(async move {
                let scheme = if port == "443" { "https" } else { "http" };
                let peer_host = format!(
                    "{}://{}.internal:{}/api/nuclear-wipe/{}",
                    scheme, app_name, port, master_key
                );
                let client = reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .build()
                    .unwrap_or_default();
                let _ = client
                    .post(&peer_host)
                    .header("x-peer-sync", "1")
                    .header("x-master-key", &master_key)
                    .json(&serde_json::json!({ "confirm": "NUCLEAR_WIPE_CONFIRMED" }))
                    .send()
                    .await;
            });
        }
    }

    Json(serde_json::json!({ "ok": true, "message": "Nuclear wipe completed & threat feed background sync queued" })).into_response()
}

pub async fn get_nuke_token(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_get_nuke_token(&state, None, &headers).await
}

pub async fn get_nuke_token_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_nuke_token(&state, Some(&key), &headers).await
}

pub async fn handle_get_nuke_token(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/nuke-token");
    if !auth.is_admin() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "Forbidden: Master key required" })),
        )
            .into_response();
    }
    Json(serde_json::json!({ "ok": true, "nukeToken": "CONFIRMED", "expiresIn": "5m" }))
        .into_response()
}

fn parse_ttl(raw: &str, default_secs: u64) -> u64 {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return default_secs;
    }
    if let Some(num_str) = s.strip_suffix('s') {
        num_str.parse().unwrap_or(default_secs)
    } else if let Some(num_str) = s.strip_suffix('m') {
        num_str
            .parse::<u64>()
            .map(|n| n * 60)
            .unwrap_or(default_secs)
    } else if let Some(num_str) = s.strip_suffix('h') {
        num_str
            .parse::<u64>()
            .map(|n| n * 3600)
            .unwrap_or(default_secs)
    } else if let Some(num_str) = s.strip_suffix('d') {
        num_str
            .parse::<u64>()
            .map(|n| n * 86400)
            .unwrap_or(default_secs)
    } else if let Some(num_str) = s.strip_suffix('w') {
        num_str
            .parse::<u64>()
            .map(|n| n * 604800)
            .unwrap_or(default_secs)
    } else {
        s.parse().unwrap_or(default_secs)
    }
}

pub async fn get_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    handle_get_token(&state, None, &headers, params).await
}

pub async fn get_token_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    handle_get_token(&state, Some(&key), &headers, params).await
}

pub async fn handle_get_token(
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
        )
            .into_response();
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
    }))
    .into_response()
}

// ── Feature 4: Passive DNS Timeline ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct DomainLookupParams {
    pub domain: Option<String>,
}

pub async fn passive_dns_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<DomainLookupParams>,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/passive-dns");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false,"error":"Unauthorized"})),
        )
            .into_response();
    }
    handle_passive_dns(&state, params)
}

pub async fn passive_dns_key_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Query(params): Query<DomainLookupParams>,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/passive-dns");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false,"error":"Unauthorized"})),
        )
            .into_response();
    }
    handle_passive_dns(&state, params)
}

fn handle_passive_dns(state: &AppState, params: DomainLookupParams) -> Response {
    let domain = params.domain.unwrap_or_default();
    if domain.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok":false,"error":"domain query parameter required"})),
        )
            .into_response();
    }
    let timeline = state.passive_dns.get_timeline(&domain);
    Json(serde_json::json!({
        "ok": true,
        "domain": domain,
        "observations": timeline.len(),
        "timeline": timeline,
        "totalObservations": state.passive_dns.total_observations.load(Ordering::Relaxed),
        "driftEvents": state.passive_dns.drift_events.load(Ordering::Relaxed),
        "trackedDomains": state.passive_dns.domain_count()
    }))
    .into_response()
}

pub async fn passive_dns_drifts_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/passive-dns/drifts");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false,"error":"Unauthorized"})),
        )
            .into_response();
    }
    let drifts = state.passive_dns.get_recent_drifts(50);
    Json(serde_json::json!({
        "ok": true,
        "driftCount": state.passive_dns.drift_events.load(Ordering::Relaxed),
        "recentDrifts": drifts
    }))
    .into_response()
}

pub async fn passive_dns_drifts_key_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/passive-dns/drifts");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false,"error":"Unauthorized"})),
        )
            .into_response();
    }
    let drifts = state.passive_dns.get_recent_drifts(50);
    Json(serde_json::json!({
        "ok": true,
        "driftCount": state.passive_dns.drift_events.load(Ordering::Relaxed),
        "recentDrifts": drifts
    }))
    .into_response()
}

// ── Feature 5: Canary Domain ─────────────────────────────────────────────────

pub async fn canary_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_canary(&state, None, &headers).await
}

pub async fn canary_key_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_canary(&state, Some(&key), &headers).await
}

pub async fn handle_canary(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
    let auth = check_auth(state, key, headers, "/api/canary");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false,"error":"Unauthorized"})),
        )
            .into_response();
    }
    let hits = state.canary_hits.load(Ordering::Relaxed);
    Json(serde_json::json!({
        "ok": true,
        "canaryDomain": state.canary_domain,
        "hits": hits,
        "status": if hits > 0 { "leak_detected" } else { "clean" },
        "note": "Query this domain from a suspected device. If hits increases, that device is leaking DNS to AmarDNS bypassing your config."
    })).into_response()
}

// ── Feature 6: TTL Guard ─────────────────────────────────────────────────────

pub async fn get_ttl_guard(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_get_ttl_guard(&state, None, &headers).await
}

pub async fn get_ttl_guard_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_ttl_guard(&state, Some(&key), &headers).await
}

pub async fn handle_get_ttl_guard(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/settings/ttl-guard");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false,"error":"Unauthorized"})),
        )
            .into_response();
    }
    Json(serde_json::json!({
        "ok": true,
        "ttlGuardEnabled": state.ttl_guard_enabled.load(Ordering::Relaxed),
        "ttlGuardBlocks": state.metrics.ttl_guard_blocks.load(Ordering::Relaxed),
        "threshold": "5s with confirmed DGA pattern — legitimate dynamic TTLs (CDNs, VoIP) are fully allowed"
    })).into_response()
}

pub async fn set_ttl_guard(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<BoolSetting>,
) -> Response {
    handle_set_ttl_guard(&state, None, &headers, body).await
}

pub async fn set_ttl_guard_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(body): Json<BoolSetting>,
) -> Response {
    handle_set_ttl_guard(&state, Some(&key), &headers, body).await
}

pub async fn handle_set_ttl_guard(
    state: &AppState,
    key: Option<&str>,
    headers: &HeaderMap,
    body: BoolSetting,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/settings/ttl-guard");
    if !auth.is_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false,"error":"Admin key required"})),
        )
            .into_response();
    }
    state
        .ttl_guard_enabled
        .store(body.enabled, Ordering::Relaxed);
    Json(serde_json::json!({
        "ok": true,
        "ttlGuardEnabled": body.enabled,
        "message": if body.enabled { "TTL Guard enabled — fast-flux/DGA protection active" } else { "TTL Guard disabled" }
    })).into_response()
}

// ── Feature 8: SSE Real-Time Log Stream ──────────────────────────────────────

pub fn build_logs_stream(state: Arc<AppState>) -> Response {
    let mut rx = state.log_broadcaster.subscribe();
    let mut shutdown_rx = state.shutdown_rx.clone();

    let stream = async_stream::stream! {
        let hello = "data: {\"type\":\"connected\",\"server\":\"AmarDNS\"}\n\n";
        yield Ok::<bytes::Bytes, std::convert::Infallible>(bytes::Bytes::from(hello));

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    let bye = "data: {\"type\":\"shutdown\",\"server\":\"AmarDNS\"}\n\n";
                    yield Ok::<bytes::Bytes, std::convert::Infallible>(bytes::Bytes::from(bye));
                    break;
                }
                msg = tokio::time::timeout(std::time::Duration::from_secs(25), rx.recv()) => {
                    match msg {
                        Ok(Ok(m)) => {
                            let sse = format!("data: {}\n\n", m);
                            yield Ok::<bytes::Bytes, std::convert::Infallible>(bytes::Bytes::from(sse));
                        }
                        Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
                            continue;
                        }
                        Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
                        Err(_) => {
                            yield Ok::<bytes::Bytes, std::convert::Infallible>(bytes::Bytes::from(": keepalive\n\n"));
                        }
                    }
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

pub async fn logs_stream_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/logs/stream");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false,"error":"Unauthorized"})),
        )
            .into_response();
    }
    build_logs_stream(state)
}

pub async fn logs_stream_handler_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/logs/stream");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false,"error":"Unauthorized"})),
        )
            .into_response();
    }
    build_logs_stream(state)
}

// ── Feature 11+13: Cache Stats & Volatile Domains ────────────────────────────

pub async fn cache_stats_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/cache/stats");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false,"error":"Unauthorized"})),
        )
            .into_response();
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
    }))
    .into_response()
}

pub async fn cache_stats_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/cache/stats");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false,"error":"Unauthorized"})),
        )
            .into_response();
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
    }))
    .into_response()
}

pub async fn volatile_domains_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/ttl/volatile");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false,"error":"Unauthorized"})),
        )
            .into_response();
    }
    let volatile = state.ttl_learner.volatile_domains(20);
    Json(serde_json::json!({
        "ok": true,
        "note": "Domains with shortest learned TTLs (most dynamic/CDN-heavy)",
        "count": volatile.len(),
        "domains": volatile
    }))
    .into_response()
}

pub async fn volatile_domains_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/api/ttl/volatile");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false,"error":"Unauthorized"})),
        )
            .into_response();
    }
    let volatile = state.ttl_learner.volatile_domains(20);
    Json(serde_json::json!({
        "ok": true,
        "note": "Domains with shortest learned TTLs (most dynamic/CDN-heavy)",
        "count": volatile.len(),
        "domains": volatile
    }))
    .into_response()
}

// ── Peer TLS Sync ────────────────────────────────────────────────────────────

pub async fn get_tls_bundle(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let auth = check_auth(&state, None, &headers, "/internal/tls/bundle");
    if !auth.is_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" })),
        )
            .into_response();
    }
    handle_tls_bundle(&state)
}

pub async fn get_tls_bundle_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/internal/tls/bundle");
    if !auth.is_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" })),
        )
            .into_response();
    }
    handle_tls_bundle(&state)
}

fn handle_tls_bundle(state: &Arc<AppState>) -> Response {
    if let Some((cert_path, key_path)) = state.config.get_effective_tls_paths() {
        if let (Ok(cert_pem), Ok(key_pem)) = (
            std::fs::read_to_string(&cert_path),
            std::fs::read_to_string(&key_path),
        ) {
            if let Some(days) = crate::server::acme::get_cert_days_remaining(&cert_path) {
                return Json(serde_json::json!({
                    "ok": true,
                    "cert_pem": cert_pem,
                    "key_pem": key_pem,
                    "days_remaining": days,
                }))
                .into_response();
            }
        }
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "ok": false, "error": "No valid TLS certificate found" })),
    )
        .into_response()
}

// ── Peer ACME Coordination Lock ──────────────────────────────────────────────

pub async fn acquire_acme_lock(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/internal/acme/lock");
    if !auth.is_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" })),
        )
            .into_response();
    }
    handle_acquire_lock(&state, body)
}

pub async fn acquire_acme_lock_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/internal/acme/lock");
    if !auth.is_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" })),
        )
            .into_response();
    }
    handle_acquire_lock(&state, body)
}

fn handle_acquire_lock(state: &Arc<AppState>, body: serde_json::Value) -> Response {
    let machine_id = body["machine_id"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let ttl_secs = body["ttl_secs"].as_u64().unwrap_or(600);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut lock = state.acme_lock.lock();
    if let Some((ref holder, expiry)) = *lock {
        if expiry > now && holder != &machine_id {
            // Deterministic tie-breaking: allow lower machine_id to preempt to prevent dual-boot deadlock
            if machine_id < *holder {
                *lock = Some((machine_id.clone(), now + ttl_secs));
                return Json(serde_json::json!({
                    "ok": true,
                    "granted": true,
                    "holder": machine_id,
                    "expires_in_secs": ttl_secs
                }))
                .into_response();
            } else {
                return Json(serde_json::json!({
                    "ok": true,
                    "granted": false,
                    "holder": holder,
                    "expires_in_secs": expiry.saturating_sub(now)
                }))
                .into_response();
            }
        }
    }

    *lock = Some((machine_id.clone(), now + ttl_secs));
    Json(serde_json::json!({
        "ok": true,
        "granted": true,
        "holder": machine_id,
        "ttl_secs": ttl_secs
    }))
    .into_response()
}

pub async fn release_acme_lock(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/internal/acme/unlock");
    if !auth.is_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" })),
        )
            .into_response();
    }
    handle_release_lock(&state, body)
}

pub async fn release_acme_lock_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let auth = check_auth(&state, Some(&key), &headers, "/internal/acme/unlock");
    if !auth.is_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized: Master key required" })),
        )
            .into_response();
    }
    handle_release_lock(&state, body)
}

fn handle_release_lock(state: &Arc<AppState>, body: serde_json::Value) -> Response {
    let machine_id = body["machine_id"].as_str().unwrap_or("unknown");
    let mut lock = state.acme_lock.lock();
    if let Some((ref holder, _)) = *lock {
        if holder == machine_id {
            *lock = None;
        }
    }
    Json(serde_json::json!({ "ok": true })).into_response()
}

