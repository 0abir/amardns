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
            "/api/settings/blocking/{key}",
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
            "/api/settings/dns-mode/{key}",
            get(get_dns_mode_key).post(set_dns_mode_key),
        )
        .route(
            "/api/settings/ttl-guard",
            get(get_ttl_guard).post(set_ttl_guard),
        )
        .route(
            "/api/settings/ttl-guard/{key}",
            get(get_ttl_guard_key).post(set_ttl_guard_key),
        )
        // Upstreams
        .route("/api/upstreams/ranked", get(get_ranked_upstreams))
        .route("/api/upstreams/ranked/", get(get_ranked_upstreams))
        .route("/api/upstreams/ranked/{key}", get(get_ranked_upstreams_key))
        .route("/api/upstreams/sync", post(sync_upstreams))
        .route("/api/upstreams/sync/", post(sync_upstreams))
        .route("/api/upstreams/sync/{key}", post(sync_upstreams_key))
        // Controls & Wipe
        .route("/api/reset-cb", post(reset_circuit_breakers))
        .route("/api/reset-cb/", post(reset_circuit_breakers))
        .route("/api/reset-cb/{key}", post(reset_circuit_breakers_key))
        .route("/api/self-heal", delete(clear_self_heal))
        .route("/api/self-heal/", delete(clear_self_heal))
        .route("/api/self-heal/{key}", delete(clear_self_heal_key))
        .route("/api/incident", delete(clear_incident))
        .route("/api/incident/", delete(clear_incident))
        .route("/api/incident/{key}", delete(clear_incident_key))
        .route("/api/nuclear-wipe", post(nuclear_wipe))
        .route("/api/nuclear-wipe/", post(nuclear_wipe))
        .route("/api/nuclear-wipe/{key}", post(nuclear_wipe_key))
        .route("/api/nuke-token", get(get_nuke_token))
        .route("/api/nuke-token/", get(get_nuke_token))
        .route("/api/nuke-token/{key}", get(get_nuke_token_key))
        .route("/api/token", get(get_token))
        .route("/api/token/", get(get_token))
        .route("/api/token/{key}", get(get_token_key))
        // Query Logs
        .route("/api/logs", get(get_logs))
        .route("/api/logs/", get(get_logs))
        .route("/api/logs/{key}", get(get_logs_key))
        // Passive DNS Timeline
        .route("/api/passive-dns", get(passive_dns_handler))
        .route("/api/passive-dns/", get(passive_dns_handler))
        .route("/api/passive-dns/{key}", get(passive_dns_key_handler))
        .route("/api/passive-dns/drifts", get(passive_dns_drifts_handler))
        .route("/api/passive-dns/drifts/", get(passive_dns_drifts_handler))
        .route(
            "/api/passive-dns/drifts/{key}",
            get(passive_dns_drifts_key_handler),
        )
        // Canary Domain Detection
        .route("/api/canary", get(canary_handler))
        .route("/api/canary/{key}", get(canary_key_handler))
        // Real-Time SSE Log Stream
        .route("/api/logs/stream", get(logs_stream_handler))
        .route("/api/logs/stream/{key}", get(logs_stream_handler_key))
        .route("/{key}/api/logs/stream", get(logs_stream_handler_key))
        // Cache & TTL stats
        .route("/api/cache/stats", get(cache_stats_handler))
        .route("/api/cache/stats/{key}", get(cache_stats_key))
        .route("/api/ttl/volatile", get(volatile_domains_handler))
        .route("/api/ttl/volatile/{key}", get(volatile_domains_key))
        // Peer TLS Bundle Sync & ACME Coordination Lock
        .route("/internal/tls/bundle", get(get_tls_bundle))
        .route("/internal/tls/bundle/{key}", get(get_tls_bundle_key))
        .route("/internal/acme/lock", post(acquire_acme_lock))
        .route("/internal/acme/lock/{key}", post(acquire_acme_lock_key))
        .route("/internal/acme/unlock", post(release_acme_lock))
        .route("/internal/acme/unlock/{key}", post(release_acme_lock_key))
        // Self-Update & Rollback
        .route("/api/system/update", post(self_update_handler))
        .route("/api/system/update/", post(self_update_handler))
        .route("/api/system/update/{key}", post(self_update_key_handler))
        .route("/api/system/update/check", get(self_update_check_handler))
        .route("/api/system/update/check/", get(self_update_check_handler))
        .route("/api/system/update/check/{key}", get(self_update_check_key_handler))
        .route("/api/system/update/releases", get(self_update_releases_handler))
        .route("/api/system/update/releases/", get(self_update_releases_handler))
        .route("/api/system/update/releases/{key}", get(self_update_releases_key_handler))
        .route("/api/system/rollback", post(self_rollback_handler))
        .route("/api/system/rollback/", post(self_rollback_handler))
        .route("/api/system/rollback/{key}", post(self_rollback_key_handler))
        // Software Binary Management
        .route("/api/system/software", get(software_list_handler))
        .route("/api/system/software/", get(software_list_handler))
        .route("/api/system/software/{key}", get(software_list_key_handler))
        .route("/api/system/software/remove", post(software_remove_handler))
        .route("/api/system/software/remove/", post(software_remove_handler))
        .route("/api/system/software/remove/{key}", post(software_remove_key_handler))
        .route("/api/system/software/prune", post(software_prune_handler))
        .route("/api/system/software/prune/", post(software_prune_handler))
        .route("/api/system/software/prune/{key}", post(software_prune_key_handler))
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
                let peer_host = format!(
                    "http://{}.internal:{}/api/nuclear-wipe",
                    app_name, port
                );
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
                    .unwrap_or_default();
                let _ = client
                    .post(&peer_host)
                    .header("x-peer-sync", "1")
                    .header("x-master-key", &master_key)
                    .header("Authorization", format!("Bearer {}", master_key))
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

// ── In-Dashboard Self-Update & Rollback ──────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize, Default)]
pub struct SelfUpdateReq {
    pub version: Option<String>,
    pub tag: Option<String>,
}

pub async fn self_update_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    payload: Option<Json<SelfUpdateReq>>,
) -> Response {
    handle_self_update(&state, None, &headers, payload.map(|j| j.0)).await
}

pub async fn self_update_key_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    payload: Option<Json<SelfUpdateReq>>,
) -> Response {
    handle_self_update(&state, Some(&key), &headers, payload.map(|j| j.0)).await
}

pub async fn self_update_check_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_self_update_check(&state, None, &headers).await
}

pub async fn self_update_check_key_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_self_update_check(&state, Some(&key), &headers).await
}

pub async fn self_update_releases_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_self_update_releases(&state, None, &headers).await
}

pub async fn self_update_releases_key_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_self_update_releases(&state, Some(&key), &headers).await
}

pub async fn self_rollback_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_self_rollback(&state, None, &headers).await
}

pub async fn self_rollback_key_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_self_rollback(&state, Some(&key), &headers).await
}

async fn handle_self_update_check(
    state: &Arc<AppState>,
    key: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/system/update/check");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized" })),
        )
            .into_response();
    }

    let client = match reqwest::Client::builder()
        .user_agent("AmarDNS")
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let current_version = env!("CARGO_PKG_VERSION");
    let release_url = "https://api.github.com/repos/0abir/amardns/releases/latest";
    match client.get(release_url).send().await {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                let tag = json["tag_name"].as_str().unwrap_or("unknown");
                let has_update = !tag.contains(current_version);
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "ok": true,
                        "current_version": current_version,
                        "latest_version": tag,
                        "update_available": has_update,
                        "running_software": "/amardns",
                        "has_backup": std::path::Path::new("/amardns.bak").exists(),
                        "local_binaries": list_software_binaries(),
                        "html_url": json["html_url"].as_str().unwrap_or("")
                    })),
                )
                    .into_response()
            } else {
                (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "ok": false, "error": "Failed to parse GitHub release response" })),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "ok": false, "error": format!("GitHub API unreachable: {}", e) })),
        )
            .into_response(),
    }
}

async fn handle_self_update_releases(
    state: &Arc<AppState>,
    key: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/system/update/releases");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized" })),
        )
            .into_response();
    }

    match fetch_remote_releases().await {
        Ok(releases) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "current_version": format!("v{}", env!("CARGO_PKG_VERSION")),
                "total": releases.len(),
                "releases": releases,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "ok": false, "error": e })),
        )
            .into_response(),
    }
}

async fn handle_self_update(
    state: &Arc<AppState>,
    key: Option<&str>,
    headers: &HeaderMap,
    payload: Option<SelfUpdateReq>,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/system/update");
    if !auth.is_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Admin credentials required for self-update" })),
        )
            .into_response();
    }

    let target_ver = payload.as_ref()
        .and_then(|p| p.version.as_deref().or(p.tag.as_deref()));

    match perform_download_and_install(target_ver).await {
        Ok(msg) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "message": msg, "restarting": true })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": e })),
        )
            .into_response(),
    }
}

async fn handle_self_rollback(
    state: &Arc<AppState>,
    key: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/system/rollback");
    if !auth.is_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Admin credentials required for rollback" })),
        )
            .into_response();
    }

    match perform_rollback().await {
        Ok(msg) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "message": msg,
                "restarting": true
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": e
            })),
        )
            .into_response(),
    }
}

// ── Software Binary Management Handlers ──────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize, Default)]
pub struct SoftwareRemoveReq {
    pub target: Option<String>,
    pub file: Option<String>,
}

pub async fn software_list_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    handle_software_list(&state, None, &headers).await
}

pub async fn software_list_key_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_software_list(&state, Some(&key), &headers).await
}

async fn handle_software_list(
    state: &Arc<AppState>,
    key: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/system/software");
    if !auth.is_view_or_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Unauthorized" })),
        )
            .into_response();
    }
    let binaries = list_software_binaries();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "running": "/amardns",
            "fallback": "/amardns.bak",
            "has_fallback": std::path::Path::new("/amardns.bak").exists(),
            "count": binaries.len(),
            "binaries": binaries,
        })),
    )
        .into_response()
}

pub async fn software_remove_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    payload: Option<Json<SoftwareRemoveReq>>,
) -> Response {
    handle_software_remove(&state, None, &headers, payload.map(|j| j.0)).await
}

pub async fn software_remove_key_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    payload: Option<Json<SoftwareRemoveReq>>,
) -> Response {
    handle_software_remove(&state, Some(&key), &headers, payload.map(|j| j.0)).await
}

async fn handle_software_remove(
    state: &Arc<AppState>,
    key: Option<&str>,
    headers: &HeaderMap,
    payload: Option<SoftwareRemoveReq>,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/system/software/remove");
    if !auth.is_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Admin credentials required" })),
        )
            .into_response();
    }

    let target = payload.as_ref()
        .and_then(|p| p.target.as_ref().or(p.file.as_ref()))
        .cloned()
        .unwrap_or_default();

    if target.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "Missing 'target' or 'file' field" })),
        )
            .into_response();
    }

    match remove_software_binary(&target).await {
        Ok(msg) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "message": msg })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": e })),
        )
            .into_response(),
    }
}

pub async fn software_prune_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    handle_software_prune(&state, None, &headers).await
}

pub async fn software_prune_key_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_software_prune(&state, Some(&key), &headers).await
}

async fn handle_software_prune(
    state: &Arc<AppState>,
    key: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/system/software/prune");
    if !auth.is_admin() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": "Admin credentials required" })),
        )
            .into_response();
    }

    match prune_software_binaries() {
        Ok(msg) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "message": msg })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": e })),
        )
            .into_response(),
    }
}

// ── Software & Binary Management Architecture ────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct SoftwareBinaryInfo {
    pub name: String,
    pub path: String,
    pub status: String,
    pub version: String,
    pub size_bytes: u64,
    pub size_mb: f64,
    pub modified_iso: String,
    pub age_str: String,
}

/// Detect the version string of an on-disk AmarDNS binary.
fn detect_binary_version(path: &std::path::Path) -> Option<String> {
    let fname = path.file_name().and_then(|n| n.to_str())?;
    if fname.starts_with("amardns-") {
        let suffix = fname.trim_start_matches("amardns-");
        if !suffix.is_empty() {
            return Some(if suffix.starts_with('v') {
                suffix.to_string()
            } else {
                format!("v{}", suffix)
            });
        }
    }

    // Try fast inspection by executing --version
    let output = std::process::Command::new(path)
        .arg("--version")
        .output()
        .ok()?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("AmarDNS") {
                if let Some(v_part) = line.split_whitespace().last() {
                    return Some(v_part.to_string());
                }
            }
        }
    }
    None
}

/// Scans local filesystems for all AmarDNS binaries, backups, and version archives.
pub fn list_software_binaries() -> Vec<SoftwareBinaryInfo> {
    let mut list = Vec::new();
    let current_pkg_version = format!("v{}", env!("CARGO_PKG_VERSION"));
    let mut seen_paths = std::collections::HashSet::new();

    // Scan root directory / (and fallback /data if present)
    for dir_str in &["/", "/data"] {
        let dir = std::path::Path::new(dir_str);
        if !dir.is_dir() {
            continue;
        }

        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let file_name = match path.file_name().and_then(|n| n.to_str()) {
                    Some(s) => s.to_string(),
                    None => continue,
                };

                // Only consider amardns binaries and backups
                if !file_name.starts_with("amardns") {
                    continue;
                }

                if !path.is_file() {
                    continue;
                }

                let path_str = path.to_string_lossy().to_string();
                if seen_paths.contains(&path_str) {
                    continue;
                }
                seen_paths.insert(path_str.clone());

                let metadata = match std::fs::metadata(&path) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                let size_bytes = metadata.len();
                let size_mb = (size_bytes as f64 / 1_048_576.0 * 100.0).round() / 100.0;

                let (modified_iso, age_str) = match metadata.modified() {
                    Ok(time) => {
                        let duration = time.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                        let secs = duration.as_secs();
                        let iso = match chrono::DateTime::from_timestamp(secs as i64, 0) {
                            Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                            None => "unknown".to_string(),
                        };
                        let age = match time.elapsed() {
                            Ok(el) => {
                                let el_secs = el.as_secs();
                                if el_secs < 60 {
                                    format!("{}s ago", el_secs)
                                } else if el_secs < 3600 {
                                    format!("{}m ago", el_secs / 60)
                                } else if el_secs < 86400 {
                                    format!("{}h ago", el_secs / 3600)
                                } else {
                                    format!("{}d ago", el_secs / 86400)
                                }
                            }
                            Err(_) => "just now".to_string(),
                        };
                        (iso, age)
                    }
                    Err(_) => ("unknown".to_string(), "unknown".to_string()),
                };

                let (status, version) = if path_str == "/amardns" {
                    ("ACTIVE / RUNNING".to_string(), current_pkg_version.clone())
                } else if path_str == "/amardns.bak" {
                    let ver = detect_binary_version(&path).unwrap_or_else(|| "backup".to_string());
                    ("BACKUP / FALLBACK".to_string(), ver)
                } else if file_name.starts_with("amardns-") {
                    let ver = detect_binary_version(&path).unwrap_or_else(|| "archived".to_string());
                    ("ARCHIVED".to_string(), ver)
                } else if path_str == "/data/amardns" {
                    ("LEGACY PERSISTENT".to_string(), detect_binary_version(&path).unwrap_or_else(|| "legacy".to_string()))
                } else {
                    ("STAGED / TEMP".to_string(), detect_binary_version(&path).unwrap_or_else(|| "temp".to_string()))
                };

                list.push(SoftwareBinaryInfo {
                    name: file_name,
                    path: path_str,
                    status,
                    version,
                    size_bytes,
                    size_mb,
                    modified_iso,
                    age_str,
                });
            }
        }
    }

    // Sort order: ACTIVE first, then BACKUP, then ARCHIVED by age
    list.sort_by(|a, b| {
        let rank = |status: &str| match status {
            "ACTIVE / RUNNING" => 0,
            "BACKUP / FALLBACK" => 1,
            "ARCHIVED" => 2,
            _ => 3,
        };
        let r_a = rank(&a.status);
        let r_b = rank(&b.status);
        if r_a != r_b {
            r_a.cmp(&r_b)
        } else {
            b.modified_iso.cmp(&a.modified_iso)
        }
    });

    list
}

/// Fallback / Rollback: restores /amardns.bak to /amardns, and archives
/// the current /amardns to /amardns-<version_number>.
pub async fn perform_rollback() -> Result<String, String> {
    let active_bin = std::path::Path::new("/amardns");
    let backup_bin = std::path::Path::new("/amardns.bak");

    // 1. Locate backup or best fallback candidate
    let fallback_source = if backup_bin.is_file() {
        backup_bin.to_path_buf()
    } else {
        // Search for newest /amardns-* archive
        let mut archives: Vec<std::path::PathBuf> = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/") {
            for e in entries.flatten() {
                let p = e.path();
                if let Some(n) = p.file_name().and_then(|s| s.to_str()) {
                    if n.starts_with("amardns-") && p.is_file() {
                        archives.push(p);
                    }
                }
            }
        }
        archives.sort_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());
        archives.reverse();
        archives.into_iter().next().ok_or_else(|| {
            "No backup binary found at /amardns.bak or /amardns-* to roll back to.".to_string()
        })?
    };

    // 2. Read version of active binary to archive it as /amardns-<version_number>
    let current_version = env!("CARGO_PKG_VERSION").trim_start_matches('v');
    let archive_path = format!("/amardns-{}", current_version);

    if active_bin.is_file() {
        let _ = std::fs::rename(active_bin, &archive_path).or_else(|_| {
            std::fs::copy(active_bin, &archive_path)?;
            std::fs::remove_file(active_bin)
        });
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&archive_path, std::fs::Permissions::from_mode(0o755));
        }
        tracing::info!("[system] Rollback: archived current binary /amardns -> {}", archive_path);
    }

    // 3. Copy fallback source into /amardns
    std::fs::copy(&fallback_source, active_bin)
        .map_err(|e| format!("Failed to restore {:?} to /amardns: {}", fallback_source, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(active_bin, std::fs::Permissions::from_mode(0o755));
    }

    let source_display = fallback_source.to_string_lossy().to_string();
    tracing::info!(
        "[system] Rollback complete: /amardns restored from {}. Previous active binary archived as {}. Triggering in-place execve...",
        source_display,
        archive_path
    );

    // 4. Trigger in-place execve restart into /amardns
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        tracing::info!("[system] Rollback: in-place restart into /amardns via execve...");
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new("/amardns")
                .args(std::env::args().skip(1))
                .envs(std::env::vars())
                .exec();
            tracing::error!("[system] In-place execve to /amardns failed: {}", err);
            std::process::exit(1);
        }
        #[cfg(not(unix))]
        std::process::exit(0);
    });

    Ok(format!(
        "Rollback successful: active binary archived as '{}', fallback '{}' restored as /amardns. Restarting in-place...",
        archive_path, source_display
    ))
}

/// Removes a software binary or version archive.
/// Discovers recovery candidates from a directory, prioritizing the newest local /amardns-* archive,
/// then /amardns.bak fallback.
pub fn find_recovery_candidate(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if let Some(n) = p.file_name().and_then(|s| s.to_str()) {
                if n.starts_with("amardns-") && p.is_file() {
                    candidates.push(p);
                }
            }
        }
    }
    candidates.sort_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());
    candidates.reverse();

    if let Some(cand) = candidates.first() {
        Some(cand.clone())
    } else {
        let backup = dir.join("amardns.bak");
        if backup.is_file() {
            Some(backup)
        } else {
            None
        }
    }
}

/// SAFETY WATCHDOG: If the running software (/amardns) is removed,
/// immediately restores from the newest local version or /amardns.bak and restarts.
pub async fn remove_software_binary(target_name: &str) -> Result<String, String> {
    let clean = target_name.trim();
    if clean.is_empty() {
        return Err("Specify binary to remove (e.g. 'amardns.bak', 'amardns-1.0.10')".to_string());
    }

    if clean.contains("..") {
        return Err("Security restriction: path traversal sequences ('..') are strictly disallowed.".to_string());
    }

    let target_path = if clean.starts_with('/') {
        std::path::PathBuf::from(clean)
    } else {
        std::path::PathBuf::from(format!("/{}", clean))
    };

    let file_name = target_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if !file_name.starts_with("amardns") {
        return Err(format!("Security restriction: can only remove AmarDNS software binaries (must begin with 'amardns'), rejected '{}'", file_name));
    }

    if !target_path.exists() {
        let rel_path = std::path::Path::new(clean);
        if !rel_path.exists() {
            return Err(format!("File '{}' not found.", target_path.display()));
        }
    }

    let target_str = target_path.to_string_lossy().to_string();

    // Check if user is removing the active running binary /amardns
    if target_str == "/amardns" {
        tracing::warn!("[watchdog] Active software /amardns was targeted for removal! Engaging safety watchdog recovery...");
        let _ = std::fs::remove_file(&target_path);

        let backup = std::path::Path::new("/amardns.bak");
        let (recovery_src, recovery_desc) = if let Some(cand) = find_recovery_candidate(std::path::Path::new("/")) {
            let is_bak = cand == backup;
            let desc = if is_bak {
                "fallback backup '/amardns.bak'".to_string()
            } else {
                format!("local newer archive '{}'", cand.display())
            };
            (cand, desc)
        } else if let Ok(exe) = std::env::current_exe() {
            (exe.clone(), format!("running process image '{}'", exe.display()))
        } else {
            return Err("CRITICAL: Failed to locate recovery binary for /amardns!".to_string());
        };

        // Restore immediately to /amardns
        std::fs::copy(&recovery_src, "/amardns")
            .map_err(|e| format!("Watchdog failed to restore {:?} to /amardns: {}", recovery_src, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions("/amardns", std::fs::Permissions::from_mode(0o755));
        }

        // Schedule immediate restart
        tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            tracing::warn!("[watchdog] Triggering emergency in-place restart into restored /amardns...");
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                let _ = std::process::Command::new("/amardns")
                    .args(std::env::args().skip(1))
                    .envs(std::env::vars())
                    .exec();
                std::process::exit(1);
            }
            #[cfg(not(unix))]
            std::process::exit(0);
        });

        return Ok(format!(
            "[SAFETY WATCHDOG ACTIVATED]\n\
             Active running software '/amardns' was deleted!\n\
             Watchdog immediately engaged automated recovery:\n\
               -> Restored from: {}\n\
               -> Reinstalled to: /amardns (0755)\n\
               -> Fresh restart: In-place execve triggered for an instant fresh start.\n",
            recovery_desc
        ));
    }

    // Normal file removal (e.g. /amardns.bak or /amardns-1.0.10)
    let size_mb = std::fs::metadata(&target_path)
        .map(|m| (m.len() as f64 / 1_048_576.0 * 100.0).round() / 100.0)
        .unwrap_or(0.0);

    std::fs::remove_file(&target_path)
        .map_err(|e| format!("Failed to delete '{}': {}", target_path.display(), e))?;

    Ok(format!(
        "Successfully removed software file '{}' ({:.2} MB).",
        target_path.display(),
        size_mb
    ))
}

/// Prunes all archived /amardns-* binaries, keeping /amardns and /amardns.bak.
pub fn prune_software_binaries() -> Result<String, String> {
    let mut removed_count = 0;
    let mut freed_bytes = 0u64;

    if let Ok(entries) = std::fs::read_dir("/") {
        for e in entries.flatten() {
            let p = e.path();
            if let Some(n) = p.file_name().and_then(|s| s.to_str()) {
                if (n.starts_with("amardns-") || n == "amardns.download") && p.is_file() {
                    if let Ok(m) = std::fs::metadata(&p) {
                        freed_bytes += m.len();
                    }
                    if std::fs::remove_file(&p).is_ok() {
                        removed_count += 1;
                    }
                }
            }
        }
    }

    let freed_mb = (freed_bytes as f64 / 1_048_576.0 * 100.0).round() / 100.0;
    Ok(format!(
        "Pruned {} old archived binary file(s). Freed {:.2} MB. Active '/amardns' and backup '/amardns.bak' preserved.",
        removed_count, freed_mb
    ))
}

/// Remote release item from GitHub repository releases API.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct RemoteReleaseInfo {
    pub tag: String,
    pub name: String,
    pub published_at: String,
    pub relative_age: String,
    pub prerelease: bool,
    pub is_current: bool,
    pub has_binary: bool,
    pub html_url: String,
}

fn format_relative_time_str(rfc3339_str: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(rfc3339_str) {
        let now = chrono::Utc::now();
        let diff = now.signed_duration_since(dt.with_timezone(&chrono::Utc));
        let secs = diff.num_seconds();
        if secs < 60 {
            "just now".to_string()
        } else if secs < 3600 {
            format!("{}m ago", secs / 60)
        } else if secs < 86400 {
            format!("{}h ago", secs / 3600)
        } else if secs < 2592000 {
            format!("{}d ago", secs / 86400)
        } else {
            format!("{}mo ago", secs / 2592000)
        }
    } else {
        "unknown".to_string()
    }
}

pub async fn fetch_remote_releases() -> Result<Vec<RemoteReleaseInfo>, String> {
    let client = reqwest::Client::builder()
        .user_agent("AmarDNS")
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let url = "https://api.github.com/repos/0abir/amardns/releases?per_page=100";
    let resp = client.get(url).send().await
        .map_err(|e| format!("GitHub API request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("GitHub API returned HTTP {}", resp.status()));
    }

    let releases_json: Vec<serde_json::Value> = resp.json().await
        .map_err(|e| format!("Failed to parse releases JSON: {}", e))?;

    let is_arm64 = std::env::consts::ARCH == "aarch64";
    let current_pkg_ver = format!("v{}", env!("CARGO_PKG_VERSION"));
    let mut results = Vec::new();

    for rel in releases_json {
        let tag = rel["tag_name"].as_str().unwrap_or("").to_string();
        if tag.is_empty() {
            continue;
        }
        let name = rel["name"].as_str().unwrap_or(&tag).to_string();
        let pub_at = rel["published_at"].as_str().unwrap_or("").to_string();
        let relative_age = format_relative_time_str(&pub_at);
        let prerelease = rel["prerelease"].as_bool().unwrap_or(false);
        let html_url = rel["html_url"].as_str().unwrap_or("").to_string();

        let has_binary = rel["assets"].as_array().map(|assets| {
            assets.iter().any(|a| {
                let n = a["name"].as_str().unwrap_or("");
                if is_arm64 {
                    n == "amardns-arm64" || n == "amardns-linux-arm64" || n == "amardns"
                } else {
                    n == "amardns" || n == "amardns-linux-amd64"
                }
            })
        }).unwrap_or(false);

        let is_current = tag == current_pkg_ver || tag.trim_start_matches('v') == env!("CARGO_PKG_VERSION");

        results.push(RemoteReleaseInfo {
            tag,
            name,
            published_at: pub_at,
            relative_age,
            prerelease,
            is_current,
            has_binary,
            html_url,
        });
    }

    Ok(results)
}

/// Official AmarDNS release signing public key (Ed25519, 32 bytes).
pub const AMARDNS_RELEASE_ED25519_PUBKEY_HEX: &str =
    "a85b9b7816f8ef1907de3bf270c3298a09cf932bb82f5b6164e2292fca3b3064";

/// Verifies Ed25519 release signature over binary bytes or SHA256 digest
pub fn verify_release_signature(
    bin_bytes: &[u8],
    actual_sha: &str,
    sig_raw: &[u8],
    override_pubkey: Option<&[u8]>,
) -> Result<(), String> {
    let pubkey_bytes = if let Some(pk) = override_pubkey {
        pk.to_vec()
    } else if let Ok(custom_hex) = std::env::var("AMARDNS_RELEASE_PUBKEY") {
        crate::dns::dnssec::hex_decode(&custom_hex)
            .map_err(|e| format!("Invalid AMARDNS_RELEASE_PUBKEY hex: {}", e))?
    } else {
        crate::dns::dnssec::hex_decode(AMARDNS_RELEASE_ED25519_PUBKEY_HEX)
            .map_err(|e| format!("Invalid embedded release pubkey hex: {}", e))?
    };

    if pubkey_bytes.len() != 32 {
        return Err("Invalid Ed25519 public key length (expected 32 bytes)".to_string());
    }

    let sig_bytes = if sig_raw.len() == 64 {
        sig_raw.to_vec()
    } else if let Ok(s) = std::str::from_utf8(sig_raw) {
        let trimmed = s.trim();
        if let Ok(b) = crate::dns::dnssec::hex_decode(trimmed) {
            b
        } else if let Ok(b) = crate::server::acme::b64url_decode(trimmed) {
            b
        } else {
            return Err("Malformed Ed25519 signature format (must be 64 raw bytes, hex, or base64)".to_string());
        }
    } else {
        return Err("Malformed Ed25519 signature bytes".to_string());
    };

    if sig_bytes.len() != 64 {
        return Err(format!("Invalid Ed25519 signature length (expected 64 bytes, got {})", sig_bytes.len()));
    }

    let peer_public_key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        &pubkey_bytes,
    );

    // Verify signature over the raw binary bytes, or over the 64-char lowercase SHA256 hex string
    if peer_public_key.verify(bin_bytes, &sig_bytes).is_ok()
        || peer_public_key.verify(actual_sha.as_bytes(), &sig_bytes).is_ok()
    {
        Ok(())
    } else {
        Err("Security alert: Ed25519 cryptographic signature verification failed! Untrusted binary.".to_string())
    }
}

/// Download, verify, and install binary (latest or specific target version) to /amardns, backing up current to /amardns.bak.
pub async fn perform_download_and_install(target_version: Option<&str>) -> Result<String, String> {
    if std::env::var("DISABLE_IN_PLACE_UPDATES")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return Err(
            "In-place binary updates are disabled in this environment. Updates are managed via container image deployment."
                .to_string(),
        );
    }

    let client = reqwest::Client::builder()
        .user_agent("AmarDNS")
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let (release_url, is_specific) = match target_version {
        Some(v) if !v.trim().is_empty() && !v.eq_ignore_ascii_case("latest") => {
            let trimmed = v.trim();
            if !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_') {
                return Err("Security restriction: invalid characters in version tag. Only alphanumeric, '.', '-', and '_' are permitted.".to_string());
            }
            let clean_tag = if trimmed.starts_with('v') {
                trimmed.to_string()
            } else {
                format!("v{}", trimmed)
            };
            (format!("https://api.github.com/repos/0abir/amardns/releases/tags/{}", clean_tag), true)
        }
        _ => ("https://api.github.com/repos/0abir/amardns/releases/latest".to_string(), false),
    };

    let resp = client.get(&release_url)
        .send()
        .await
        .map_err(|e| format!("GitHub API request failed: {}", e))?;

    if !resp.status().is_success() {
        if resp.status() == reqwest::StatusCode::NOT_FOUND && is_specific {
            return Err(format!("Release version '{}' was not found on GitHub. Please check the version catalog.", target_version.unwrap_or("")));
        }
        return Err(format!("GitHub API returned HTTP {}", resp.status()));
    }

    let release_json: serde_json::Value = resp.json().await
        .map_err(|e| format!("Failed to parse release JSON: {}", e))?;

    let tag_name = release_json["tag_name"].as_str().unwrap_or("latest").to_string();
    let assets = release_json["assets"].as_array()
        .ok_or_else(|| "No assets attached to release".to_string())?;

    let is_arm64 = std::env::consts::ARCH == "aarch64";
    let binary_asset = assets.iter().find(|a| {
        let name = a["name"].as_str().unwrap_or("");
        if is_arm64 {
            name == "amardns-arm64" || name == "amardns-linux-arm64" || name == "amardns"
        } else {
            name == "amardns" || name == "amardns-linux-amd64"
        }
    }).ok_or_else(|| format!("No compatible static binary asset found in release {}", tag_name))?;

    let download_url = binary_asset["browser_download_url"].as_str()
        .ok_or_else(|| "Missing download URL on binary asset".to_string())?;

    tracing::info!("[update] Downloading binary ({}) from: {}", tag_name, download_url);
    let bin_bytes = client.get(download_url)
        .send()
        .await
        .map_err(|e| format!("Binary download request failed: {}", e))?
        .bytes()
        .await
        .map_err(|e| format!("Failed to read binary bytes: {}", e))?;

    if bin_bytes.len() < 500_000 {
        return Err(format!("Downloaded file is too small ({} bytes) to be a valid binary", bin_bytes.len()));
    }

    // MANDATORY Cryptographic Checksum Verification (Pre-execution gate)
    let expected_sha_name = if is_arm64 { "amardns-arm64.sha256" } else { "amardns.sha256" };
    let sha_asset = assets.iter().find(|a| {
        let n = a["name"].as_str().unwrap_or("");
        n == expected_sha_name || n == "amardns.sha256"
    }).ok_or_else(|| "Security violation: Release has no published SHA256 checksum asset. Update refused.".to_string())?;

    let sha_url = sha_asset["browser_download_url"].as_str()
        .ok_or_else(|| "Missing download URL for SHA256 asset".to_string())?;
    let sha_res = client.get(sha_url).send().await
        .map_err(|e| format!("Failed to download SHA256 checksum: {}", e))?;
    let sha_text = sha_res.text().await
        .map_err(|e| format!("Failed to read SHA256 checksum text: {}", e))?;
    let expected_sha = sha_text.split_whitespace().next().unwrap_or("").to_lowercase();
    if expected_sha.len() != 64 {
        return Err("Security violation: Malformed SHA256 checksum asset.".to_string());
    }

    let actual_digest = ring::digest::digest(&ring::digest::SHA256, &bin_bytes);
    let actual_sha: String = actual_digest.as_ref().iter().map(|b| format!("{:02x}", b)).collect();
    if actual_sha != expected_sha {
        return Err(format!("Security alert: SHA256 checksum verification failed! Expected {}, got {}", expected_sha, actual_sha));
    }
    tracing::info!("[update] Cryptographic SHA256 checksum verified: {}", actual_sha);

    // MANDATORY Ed25519 Cryptographic Signature Verification (Pre-execution gate)
    let expected_sig_name = if is_arm64 { "amardns-arm64.sig" } else { "amardns.sig" };
    let sig_asset = assets.iter().find(|a| {
        let n = a["name"].as_str().unwrap_or("");
        n == expected_sig_name || n == "amardns.sig" || n.ends_with(".sig") || n.ends_with(".minisig")
    });

    let bypass_sig = std::env::var("DISABLE_OTA_SIGNATURE_CHECK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !bypass_sig {
        let sig_asset = sig_asset.ok_or_else(|| {
            "Security violation: Release has no published Ed25519 signature asset (.sig). Update refused."
                .to_string()
        })?;
        let sig_url = sig_asset["browser_download_url"].as_str()
            .ok_or_else(|| "Missing download URL for signature asset".to_string())?;
        let sig_res = client.get(sig_url).send().await
            .map_err(|e| format!("Failed to download Ed25519 signature: {}", e))?;
        let sig_raw = sig_res.bytes().await
            .map_err(|e| format!("Failed to read Ed25519 signature: {}", e))?;

        verify_release_signature(&bin_bytes, &actual_sha, &sig_raw, None)?;
        tracing::info!("[update] Cryptographic Ed25519 signature verified successfully.");
    } else {
        tracing::warn!("[update] WARNING: Ed25519 release signature check bypassed by environment flag.");
    }

    let tmp_bin = "/amardns.download";
    let target_bin = "/amardns";
    let backup_bin = "/amardns.bak";

    std::fs::write(tmp_bin, &bin_bytes)
        .map_err(|e| format!("Failed to write binary to {}: {}", tmp_bin, e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(tmp_bin, std::fs::Permissions::from_mode(0o755));
    }

    // Execute sandboxed pre-flight verification test on downloaded binary before swapping
    let verify_check = std::process::Command::new(tmp_bin)
        .arg("--verify")
        .output();

    match verify_check {
        Ok(out) if out.status.success() && String::from_utf8_lossy(&out.stdout).contains("AMARDNS_OK") => {
            tracing::info!("[update] Pre-flight binary verification passed successfully.");
        }
        Ok(out) => {
            let _ = std::fs::remove_file(tmp_bin);
            let err_msg = String::from_utf8_lossy(&out.stderr);
            return Err(format!("Pre-flight verification failed (exit code {:?}): {}. Update aborted, running production binary untouched.", out.status.code(), err_msg.trim()));
        }
        Err(e) => {
            let _ = std::fs::remove_file(tmp_bin);
            return Err(format!("Pre-flight binary execution failed: {}. Binary is corrupted or incompatible. Update aborted, running production binary untouched.", e));
        }
    }

    // Rotate: current /amardns -> /amardns.bak
    if std::path::Path::new(target_bin).exists() {
        let _ = std::fs::copy(target_bin, backup_bin);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(backup_bin, std::fs::Permissions::from_mode(0o755));
        }
        tracing::info!("[update] Backed up current binary to {}", backup_bin);
    }

    std::fs::rename(tmp_bin, target_bin)
        .map_err(|e| format!("Failed to atomically rename {} to {}: {}", tmp_bin, target_bin, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(target_bin, std::fs::Permissions::from_mode(0o755));
    }

    tracing::info!("[update] AmarDNS binary installed to {} (version {}). Triggering restart...", target_bin, tag_name);

    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        tracing::info!("[system] Hot-restarting AmarDNS into new /amardns binary via in-place execve...");
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new("/amardns")
                .args(std::env::args().skip(1))
                .envs(std::env::vars())
                .exec();
            tracing::error!(
                "[system] In-place execve to /amardns failed: {}. Exiting with code 1 to trigger supervisor restart...",
                err
            );
            std::process::exit(1);
        }
        #[cfg(not(unix))]
        std::process::exit(0);
    });

    Ok(format!(
        "Successfully upgraded to {} ({:.2} MB). Previous binary saved to /amardns.bak. In-place restart triggered.",
        tag_name, bin_bytes.len() as f64 / 1_048_576.0
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_software_binaries_structure() {
        let binaries = list_software_binaries();
        // Should execute cleanly without panicking
        for b in &binaries {
            assert!(!b.name.is_empty());
            assert!(!b.path.is_empty());
            assert!(!b.status.is_empty());
            assert!(!b.version.is_empty());
        }
    }

    #[tokio::test]
    async fn test_remove_software_binary_validation() {
        let err_empty = remove_software_binary("   ").await;
        assert!(err_empty.is_err());
        assert!(err_empty.unwrap_err().contains("Specify binary to remove"));

        // Path traversal protection
        let err_traversal = remove_software_binary("../../../etc/shadow").await;
        assert!(err_traversal.is_err());
        assert!(err_traversal.unwrap_err().contains("path traversal"));

        // Restricted to amardns files only
        let err_non_amardns = remove_software_binary("/etc/passwd").await;
        assert!(err_non_amardns.is_err());
        assert!(err_non_amardns.unwrap_err().contains("Security restriction"));

        let err_not_found = remove_software_binary("amardns-nonexistent-123.bak").await;
        assert!(err_not_found.is_err());
        assert!(err_not_found.unwrap_err().contains("not found"));
    }

    #[tokio::test]
    async fn test_perform_download_tag_sanitization() {
        let err_invalid_chars = perform_download_and_install(Some("v1.0.0;rm -rf /")).await;
        assert!(err_invalid_chars.is_err());
        assert!(err_invalid_chars.unwrap_err().contains("Security restriction: invalid characters"));
    }

    #[test]
    fn test_format_relative_time_str() {
        let age_now = format_relative_time_str(&chrono::Utc::now().to_rfc3339());
        assert_eq!(age_now, "just now");

        let past = chrono::Utc::now() - chrono::Duration::hours(5);
        let age_hours = format_relative_time_str(&past.to_rfc3339());
        assert_eq!(age_hours, "5h ago");

        let past_days = chrono::Utc::now() - chrono::Duration::days(3);
        let age_days = format_relative_time_str(&past_days.to_rfc3339());
        assert_eq!(age_days, "3d ago");

        let invalid = format_relative_time_str("not_a_date");
        assert_eq!(invalid, "unknown");
    }

    #[test]
    fn test_safety_watchdog_auto_recovery_candidate_resolution() {
        let temp_dir = std::env::temp_dir().join(format!("amardns_wd_test_{}_{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let _ = std::fs::create_dir_all(&temp_dir);

        // 1. In empty directory: no candidate
        assert_eq!(find_recovery_candidate(&temp_dir), None);

        // 2. Only fallback backup exists: selects amardns.bak
        let bak_path = temp_dir.join("amardns.bak");
        let _ = std::fs::write(&bak_path, b"backup binary content");
        assert_eq!(find_recovery_candidate(&temp_dir), Some(bak_path.clone()));

        // 3. Newer archive exists: prioritizes newer amardns-v1.0.10 over amardns.bak
        let v1_path = temp_dir.join("amardns-v1.0.10");
        std::thread::sleep(std::time::Duration::from_millis(15));
        let _ = std::fs::write(&v1_path, b"v1.0.10 binary content");
        assert_eq!(find_recovery_candidate(&temp_dir), Some(v1_path.clone()));

        // 4. Even newer archive added: prioritizes newest
        let v2_path = temp_dir.join("amardns-v1.0.11");
        std::thread::sleep(std::time::Duration::from_millis(15));
        let _ = std::fs::write(&v2_path, b"v1.0.11 binary content");
        assert_eq!(find_recovery_candidate(&temp_dir), Some(v2_path.clone()));

        // 5. Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_verify_release_signature() {
        // RFC 8032 Test Vector 1 for Ed25519
        let pubkey_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let pubkey_bytes = crate::dns::dnssec::hex_decode(pubkey_hex).unwrap();
        let msg = b"";
        let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        let sig_bytes = crate::dns::dnssec::hex_decode(sig_hex).unwrap();

        // Valid signature over binary content
        assert!(verify_release_signature(msg, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", &sig_bytes, Some(&pubkey_bytes)).is_ok());

        // Tampered signature should fail
        let mut bad_sig = sig_bytes.clone();
        bad_sig[0] ^= 0xFF;
        assert!(verify_release_signature(msg, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", &bad_sig, Some(&pubkey_bytes)).is_err());
    }
}



