use std::sync::Arc;
use std::time::SystemTime;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;

use super::{broadcast_peer_sync, DomainReq};
use crate::security::auth::{check_auth, AuthRole};
use crate::state::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
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

        // Feature 9: Scheduled Blocking Rules
        .route("/api/schedule", get(get_schedule).post(add_schedule))
        .route("/api/schedule/:id", delete(delete_schedule))
}

// ── Blocklist Handlers ──────────────────────────────────────────────────────

pub async fn get_blocklist(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_get_blocklist(&state, None, &headers).await
}

pub async fn get_blocklist_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_blocklist(&state, Some(&key), &headers).await
}

pub async fn handle_get_blocklist(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
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

pub async fn add_blocklist(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_add_blocklist(&state, None, &headers, payload).await
}

pub async fn add_blocklist_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_add_blocklist(&state, Some(&key), &headers, payload).await
}

pub async fn handle_add_blocklist(
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
            let clean = match crate::security::sanitizer::sanitize_domain(&raw) {
                Ok(c) => c,
                Err(err) => {
                    skipped.push(format!("{}: {}", raw.trim(), err));
                    continue;
                }
            };
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

pub async fn delete_blocklist(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_delete_blocklist(&state, None, &headers, payload).await
}

pub async fn delete_blocklist_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_delete_blocklist(&state, Some(&key), &headers, payload).await
}

pub async fn handle_delete_blocklist(
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

    let raw = payload.domain.clone().unwrap_or_default();
    let clean = match crate::security::sanitizer::sanitize_domain(&raw) {
        Ok(c) => c,
        Err(err) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "ok": false, "error": format!("invalid domain: {}", err) }))).into_response();
        }
    };
    state.wal.append_unblock(&clean);
    state.custom_blocklist.write().remove(&clean);
    broadcast_peer_sync(headers, &state.config.dns_master_key, reqwest::Method::DELETE, "/api/blocklist", Some(serde_json::json!(payload)));
    state.log_action("blocklist_removed", &clean);
    Json(serde_json::json!({ "ok": true, "domain": clean })).into_response()
}

pub async fn clear_blocklist(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_clear_blocklist(&state, None, &headers).await
}

pub async fn clear_blocklist_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_clear_blocklist(&state, Some(&key), &headers).await
}

pub async fn handle_clear_blocklist(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
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

pub async fn get_whitelist(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_get_whitelist(&state, None, &headers).await
}

pub async fn get_whitelist_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_whitelist(&state, Some(&key), &headers).await
}

pub async fn handle_get_whitelist(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
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

pub async fn add_whitelist(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_add_whitelist(&state, None, &headers, payload).await
}

pub async fn add_whitelist_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_add_whitelist(&state, Some(&key), &headers, payload).await
}

pub async fn handle_add_whitelist(
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
            let clean = match crate::security::sanitizer::sanitize_domain(&raw) {
                Ok(c) => c,
                Err(err) => {
                    skipped.push(format!("{}: {}", raw.trim(), err));
                    continue;
                }
            };
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
    for dom in &added_domains {
        state.cache.invalidate_negative(dom).await;
    }

    broadcast_peer_sync(headers, &state.config.dns_master_key, reqwest::Method::POST, "/api/whitelist", Some(serde_json::json!(payload)));
    state.log_action("whitelist_added", &format!("Added {} domain(s)", added));
    Json(serde_json::json!({
        "ok": true,
        "added": added,
        "skipped": skipped
    })).into_response()
}

pub async fn delete_whitelist(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_delete_whitelist(&state, None, &headers, payload).await
}

pub async fn delete_whitelist_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_delete_whitelist(&state, Some(&key), &headers, payload).await
}

pub async fn handle_delete_whitelist(
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

    let raw = payload.domain.clone().unwrap_or_default();
    let clean = match crate::security::sanitizer::sanitize_domain(&raw) {
        Ok(c) => c,
        Err(err) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "ok": false, "error": format!("invalid domain: {}", err) }))).into_response();
        }
    };
    state.wal.append_unwhitelist(&clean);
    state.custom_whitelist.write().remove(&clean);
    broadcast_peer_sync(headers, &state.config.dns_master_key, reqwest::Method::DELETE, "/api/whitelist", Some(serde_json::json!(payload)));
    state.log_action("whitelist_removed", &clean);
    Json(serde_json::json!({ "ok": true, "domain": clean })).into_response()
}

pub async fn clear_whitelist(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_clear_whitelist(&state, None, &headers).await
}

pub async fn clear_whitelist_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_clear_whitelist(&state, Some(&key), &headers).await
}

pub async fn handle_clear_whitelist(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
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

pub async fn get_common(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_get_common(&state, None, &headers).await
}

pub async fn get_common_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_common(&state, Some(&key), &headers).await
}

pub async fn handle_get_common(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
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

pub async fn add_common(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_add_common(&state, None, &headers, payload).await
}

pub async fn add_common_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_add_common(&state, Some(&key), &headers, payload).await
}

pub async fn handle_add_common(
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
            let clean = match crate::security::sanitizer::sanitize_domain(&raw) {
                Ok(c) => c,
                Err(err) => {
                    skipped.push(format!("{}: {}", raw.trim(), err));
                    continue;
                }
            };
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
    for dom in &added_domains {
        state.cache.invalidate_negative(dom).await;
    }

    broadcast_peer_sync(headers, &state.config.dns_master_key, reqwest::Method::POST, "/api/common", Some(serde_json::json!(payload)));
    state.log_action("common_added", &format!("Added {} domain(s)", added));
    Json(serde_json::json!({
        "ok": true,
        "added": added,
        "skipped": skipped
    })).into_response()
}

pub async fn delete_common(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_delete_common(&state, None, &headers, payload).await
}

pub async fn delete_common_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_delete_common(&state, Some(&key), &headers, payload).await
}

pub async fn handle_delete_common(
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

    let raw = payload.domain.clone().unwrap_or_default();
    let clean = match crate::security::sanitizer::sanitize_domain(&raw) {
        Ok(c) => c,
        Err(err) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "ok": false, "error": format!("invalid domain: {}", err) }))).into_response();
        }
    };
    state.wal.append_uncommon(&clean);
    state.custom_common.write().remove(&clean);
    broadcast_peer_sync(headers, &state.config.dns_master_key, reqwest::Method::DELETE, "/api/common", Some(serde_json::json!(payload)));
    state.log_action("common_removed", &clean);
    Json(serde_json::json!({ "ok": true, "domain": clean })).into_response()
}

pub async fn clear_common(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    handle_clear_common(&state, None, &headers).await
}

pub async fn clear_common_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_clear_common(&state, Some(&key), &headers).await
}

pub async fn handle_clear_common(state: &AppState, key: Option<&str>, headers: &HeaderMap) -> Response {
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

pub async fn add_auto_block(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_add_auto_block(&state, None, &headers, payload).await
}

pub async fn add_auto_block_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_add_auto_block(&state, Some(&key), &headers, payload).await
}

pub async fn handle_add_auto_block(
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

    if let Some(ref raw) = payload.domain {
        if let Ok(clean) = crate::security::sanitizer::sanitize_domain(raw) {
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

pub async fn delete_auto_block(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_delete_auto_block(&state, None, &headers, payload).await
}

pub async fn delete_auto_block_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<DomainReq>,
) -> Response {
    handle_delete_auto_block(&state, Some(&key), &headers, payload).await
}

pub async fn handle_delete_auto_block(
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

    if let Some(ref raw) = payload.domain {
        if let Ok(clean) = crate::security::sanitizer::sanitize_domain(raw) {
            state.custom_blocklist.write().remove(&clean);
            state.wal.append_unblock(&clean);
            state.log_action("auto_block_removed", &clean);
        }
    }
    Json(serde_json::json!({ "ok": true })).into_response()
}

// ── Heatmap Handlers ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct HeatmapLookupQuery {
    pub domain: Option<String>,
}

pub async fn get_heatmap_top(
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

pub async fn get_heatmap_top_key(
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

pub fn handle_heatmap_lookup(state: &AppState, domain_opt: Option<&str>) -> Json<serde_json::Value> {
    let raw = domain_opt.unwrap_or_default();
    let clean = match crate::security::sanitizer::sanitize_domain(raw) {
        Ok(c) => c,
        Err(_) => return Json(serde_json::json!({ "ok": true, "domain": "", "found": false })),
    };
    let guard = state.heatmap.read();
    if let Some(rec) = guard.get(&clean) {
        let max_val = *rec.hourly.iter().max().unwrap_or(&0);
        let peak_hour = rec.hourly.iter().position(|&v| v == max_val).unwrap_or(0);
        Json(serde_json::json!({
            "ok": true,
            "found": true,
            "domain": clean,
            "total": rec.total,
            "peak": peak_hour,
            "peakRps": max_val,
            "hourly": rec.hourly
        }))
    } else {
        Json(serde_json::json!({
            "ok": true,
            "domain": clean,
            "found": false
        }))
    }
}

pub async fn heatmap_lookup(
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

pub async fn heatmap_lookup_key(
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

// ── DGA Test Handlers ───────────────────────────────────────────────────────

pub async fn dga_test(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DomainReq>,
) -> Json<serde_json::Value> {
    let raw = payload.domain.unwrap_or_default();
    let clean = match crate::security::sanitizer::sanitize_domain(&raw) {
        Ok(c) => c,
        Err(err) => {
            return Json(serde_json::json!({ "ok": false, "error": format!("Invalid domain: {}", err) }));
        }
    };
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

pub async fn dga_test_key(
    State(state): State<Arc<AppState>>,
    Path(_key): Path<String>,
    Json(payload): Json<DomainReq>,
) -> Json<serde_json::Value> {
    dga_test(State(state), Json(payload)).await
}

// ── Feature 9: Scheduled Blocking Rules ──────────────────────────────────────

pub async fn get_schedule(
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
pub struct AddScheduleReq {
    pub domain: String,
    #[serde(rename = "startHour")] pub start_hour: u8,
    #[serde(rename = "endHour")] pub end_hour: u8,
    #[serde(rename = "tzOffset", default)] pub tz_offset: i8,
    #[serde(default)] pub reason: String,
}

pub async fn add_schedule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AddScheduleReq>,
) -> Response {
    let auth = check_auth(&state, None, &headers, "/api/schedule");
    if !auth.is_admin() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"Admin key required"}))).into_response();
    }
    let clean_domain = match crate::security::sanitizer::sanitize_domain(&body.domain) {
        Ok(d) => d,
        Err(err) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"ok":false,"error":format!("Invalid domain: {}", err)}))).into_response();
        }
    };
    if body.start_hour > 23 || body.end_hour > 23 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"ok":false,"error":"Hours must be 0-23"}))).into_response();
    }
    let reason = if body.reason.is_empty() {
        format!("Blocked {}-{}h", body.start_hour, body.end_hour)
    } else { body.reason };
    let id = state.schedule_store.add_rule(clean_domain.clone(), body.start_hour, body.end_hour, body.tz_offset, reason);
    Json(serde_json::json!({
        "ok": true,
        "id": id,
        "domain": clean_domain,
        "startHour": body.start_hour,
        "endHour": body.end_hour,
        "tzOffset": body.tz_offset,
        "message": "Schedule rule added"
    })).into_response()
}

pub async fn delete_schedule(
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
