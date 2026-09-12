use std::sync::atomic::Ordering;
use std::sync::Arc;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

use crate::security::auth::check_auth;
use crate::state::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
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
        // AI Brain Telemetry & Learning Curve
        .route("/api/ai/brain", get(get_ai_brain))
        .route("/api/ai/brain/", get(get_ai_brain))
        .route("/api/ai/brain/:key", get(get_ai_brain_key))
}

pub async fn get_ai_brain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    handle_get_ai_brain(&state, None, &headers).await
}

pub async fn get_ai_brain_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_get_ai_brain(&state, Some(&key), &headers).await
}

pub async fn handle_get_ai_brain(
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

pub async fn ai_export(
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

pub async fn ai_export_key(
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

pub async fn ai_import(
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

pub async fn ai_import_key(
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

pub async fn ai_prune(
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

pub async fn ai_prune_key(
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
