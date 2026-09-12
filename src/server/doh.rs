// src/server/doh.rs
// Zero-GC, high-performance DNS-over-HTTPS (DoH) engine with Master Key & HMAC authentication,
// Google Safe Browsing cloud threat intelligence, and multi-machine peer synchronization.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Deserialize;

use crate::dns::parser::{build_blocked_response, build_servfail_response, parse_dns_query};
use crate::security::auth::check_auth;
use crate::server::api::DnsQueryParam;
use crate::state::AppState;

pub fn create_doh_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Mount all modular REST API routes
        .merge(crate::server::api::api_routes())
        // DNS wire queries
        .route("/dns-query", get(doh_get_handler).post(doh_post_handler))
        // DoH JSON API (RFC 8427) — browser-testable
        .route("/resolve", get(doh_json_handler))
        .layer(axum::middleware::map_response(add_security_headers))
        .with_state(state)
}

pub async fn add_security_headers(mut response: Response) -> Response {
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
        header::X_XSS_PROTECTION,
        header::HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        header::HeaderName::from_static("x-dns-prefetch-control"),
        header::HeaderValue::from_static("off"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-opener-policy"),
        header::HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        header::HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(
            "default-src 'self'; script-src 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'",
        ),
    );
    response
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

pub async fn doh_post_handler(
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

pub async fn doh_get_handler(
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

pub async fn process_dns_query(state: Arc<AppState>, query_wire: &[u8], client_ip: IpAddr, dev_tag: Option<&str>, proto: &str) -> Response {
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
            state.ttl_learner.record_hit(&q.name);
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
            state.ttl_learner.record_hit(&q.name);
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
                    let (smart_ttl, smart_grace) = if let Some(raw_ttl) = crate::dns::parser::extract_answer_ttl(&upstream_resp) {
                        state_bg.ttl_learner.observe(&q_name, raw_ttl);
                        state_bg.ttl_learner.smart_ttl_and_grace(&q_name, raw_ttl)
                    } else {
                        (300, 300)
                    };
                    state_bg.cache.insert_with_grace(&q_name, q_type, upstream_resp, smart_ttl, smart_grace).await;
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

    if let Some((mut upstream_resp, upstream_name)) = resolve_result {
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

        // Feature 6: TTL Manipulation Guard — detect fast-flux botnets (extremely low TTL + DGA / AI anomaly)
        // & TTL Inflation Guard (clamp bogus high TTLs > 86400s)
        if state.ttl_guard_enabled.load(Ordering::Relaxed)
            && state.blocking_enabled.load(Ordering::Relaxed)
            && !state.is_exempt(&q.name)
            && rcode == 0
        {
            if let Some(min_ttl) = crate::dns::parser::extract_min_ttl(&upstream_resp) {
                let is_dga_suspect = crate::security::heuristics::is_dga_threat(&q.name);
                let (ai_score, _) = state.brain.evaluate_internal(&q.name);
                let learned_ttl = state.ttl_learner.smart_ttl(&q.name, 300);
                let is_fast_flux = min_ttl <= 5 && (is_dga_suspect || ai_score > 0.50 || (learned_ttl >= 60 && ai_score > 0.35));

                if is_fast_flux {
                    state.metrics.ttl_guard_blocks.fetch_add(1, Ordering::Relaxed);
                    state.metrics.threat_blocks.fetch_add(1, Ordering::Relaxed);
                    state.log_action("ttl_guard_block", &format!(
                        "{} TTL={}s (fast-flux/DGA confirmed, AI={:.2})", q.name, min_ttl, ai_score
                    ));
                    state.log_anomaly("ttl_manipulation_guard", &format!(
                        "Fast-flux botnet blocked: low TTL {}s + DGA/AI pattern (AI={:.2}) on {}", min_ttl, ai_score, q.name
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

                if min_ttl > 86400 {
                    crate::dns::cache::DnsCache::cap_response_ttl(&mut upstream_resp, 86400);
                }
            }
        }

        // 4b. DNS Rebinding Protection: Block public domains resolving to private/loopback/link-local IP addresses
        if state.blocking_enabled.load(Ordering::Relaxed)
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

        // Feature 13: Smart TTL & SWR grace learning with dynamic frequency booster
        let (smart_ttl, smart_grace) = if let Some(raw_ttl) = crate::dns::parser::extract_answer_ttl(&upstream_resp) {
            state.ttl_learner.observe(&q.name, raw_ttl);
            state.ttl_learner.smart_ttl_and_grace(&q.name, raw_ttl)
        } else {
            (300, 300)
        };

        state.cache.insert_with_grace(&q.name, q.qtype, upstream_resp.clone(), smart_ttl, smart_grace).await;
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

pub async fn doh_json_handler(
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
        state.ttl_learner.record_hit(&clean_domain);
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
                let (ttl, grace) = if let Some(raw_ttl) = crate::dns::parser::extract_answer_ttl(&resp_wire) {
                    state.ttl_learner.observe(&clean_domain, raw_ttl);
                    state.ttl_learner.smart_ttl_and_grace(&clean_domain, raw_ttl)
                } else {
                    (300, 300)
                };
                state.cache.insert_with_grace(&clean_domain, qtype, resp_wire.clone(), ttl, grace).await;
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
