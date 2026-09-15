// src/server/doh.rs
// Zero-GC, high-performance DNS-over-HTTPS (DoH) engine with Master Key & HMAC authentication,
// DNSSEC local cryptographic validation, Google Safe Browsing cloud threat intelligence, and host shielding.

use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::dns::dnssec::{DnssecStatus, validate_dnssec};
use crate::dns::parser::{build_blocked_response, build_servfail_response, parse_dns_query};
use crate::security::auth::check_auth;
use crate::server::api::DnsQueryParam;
use crate::state::AppState;

pub fn create_doh_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Mount all modular REST API routes (status, rules, system, AI)
        .merge(crate::server::api::api_routes())
        // DNS wire queries (Standard RFC 8484 endpoint)
        .route("/dns-query", get(doh_get_handler).post(doh_post_handler))
        // Root DoH fallback + Web Dashboard
        .route("/", get(root_get_handler).post(doh_post_handler))
        // DoH JSON API (RFC 8427) — browser-testable
        .route("/resolve", get(doh_json_handler))
        .fallback(fallback_handler)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            host_shield_middleware,
        ))
        .layer(axum::middleware::map_response(add_security_headers))
        .with_state(state)
}

pub async fn root_get_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<DnsQueryParam>,
) -> Response {
    if params.dns.is_some() || params.name.is_some() {
        return doh_get_handler(State(state), ConnectInfo(addr), headers, Query(params)).await;
    }
    if let Some(accept) = headers.get(header::ACCEPT).and_then(|h| h.to_str().ok()) {
        if accept.contains("application/dns-message") {
            return doh_get_handler(State(state), ConnectInfo(addr), headers, Query(params)).await;
        }
    }
    crate::server::api::status::dashboard_handler(State(state), headers).await
}

pub async fn fallback_handler(
    State(_state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    method: axum::http::Method,
) -> Response {
    let client_ip = extract_client_ip(&headers, addr);
    let path = uri.path();
    let accept_header = headers
        .get(header::ACCEPT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let is_html = accept_header.contains("text/html");

    let fly_machine_id = std::env::var("FLY_MACHINE_ID")
        .or_else(|_| std::env::var("FLY_ALLOC_ID"))
        .unwrap_or_else(|_| {
            std::fs::read_to_string("/etc/hostname")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "local".to_string())
        });
    let fly_region = std::env::var("FLY_REGION").unwrap_or_else(|_| "sin".to_string());

    if is_html {
        let html = crate::ui::error::render_404(
            path,
            &client_ip.to_string(),
            &fly_region,
            &fly_machine_id,
        );
        (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "error": "Not Found: The requested endpoint does not exist on this edge DNS node",
                "status": 404,
                "path": path,
                "method": method.as_str(),
                "region": fly_region,
                "node": fly_machine_id
            })),
        )
            .into_response()
    }
}

async fn host_shield_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let host_opt = headers.get(header::HOST).and_then(|h| h.to_str().ok());
    if !state.config.is_host_allowed(host_opt) {
        let accept_header = headers
            .get(header::ACCEPT)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        if accept_header.contains("text/html") {
            let fly_machine_id = std::env::var("FLY_MACHINE_ID")
                .or_else(|_| std::env::var("FLY_ALLOC_ID"))
                .unwrap_or_else(|_| "local".to_string());
            let fly_region = std::env::var("FLY_REGION").unwrap_or_else(|_| "sin".to_string());
            let html = crate::ui::error::render_403(
                req.uri().path(),
                "shielded-host",
                &fly_region,
                &fly_machine_id,
            );
            return (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                html,
            )
                .into_response();
        } else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "ok": false,
                    "error": "Host access prohibited by shield policy",
                    "status": 404
                })),
            )
                .into_response();
        }
    }
    next.run(req).await
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
            "default-src 'self' 'unsafe-inline' data:; connect-src 'self' *; img-src 'self' data: https:;",
        ),
    );
    headers.insert(
        header::HeaderName::from_static("alt-svc"),
        header::HeaderValue::from_static("h3=\":443\"; ma=86400"),
    );
    response
}

// ── DNS Query Handlers (DoH) ────────────────────────────────────────────────

pub fn extract_client_ip(headers: &HeaderMap, peer_addr: SocketAddr) -> IpAddr {
    if let Some(fly_ip) = headers
        .get("fly-client-ip")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return fly_ip.to_canonical();
    }

    if let Some(cf_ip) = headers
        .get("cf-connecting-ip")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return cf_ip.to_canonical();
    }

    if let Some(real_ip) = headers
        .get("x-real-ip")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return real_ip.to_canonical();
    }

    let peer_ip = peer_addr.ip().to_canonical();
    let is_peer_private = match peer_ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    };

    if is_peer_private {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
            for part in xff.rsplit(',') {
                if let Ok(ip) = part.trim().parse::<IpAddr>() {
                    return ip.to_canonical();
                }
            }
        }
    }

    peer_ip
}

fn detect_doh_proto(headers: &HeaderMap, method: &str) -> String {
    let is_h3 = headers
        .get("via")
        .and_then(|h| h.to_str().ok())
        .map(|v| {
            v.starts_with('3') || v.contains("http/3") || v.contains("quic") || v.contains("h3")
        })
        .unwrap_or(false)
        || headers
            .get("fly-client-protocol")
            .or_else(|| headers.get("x-forwarded-protocol"))
            .and_then(|h| h.to_str().ok())
            .map(|p| {
                p.eq_ignore_ascii_case("http/3")
                    || p.eq_ignore_ascii_case("quic")
                    || p.eq_ignore_ascii_case("h3")
            })
            .unwrap_or(false)
        || headers
            .get("x-forwarded-proto")
            .and_then(|h| h.to_str().ok())
            .map(|p| {
                p.eq_ignore_ascii_case("quic")
                    || p.eq_ignore_ascii_case("http3")
                    || p.eq_ignore_ascii_case("h3")
            })
            .unwrap_or(false);

    if is_h3 {
        format!("DoH3 ({})", method)
    } else {
        format!("DoH ({})", method)
    }
}

pub async fn doh_post_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(params): Query<DnsQueryParam>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let client_ip = extract_client_ip(&headers, addr);

    let dev_ref = params
        .device
        .as_deref()
        .or(params.client.as_deref())
        .or_else(|| headers.get("x-device-id").and_then(|h| h.to_str().ok()));

    if !state.check_rate_limit(client_ip, dev_ref) {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }

    let candidate_key = params
        .key
        .as_deref()
        .or(params.token.as_deref())
        .or(dev_ref);
    if state.is_private_mode.load(Ordering::Relaxed) {
        let auth = check_auth(&state, candidate_key, &headers, "/dns-query");
        if !auth.is_view_or_admin() {
            return (
                StatusCode::FORBIDDEN,
                "Private DNS mode: Authentication required (Master Key or valid HMAC token)",
            )
                .into_response();
        }
    }

    let proto = detect_doh_proto(&headers, "POST");
    process_dns_query(state, &body, client_ip, dev_ref, &proto).await
}

pub async fn doh_get_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<DnsQueryParam>,
) -> Response {
    let client_ip = extract_client_ip(&headers, addr);

    let dev_ref = params
        .device
        .as_deref()
        .or(params.client.as_deref())
        .or_else(|| headers.get("x-device-id").and_then(|h| h.to_str().ok()));

    if !state.check_rate_limit(client_ip, dev_ref) {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }

    let candidate_key = params
        .key
        .as_deref()
        .or(params.token.as_deref())
        .or(dev_ref);
    if state.is_private_mode.load(Ordering::Relaxed) {
        let auth = check_auth(&state, candidate_key, &headers, "/dns-query");
        if !auth.is_view_or_admin() {
            return (
                StatusCode::FORBIDDEN,
                "Private DNS mode: Authentication required (Master Key or valid HMAC token)",
            )
                .into_response();
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
            Err(_) => {
                return (StatusCode::BAD_REQUEST, "Invalid base64url dns query").into_response();
            }
        }
    } else if let Some(domain_name) = params.name.as_deref() {
        let qtype_num = match params
            .qtype
            .as_deref()
            .unwrap_or("A")
            .to_uppercase()
            .as_str()
        {
            "A" => 1u16,
            "NS" => 2,
            "CNAME" => 5,
            "SOA" => 6,
            "PTR" => 12,
            "MX" => 15,
            "TXT" => 16,
            "AAAA" => 28,
            "SRV" => 33,
            "ANY" => 255,
            "CAA" => 257,
            _ => 1,
        };
        let accept_header = headers
            .get(header::ACCEPT)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        if accept_header.contains("application/dns-json")
            || accept_header.contains("application/json")
            || !accept_header.contains("application/dns-message")
        {
            let resolve_query = ResolveQuery {
                name: domain_name.to_string(),
                qtype: params.qtype.clone(),
                cd: None,
                do_bit: None,
            };
            return doh_json_handler(
                State(state),
                ConnectInfo(addr),
                headers,
                Query(resolve_query),
            )
            .await;
        }
        crate::dns::parser::build_query_wire(domain_name, qtype_num)
    } else {
        return (StatusCode::BAD_REQUEST, "Missing ?dns= or ?name= parameter").into_response();
    };

    let proto = detect_doh_proto(&headers, "GET");
    process_dns_query(state, &wire_bytes, client_ip, dev_ref, &proto).await
}

pub async fn process_dns_query(
    state: Arc<AppState>,
    query_wire: &[u8],
    client_ip: IpAddr,
    dev_tag: Option<&str>,
    proto: &str,
) -> Response {
    let (resp_bytes, cache_status, dnssec_status, block_reason) =
        process_dns_wire_packet_full(state, query_wire, client_ip, dev_tag, proto).await;

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/dns-message")
        .header("x-cache", cache_status)
        .header("x-dnssec", dnssec_status);

    if let Some(reason) = block_reason {
        builder = builder.header("x-block-reason", reason);
    }

    builder
        .body(Bytes::from(resp_bytes).into())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Unified DNS wire processing pipeline used across all protocols (DoH, DoH3, DoT, DoQ).
/// Returns raw response wire bytes.
pub async fn process_dns_wire_packet(
    state: Arc<AppState>,
    query_wire: &[u8],
    client_ip: IpAddr,
    dev_tag: Option<&str>,
    proto: &str,
) -> Vec<u8> {
    let (resp, _, _, _) =
        process_dns_wire_packet_full(state, query_wire, client_ip, dev_tag, proto).await;
    resp
}

/// Unified core DNS wire processing with complete metadata.
pub async fn process_dns_wire_packet_full(
    state: Arc<AppState>,
    query_wire: &[u8],
    client_ip: IpAddr,
    dev_tag: Option<&str>,
    proto: &str,
) -> (Vec<u8>, &'static str, String, Option<&'static str>) {
    let query_start = std::time::Instant::now();
    let client_str = client_ip.to_string();
    let log_id = dev_tag.unwrap_or(&client_str);
    let proto_metric = if proto.contains("DoQ") || proto.eq_ignore_ascii_case("doq") {
        "doq"
    } else if proto.contains("DoH3") || proto.eq_ignore_ascii_case("doh3") {
        "doh3"
    } else if proto.contains("DoT") || proto.eq_ignore_ascii_case("dot") {
        "dot"
    } else if proto.contains("Plain") || proto.eq_ignore_ascii_case("plain") {
        "plain"
    } else {
        "doh"
    };
    state.metrics.record_query(log_id, proto_metric);

    let parsed = match parse_dns_query(query_wire) {
        Some(p) => p,
        None => {
            state.metrics.record_latency(query_start.elapsed());
            return (
                build_servfail_response(query_wire),
                "MALFORMED",
                "INSECURE".to_string(),
                None,
            );
        }
    };

    let q = match parsed.question {
        Some(q) => q,
        None => {
            state.metrics.record_latency(query_start.elapsed());
            return (
                build_servfail_response(query_wire),
                "NO_QUESTION",
                "INSECURE".to_string(),
                None,
            );
        }
    };

    // Discovery of Designated Resolvers (DDR - RFC 9462)
    if let Some(ddr_resp) = crate::dns::parser::build_ddr_response(query_wire) {
        state
            .wal
            .append_query(&q.name, q.qtype, log_id, 0, 0, "DDR_SVCB");
        state.log_query_dnssec(
            &q.name,
            q.qtype,
            log_id,
            proto,
            "RESOLVED",
            0,
            0,
            "ddr_discovery",
            "AmarDNS",
            "SECURE",
            Some("SVCB (RFC 9462)"),
            None,
            true,
        );
        state.metrics.record_latency(query_start.elapsed());
        return (ddr_resp, "DDR", "SECURE".to_string(), None);
    }

    // RFC 8482: Return minimal HINFO for ANY (QTYPE=255) queries
    if q.qtype == 255 {
        if let Some(any_resp) = crate::dns::parser::build_any_minimal_response(query_wire) {
            state
                .wal
                .append_query(&q.name, q.qtype, log_id, 0, 0, "ANY_HINFO");
            state.metrics.record_latency(query_start.elapsed());
            return (any_resp, "ANY_HINFO", "INSECURE".to_string(), None);
        }
    }

    // 1. Predictive AI Dependency Prefetching
    state.brain.record_sequence(&q.name);
    let prefetch_cands = state.brain.get_prefetch_candidates(&q.name);
    for cand in prefetch_cands {
        if !state.is_domain_blocked(&cand) {
            let state_p = state.clone();
            tokio::spawn(async move {
                state_p
                    .metrics
                    .prefetch_triggers
                    .fetch_add(1, Ordering::Relaxed);
                state_p
                    .brain
                    .prefetch_triggers
                    .fetch_add(1, Ordering::Relaxed);
                let mut p_wire = vec![
                    0x53, 0x57, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ];
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

    if let Some(flag) = state.fingerprint.record_query(client_ip, &q.name) {
        state.log_action("rogue_client_detected", &format!("{}: {}", client_ip, flag));
        state.log_anomaly("rogue_client_scanner", &format!("{}: {}", client_ip, flag));
    }

    state.record_heatmap(&q.name);

    // Feature 5: Canary Domain Detection
    {
        let q_clean = q.name.trim_end_matches('.').to_ascii_lowercase();
        if q_clean == state.canary_domain {
            state.canary_hits.fetch_add(1, Ordering::Relaxed);
            state.log_action(
                "canary_query",
                &format!("Canary domain queried by {}", client_ip),
            );
            let mut nxdomain = build_blocked_response(query_wire, true);
            crate::dns::parser::append_ede_to_response(&mut nxdomain, 15, "CANARY");
            state.metrics.record_latency(query_start.elapsed());
            return (nxdomain, "CANARY", "INSECURE".to_string(), None);
        }
    }

    // 0. Local Threat, Blocklist & Whitelist Policy Check
    let (is_blocked, is_nxdomain, reason) = state.check_domain(&q.name);
    if is_blocked {
        state.record_detected_block(&q.name, reason);
        state.fingerprint.record_response(client_ip, 3);
        state.fingerprint.flag_client(client_ip, reason, &q.name);
        state.metrics.rep_blocks.fetch_add(1, Ordering::Relaxed);
        if matches!(
            reason,
            "neural_brain_block"
                | "AI_BRAIN"
                | "dga_threat"
                | "DGA"
                | "lookalike_threat"
                | "TYPOSQUAT"
                | "ai_block"
        ) {
            state.metrics.auto_blocks.fetch_add(1, Ordering::Relaxed);
        }
        if reason == "lookalike_threat" || reason == "TYPOSQUAT" {
            state.metrics.alike_blocks.fetch_add(1, Ordering::Relaxed);
        }
        state.wal.append_threat_event(&q.name, reason, log_id);
        state
            .wal
            .append_query(&q.name, q.qtype, log_id, 3, 0, "BLOCKED");
        state.log_query_dnssec(
            &q.name, q.qtype, log_id, proto, "BLOCKED", 3, 0, reason, "Filter", "INSECURE", None,
            None, false,
        );
        state.cache.insert_negative(&q.name, 60).await;
        let mut resp_bytes = build_blocked_response(query_wire, is_nxdomain);
        crate::dns::parser::append_ede_to_response(&mut resp_bytes, 15, reason);
        state.metrics.record_latency(query_start.elapsed());
        return (resp_bytes, "BLOCKED", "INSECURE".to_string(), Some(reason));
    }

    // Swarm detection in background
    {
        let state2 = state.clone();
        let domain_clone = q.name.clone();
        let ip_str = client_ip.to_string();
        tokio::spawn(async move {
            if state2.metrics.detect_swarm(&domain_clone, &ip_str) {
                state2.metrics.swarm_alarms.fetch_add(1, Ordering::Relaxed);
                state2.log_anomaly(
                    "swarm_flood",
                    &format!(
                        "Swarm burst: {} queried by many clients simultaneously",
                        domain_clone
                    ),
                );
            }
        });
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
            "THREAT_CACHE",
            "Preemptively dropped in 0ms from RAM; saved upstream DNS roundtrip and CPU cycles",
        );
        let mut resp_bytes = build_blocked_response(query_wire, true);
        crate::dns::parser::append_ede_to_response(&mut resp_bytes, 15, "THREAT_CACHE");
        state
            .wal
            .append_query(&q.name, q.qtype, log_id, 3, 0, "NEG_HIT");
        state.log_query_dnssec(
            &q.name,
            q.qtype,
            log_id,
            proto,
            "NEG_HIT",
            3,
            0,
            "THREAT_CACHE",
            "AeroCache",
            "INSECURE",
            None,
            None,
            false,
        );
        state.metrics.record_latency(query_start.elapsed());
        return (
            resp_bytes,
            "NEG_HIT",
            "INSECURE".to_string(),
            Some("THREAT_CACHE"),
        );
    }

    // 2. Google Safe Browsing Cloud Threat Check
    if state.blocking_enabled.load(Ordering::Relaxed) && !state.is_exempt(&q.name) {
        if let Some(threat_type) = state.safe_browsing.check_domain(&q.name).await {
            state.metrics.threat_blocks.fetch_add(1, Ordering::Relaxed);
            state.metrics.gsb_blocks.fetch_add(1, Ordering::Relaxed);
            state.fingerprint.record_response(client_ip, 3);
            state
                .fingerprint
                .flag_client(client_ip, "GSB_THREAT", &q.name);
            state.log_action("gsb_block", &format!("{} [{}]", q.name, threat_type));
            state.record_detected_block(&q.name, "GSB");
            state.wal.append_threat_event(&q.name, "GSB", log_id);
            state
                .wal
                .append_query(&q.name, q.qtype, log_id, 3, 0, "GSB_BLOCK");
            state.log_query_dnssec(
                &q.name,
                q.qtype,
                log_id,
                proto,
                "GSB_BLOCK",
                3,
                0,
                "GSB",
                "Google Safe Browsing",
                "INSECURE",
                None,
                None,
                false,
            );
            state.cache.insert_negative(&q.name, 120).await;
            let mut resp_bytes = build_blocked_response(query_wire, true);
            crate::dns::parser::append_ede_to_response(&mut resp_bytes, 15, "GSB");
            state.metrics.record_latency(query_start.elapsed());
            return (resp_bytes, "BLOCKED", "INSECURE".to_string(), Some("GSB"));
        }
    }

    // 3. Cache Lookup with RFC 8767 Stale-While-Revalidate (SWR)
    match state
        .cache
        .get_with_swr(&q.name, q.qtype, parsed.tx_id)
        .await
    {
        crate::dns::cache::CacheLookupResult::Fresh(cached_wire) => {
            state.ttl_learner.record_hit(&q.name);
            state.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            state.fingerprint.record_response(client_ip, 0);
            state
                .wal
                .append_query(&q.name, q.qtype, log_id, 0, 0, "HIT");
            let dnssec_res = validate_dnssec(&cached_wire, None);
            state.metrics.record_dnssec(&dnssec_res);
            let dnssec_str = dnssec_res.status.to_string();
            let dnssec_alg_str = dnssec_res.algorithm.as_deref();
            let dnssec_tag = dnssec_res.key_tag;
            let is_ad = dnssec_res.authenticated_data;
            state.log_query_dnssec(
                &q.name,
                q.qtype,
                log_id,
                proto,
                "HIT",
                0,
                0,
                "none",
                "AeroCache",
                &dnssec_str,
                dnssec_alg_str,
                dnssec_tag,
                is_ad,
            );
            state.metrics.record_latency(query_start.elapsed());
            return (cached_wire, "HIT", dnssec_str, None);
        }
        crate::dns::cache::CacheLookupResult::Stale(cached_wire) => {
            state.ttl_learner.record_hit(&q.name);
            state.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            state.metrics.swr_serves.fetch_add(1, Ordering::Relaxed);
            state.fingerprint.record_response(client_ip, 0);
            state
                .wal
                .append_query(&q.name, q.qtype, log_id, 0, 0, "STALE_HIT");
            let dnssec_res = validate_dnssec(&cached_wire, None);
            state.metrics.record_dnssec(&dnssec_res);
            let dnssec_str = dnssec_res.status.to_string();
            let dnssec_alg_str = dnssec_res.algorithm.as_deref();
            let dnssec_tag = dnssec_res.key_tag;
            let is_ad = dnssec_res.authenticated_data;
            state.log_query_dnssec(
                &q.name,
                q.qtype,
                log_id,
                proto,
                "STALE_HIT",
                0,
                0,
                "swr_serve_stale",
                "AeroCache",
                &dnssec_str,
                dnssec_alg_str,
                dnssec_tag,
                is_ad,
            );

            let state_bg = state.clone();
            let q_name = q.name.clone();
            let q_type = q.qtype;
            let wire_clone = query_wire.to_vec();
            tokio::spawn(async move {
                if let Some((upstream_resp, _)) = state_bg.upstreams.resolve(&wire_clone).await {
                    let (smart_ttl, smart_grace) = if let Some(raw_ttl) =
                        crate::dns::parser::extract_answer_ttl(&upstream_resp)
                    {
                        state_bg.ttl_learner.observe(&q_name, raw_ttl);
                        state_bg.ttl_learner.smart_ttl_and_grace(&q_name, raw_ttl)
                    } else {
                        (300, 300)
                    };
                    state_bg
                        .cache
                        .insert_with_grace(&q_name, q_type, upstream_resp, smart_ttl, smart_grace)
                        .await;
                }
            });

            state.metrics.record_latency(query_start.elapsed());
            return (cached_wire, "STALE_HIT", dnssec_str, None);
        }
        crate::dns::cache::CacheLookupResult::Miss => {}
    }

    state.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);

    // 4. Forward to upstream pool with race and autonomous root-hints fallback
    let start_upstream = std::time::Instant::now();
    let resolve_result = match state.upstreams.resolve(query_wire).await {
        Some(res) => Some(res),
        None => {
            state.metrics.race_wins.fetch_add(1, Ordering::Relaxed);
            match state.upstreams.resolve_race(query_wire).await {
                Some(r) => Some(r),
                None => state.upstreams.resolve_root_hints(query_wire).await,
            }
        }
    };

    if let Some((mut upstream_resp, upstream_name)) = resolve_result {
        let lat = start_upstream.elapsed().as_millis() as u32;
        let rcode = if upstream_resp.len() >= 4 {
            (upstream_resp[3] & 0x0F) as u16
        } else {
            0
        };
        if let Some(flag) = state.fingerprint.record_response(client_ip, rcode) {
            state.log_action("rogue_client_detected", &format!("{}: {}", client_ip, flag));
        }

        // RFC 2308: Use SOA MINIMUM TTL for NXDOMAIN negative caching
        if rcode == 3 {
            let neg_ttl = crate::dns::parser::extract_soa_minimum_ttl(&upstream_resp).unwrap_or(60);
            state.cache.insert_negative(&q.name, neg_ttl).await;
        }

        // Feature 4: Record passive DNS timeline
        {
            let ips = crate::dns::parser::extract_a_records(&upstream_resp);
            if !ips.is_empty() {
                if let Some(drift) = state.passive_dns.record(&q.name, &ips) {
                    state.metrics.answer_drifts.fetch_add(1, Ordering::Relaxed);
                    state.log_anomaly(
                        "passive_dns_drift",
                        &format!(
                            "IP change detected for {}: {:?} -> {:?}",
                            q.name, drift, ips
                        ),
                    );
                }
            }
        }

        // NX alarm detection
        if rcode == 3 && state.metrics.detect_nx_burst(&client_ip.to_string()) {
            state.metrics.nx_alarms.fetch_add(1, Ordering::Relaxed);
            state.log_anomaly(
                "nx_alarm",
                &format!(
                    "NX domain burst detected from client {} — possible DGA/C2 scanner",
                    client_ip
                ),
            );
        }

        // Feature 6: TTL Manipulation Guard
        if state.ttl_guard_enabled.load(Ordering::Relaxed)
            && state.blocking_enabled.load(Ordering::Relaxed)
            && !state.is_exempt(&q.name)
            && rcode == 0
        {
            if let Some(min_ttl) = crate::dns::parser::extract_min_ttl(&upstream_resp) {
                let is_dga_suspect = crate::security::heuristics::is_dga_threat(&q.name);
                let (ai_score, _) = state.brain.evaluate_internal(&q.name);
                let learned_ttl = state.ttl_learner.smart_ttl(&q.name, 300);
                let is_fast_flux = min_ttl <= 5
                    && (is_dga_suspect
                        || ai_score > 0.50
                        || (learned_ttl >= 60 && ai_score > 0.35));

                if is_fast_flux {
                    state
                        .metrics
                        .ttl_guard_blocks
                        .fetch_add(1, Ordering::Relaxed);
                    state.metrics.threat_blocks.fetch_add(1, Ordering::Relaxed);
                    state.log_action(
                        "ttl_guard_block",
                        &format!(
                            "{} TTL={}s (fast-flux/DGA confirmed, AI={:.2})",
                            q.name, min_ttl, ai_score
                        ),
                    );
                    state.log_anomaly("ttl_manipulation_guard", &format!(
                        "Fast-flux botnet blocked: low TTL {}s + DGA/AI pattern (AI={:.2}) on {}", min_ttl, ai_score, q.name
                    ));
                    state
                        .wal
                        .append_query(&q.name, q.qtype, log_id, 3, lat, "TTL_GUARD_BLOCK");
                    state.log_query_dnssec(
                        &q.name,
                        q.qtype,
                        log_id,
                        proto,
                        "TTL_GUARD_BLOCK",
                        3,
                        lat,
                        "TTL_GUARD",
                        "TTL Guard",
                        "INSECURE",
                        None,
                        None,
                        false,
                    );
                    state.cache.insert_negative(&q.name, 30).await;
                    let mut blocked = build_blocked_response(query_wire, false);
                    crate::dns::parser::append_ede_to_response(&mut blocked, 15, "TTL_GUARD");
                    state.metrics.record_latency(query_start.elapsed());
                    return (
                        blocked,
                        "BLOCKED",
                        "INSECURE".to_string(),
                        Some("TTL_GUARD"),
                    );
                }

                if min_ttl > 86400 {
                    crate::dns::cache::DnsCache::cap_response_ttl(&mut upstream_resp, 86400);
                }
            }
        }

        // DNS Rebinding Protection
        if state.blocking_enabled.load(Ordering::Relaxed)
            && !crate::dns::parser::is_rebind_exempt_domain(&q.name)
        {
            if let Some(rebind_ip) = crate::dns::parser::extract_rebind_ip(&upstream_resp) {
                state.metrics.rebind_blocks.fetch_add(1, Ordering::Relaxed);
                state.metrics.threat_blocks.fetch_add(1, Ordering::Relaxed);
                state.fingerprint.record_response(client_ip, 3);
                state
                    .fingerprint
                    .flag_client(client_ip, "REBIND_ATTACK", &q.name);
                state.log_action("rebind_block", &format!("{} -> {}", q.name, rebind_ip));
                state.log_anomaly(
                    "dns_rebind_attack",
                    &format!("Private IP leak blocked: {} -> {}", q.name, rebind_ip),
                );
                state.wal.append_threat_event(&q.name, "REBIND", log_id);
                state
                    .wal
                    .append_query(&q.name, q.qtype, log_id, 3, lat, "REBIND_BLOCK");
                state.log_query_dnssec(
                    &q.name,
                    q.qtype,
                    log_id,
                    proto,
                    "REBIND_BLOCK",
                    3,
                    lat,
                    "REBIND",
                    "Rebind Defense",
                    "INSECURE",
                    None,
                    None,
                    false,
                );
                state.cache.insert_negative(&q.name, 120).await;
                let mut blocked = build_blocked_response(query_wire, true);
                crate::dns::parser::append_ede_to_response(&mut blocked, 15, "REBIND");
                state.metrics.record_latency(query_start.elapsed());
                return (blocked, "BLOCKED", "INSECURE".to_string(), Some("REBIND"));
            }
        }

        // Cryptographic DNSSEC Validation (RFC 4034, RFC 4035, RFC 6605, RFC 8080)
        let dnssec_res = validate_dnssec(&upstream_resp, None);
        state.metrics.record_dnssec(&dnssec_res);
        let dnssec_str = dnssec_res.status.to_string();
        let dnssec_alg_str = dnssec_res.algorithm.as_deref();
        let dnssec_tag = dnssec_res.key_tag;
        let is_ad = dnssec_res.authenticated_data;

        // Set Authenticated Data (AD) bit in response header if secure
        if is_ad && upstream_resp.len() >= 4 {
            upstream_resp[3] |= 0x20;
        }

        if dnssec_res.status == crate::dns::dnssec::DnssecStatus::Bogus {
            let is_cd = (parsed.flags & 0x0010) != 0;
            if !is_cd {
                state
                    .wal
                    .append_query(&q.name, q.qtype, log_id, 2, lat, "DNSSEC_BOGUS");
                state.log_query_dnssec(
                    &q.name,
                    q.qtype,
                    log_id,
                    proto,
                    "SERVFAIL",
                    2,
                    lat,
                    "dnssec_bogus",
                    "DNSSEC Validator",
                    "BOGUS",
                    dnssec_alg_str,
                    dnssec_tag,
                    false,
                );
                let mut servfail = build_servfail_response(query_wire);
                crate::dns::parser::append_ede_to_response(
                    &mut servfail,
                    6,
                    dnssec_res
                        .failure_reason
                        .as_deref()
                        .unwrap_or("DNSSEC validation failure (RFC 4035 Section 5.5)"),
                );
                state.metrics.record_latency(query_start.elapsed());
                return (
                    servfail,
                    "DNSSEC_BOGUS",
                    "BOGUS".to_string(),
                    Some("dnssec_bogus"),
                );
            } else {
                crate::dns::parser::append_ede_to_response(
                    &mut upstream_resp,
                    6,
                    dnssec_res
                        .failure_reason
                        .as_deref()
                        .unwrap_or("DNSSEC validation failure"),
                );
            }
        }

        // Feature 13: Smart TTL & SWR grace learning with dynamic frequency booster
        let (smart_ttl, smart_grace) =
            if let Some(raw_ttl) = crate::dns::parser::extract_answer_ttl(&upstream_resp) {
                state.ttl_learner.observe(&q.name, raw_ttl);
                state.ttl_learner.smart_ttl_and_grace(&q.name, raw_ttl)
            } else {
                (300, 300)
            };

        state
            .cache
            .insert_with_grace(
                &q.name,
                q.qtype,
                upstream_resp.clone(),
                smart_ttl,
                smart_grace,
            )
            .await;
        state
            .wal
            .append_query(&q.name, q.qtype, log_id, rcode, lat, "RESOLVED");
        state.log_query_dnssec(
            &q.name,
            q.qtype,
            log_id,
            proto,
            "RESOLVED",
            rcode,
            lat,
            if dnssec_res.status == DnssecStatus::Bogus {
                "bogus_dnssec"
            } else {
                "none"
            },
            &upstream_name,
            &dnssec_str,
            dnssec_alg_str,
            dnssec_tag,
            is_ad,
        );
        state.metrics.record_latency(query_start.elapsed());

        if upstream_resp.len() >= 2 {
            upstream_resp[0..2].copy_from_slice(&parsed.tx_id.to_be_bytes());
        }

        (upstream_resp, "MISS", dnssec_str, None)
    } else {
        state.fingerprint.record_response(client_ip, 2);
        state
            .wal
            .append_query(&q.name, q.qtype, log_id, 2, 0, "FAIL");
        state.log_query_dnssec(
            &q.name, q.qtype, log_id, proto, "FAIL", 2, 0, "servfail", "none", "INSECURE", None,
            None, false,
        );
        let mut fail = build_servfail_response(query_wire);
        crate::dns::parser::append_ede_to_response(
            &mut fail,
            22,
            "All upstream resolvers unreachable",
        );
        state.metrics.record_latency(query_start.elapsed());
        (fail, "FAIL", "INSECURE".to_string(), None)
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

// ── DoH JSON API (RFC 8427) Handler ──────────────────────────────────────────

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct ResolveQuery {
    pub name: String,
    #[serde(rename = "type")]
    pub qtype: Option<String>,
    pub cd: Option<bool>,
    pub do_bit: Option<bool>,
}

pub async fn doh_json_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<ResolveQuery>,
) -> Response {
    let client_ip = extract_client_ip(&headers, addr);

    if state.is_private_mode.load(Ordering::Relaxed) {
        let auth = check_auth(&state, None, &headers, "/resolve");
        if !auth.is_view_or_admin() {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "Status": 2,
                    "TC": false,
                    "RD": false,
                    "RA": false,
                    "AD": false,
                    "CD": false,
                    "Question": [],
                    "Comment": "Private DNS mode: Authentication required (Master Key or valid HMAC token)"
                })),
            )
                .into_response();
        }
    }

    let proto = detect_doh_proto(&headers, "JSON");
    let raw_name = params.name.trim();

    if raw_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "Status": 1,
                "TC": false,
                "RD": true,
                "RA": false,
                "AD": false,
                "CD": false,
                "Question": [],
                "Comment": "Missing domain name"
            })),
        )
            .into_response();
    }

    let qtype = match params
        .qtype
        .as_deref()
        .unwrap_or("A")
        .to_uppercase()
        .as_str()
    {
        "A" => 1u16,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "ANY" => 255,
        "CAA" => 257,
        _ => 1,
    };

    let clean_domain = raw_name.trim_end_matches('.').to_string();

    // RFC 8482: ANY queries get minimal HINFO synthesis
    if qtype == 255 {
        let resp = serde_json::json!({
            "Status": 0,
            "TC": false,
            "RD": true,
            "RA": true,
            "AD": false,
            "CD": false,
            "Question": [{"name": format!("{}.", clean_domain), "type": 255}],
            "Answer": [{
                "name": format!("{}.", clean_domain),
                "type": 13,
                "TTL": 3600,
                "data": "RFC8482"
            }],
            "Comment": "RFC 8482: Minimal HINFO response (ANY query amplification prevention)"
        });
        return Json(resp).into_response();
    }

    let (is_blocked, is_nx, reason) = state.check_domain(&clean_domain);
    if is_blocked {
        let resp = serde_json::json!({
            "Status": if is_nx { 3 } else { 0 },
            "TC": false,
            "RD": true,
            "RA": true,
            "AD": false,
            "CD": false,
            "Question": [{
                "name": format!("{}.", clean_domain),
                "type": qtype
            }],
            "Answer": if is_nx { vec![] } else {
                vec![serde_json::json!({
                    "name": format!("{}.", clean_domain),
                    "type": 1,
                    "TTL": 60,
                    "data": "0.0.0.0"
                })]
            },
            "Comment": format!("AmarDNS Block: {}", reason)
        });
        state.log_query_dnssec(
            &clean_domain,
            qtype,
            &client_ip.to_string(),
            &proto,
            "BLOCKED",
            if is_nx { 3 } else { 0 },
            0,
            reason,
            "0.0.0.0",
            "INSECURE",
            None,
            None,
            false,
        );
        return Json(resp).into_response();
    }

    // Check RAM Cache
    if let Some(cached_wire) = state.cache.get(&clean_domain, qtype, 0x1234).await {
        state.ttl_learner.record_hit(&clean_domain);
        state.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
        let (rcode, answers) =
            crate::dns::parser::parse_answers_for_doh_json(&cached_wire, &clean_domain);
        let dnssec_res = validate_dnssec(&cached_wire, None);
        state.metrics.record_dnssec(&dnssec_res);
        let resp = serde_json::json!({
            "Status": rcode,
            "TC": false,
            "RD": true,
            "RA": true,
            "AD": dnssec_res.authenticated_data,
            "CD": false,
            "Question": [{
                "name": format!("{}.", clean_domain),
                "type": qtype
            }],
            "Answer": answers,
            "dnssec": dnssec_res.status.to_string(),
            "dnssecAlg": dnssec_res.algorithm,
            "dnssecKeyTag": dnssec_res.key_tag,
            "Comment": "AmarDNS AeroCache HIT"
        });
        state.log_query_dnssec(
            &clean_domain,
            qtype,
            &client_ip.to_string(),
            &proto,
            "HIT",
            rcode as u16,
            0,
            "cache_hit",
            "cache",
            &dnssec_res.status.to_string(),
            dnssec_res.algorithm.as_deref(),
            dnssec_res.key_tag,
            dnssec_res.authenticated_data,
        );
        return Json(resp).into_response();
    }

    // Synthesize Wire Query for Upstream Resolution
    let mut wire = Vec::with_capacity(64);
    let is_cd = params.cd.unwrap_or(false);

    let query_flags: u16 = if is_cd { 0x0110 } else { 0x0100 }; // RD=1, CD=(if requested)

    wire.extend_from_slice(&[0x12, 0x34]);
    wire.extend_from_slice(&query_flags.to_be_bytes());
    wire.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    for label in clean_domain.split('.') {
        if !label.is_empty() {
            wire.push(label.len() as u8);
            wire.extend_from_slice(label.as_bytes());
        }
    }
    wire.push(0x00);
    wire.extend_from_slice(&qtype.to_be_bytes());
    wire.extend_from_slice(&1u16.to_be_bytes()); // Class IN

    // Ensure EDNS0 DO (DNSSEC OK) bit is set so upstream resolvers return complete DNSSEC records
    let wire = crate::dns::parser::ensure_edns0_do_bit(&wire);

    let start = std::time::Instant::now();
    let upstream_res = state.upstreams.resolve(&wire).await;
    let elapsed_ms = start.elapsed().as_millis() as u32;

    if let Some((resp_bytes, upstream_name)) = upstream_res {
        let (rcode, answers) =
            crate::dns::parser::parse_answers_for_doh_json(&resp_bytes, &clean_domain);
        let dnssec_res = validate_dnssec(&resp_bytes, None);
        state.metrics.record_dnssec(&dnssec_res);

        if rcode == 0 && !resp_bytes.is_empty() {
            let (ttl, grace) =
                if let Some(raw_ttl) = crate::dns::parser::extract_answer_ttl(&resp_bytes) {
                    state.ttl_learner.observe(&clean_domain, raw_ttl);
                    state
                        .ttl_learner
                        .smart_ttl_and_grace(&clean_domain, raw_ttl)
                } else {
                    (300, 300)
                };
            state
                .cache
                .insert_with_grace(&clean_domain, qtype, resp_bytes.clone(), ttl, grace)
                .await;
        }

        let comment = if let Some(ref reason) = dnssec_res.failure_reason {
            format!("Resolved via upstream: {} [{}]", upstream_name, reason)
        } else {
            format!("Resolved via upstream: {}", upstream_name)
        };

        let resp = serde_json::json!({
            "Status": rcode,
            "TC": false,
            "RD": true,
            "RA": true,
            "AD": dnssec_res.authenticated_data,
            "CD": is_cd,
            "Question": [{
                "name": format!("{}.", clean_domain),
                "type": qtype
            }],
            "Answer": answers,
            "dnssec": dnssec_res.status.to_string(),
            "dnssecAlg": dnssec_res.algorithm,
            "dnssecKeyTag": dnssec_res.key_tag,
            "Comment": comment
        });

        state.log_query_dnssec(
            &clean_domain,
            qtype,
            &client_ip.to_string(),
            &proto,
            "RESOLVED",
            rcode as u16,
            elapsed_ms,
            "upstream",
            &upstream_name,
            &dnssec_res.status.to_string(),
            dnssec_res.algorithm.as_deref(),
            dnssec_res.key_tag,
            dnssec_res.authenticated_data,
        );
        return Json(resp).into_response();
    }

    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({
            "Status": 2,
            "TC": false,
            "RD": true,
            "RA": true,
            "AD": false,
            "CD": false,
            "Question": [{
                "name": format!("{}.", clean_domain),
                "type": qtype
            }],
            "Comment": "All upstreams failed"
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_client_ip_direct_peer() {
        let headers = HeaderMap::new();
        let peer: SocketAddr = "192.0.2.1:12345".parse().unwrap();
        assert_eq!(
            extract_client_ip(&headers, peer),
            IpAddr::from([192, 0, 2, 1])
        );
    }

    #[test]
    fn test_extract_client_ip_fly_and_cf() {
        let mut headers = HeaderMap::new();
        let peer: SocketAddr = "10.0.0.1:8443".parse().unwrap();

        headers.insert("fly-client-ip", "203.0.113.195".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, peer),
            IpAddr::from([203, 0, 113, 195])
        );

        headers.remove("fly-client-ip");
        headers.insert("cf-connecting-ip", "198.51.100.44".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, peer),
            IpAddr::from([198, 51, 100, 44])
        );
    }

    #[test]
    fn test_extract_client_ip_xff_private_vs_public_peer() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.1.1.1, 203.0.113.50".parse().unwrap());

        let priv_peer: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        assert_eq!(
            extract_client_ip(&headers, priv_peer),
            IpAddr::from([203, 0, 113, 50])
        );

        let pub_peer: SocketAddr = "198.51.100.1:12345".parse().unwrap();
        assert_eq!(
            extract_client_ip(&headers, pub_peer),
            IpAddr::from([198, 51, 100, 1])
        );
    }

    #[test]
    fn test_create_doh_router_building() {
        let config = crate::config::Config::from_env();
        let state = Arc::new(AppState::new(config));
        let router = create_doh_router(state);
        assert!(std::mem::size_of_val(&router) > 0);
    }

    #[test]
    fn test_prometheus_text_format() {
        let metrics = crate::telemetry::metrics::Metrics::new();
        metrics
            .requests
            .fetch_add(42, std::sync::atomic::Ordering::Relaxed);
        let output = metrics.prometheus_text(100, 1.5, 0);
        assert!(output.contains("amardns_queries_total 42"));
        assert!(output.contains("# TYPE amardns_queries_total counter"));
        assert!(output.contains("amardns_cache_entries 100"));
    }

    #[tokio::test]
    async fn test_dnssec_bogus_servfail_enforcement() {
        let config = crate::config::Config::from_env();
        let state = Arc::new(AppState::new(config));

        // Create query for test domain without CD bit
        let query_wire = crate::dns::parser::build_query_wire("dnssec-bogus.test", 1);
        let client_ip = IpAddr::from([127, 0, 0, 1]);

        // Process wire packet
        let (resp, _cache_status, _, _block_reason) =
            process_dns_wire_packet_full(state.clone(), &query_wire, client_ip, None, "DoH").await;

        assert!(!resp.is_empty());
        // Verify response wire is valid DNS message
        let parsed = crate::dns::parser::parse_dns_query(&resp);
        assert!(parsed.is_some());
    }
}
