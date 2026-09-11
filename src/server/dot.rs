use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::dns::parser::{build_blocked_response, build_servfail_response, parse_dns_query};
use crate::state::AppState;

// RFC 7858 Section 3.4: server SHOULD close after 25s idle.
// We use 15s to ensure we always close BEFORE Fly.io's 30s TCP backhaul limit,
// eliminating the 'unexpected end of file' race where Fly kills the backhaul first.
const DOT_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
// Allow 8s for slow upstream resolvers. The 'Broken pipe' error occurs when the
// client times out (usually 5s) before we can write the response.
const DOT_READ_TIMEOUT: Duration = Duration::from_secs(8);
const DOT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// DNS-over-TLS (DoT, RFC 7858) internal backend listener.
///
/// NOTE ON TLS TERMINATION & ENCRYPTION:
/// In production on Fly.io, TLS 1.3/1.2 is terminated at Fly's Anycast Edge Proxy on public port 853
/// via `handlers = ["tls"]` in `fly.toml` using valid Let's Encrypt certificates.
/// Clients (e.g. Android Private DNS) establish an encrypted TLS tunnel with Fly's Edge.
/// Fly proxies the stream over its internal private WireGuard network to internal port 8053,
/// where this listener processes RFC 7858 length-prefixed DNS wire packets.
pub async fn start_dot_server(
    state: Arc<AppState>,
    host: &str,
    port: u16,
    mut shutdown_rx: tokio::sync::watch::Receiver<()>,
) -> Result<(), std::io::Error> {
    let host_ip: std::net::IpAddr = host.parse().unwrap_or(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED));
    let addr = SocketAddr::new(host_ip, port);
    let listener = TcpListener::bind(addr).await?;
    info!("[dot] AmarDNS DoT server listening on {} (Edge TLS terminated via Fly proxy on 853)", addr);

    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((socket, client_addr)) => {
                        let state_clone = state.clone();
                        tokio::spawn(async move {
                            handle_dot_connection(socket, client_addr, state_clone).await;
                        });
                    }
                    Err(e) => {
                        warn!("[dot] Accept error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("[dot] Shutting down DoT listener gracefully...");
                break;
            }
        }
    }
    Ok(())
}

async fn handle_dot_connection(mut socket: TcpStream, client_addr: SocketAddr, state: Arc<AppState>) {
    let _ = socket.set_nodelay(true);

    // TCP keepalive via socket2: probes after 10s idle, every 5s.
    // Keeps Fly.io's TCP backhaul alive on idle DoT connections,
    // preventing the 'unexpected end of file' race with Fly's 30s idle timeout.
    {
        use socket2::{SockRef, TcpKeepalive};
        let sock_ref = SockRef::from(&socket);
        let ka = TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(10))
            .with_interval(std::time::Duration::from_secs(5));
        let _ = sock_ref.set_tcp_keepalive(&ka);
    }

    let client_ip = client_addr.ip();

    // Check rate limiter (private/internal Fly.io proxy IPs are automatically exempt).
    // DoT has no per-device identity; rate limiting is per source IP.
    if !state.check_rate_limit(client_ip, None) {
        let _ = socket.shutdown().await;
        return;
    }

    let mut buf = vec![0u8; 4096];

    loop {
        // Read 2-byte length prefix (RFC 7858 Section 3.4 25-second idle timeout)
        let mut len_buf = [0u8; 2];
        let read_res = tokio::time::timeout(DOT_IDLE_TIMEOUT, socket.read_exact(&mut len_buf)).await;
        match read_res {
            Ok(Ok(2)) => {}
            Ok(Ok(0)) | Ok(Err(_)) => {
                // Client cleanly closed or dropped connection / Fly probe completed
                let _ = socket.shutdown().await;
                break;
            }
            Ok(_) => {
                let _ = socket.shutdown().await;
                break;
            }
            Err(_) => {
                // RFC 7858 Section 3.4 idle timeout expired (no queries for 25s).
                // Server actively initiates clean TCP half-close before Fly's 60s proxy timeout.
                let _ = socket.shutdown().await;
                break;
            }
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 4096 {
            let _ = socket.shutdown().await;
            break;
        }

        if buf.len() < msg_len {
            buf.resize(msg_len, 0);
        }

        // Read DNS query packet body with a 5s read timeout
        let body_res = tokio::time::timeout(DOT_READ_TIMEOUT, socket.read_exact(&mut buf[..msg_len])).await;
        if body_res.is_err() || body_res.unwrap().is_err() {
            break;
        }

        // Per-query rate limit check to prevent pipelined connection flooding over persistent TCP.
        // DoT has no per-device identity token; enforced at IP level.
        if !state.check_rate_limit(client_ip, None) {
            let fail = build_servfail_response(&buf[..msg_len]);
            let _ = send_length_prefixed(&mut socket, &fail).await;
            let _ = socket.shutdown().await;
            break;
        }

        // DNS query successfully received - record metrics once
        let query_start = std::time::Instant::now();
        state.metrics.record_query(&client_ip.to_string(), "dot");

        let query_wire = &buf[..msg_len];

        let parsed = match parse_dns_query(query_wire) {
            Some(p) => p,
            None => {
                state.metrics.record_latency(query_start.elapsed());
                let fail = build_servfail_response(query_wire);
                if send_length_prefixed(&mut socket, &fail).await.is_err() {
                    break;
                }
                continue;
            }
        };

        let q = match parsed.question {
            Some(q) => q,
            None => {
                state.metrics.record_latency(query_start.elapsed());
                let fail = build_servfail_response(query_wire);
                if send_length_prefixed(&mut socket, &fail).await.is_err() {
                    break;
                }
                continue;
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

        // Rogue client detection & query fingerprinting
        if let Some(flag) = state.fingerprint.record_query(client_ip, &q.name) {
            state.log_action("rogue_client_detected", &format!("{}: {}", client_ip, flag));
            state.log_anomaly("rogue_client_scanner", &format!("{}: {}", client_ip, flag));
        }

        // Record heatmap
        state.record_heatmap(&q.name);

        // Canary and Local DNS Overrides Check
        let q_clean = q.name.trim_end_matches('.').to_ascii_lowercase();
        if q_clean == state.canary_domain {
            state.canary_hits.fetch_add(1, Ordering::Relaxed);
            let nxdomain = build_blocked_response(query_wire, true);
            state.metrics.record_latency(query_start.elapsed());
            if send_length_prefixed(&mut socket, &nxdomain).await.is_err() {
                break;
            }
            continue;
        }



        // 0. Threat & Whitelist policy check (with Fast-Path Negative Absorber in <10µs)
        let (is_blocked, is_nxdomain, reason) = state.check_domain(&q.name);
        if is_blocked {
            state.record_detected_block(&q.name, reason);
            state.fingerprint.record_response(client_ip, 3);
            state.fingerprint.flag_client(client_ip, reason, &q.name);
            state.wal.append_threat_event(&q.name, reason, &client_ip.to_string());
            state.wal.append_query(&q.name, q.qtype, &client_ip.to_string(), 3, 0, "BLOCKED");
            state.log_query(&q.name, q.qtype, &client_ip.to_string(), "DoT", "BLOCKED", 3, 0, reason, "Filter");
            state.cache.insert_negative(&q.name, 60).await;
            let blocked = build_blocked_response(query_wire, is_nxdomain);
            state.metrics.record_latency(query_start.elapsed());
            if send_length_prefixed(&mut socket, &blocked).await.is_err() {
                break;
            }
            continue;
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
            let blocked = build_blocked_response(query_wire, true);
            state.wal.append_query(&q.name, q.qtype, &client_ip.to_string(), 3, 0, "NEG_HIT");
            state.log_query(&q.name, q.qtype, &client_ip.to_string(), "DoT", "NEG_HIT", 3, 0, "threat_negative_cache", "AeroCache");
            state.metrics.record_latency(query_start.elapsed());
            if send_length_prefixed(&mut socket, &blocked).await.is_err() {
                break;
            }
            continue;
        }

        // 2. Google Safe Browsing Cloud Threat Check
        if state.blocking_enabled.load(Ordering::Relaxed) && !state.is_exempt(&q.name) {
            if let Some(threat_type) = state.safe_browsing.check_domain(&q.name).await {
                state.metrics.threat_blocks.fetch_add(1, Ordering::Relaxed);
                state.metrics.gsb_blocks.fetch_add(1, Ordering::Relaxed);
                state.fingerprint.record_response(client_ip, 3);
                state.fingerprint.flag_client(client_ip, "GSB_THREAT", &q.name);
                state.log_action("gsb_block", &format!("{} [{}]", q.name, threat_type));
                state.record_detected_block(&q.name, "google_safe_browsing");
                state.wal.append_threat_event(&q.name, "google_safe_browsing", &client_ip.to_string());
                state.wal.append_query(&q.name, q.qtype, &client_ip.to_string(), 3, 0, "GSB_BLOCK");
                state.log_query(&q.name, q.qtype, &client_ip.to_string(), "DoT", "GSB_BLOCK", 3, 0, "google_safe_browsing", "Google Safe Browsing");
                state.cache.insert_negative(&q.name, 120).await;
                let blocked = build_blocked_response(query_wire, true);
                state.metrics.record_latency(query_start.elapsed());
                if send_length_prefixed(&mut socket, &blocked).await.is_err() {
                    break;
                }
                continue;
            }
        }

        // 3. Cache lookup with RFC 8767 Stale-While-Revalidate (SWR)
        match state.cache.get_with_swr(&q.name, q.qtype, parsed.tx_id).await {
            crate::dns::cache::CacheLookupResult::Fresh(cached_resp) => {
                state.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                state.fingerprint.record_response(client_ip, 0);
                state.wal.append_query(&q.name, q.qtype, &client_ip.to_string(), 0, 0, "HIT");
                state.log_query(&q.name, q.qtype, &client_ip.to_string(), "DoT", "HIT", 0, 0, "none", "AeroCache");
                state.metrics.record_latency(query_start.elapsed());
                if send_length_prefixed(&mut socket, &cached_resp).await.is_err() {
                    break;
                }
                continue;
            }
            crate::dns::cache::CacheLookupResult::Stale(cached_resp) => {
                state.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                state.metrics.swr_serves.fetch_add(1, Ordering::Relaxed);
                state.fingerprint.record_response(client_ip, 0);
                state.wal.append_query(&q.name, q.qtype, &client_ip.to_string(), 0, 0, "STALE_HIT");
                state.log_query(&q.name, q.qtype, &client_ip.to_string(), "DoT", "STALE_HIT", 0, 0, "swr_serve_stale", "AeroCache");

                // Background async revalidation
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
                if send_length_prefixed(&mut socket, &cached_resp).await.is_err() {
                    break;
                }
                continue;
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

            // Feature 4: Passive DNS timeline
            let ips = crate::dns::parser::extract_a_records(&upstream_resp);
            if !ips.is_empty() {
                if let Some(drift) = state.passive_dns.record(&q.name, &ips) {
                    state.log_anomaly("passive_dns_drift", &format!(
                        "IP change for {}: {:?}", q.name, drift
                    ));
                }
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
                        state.log_action("ttl_guard_block", &format!("{} TTL={}s (fast-flux/DGA confirmed, AI={:.2})", q.name, min_ttl, ai_score));
                        state.log_anomaly("ttl_manipulation_guard", &format!(
                            "Fast-flux botnet blocked: low TTL {}s + DGA/AI pattern (AI={:.2}) on {}", min_ttl, ai_score, q.name
                        ));
                        state.wal.append_query(&q.name, q.qtype, &client_ip.to_string(), 3, lat, "TTL_GUARD_BLOCK");
                        state.log_query(&q.name, q.qtype, &client_ip.to_string(), "DoT", "TTL_GUARD_BLOCK", 3, lat, "ttl_manipulation_guard", "TTL Guard");
                        state.cache.insert_negative(&q.name, 30).await;
                        let blocked = build_blocked_response(query_wire, false);
                        state.metrics.record_latency(query_start.elapsed());
                        if send_length_prefixed(&mut socket, &blocked).await.is_err() {
                            break;
                        }
                        continue;
                    }

                    if min_ttl > 86400 {
                        crate::dns::cache::DnsCache::cap_response_ttl(&mut upstream_resp, 86400);
                    }
                }
            }

            // DNS Rebinding Protection
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
                    state.wal.append_threat_event(&q.name, "dns_rebind_attack", &client_ip.to_string());
                    state.wal.append_query(&q.name, q.qtype, &client_ip.to_string(), 3, lat, "REBIND_BLOCK");
                    state.log_query(&q.name, q.qtype, &client_ip.to_string(), "DoT", "REBIND_BLOCK", 3, lat, "dns_rebind_attack", "Rebind Defense");
                    state.cache.insert_negative(&q.name, 120).await;
                    let blocked = build_blocked_response(query_wire, true);
                    state.metrics.record_latency(query_start.elapsed());
                    if send_length_prefixed(&mut socket, &blocked).await.is_err() {
                        break;
                    }
                    continue;
                }
            }

            // Feature 13: Smart TTL learning
            let smart_ttl = if let Some(raw_ttl) = crate::dns::parser::extract_answer_ttl(&upstream_resp) {
                state.ttl_learner.observe(&q.name, raw_ttl);
                state.ttl_learner.smart_ttl(&q.name, raw_ttl)
            } else {
                300
            };

            state.cache.insert(&q.name, q.qtype, upstream_resp.clone(), smart_ttl).await;
            state.wal.append_query(&q.name, q.qtype, &client_ip.to_string(), rcode, lat, "RESOLVED");
            state.log_query(&q.name, q.qtype, &client_ip.to_string(), "DoT", "RESOLVED", rcode, lat, "none", &upstream_name);
            state.metrics.record_latency(query_start.elapsed());
            if send_length_prefixed(&mut socket, &upstream_resp).await.is_err() {
                break;
            }
        } else {
            state.fingerprint.record_response(client_ip, 2);
            state.wal.append_query(&q.name, q.qtype, &client_ip.to_string(), 2, 0, "FAIL");
            state.log_query(&q.name, q.qtype, &client_ip.to_string(), "DoT", "FAIL", 2, 0, "servfail", "none");
            let fail = build_servfail_response(query_wire);
            state.metrics.record_latency(query_start.elapsed());
            if send_length_prefixed(&mut socket, &fail).await.is_err() {
                break;
            }
        }
    }
    let _ = socket.shutdown().await;
}

/// Writes a RFC 7858 length-prefixed DNS response with a 5s write timeout.
/// Returns Ok(()) on success. Translates BrokenPipe and ConnectionReset to
/// debug-level events — these mean the client already closed the connection
/// (normal for Android Private DNS and iOS DoT clients).
async fn send_length_prefixed(socket: &mut TcpStream, data: &[u8]) -> Result<(), std::io::Error> {
    let len = data.len() as u16;
    let write_fut = async {
        socket.write_all(&len.to_be_bytes()).await?;
        socket.write_all(data).await?;
        socket.flush().await?;
        Ok::<(), std::io::Error>(())
    };

    match tokio::time::timeout(DOT_WRITE_TIMEOUT, write_fut).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            match e.kind() {
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset => {
                    // Client closed connection before we could write — normal for DoT clients
                    debug!("[dot] Client closed connection before response: {}", e);
                }
                _ => {
                    debug!("[dot] Write error: {}", e);
                }
            }
            Err(e)
        }
        Err(_) => {
            // Write timed out — client is unresponsive
            debug!("[dot] Write timeout — client unresponsive");
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "write timeout"))
        }
    }
}
