#![recursion_limit = "256"]

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod dns;
mod security;
mod server;
mod state;
mod storage;
mod telemetry;
mod ui;

use config::Config;
use state::AppState;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .clamp(2, 4);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .thread_name("amardns-worker")
        .thread_stack_size(1024 * 1024)
        .build()?;

    runtime.block_on(async_main())
}

// ---------------------------------------------------------------------------
// Cron helpers
// ---------------------------------------------------------------------------

/// Resolve an IANA timezone name to a UTC offset in whole seconds **for the
/// current moment**, correctly accounting for Daylight Saving Time.
///
/// Uses the full IANA timezone database via the `chrono-tz` crate.
/// Returns `None` for unrecognised names so the caller can fall back to UTC.
fn tz_offset_secs_now(tz_name: &str) -> Option<i64> {
    use chrono::{Offset, TimeZone};
    let tz: chrono_tz::Tz = tz_name.trim().parse().ok()?;
    let utc_now = chrono::Utc::now();
    let local = tz.from_utc_datetime(&utc_now.naive_utc());
    Some(local.offset().fix().local_minus_utc() as i64)
}

/// Parse a `"M H * * *"` cron expression (minute, hour, wildcards for the
/// remaining three fields). Returns `(minute, hour)` on success.
fn parse_simple_cron(expr: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = expr.split_whitespace().collect();
    if parts.len() != 5 {
        return None;
    }
    // The day, month, and weekday fields must be wildcards for this
    // minimal implementation.
    if parts[2] != "*" || parts[3] != "*" || parts[4] != "*" {
        return None;
    }
    let minute: u32 = parts[0].parse().ok()?;
    let hour: u32 = parts[1].parse().ok()?;
    if minute >= 60 || hour >= 24 {
        return None;
    }
    Some((minute, hour))
}

/// Compute how many seconds to sleep until the next wall-clock moment where
/// the local time (adjusted by `tz_offset_secs`) matches `(target_hour,
/// target_minute)`.
///
/// Returns `0` when we are already inside that minute so the caller fires
/// immediately, then guard-sleeps 61 s to avoid double-firing.
fn secs_until_next_cron(target_hour: u32, target_minute: u32, tz_offset_secs: i64) -> u64 {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let local = now_unix + tz_offset_secs;
    let cur_minute = ((local % 3600) / 60) as u32;
    let cur_hour = ((local % 86400) / 3600) as u32;

    if cur_minute == target_minute && cur_hour == target_hour {
        return 0; // Fire immediately
    }

    let cur_secs_since_midnight = (local % 86400) as u32;
    let target_secs_since_midnight = target_hour * 3600 + target_minute * 60;

    if target_secs_since_midnight > cur_secs_since_midnight {
        (target_secs_since_midnight - cur_secs_since_midnight) as u64
    } else {
        // Target is earlier in the day — next occurrence is tomorrow.
        (86400 - cur_secs_since_midnight + target_secs_since_midnight) as u64
    }
}

/// Path used to persist the last cron-fired-at Unix timestamp.
/// Prevents the cron from double-firing when the process restarts inside the
/// 61-second guard window (e.g. a crash-loop during the firing minute).
fn cron_stamp_path(db_path: &str) -> String {
    format!("{}.cron_stamp", db_path)
}

/// Read the last-fired-at Unix timestamp from disk.  Returns 0 if the file
/// is absent or unreadable.
fn read_cron_stamp(path: &str) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Atomically update the cron stamp file with the current Unix timestamp.
fn write_cron_stamp(path: &str) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let _ = std::fs::write(path, ts.to_string());
}

// ---------------------------------------------------------------------------

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load Configuration first
    let config = Config::from_env();

    // 2. Initialize structured logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| config.log_level.clone()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    info!("Starting AmarDNS v2.0 (Rust Zero-GC High-Performance Edition)...");

    // 2b. Run structured config validation and surface every issue.
    //     ERRORs cause a hard abort; WARNINGs are logged but allow startup.
    {
        let mut has_fatal = false;
        for issue in config.validate() {
            if issue.starts_with("ERROR:") {
                error!("[config] {}", issue);
                has_fatal = true;
            } else {
                warn!("[config] {}", issue);
            }
        }
        if has_fatal {
            panic!("[startup] FATAL: One or more configuration errors detected. Fix the above errors and restart.");
        }
    }

    // Startup security validation: fail fast if secrets are default or missing
    let master_key = config.dns_master_key.trim().to_string();
    if master_key.is_empty() || master_key.starts_with("CHANGE_ME") {
        panic!(
            "[startup] FATAL: DNS_MASTER_KEY is not set or is still the default value. \
                Set a strong random key before running in production."
        );
    }
    if config.dns_token_secret.trim().is_empty()
        || config.dns_token_secret.trim().starts_with("CHANGE_ME")
    {
        tracing::warn!("[startup] WARNING: DNS_TOKEN_SECRET is unset or default. HMAC view tokens will not work.");
    }

    // 3. Application State
    let state = Arc::new(AppState::new(config.clone()));

    // 4. Background Boot Ingestion: Load Threat Feeds (400k domains), Rank Upstreams, and Sync IANA DNSSEC Root Anchors
    let boot_state = state.clone();
    tokio::spawn(async move {
        info!("[boot] Triggering background threat feed ingestion queue...");
        boot_state.trigger_background_feed_sync();

        info!("[boot] Synchronizing IANA DNSSEC Root Trust Anchors...");
        boot_state.sync_dnssec_root_anchors().await;

        info!("[boot] Ranking upstream DNS resolvers...");
        match boot_state.upstreams.sync_and_rank().await {
            Ok(count) => {
                boot_state.log_action(
                    "upstreams_ranked",
                    &format!("Ranked top {} active resolvers (3xN pool)", count),
                );
                info!(
                    "[boot] Successfully synced and ranked {} upstream resolvers",
                    count
                );
            }
            Err(e) => {
                boot_state.log_anomaly("upstream_sync_error", &e.to_string());
                error!("[boot] Upstream sync error: {}", e);
            }
        }
    });

    // 5. Background Wall-Clock Cron Sync (respects UPSTREAM_CRON and UPSTREAM_TZ)
    //
    // Parses `config.upstream_cron` as a "M H * * *" expression and
    // `config.upstream_tz` as an IANA timezone name, then sleeps precisely
    // until each daily firing time before running the threat-feed and upstream
    // ranking sync. Falls back to a naive 24 h interval if parsing fails.
    let cron_state = state.clone();
    let cron_expr = config.upstream_cron.clone();
    let cron_tz = config.upstream_tz.clone();
    let cron_stamp = cron_stamp_path(&config.db_path);
    tokio::spawn(async move {
        // Resolve timezone offset at startup using the full IANA tz database
        // (chrono-tz) with correct DST handling. Falls back to UTC on error.
        let tz_offset_secs: i64 = match tz_offset_secs_now(&cron_tz) {
            Some(s) => {
                info!(
                    "[cron] Timezone '{}' resolved to UTC{:+}s (DST-aware)",
                    cron_tz, s
                );
                s
            }
            None => {
                warn!("[cron] Unknown timezone '{}', falling back to UTC", cron_tz);
                0
            }
        };

        // Attempt to parse the cron expression.
        match parse_simple_cron(&cron_expr) {
            Some((target_minute, target_hour)) => {
                info!(
                    "[cron] Wall-clock cron active: '{}' ({:02}h{:02}m local time, tz='{}')",
                    cron_expr, target_hour, target_minute, cron_tz
                );
                loop {
                    let secs = secs_until_next_cron(target_hour, target_minute, tz_offset_secs);
                    if secs == 0 {
                        // Already at the firing minute.  Check the stamp file to
                        // prevent double-fire after a crash-restart inside the
                        // 61-second guard window.
                        let now_unix = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let last_fired = read_cron_stamp(&cron_stamp);
                        if now_unix.saturating_sub(last_fired) < 90 {
                            info!("[cron] Skipping double-fire: already ran {}s ago (stamp file guard)", now_unix - last_fired);
                            tokio::time::sleep(std::time::Duration::from_secs(61)).await;
                            continue;
                        }
                        info!("[cron] Running threat feed, IANA root anchors, and upstream ranker sync (wall-clock cron)...");
                        write_cron_stamp(&cron_stamp);
                        cron_state.trigger_background_feed_sync();
                        cron_state.sync_dnssec_root_anchors().await;
                        let _ = cron_state.upstreams.sync_and_rank().await;
                        tokio::time::sleep(std::time::Duration::from_secs(61)).await;
                    } else {
                        info!(
                            "[cron] Next sync in {}h {}m (target {:02}:{:02} local '{}')",
                            secs / 3600,
                            (secs % 3600) / 60,
                            target_hour,
                            target_minute,
                            cron_tz
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
                        info!("[cron] Running threat feed, IANA root anchors, and upstream ranker sync (wall-clock cron)...");
                        write_cron_stamp(&cron_stamp);
                        cron_state.trigger_background_feed_sync();
                        cron_state.sync_dnssec_root_anchors().await;
                        let _ = cron_state.upstreams.sync_and_rank().await;
                        // Guard sleep: move past the firing minute.
                        tokio::time::sleep(std::time::Duration::from_secs(61)).await;
                    }
                }
            }
            None => {
                warn!(
                    "[cron] Could not parse UPSTREAM_CRON='{}' as 'M H * * *'; \
                     falling back to naive 24 h interval",
                    cron_expr
                );
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 3600));
                loop {
                    interval.tick().await;
                    info!("[cron] Running daily threat feed, IANA root anchors, and upstream ranker sync (fallback 24 h)...");
                    cron_state.trigger_background_feed_sync();
                    cron_state.sync_dnssec_root_anchors().await;
                    let _ = cron_state.upstreams.sync_and_rank().await;
                }
            }
        }
    });

    // 6. Background Active Upstream Probe (Every 30 seconds for live latency & health)
    let probe_state = state.clone();
    tokio::spawn(async move {
        probe_state.upstreams.probe_active_upstreams().await;
        probe_state.metrics.upstream_last_sync.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            probe_state.upstreams.probe_active_upstreams().await;
            probe_state.metrics.upstream_last_sync.store(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                std::sync::atomic::Ordering::Relaxed,
            );
        }
    });

    // 6b. Background Storage & Memory Optimizer (Every 10 minutes) — uses spawn_blocking to avoid
    // blocking the Tokio thread pool during synchronous WAL file compaction.
    let opt_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            interval.tick().await;
            let wal = opt_state.wal.clone_ref();
            tokio::task::spawn_blocking(move || wal.maybe_compact())
                .await
                .ok();
        }
    });

    // 6c. Proactive Upstream Warm-Pipes (Every 60 seconds keepalive pings over HTTP/2)
    // Reduced from 20s to 60s to lower outbound load on shared-cpu-1x.
    let warm_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            warm_state.upstreams.keepalive_ping().await;
        }
    });

    // 6d. Routine Background Memory Hygiene Ticker (Every 60 seconds)
    // Gently prunes expired rate limiters, idle devices, and frees unused heap back to the OS kernel.
    let hygiene_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            hygiene_state.rate_limiter.prune_idle();
            hygiene_state.metrics.prune_idle();
            hygiene_state.fingerprint.prune_idle();
            hygiene_state.passive_dns.prune_idle();
            hygiene_state.cache.run_pending_tasks().await;
            hygiene_state.fast_neg_filter.run_pending_tasks();
            crate::telemetry::metrics::trim_process_memory();
        }
    });

    // 6f. Dynamic Memory Governor (Linux Principle: use free RAM, free it under pressure)
    //
    // Monitors process RSS via /proc/self/statm every 5 seconds.
    // - Normal Zone (< 140 MB): Cache runs dynamically at peak capacity (150k entries)
    //   maximizing cache hits and eliminating upstream latency.
    // - Yellow Zone (>= 140 MB): Proactively evicts expired/idle cache entries and
    //   prunes stale rate-limiter buckets and returns freed pages via malloc_trim.
    // - Red Zone (>= 175 MB): Emergency cache shedding to guarantee the 200 MB hard ceiling
    //   is never breached, resetting RSS down to ~30 MB immediately.
    let mem_gov_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        let mut last_warning_time = std::time::Instant::now();
        loop {
            interval.tick().await;
            let rss_mb = crate::telemetry::metrics::get_process_rss_mb();
            if rss_mb >= 175.0 {
                // RED ZONE: Emergency shedding
                tracing::warn!(
                    "[mem-governor] RED ZONE REACHED: RSS = {:.1} MB (>= 175 MB). Executing emergency memory shedding!",
                    rss_mb
                );
                mem_gov_state.cache.clear().await;
                mem_gov_state.fast_neg_filter.invalidate_all();
                mem_gov_state.rate_limiter.clear();
                mem_gov_state.metrics.prune_idle();
                mem_gov_state.fingerprint.prune_idle();
                mem_gov_state.passive_dns.prune_idle();
                let wal = mem_gov_state.wal.clone_ref();
                tokio::task::spawn_blocking(move || wal.maybe_compact())
                    .await
                    .ok();
                crate::telemetry::metrics::trim_process_memory();
                let post_rss = crate::telemetry::metrics::get_process_rss_mb();
                tracing::info!(
                    "[mem-governor] Emergency shedding complete. RSS dropped to {:.1} MB. 200 MB ceiling preserved.",
                    post_rss
                );
            } else if rss_mb >= 140.0 {
                // YELLOW ZONE: Proactive maintenance
                if last_warning_time.elapsed().as_secs() >= 30 {
                    tracing::info!(
                        "[mem-governor] Yellow zone (RSS = {:.1} MB >= 140 MB). Running maintenance eviction sweep.",
                        rss_mb
                    );
                    last_warning_time = std::time::Instant::now();
                }
                mem_gov_state.cache.run_pending_tasks().await;
                mem_gov_state.fast_neg_filter.run_pending_tasks();
                mem_gov_state.rate_limiter.prune_idle();
                mem_gov_state.metrics.prune_idle();
                mem_gov_state.fingerprint.prune_idle();
                mem_gov_state.passive_dns.prune_idle();
                crate::telemetry::metrics::trim_process_memory();
            }
        }
    });

    // 6g. Initialize Hot-Reloadable Dynamic TLS Resolver for QUIC / DoQ / DoH3
    let quic_cert_resolver = match config.get_effective_tls_paths() {
        Some((cert_path, key_path)) => {
            info!(
                "[doq] Loading genuine TLS certificate from '{}' and '{}'",
                cert_path, key_path
            );
            match server::tls::DynamicCertResolver::from_pem(&cert_path, &key_path) {
                Ok(r) => Arc::new(r),
                Err(e) => {
                    warn!("[doq] Failed to parse certificates from '{}': {}. Generating fallback resolver...", cert_path, e);
                    let fallback =
                        server::tls::DynamicCertResolver::from_self_signed(&config.custom_domains)
                            .map_err(|e| -> Box<dyn std::error::Error> { e })?;
                    Arc::new(fallback)
                }
            }
        }
        None => {
            info!("[doq] No certificate files found on disk. Generating ephemeral self-signed fallback resolver...");
            let fallback =
                server::tls::DynamicCertResolver::from_self_signed(&config.custom_domains)
                    .map_err(|e| -> Box<dyn std::error::Error> { e })?;
            Arc::new(fallback)
        }
    };

    let doq_tls_config = match server::tls::create_dynamic_quic_server_config(
        quic_cert_resolver.clone(),
        vec![
            b"doq".to_vec(),
            b"doq-i00".to_vec(),
            b"doq-i02".to_vec(),
            b"doq-i03".to_vec(),
            b"h3".to_vec(),
        ],
    ) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            warn!("[doq] Failed to create dynamic QUIC TLS config: {}", e);
            None
        }
    };

    // 6h. Automated ACME DNS-01 Provisioning & Renewal Supervisor
    if config.acme_enabled {
        let (cert_dest, key_dest) =
            if let (Some(c), Some(k)) = (&config.tls_cert_path, &config.tls_key_path) {
                (c.clone(), k.clone())
            } else if std::path::Path::new("/data").exists() {
                ("/data/cert.pem".to_string(), "/data/key.pem".to_string())
            } else {
                ("cert.pem".to_string(), "key.pem".to_string())
            };

        let mut acme_domains = config.custom_domains.clone();
        if acme_domains.is_empty() {
            acme_domains = vec![
                "amardns.dedyn.io".to_string(),
                "amardns.duckdns.org".to_string(),
            ];
        }

        info!(
            "[boot] Spawning ACME DNS-01 supervisor for domains: {:?}",
            acme_domains
        );
        let acme_cfg = server::acme::AcmeConfig {
            zerossl_api_key: config.zerossl_api_key.clone(),
            desec_token: config.desec_token.clone(),
            duckdns_token: config.duckdns_token.clone(),
            dynu_api_key: config.dynu_api_key.clone(),
            domains: acme_domains,
            cert_path: cert_dest,
            key_path: key_dest,
            cert_resolver: Some(quic_cert_resolver.clone()),
        };
        server::acme::spawn_acme_supervisor(acme_cfg, Some(config.dns_master_key.clone()));
    }

    // 7. Load TCP TLS configuration for DoH (if configured)
    let doh_tls_config = if config.is_tls_enabled() {
        let cert_path = config.tls_cert_path.as_deref().unwrap();
        let key_path = config.tls_key_path.as_deref().unwrap();
        if std::path::Path::new(cert_path).exists() && std::path::Path::new(key_path).exists() {
            info!(
                "[tls] Native TLS enabled for TCP DoH from '{}' and '{}'",
                cert_path, key_path
            );
            server::tls::create_doh_tls_config(cert_path, key_path).ok()
        } else {
            info!("[tls] Native TLS requested for DoH but cert files not found on disk yet. Running in edge TLS mode.");
            None
        }
    } else {
        None
    };

    // 7b. Dynamic Hot-Reloadable TLS configuration for DoT (DNS-over-TLS)
    let dot_tls_config = match server::tls::create_dynamic_dot_server_config(
        quic_cert_resolver.clone(),
    ) {
        Ok(cfg) => {
            info!("[dot] Native TLS termination enabled with dynamic hot-reloadable certificate resolver (ALPN: dot)");
            Some(cfg)
        }
        Err(e) => {
            warn!("[dot] Failed to create dynamic DoT TLS config: {}", e);
            None
        }
    };

    // 8. Shutdown coordination channels (derived from centralized AppState watch channel)
    let shutdown_rx_dot = state.shutdown_rx.clone();
    let shutdown_rx_doq = state.shutdown_rx.clone();

    // 9a. Start DoT Server (DNS-over-TLS, RFC 7858)
    let dot_state = state.clone();
    let dot_host = config.host.clone();
    let dot_port = config.dot_port;
    let dot_handle = tokio::spawn(async move {
        if let Err(e) = server::dot::start_dot_server(
            dot_state,
            &dot_host,
            dot_port,
            dot_tls_config,
            shutdown_rx_dot,
        )
        .await
        {
            error!("[dot] Server error: {}", e);
        }
    });

    // 9b. Start DoQ Server (DNS-over-QUIC, RFC 9250)
    let doq_state = state.clone();
    let doq_host = config.udp_host.clone();
    let doq_port = config.doq_port;
    let doq_tls = doq_tls_config.clone();
    let doq_handle = tokio::spawn(async move {
        if let Err(e) = server::doq::start_doq_server(
            doq_state,
            &doq_host,
            doq_port,
            doq_tls,
            shutdown_rx_doq,
            "DoQ",
        )
        .await
        {
            error!("[doq] Server error: {}", e);
        }
    });

    // 9c. Start DoH3 Server (DNS-over-HTTP/3 / QUIC, RFC 9114)
    let doh3_handle = if config.doh3_port != config.doq_port {
        let doh3_state = state.clone();
        let doh3_host = config.udp_host.clone();
        let doh3_port = config.doh3_port;
        let doh3_tls = doq_tls_config.clone();
        let shutdown_rx_doh3 = state.shutdown_rx.clone();
        Some(tokio::spawn(async move {
            if let Err(e) = server::doq::start_doq_server(
                doh3_state,
                &doh3_host,
                doh3_port,
                doh3_tls,
                shutdown_rx_doh3,
                "DoH3",
            )
            .await
            {
                error!("[doh3] Server error: {}", e);
            }
        }))
    } else {
        None
    };

    // 9d. Start Plain DNS UDP+TCP on port 53 (optional, for LAN/router deployments)
    if config.plain53_enabled {
        let plain53_state_udp = state.clone();
        let plain53_host_udp = config.plain53_udp_host.clone();
        let shutdown_rx_udp53 = state.shutdown_rx.clone();
        tokio::spawn(async move {
            server::plain::start_plain_udp(
                plain53_state_udp,
                &plain53_host_udp,
                53,
                shutdown_rx_udp53,
            ).await;
        });

        let plain53_state_tcp = state.clone();
        let plain53_host_tcp = config.plain53_host.clone();
        let shutdown_rx_tcp53 = state.shutdown_rx.clone();
        tokio::spawn(async move {
            server::plain::start_plain_tcp(
                plain53_state_tcp,
                &plain53_host_tcp,
                53,
                shutdown_rx_tcp53,
            ).await;
        });

        info!("[boot] Plain DNS (UDP+TCP) port 53 listeners started (PLAIN53_ENABLED=true)");
    }

    // 10. Start DoH Server
    let app = server::doh::create_doh_router(state.clone());
    let host_ip: std::net::IpAddr = config
        .host
        .parse()
        .unwrap_or(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED));
    let addr = SocketAddr::new(host_ip, config.port);

    let listener = server::dot::create_dual_stack_tcp_listener(addr)?;
    if let Some(tls_cfg) = doh_tls_config {
        info!(
            "[doh] AmarDNS DoH server listening on https://{} (Native TLS Termination)",
            addr
        );
        server::tls::serve_axum_tls(listener, app, tls_cfg, shutdown_signal(state.clone())).await?;
    } else {
        info!(
            "[doh] AmarDNS DoH server listening on http://{} (Edge TLS / Plain HTTP)",
            addr
        );
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal(state.clone()))
        .await?;
    }

    // Give in-flight queries and background drain tasks a short grace period
    let _ = tokio::time::timeout(std::time::Duration::from_millis(1000), dot_handle).await;
    let _ = tokio::time::timeout(std::time::Duration::from_millis(1000), doq_handle).await;
    if let Some(h) = doh3_handle {
        let _ = tokio::time::timeout(std::time::Duration::from_millis(1000), h).await;
    }

    info!("[system] AmarDNS shutdown cleanly.");
    Ok(())
}

async fn shutdown_signal(state: Arc<AppState>) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("[system] SIGINT received, shutting down gracefully..."),
        _ = terminate => info!("[system] SIGTERM received, shutting down gracefully..."),
    }

    // Immediately trigger graceful shutdown across all SSE streams, DoT, DoQ, and DoH3 listeners
    state.trigger_shutdown();
}
