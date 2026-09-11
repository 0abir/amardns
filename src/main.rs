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
    let hour: u32   = parts[1].parse().ok()?;
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
    let cur_hour   = ((local % 86400) / 3600) as u32;

    if cur_minute == target_minute && cur_hour == target_hour {
        return 0; // Fire immediately
    }

    let cur_secs_since_midnight    = (local % 86400) as u32;
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
        panic!("[startup] FATAL: DNS_MASTER_KEY is not set or is still the default value. \
                Set a strong random key before running in production.");
    }
    if config.dns_token_secret.trim().is_empty() || config.dns_token_secret.trim().starts_with("CHANGE_ME") {
        tracing::warn!("[startup] WARNING: DNS_TOKEN_SECRET is unset or default. HMAC view tokens will not work.");
    }

    // 3. Application State
    let state = Arc::new(AppState::new(config.clone()));

    // 4. Background Boot Ingestion: Load Threat Feeds (400k domains) and Rank Upstreams
    let boot_state = state.clone();
    tokio::spawn(async move {
        info!("[boot] Syncing global threat feeds from CDN...");
        match boot_state.sync_threat_feeds().await {
            Ok((b, w)) => {
                boot_state.log_action("threat_feed_synced", &format!("Ingested {} threat & {} whitelist domains", b, w));
                info!("[boot] Successfully ingested {} blocked and {} whitelisted domains into Bloom filter", b, w);
            }
            Err(e) => {
                boot_state.log_anomaly("threat_feed_sync_error", &e.to_string());
                error!("[boot] Threat feed sync deferred: {}", e);
            }
        }

        info!("[boot] Ranking upstream DNS resolvers...");
        match boot_state.upstreams.sync_and_rank().await {
            Ok(count) => {
                boot_state.log_action("upstreams_ranked", &format!("Ranked top {} active resolvers (3xN pool)", count));
                info!("[boot] Successfully synced and ranked {} upstream resolvers", count);
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
    let cron_expr  = config.upstream_cron.clone();
    let cron_tz    = config.upstream_tz.clone();
    let cron_stamp = cron_stamp_path(&config.db_path);
    tokio::spawn(async move {
        // Resolve timezone offset at startup using the full IANA tz database
        // (chrono-tz) with correct DST handling. Falls back to UTC on error.
        let tz_offset_secs: i64 = match tz_offset_secs_now(&cron_tz) {
            Some(s) => {
                info!("[cron] Timezone '{}' resolved to UTC{:+}s (DST-aware)", cron_tz, s);
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
                        info!("[cron] Running threat feed and upstream ranker sync (wall-clock cron)...");
                        write_cron_stamp(&cron_stamp);
                        let _ = cron_state.sync_threat_feeds().await;
                        let _ = cron_state.upstreams.sync_and_rank().await;
                        tokio::time::sleep(std::time::Duration::from_secs(61)).await;
                    } else {
                        info!(
                            "[cron] Next sync in {}h {}m (target {:02}:{:02} local '{}')",
                            secs / 3600, (secs % 3600) / 60, target_hour, target_minute, cron_tz
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
                        info!("[cron] Running threat feed and upstream ranker sync (wall-clock cron)...");
                        write_cron_stamp(&cron_stamp);
                        let _ = cron_state.sync_threat_feeds().await;
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
                    info!("[cron] Running daily threat feed and upstream ranker sync (fallback 24 h)...");
                    let _ = cron_state.sync_threat_feeds().await;
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
            tokio::task::spawn_blocking(move || wal.maybe_compact()).await.ok();
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

    // Feature 10: Daily blocklist feed subscription sync
    let feed_state = state.clone();
    tokio::spawn(async move {
        // Initial sync 5 minutes after boot (lets system stabilize first)
        tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("AmarDNS/1.0 blocklist-feed-sync")
            .build()
            .unwrap_or_default();
        let mut daily = tokio::time::interval(std::time::Duration::from_secs(24 * 3600));
        loop {
            daily.tick().await;
            let feeds = feed_state.feed_manager.enabled_feeds();
            for (feed_id, url, format) in feeds {
                tracing::info!("[feed] Syncing {} from {}", feed_id, url);
                if let Ok(resp) = http.get(&url).send().await {
                    if resp.status().is_success() {
                        if let Ok(text) = resp.text().await {
                            let mut bloom = feed_state.threat_bloom.write();
                            let count = crate::security::feed_manager::FeedManager::for_each_domain(&text, &format, |d| {
                                bloom.insert(d);
                            });
                            drop(bloom);
                            feed_state.feed_manager.update_sync_stats(feed_id, count);
                            tracing::info!("[feed] {} synced {} domains", feed_id, count);
                        }
                    }
                }
            }
        }
    });

    // 6e. Boot Pre-warming: Prime cache with top popular domains 3s after startup
    let prewarm_state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let top_domains = [
            "google.com", "cloudflare.com", "apple.com",
            "microsoft.com", "github.com", "amazon.com", "wikipedia.org",
            "openai.com", "netflix.com", "youtube.com"
        ];
        tracing::info!("[prewarm] Pre-warming cache with top domains...");
        let mut primed = 0;
        for domain in &top_domains {
            let wire = crate::dns::parser::build_query_wire(domain, 1);
            if let Some((resp, _)) = prewarm_state.upstreams.resolve_race(&wire).await {
                let ttl = crate::dns::parser::extract_answer_ttl(&resp).unwrap_or(300);
                prewarm_state.cache.insert(domain, 1, resp, ttl).await;
                primed += 1;
            }
        }
        tracing::info!("[prewarm] Cache pre-warming complete: {}/{} domains primed into zero-latency cache", primed, top_domains.len());
    });

    // 6f. Dynamic Memory Governor (Linux Principle: use free RAM, free it under pressure)
    //
    // Monitors process RSS via /proc/self/statm every 5 seconds.
    // - Normal Zone (< 140 MB): Cache runs dynamically at peak capacity (150k entries)
    //   maximizing cache hits and eliminating upstream latency.
    // - Yellow Zone (>= 140 MB): Proactively evicts expired/idle cache entries and
    //   prunes stale rate-limiter buckets.
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
                let wal = mem_gov_state.wal.clone_ref();
                tokio::task::spawn_blocking(move || wal.maybe_compact()).await.ok();
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
            }
        }
    });

    // 7. Shutdown coordination channel
    let (shutdown_tx, shutdown_rx_dot) = tokio::sync::watch::channel(());

    // 8. Start DoT Server
    let dot_state = state.clone();
    let dot_host = config.host.clone();
    let dot_port = config.dot_port;
    let dot_handle = tokio::spawn(async move {
        if let Err(e) = server::dot::start_dot_server(dot_state, &dot_host, dot_port, shutdown_rx_dot).await {
            error!("[dot] Server error: {}", e);
        }
    });

    // 9. Start DoH Server
    let app = server::doh::create_doh_router(state.clone());
    let host_ip: std::net::IpAddr = config.host.parse().unwrap_or(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED));
    let addr = SocketAddr::new(host_ip, config.port);
    info!("[doh] AmarDNS DoH server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Signal DoT server to shut down cleanly
    let _ = shutdown_tx.send(());
    // Give in-flight DoT queries a short grace period to flush
    let _ = tokio::time::timeout(std::time::Duration::from_millis(500), dot_handle).await;

    info!("[system] AmarDNS shutdown cleanly.");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
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
}
