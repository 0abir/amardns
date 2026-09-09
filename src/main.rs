#![recursion_limit = "256"]

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};
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
        .unwrap_or(4)
        .max(4);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .thread_name("amardns-worker")
        .thread_stack_size(2 * 1024 * 1024)
        .build()?;

    runtime.block_on(async_main())
}

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

    // 5. Background Daily Sync (Daily at midnight GMT+6)
    let cron_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 3600));
        loop {
            interval.tick().await;
            info!("[cron] Running daily threat feed and upstream ranker sync...");
            let _ = cron_state.sync_threat_feeds().await;
            let _ = cron_state.upstreams.sync_and_rank().await;
        }
    });

    // 6. Background Active Upstream Probe (Every 30 seconds for live latency & health)
    let probe_state = state.clone();
    tokio::spawn(async move {
        probe_state.upstreams.probe_active_upstreams().await;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            probe_state.upstreams.probe_active_upstreams().await;
        }
    });

    // 6b. Background Storage & Memory Optimizer (Every 10 minutes)
    let opt_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            interval.tick().await;
            opt_state.wal.maybe_compact();
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
