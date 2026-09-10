use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub provider: String,
    pub url: String,
    pub aura: String, // "high", "medium", "low"
}

#[derive(Debug)]
pub struct UpstreamNode {
    pub provider: String,
    pub url: String,
    pub aura: String,
    pub latency_ms: AtomicU32,
    pub errors: AtomicU64,
    pub pulls: AtomicU64,
    pub successes: AtomicU64,
    pub consecutive_successes: AtomicU64,
    pub recent_latencies: parking_lot::RwLock<Vec<u32>>,
}

impl UpstreamNode {
    pub fn new(cfg: UpstreamConfig) -> Self {
        Self {
            provider: cfg.provider,
            url: cfg.url,
            aura: cfg.aura,
            latency_ms: AtomicU32::new(0),
            errors: AtomicU64::new(0),
            pulls: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            consecutive_successes: AtomicU64::new(0),
            recent_latencies: parking_lot::RwLock::new(Vec::with_capacity(30)),
        }
    }

    pub fn record_success(&self, latency: u32) {
        self.successes.fetch_add(1, Ordering::Relaxed);
        let cons = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
        // Circuit breaker healing: every 2 consecutive successes, heal 1 error!
        if cons.is_multiple_of(2) {
            let errs = self.errors.load(Ordering::Relaxed);
            if errs > 0 {
                self.errors.store(errs.saturating_sub(1), Ordering::Relaxed);
            }
        }
        let old = self.latency_ms.load(Ordering::Relaxed);
        let new_lat = if old == 0 || old == 9999 {
            latency.max(1)
        } else {
            ((old as f64 * 0.7) + (latency.max(1) as f64 * 0.3)).round() as u32
        };
        self.latency_ms.store(new_lat.max(1), Ordering::Relaxed);

        let mut rec = self.recent_latencies.write();
        if rec.len() >= 30 {
            rec.remove(0);
        }
        rec.push(latency.max(1));
    }

    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        self.consecutive_successes.store(0, Ordering::Relaxed);
    }

    pub fn get_percentiles(&self) -> (u32, u32, u32) {
        let rec = self.recent_latencies.read();
        if rec.len() >= 4 {
            let mut sorted = rec.clone();
            sorted.sort_unstable();
            let p50 = sorted[sorted.len() / 2];
            let p95_idx = ((sorted.len() as f64 * 0.95).round() as usize).min(sorted.len() - 1);
            let p99_idx = ((sorted.len() as f64 * 0.99).round() as usize).min(sorted.len() - 1);
            (p50, sorted[p95_idx], sorted[p99_idx])
        } else if !rec.is_empty() {
            let mut sorted = rec.clone();
            sorted.sort_unstable();
            let p50 = sorted[sorted.len() / 2];
            let p95 = sorted[sorted.len() - 1];
            (p50, p95, p95)
        } else {
            let base = self.latency_ms.load(Ordering::Relaxed);
            (base, base, base)
        }
    }

    pub fn aura_rank(&self) -> u8 {
        match self.aura.to_lowercase().as_str() {
            "high" => 3,
            "medium" => 2,
            _ => 1,
        }
    }

    pub fn effective_latency(&self) -> u32 {
        let err = self.errors.load(Ordering::Relaxed).min(20) as u32 * 50;
        self.latency_ms.load(Ordering::Relaxed) + err
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum UpstreamPayload {
    Wrapped { dns_over_https: Vec<UpstreamConfig> },
    Direct(Vec<UpstreamConfig>),
}

pub struct UpstreamPool {
    client: reqwest::Client,
    upstreams: RwLock<Vec<Arc<UpstreamNode>>>,
}

impl UpstreamPool {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(3000))
            .pool_idle_timeout(Duration::from_secs(120))
            .pool_max_idle_per_host(64)
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .tcp_nodelay(true)
            .http2_adaptive_window(true)
            .http2_keep_alive_interval(Some(Duration::from_secs(15)))
            .http2_keep_alive_timeout(Duration::from_secs(5))
            .user_agent("AmarDNS/2.0")
            .build()
            .unwrap_or_default();

        let default_upstreams = vec![
            Arc::new(UpstreamNode::new(UpstreamConfig {
                provider: "Cloudflare".to_string(),
                url: "https://cloudflare-dns.com/dns-query".to_string(),
                aura: "high".to_string(),
            })),
            Arc::new(UpstreamNode::new(UpstreamConfig {
                provider: "Cloudflare (1.1.1.1)".to_string(),
                url: "https://1.1.1.1/dns-query".to_string(),
                aura: "high".to_string(),
            })),
            Arc::new(UpstreamNode::new(UpstreamConfig {
                provider: "Cloudflare (1.0.0.1)".to_string(),
                url: "https://1.0.0.1/dns-query".to_string(),
                aura: "high".to_string(),
            })),
            Arc::new(UpstreamNode::new(UpstreamConfig {
                provider: "Google DNS".to_string(),
                url: "https://dns.google/dns-query".to_string(),
                aura: "high".to_string(),
            })),
            Arc::new(UpstreamNode::new(UpstreamConfig {
                provider: "Google (8.8.8.8)".to_string(),
                url: "https://8.8.8.8/dns-query".to_string(),
                aura: "high".to_string(),
            })),
            Arc::new(UpstreamNode::new(UpstreamConfig {
                provider: "Google (8.8.4.4)".to_string(),
                url: "https://8.8.4.4/dns-query".to_string(),
                aura: "high".to_string(),
            })),
            Arc::new(UpstreamNode::new(UpstreamConfig {
                provider: "Quad9".to_string(),
                url: "https://dns.quad9.net/dns-query".to_string(),
                aura: "high".to_string(),
            })),
            Arc::new(UpstreamNode::new(UpstreamConfig {
                provider: "OpenDNS".to_string(),
                url: "https://doh.opendns.com/dns-query".to_string(),
                aura: "medium".to_string(),
            })),
            Arc::new(UpstreamNode::new(UpstreamConfig {
                provider: "AdGuard".to_string(),
                url: "https://dns.adguard-dns.com/dns-query".to_string(),
                aura: "medium".to_string(),
            })),
        ];

        Self {
            client,
            upstreams: RwLock::new(default_upstreams),
        }
    }

    /// Returns upstream nodes ordered by performance: lowest effective latency first, healthy first
    pub fn ranked_nodes(&self) -> Vec<Arc<UpstreamNode>> {
        let guard = self.upstreams.read();
        let mut nodes = guard.clone();
        nodes.sort_by(|a, b| {
            let err_a = a.errors.load(Ordering::Relaxed);
            let err_b = b.errors.load(Ordering::Relaxed);
            let ok_a = err_a < 10;
            let ok_b = err_b < 10;
            if ok_a != ok_b {
                return ok_b.cmp(&ok_a);
            }
            let lat_a = a.effective_latency();
            let lat_b = b.effective_latency();
            lat_a.cmp(&lat_b).then_with(|| {
                b.aura_rank().cmp(&a.aura_rank())
            })
        });
        nodes
    }

    /// Selects the best upstream based on lowest latency and health
    #[allow(dead_code)]
    pub fn select_best(&self) -> Option<Arc<UpstreamNode>> {
        self.ranked_nodes().into_iter().next()
    }

    /// Sends proactive keep-alive pings over HTTP/2 to top ranked nodes.
    /// Keeps TCP/TLS connections permanently warm in reqwest's pool,
    /// measures real-time upstream latency, and eliminates cold-start TLS latency.
    pub async fn keepalive_ping(&self) {
        let nodes = self.ranked_nodes();
        if nodes.is_empty() {
            return;
        }

        // Minimal RFC 1035 query packet for "." IN NS (17 bytes)
        let ping_wire = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Standard query, RD=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            0x00,       // Root label '.'
            0x00, 0x02, // QTYPE = NS (2)
            0x00, 0x01, // QCLASS = IN (1)
        ];

        let mut handles = Vec::new();
        for node in nodes.into_iter().take(2) {
            let client = self.client.clone();
            let wire = ping_wire.clone();
            handles.push(tokio::spawn(async move {
                let start = Instant::now();
                let res = client
                    .post(&node.url)
                    .header("content-type", "application/dns-message")
                    .header("accept", "application/dns-message")
                    .timeout(Duration::from_millis(1500))
                    .body(wire)
                    .send()
                    .await;

                if let Ok(resp) = res {
                    if resp.status().is_success() {
                        let lat = start.elapsed().as_millis().max(1) as u32;
                        node.record_success(lat);
                    }
                }
            }));
        }

        for h in handles {
            let _ = h.await;
        }
    }

    /// Resolves DNS wire query using ultra-fast hedged queries across the top 2 resolvers
    pub async fn resolve(&self, query_wire: &[u8]) -> Option<(Vec<u8>, String)> {
        let nodes = self.ranked_nodes();
        if nodes.is_empty() {
            return None;
        }

        let first = nodes[0].clone();
        let second = if nodes.len() > 1 { Some(nodes[1].clone()) } else { None };
        let third = if nodes.len() > 2 { Some(nodes[2].clone()) } else { None };
        let client = self.client.clone();
        let wire = query_wire.to_vec();

        let execute_query = |node: Arc<UpstreamNode>, wire: Vec<u8>| {
            let client = client.clone();
            async move {
                let start = Instant::now();
                node.pulls.fetch_add(1, Ordering::Relaxed);
                let mut resolved = None;

                // 1. Fast POST attempt with 1500ms timeout
                let res = client
                    .post(&node.url)
                    .header("content-type", "application/dns-message")
                    .header("accept", "application/dns-message")
                    .timeout(Duration::from_millis(1500))
                    .body(wire.clone())
                    .send()
                    .await;

                if let Ok(resp) = res {
                    if resp.status().is_success() {
                        if let Ok(bytes) = resp.bytes().await {
                            if bytes.len() >= 12 {
                                resolved = Some(bytes.to_vec());
                            }
                        }
                    }
                }

                // 2. Fallback to GET if POST failed
                if resolved.is_none() {
                    let b64 = to_base64_url(&wire);
                    let get_url = if node.url.contains('?') {
                        format!("{}&dns={}", node.url, b64)
                    } else {
                        format!("{}?dns={}", node.url, b64)
                    };
                    if let Ok(resp) = client
                        .get(&get_url)
                        .header("accept", "application/dns-message")
                        .timeout(Duration::from_millis(1500))
                        .send()
                        .await
                    {
                        if resp.status().is_success() {
                            if let Ok(bytes) = resp.bytes().await {
                                if bytes.len() >= 12 {
                                    resolved = Some(bytes.to_vec());
                                }
                            }
                        }
                    }
                }

                if let Some(bytes) = resolved {
                    let elapsed = start.elapsed().as_millis() as u32;
                    node.record_success(elapsed);
                    Some((bytes, node.provider.clone()))
                } else {
                    node.record_error();
                    None
                }
            }
        };

        // Stage 1: Fire fastest resolver immediately
        let fut1 = execute_query(first, wire.clone());
        tokio::pin!(fut1);

        // Stage 1 hedge timer: 10ms (top resolvers typically answer in 2-6ms)
        let hedge_sleep_1 = tokio::time::sleep(Duration::from_millis(10));
        tokio::pin!(hedge_sleep_1);

        tokio::select! {
            res1 = &mut fut1 => {
                if let Some(res) = res1 {
                    return Some(res);
                }
            }
            _ = &mut hedge_sleep_1 => {
                // First didn't finish in 10ms, race with second resolver!
            }
        }

        if let Some(sec) = second {
            let fut2 = execute_query(sec, wire.clone());
            tokio::pin!(fut2);

            let hedge_sleep_2 = tokio::time::sleep(Duration::from_millis(15));
            tokio::pin!(hedge_sleep_2);

            tokio::select! {
                res1 = &mut fut1 => {
                    if let Some(res) = res1 {
                        return Some(res);
                    }
                }
                res2 = &mut fut2 => {
                    if let Some(res) = res2 {
                        return Some(res);
                    }
                }
                _ = &mut hedge_sleep_2 => {
                    // Neither finished in 25ms, race with third resolver!
                }
            }

            if let Some(thd) = third {
                let fut3 = execute_query(thd, wire.clone());
                tokio::pin!(fut3);

                tokio::select! {
                    res1 = &mut fut1 => {
                        if let Some(res) = res1 { return Some(res); }
                        tokio::select! {
                            res2 = &mut fut2 => { if let Some(res) = res2 { return Some(res); } fut3.await }
                            res3 = &mut fut3 => { if let Some(res) = res3 { return Some(res); } fut2.await }
                        }
                    }
                    res2 = &mut fut2 => {
                        if let Some(res) = res2 { return Some(res); }
                        tokio::select! {
                            res1 = &mut fut1 => { if let Some(res) = res1 { return Some(res); } fut3.await }
                            res3 = &mut fut3 => { if let Some(res) = res3 { return Some(res); } fut1.await }
                        }
                    }
                    res3 = &mut fut3 => {
                        if let Some(res) = res3 { return Some(res); }
                        tokio::select! {
                            res1 = &mut fut1 => { if let Some(res) = res1 { return Some(res); } fut2.await }
                            res2 = &mut fut2 => { if let Some(res) = res2 { return Some(res); } fut1.await }
                        }
                    }
                }
            } else {
                tokio::select! {
                    res1 = &mut fut1 => {
                        if let Some(res) = res1 { return Some(res); }
                        fut2.await
                    }
                    res2 = &mut fut2 => {
                        if let Some(res) = res2 { return Some(res); }
                        fut1.await
                    }
                }
            }
        } else {
            fut1.await
        }
    }

    /// Syncs upstream list from CDN, probes candidates concurrently, and ranks top 9 (3xN pool)
    pub async fn sync_and_rank(&self) -> Result<usize, String> {
        let cdn_url = "https://cdn.jsdelivr.net/gh/abir614/-@latest/dns-upstream.json";
        let resp = self.client.get(cdn_url).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("CDN returned HTTP {}", resp.status()));
        }

        let payload: UpstreamPayload = resp.json().await.map_err(|e| e.to_string())?;
        let cfgs = match payload {
            UpstreamPayload::Wrapped { dns_over_https } => dns_over_https,
            UpstreamPayload::Direct(list) => list,
        };

        // Probe packet: query for cloudflare.com A record
        const PROBE_PACKET: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\ncloudflare\x03com\x00\x00\x01\x00\x01";
        const PROBE_B64: &str = "EjQBAAABAAAAAAAACmNsb3VkZmxhcmUDY29tAAABAAE";

        // Probe all candidates in parallel
        let mut tasks = Vec::new();
        for cfg in cfgs {
            let client = self.client.clone();
            tasks.push(tokio::spawn(async move {
                let start = Instant::now();
                let mut ok = false;
                let mut latency = 9999;

                let res = client
                    .post(&cfg.url)
                    .header("content-type", "application/dns-message")
                    .header("accept", "application/dns-message")
                    .timeout(Duration::from_millis(2500))
                    .body(PROBE_PACKET.to_vec())
                    .send()
                    .await;

                if let Ok(r) = res {
                    if r.status().is_success() {
                        ok = true;
                        latency = start.elapsed().as_millis().max(1) as u32;
                    }
                }

                if !ok {
                    let get_url = if cfg.url.contains('?') {
                        format!("{}&dns={}", cfg.url, PROBE_B64)
                    } else {
                        format!("{}?dns={}", cfg.url, PROBE_B64)
                    };
                    if let Ok(r) = client
                        .get(&get_url)
                        .header("accept", "application/dns-message")
                        .timeout(Duration::from_millis(2500))
                        .send()
                        .await
                    {
                        if r.status().is_success() {
                            ok = true;
                            latency = start.elapsed().as_millis().max(1) as u32;
                        }
                    }
                }

                let node = UpstreamNode {
                    provider: cfg.provider,
                    url: cfg.url,
                    aura: cfg.aura,
                    latency_ms: AtomicU32::new(latency),
                    errors: AtomicU64::new(if ok { 0 } else { 1 }),
                    pulls: AtomicU64::new(1),
                    successes: AtomicU64::new(if ok { 1 } else { 0 }),
                    consecutive_successes: AtomicU64::new(if ok { 1 } else { 0 }),
                    recent_latencies: parking_lot::RwLock::new(if ok { vec![latency] } else { vec![] }),
                };
                (ok, node)
            }));
        }

        let mut probed = Vec::new();
        for task in tasks {
            if let Ok(res) = task.await {
                probed.push(res);
            }
        }

        // Rank upstreams:
        // 1. ok (healthy) first
        // 2. aura: "high" (3) > "medium" (2) > "low" (1)
        // Rank upstreams:
        // 1. ok (healthy) first
        // 2. High performance (lowest latency with slight aura tie-break bonus)
        probed.sort_by(|(ok_a, node_a), (ok_b, node_b)| {
            if ok_a != ok_b {
                return ok_b.cmp(ok_a);
            }
            let lat_a = node_a.latency_ms.load(Ordering::Relaxed);
            let lat_b = node_b.latency_ms.load(Ordering::Relaxed);
            let score_a = (1000.0 / lat_a.max(1) as f64) * (1.0 + (node_a.aura_rank() as f64 * 0.15));
            let score_b = (1000.0 / lat_b.max(1) as f64) * (1.0 + (node_b.aura_rank() as f64 * 0.15));
            score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
        });

        // Select 3xN active upstreams (default 9 = 3x3 pool)
        let active_count = if probed.len() >= 9 { 9 } else { (probed.len() / 3) * 3 };
        let count = if active_count >= 3 { active_count } else { probed.len() };

        let active_nodes: Vec<Arc<UpstreamNode>> = probed
            .into_iter()
            .take(count)
            .map(|(_, node)| Arc::new(node))
            .collect();

        let final_count = active_nodes.len();
        *self.upstreams.write() = active_nodes;
        Ok(final_count)
    }

    /// Periodically probes all active upstreams concurrently with a lightweight query to ensure real-time metrics
    pub async fn probe_active_upstreams(&self) {
        const PROBE_PACKET: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\ncloudflare\x03com\x00\x00\x01\x00\x01";
        const PROBE_B64: &str = "EjQBAAABAAAAAAAACmNsb3VkZmxhcmUDY29tAAABAAE";

        let nodes = {
            let guard = self.upstreams.read();
            guard.clone()
        };

        let mut tasks = Vec::new();
        for node in nodes {
            let client = self.client.clone();
            tasks.push(tokio::spawn(async move {
                let start = Instant::now();
                let mut ok = false;
                let mut latency = 9999;

                let res = client
                    .post(&node.url)
                    .header("content-type", "application/dns-message")
                    .header("accept", "application/dns-message")
                    .timeout(Duration::from_millis(2500))
                    .body(PROBE_PACKET.to_vec())
                    .send()
                    .await;

                if let Ok(r) = res {
                    if r.status().is_success() {
                        ok = true;
                        latency = start.elapsed().as_millis().max(1) as u32;
                    }
                }

                if !ok {
                    let get_url = if node.url.contains('?') {
                        format!("{}&dns={}", node.url, PROBE_B64)
                    } else {
                        format!("{}?dns={}", node.url, PROBE_B64)
                    };
                    if let Ok(r) = client
                        .get(&get_url)
                        .header("accept", "application/dns-message")
                        .timeout(Duration::from_millis(2500))
                        .send()
                        .await
                    {
                        if r.status().is_success() {
                            ok = true;
                            latency = start.elapsed().as_millis().max(1) as u32;
                        }
                    }
                }

                node.pulls.fetch_add(1, Ordering::Relaxed);
                if ok {
                    node.record_success(latency);
                } else {
                    node.record_error();
                }
            }));
        }

        for t in tasks {
            let _ = t.await;
        }

        // Re-sort pool so fastest resolvers are always ranked #1
        let mut guard = self.upstreams.write();
        guard.sort_by(|a, b| {
            let err_a = a.errors.load(Ordering::Relaxed);
            let err_b = b.errors.load(Ordering::Relaxed);
            let ok_a = err_a < 10;
            let ok_b = err_b < 10;
            if ok_a != ok_b {
                return ok_b.cmp(&ok_a);
            }
            let lat_a = a.effective_latency();
            let lat_b = b.effective_latency();
            lat_a.cmp(&lat_b).then_with(|| {
                b.aura_rank().cmp(&a.aura_rank())
            })
        });
    }

    pub fn reset_cb(&self) {
        let guard = self.upstreams.read();
        for u in guard.iter() {
            u.errors.store(0, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> Vec<serde_json::Value> {
        let guard = self.upstreams.read();
        guard.iter().enumerate().map(|(idx, u)| {
            let (p50, p95, p99) = u.get_percentiles();
            let lat = p50;
            let errs = u.errors.load(Ordering::Relaxed);
            let pulls = u.pulls.load(Ordering::Relaxed);
            let successes = u.successes.load(Ordering::Relaxed);
            let total_attempts = errs + successes;
            let err_pct = if total_attempts > 0 {
                ((errs as f64 / total_attempts as f64) * 100.0).min(100.0)
            } else {
                0.0
            };
            let score = if lat > 0 { (1000 / lat.max(1)).min(100) } else { 0 };
            let healthy = errs < 5 || (err_pct < 25.0 && lat < 1000);
            serde_json::json!({
                "index": idx,
                "provider": u.provider,
                "url": u.url,
                "base": u.url,
                "aura": u.aura,
                "latencyMs": lat,
                "p50": p50,
                "p95": p95,
                "p99": p99,
                "errors": errs,
                "totalErrors": errs,
                "pulls": pulls,
                "hits": pulls,
                "errorRatePct": err_pct.round() as u64,
                "score": score,
                "healthy": healthy
            })
        }).collect()
    }

    /// Fires queries to all healthy upstreams simultaneously and returns the first valid response.
    /// This is the "turbo fallback" for worst-case latency scenarios.
    pub async fn resolve_race(&self, query_wire: &[u8]) -> Option<(Vec<u8>, String)> {
        let nodes = self.ranked_nodes();
        let healthy_nodes: Vec<_> = nodes.into_iter()
            .filter(|n| n.errors.load(Ordering::Relaxed) < 10)
            .collect();

        if healthy_nodes.is_empty() {
            return self.resolve(query_wire).await;
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<(Vec<u8>, String)>(1);
        let client = self.client.clone();

        for node in healthy_nodes {
            let tx = tx.clone();
            let wire = query_wire.to_vec();
            let client = client.clone();
            tokio::spawn(async move {
                let start = Instant::now();
                node.pulls.fetch_add(1, Ordering::Relaxed);
                let res = client
                    .post(&node.url)
                    .header("content-type", "application/dns-message")
                    .header("accept", "application/dns-message")
                    .timeout(Duration::from_millis(2000))
                    .body(wire)
                    .send()
                    .await;

                if let Ok(resp) = res {
                    if resp.status().is_success() {
                        if let Ok(bytes) = resp.bytes().await {
                            if bytes.len() >= 12 {
                                let lat = start.elapsed().as_millis() as u32;
                                node.record_success(lat);
                                let _ = tx.try_send((bytes.to_vec(), node.provider.clone()));
                            }
                        }
                    }
                }
                // If failed, don't send — other spawns will win
            });
        }
        drop(tx); // close sender side so recv terminates if all fail

        // First response wins
        rx.recv().await
    }
}

fn to_base64_url(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() { input[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < input.len() {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        }
        if i + 2 < input.len() {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        }
        i += 3;
    }
    out
}
