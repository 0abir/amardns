use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
// Removed unused imports

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub const DEFAULT_UPSTREAM_URL: &str =
    "https://cdn.jsdelivr.net/gh/abir614/-@latest/dns-upstream.json";

/// Official IANA Root Server Hints (13 Root Name Server clusters).
pub const IANA_ROOT_HINTS: &[&str] = &[
    "198.41.0.4:53",     // a.root-servers.net (Verisign)
    "199.9.14.201:53",   // b.root-servers.net (USC-ISI)
    "192.33.4.12:53",    // c.root-servers.net (Cogent)
    "199.7.91.13:53",    // d.root-servers.net (University of Maryland)
    "192.203.230.10:53", // e.root-servers.net (NASA)
    "192.5.5.241:53",    // f.root-servers.net (Internet Systems Consortium)
    "192.112.36.4:53",   // g.root-servers.net (US Department of Defense)
    "198.97.190.53:53",  // h.root-servers.net (US Army Research Lab)
    "192.36.148.17:53",  // i.root-servers.net (Netnod)
    "192.58.128.30:53",  // j.root-servers.net (Verisign)
    "193.0.14.129:53",   // k.root-servers.net (RIPE NCC)
    "199.7.83.42:53",    // l.root-servers.net (ICANN)
    "202.12.27.33:53",   // m.root-servers.net (WIDE Project)
];

type InFlightMap =
    std::collections::HashMap<String, tokio::sync::broadcast::Sender<(Vec<u8>, String)>>;

pub struct Singleflight {
    in_flight: parking_lot::Mutex<InFlightMap>,
    pub coalesced: std::sync::atomic::AtomicU64,
}

struct SingleflightGuard<'a> {
    in_flight: &'a parking_lot::Mutex<InFlightMap>,
    key: &'a str,
    result: Option<(Vec<u8>, String)>,
    completed: bool,
}

impl<'a> Drop for SingleflightGuard<'a> {
    fn drop(&mut self) {
        let mut map = self.in_flight.lock();
        if let Some(tx) = map.remove(self.key) {
            if self.completed {
                if let Some(ref res) = self.result {
                    let _ = tx.send(res.clone());
                }
            }
        }
    }
}

impl Default for Singleflight {
    fn default() -> Self {
        Self::new()
    }
}

impl Singleflight {
    pub fn new() -> Self {
        Self {
            in_flight: parking_lot::Mutex::new(std::collections::HashMap::new()),
            coalesced: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn in_flight_count(&self) -> usize {
        self.in_flight.lock().len()
    }

    pub async fn do_call<F, Fut>(&self, key: &str, upstream_fn: F) -> Option<(Vec<u8>, String)>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Option<(Vec<u8>, String)>>,
    {
        let mut rx = {
            let mut map = self.in_flight.lock();
            if let Some(tx) = map.get(key) {
                Some(tx.subscribe())
            } else {
                let (tx, _) = tokio::sync::broadcast::channel(1);
                map.insert(key.to_string(), tx);
                None
            }
        };

        if let Some(ref mut receiver) = rx {
            match receiver.recv().await {
                Ok(res) => {
                    self.coalesced
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Some(res);
                }
                Err(_) => return None,
            }
        }

        let mut guard = SingleflightGuard {
            in_flight: &self.in_flight,
            key,
            result: None,
            completed: false,
        };

        let result = upstream_fn().await;
        guard.result = result.clone();
        guard.completed = true;

        result
    }
}

/// Normalizes any upstream provider name into a single clean word without spaces, hyphens, or parenthetical modifiers.
pub fn normalize_provider_name(name: &str) -> String {
    let lower = name.to_lowercase();
    if lower.contains("mullvad") {
        "Mullvad".to_string()
    } else if lower.contains("quad9") {
        "Quad9".to_string()
    } else if lower.contains("adguard") {
        "AdGuard".to_string()
    } else if lower.contains("cloudflare") {
        "Cloudflare".to_string()
    } else if lower.contains("digitale") {
        "Digitale".to_string()
    } else if lower.contains("nextdns") {
        "NextDNS".to_string()
    } else if lower.contains("control") {
        "ControlD".to_string()
    } else if lower.contains("sb") {
        "DNSSB".to_string()
    } else if lower.contains("google") {
        "Google".to_string()
    } else if lower.contains("opendns") {
        "OpenDNS".to_string()
    } else if lower.contains("rethink") {
        "Rethink".to_string()
    } else if lower.contains("aerocache") || lower.contains("cache") {
        "AeroCache".to_string()
    } else if lower.contains("root") {
        "Root".to_string()
    } else if lower.contains("filter") || lower.contains("block") || lower.contains("0.0.0.0") {
        "Filter".to_string()
    } else if lower.contains("rebind") {
        "RebindGuard".to_string()
    } else if lower.contains("ttl") {
        "TTLGuard".to_string()
    } else if lower.contains("dnssec") {
        "DNSSEC".to_string()
    } else if lower.contains("amardns") {
        "AmarDNS".to_string()
    } else if lower.is_empty() || lower == "none" || lower == "-" {
        "None".to_string()
    } else {
        let first_word = name
            .split(|c: char| !c.is_alphanumeric())
            .find(|s| !s.is_empty())
            .unwrap_or("Upstream");
        let mut chars = first_word.chars();
        match chars.next() {
            None => "Upstream".to_string(),
            Some(f) => f.to_uppercase().collect::<String>() + chars.as_str(),
        }
    }
}

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
    pub recent_latencies: parking_lot::RwLock<VecDeque<u32>>,
}

impl UpstreamNode {
    pub fn new(cfg: UpstreamConfig) -> Self {
        Self {
            provider: normalize_provider_name(&cfg.provider),
            url: cfg.url,
            aura: cfg.aura,
            latency_ms: AtomicU32::new(0),
            errors: AtomicU64::new(0),
            pulls: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            consecutive_successes: AtomicU64::new(0),
            recent_latencies: parking_lot::RwLock::new(VecDeque::with_capacity(30)),
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
            rec.pop_front();
        }
        rec.push_back(latency.max(1));
    }

    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        self.consecutive_successes.store(0, Ordering::Relaxed);
    }

    pub fn get_percentiles(&self) -> (u32, u32, u32) {
        let rec = self.recent_latencies.read();
        if rec.len() >= 4 {
            let mut sorted: Vec<u32> = rec.iter().copied().collect();
            sorted.sort_unstable();
            let p50 = sorted[sorted.len() / 2];
            let p95_idx = ((sorted.len() as f64 * 0.95).round() as usize).min(sorted.len() - 1);
            let p99_idx = ((sorted.len() as f64 * 0.99).round() as usize).min(sorted.len() - 1);
            (p50, sorted[p95_idx], sorted[p99_idx])
        } else if !rec.is_empty() {
            let mut sorted: Vec<u32> = rec.iter().copied().collect();
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

    pub fn is_degraded(&self) -> bool {
        let errs = self.errors.load(Ordering::Relaxed);
        let lat = self.latency_ms.load(Ordering::Relaxed);
        let eff_lat = self.effective_latency();
        errs >= 3 || lat >= 500 || eff_lat >= 350
    }

    pub fn score(&self) -> u32 {
        let errs = self.errors.load(Ordering::Relaxed);
        if errs >= 5 {
            return 0;
        }
        let eff_lat = self.effective_latency();
        if eff_lat > 0 {
            (1000 / eff_lat.max(1)).min(100)
        } else {
            0
        }
    }

    pub fn rank_key(&self) -> (bool, u32, std::cmp::Reverse<u8>, u32) {
        let ok = self.errors.load(Ordering::Relaxed) < 5;
        let eff_lat = self.effective_latency();
        let bucket = eff_lat / 5;
        let aura = self.aura_rank();
        (!ok, bucket, std::cmp::Reverse(aura), eff_lat)
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
    cached_ranked: RwLock<Arc<Vec<Arc<UpstreamNode>>>>,
    candidates: RwLock<Vec<UpstreamConfig>>,
    pub singleflight: Singleflight,
    pub hedged_wins: AtomicU64,
}

impl Default for UpstreamPool {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamPool {
    /// Comprehensive built-in candidate pool of high-reputation public DoH resolvers
    pub fn all_default_candidate_configs() -> Vec<UpstreamConfig> {
        vec![
            UpstreamConfig {
                provider: "Mullvad".to_string(),
                url: "https://doh.mullvad.net/dns-query".to_string(),
                aura: "high".to_string(),
            },
            UpstreamConfig {
                provider: "Quad9".to_string(),
                url: "https://dns.quad9.net/dns-query".to_string(),
                aura: "high".to_string(),
            },
            UpstreamConfig {
                provider: "AdGuard".to_string(),
                url: "https://dns.adguard-dns.com/dns-query".to_string(),
                aura: "high".to_string(),
            },
            UpstreamConfig {
                provider: "Cloudflare".to_string(),
                url: "https://security.cloudflare-dns.com/dns-query".to_string(),
                aura: "high".to_string(),
            },
            UpstreamConfig {
                provider: "Digitale".to_string(),
                url: "https://dns.digitale-gesellschaft.ch/dns-query".to_string(),
                aura: "medium".to_string(),
            },
            UpstreamConfig {
                provider: "Cloudflare".to_string(),
                url: "https://cloudflare-dns.com/dns-query".to_string(),
                aura: "high".to_string(),
            },
            UpstreamConfig {
                provider: "NextDNS".to_string(),
                url: "https://dns.nextdns.io/dns-query".to_string(),
                aura: "high".to_string(),
            },
            UpstreamConfig {
                provider: "ControlD".to_string(),
                url: "https://freedns.controld.com/p0".to_string(),
                aura: "medium".to_string(),
            },
            UpstreamConfig {
                provider: "DNSSB".to_string(),
                url: "https://doh.dns.sb/dns-query".to_string(),
                aura: "medium".to_string(),
            },
            UpstreamConfig {
                provider: "LibreDNS".to_string(),
                url: "https://doh.libredns.gr/dns-query".to_string(),
                aura: "medium".to_string(),
            },
            UpstreamConfig {
                provider: "CleanBrowsing".to_string(),
                url: "https://doh.cleanbrowsing.org/doh/security-filter/".to_string(),
                aura: "medium".to_string(),
            },
            UpstreamConfig {
                provider: "HageZi".to_string(),
                url: "https://root.hagezi.org/dns-query".to_string(),
                aura: "medium".to_string(),
            },
            UpstreamConfig {
                provider: "Google".to_string(),
                url: "https://dns.google/dns-query".to_string(),
                aura: "low".to_string(),
            },
            UpstreamConfig {
                provider: "OpenDNS".to_string(),
                url: "https://doh.opendns.com/dns-query".to_string(),
                aura: "low".to_string(),
            },
            UpstreamConfig {
                provider: "AppliedPrivacy".to_string(),
                url: "https://doh.applied-privacy.net/query".to_string(),
                aura: "high".to_string(),
            },
            UpstreamConfig {
                provider: "dns0.eu".to_string(),
                url: "https://dns0.eu/dns-query".to_string(),
                aura: "high".to_string(),
            },
            UpstreamConfig {
                provider: "DNS4EU".to_string(),
                url: "https://unfiltered.joindns4.eu/dns-query".to_string(),
                aura: "high".to_string(),
            },
            UpstreamConfig {
                provider: "SecureDNS".to_string(),
                url: "https://doh.securedns.eu/dns-query".to_string(),
                aura: "medium".to_string(),
            },
            UpstreamConfig {
                provider: "dnsforge".to_string(),
                url: "https://dnsforge.de/dns-query".to_string(),
                aura: "medium".to_string(),
            },
            UpstreamConfig {
                provider: "AhaDNS".to_string(),
                url: "https://dns.ahadns.com/dns-query".to_string(),
                aura: "medium".to_string(),
            },
            UpstreamConfig {
                provider: "BlahDNS".to_string(),
                url: "https://doh-jp.blahdns.com/dns-query".to_string(),
                aura: "medium".to_string(),
            },
            UpstreamConfig {
                provider: "CIRA".to_string(),
                url: "https://protected.canadianshield.cira.ca/dns-query".to_string(),
                aura: "medium".to_string(),
            },
            UpstreamConfig {
                provider: "Switch".to_string(),
                url: "https://dns.switch.ch/dns-query".to_string(),
                aura: "medium".to_string(),
            },
            UpstreamConfig {
                provider: "ODVR".to_string(),
                url: "https://odvr.nic.cz/doh".to_string(),
                aura: "medium".to_string(),
            },
            UpstreamConfig {
                provider: "Njalla".to_string(),
                url: "https://dns.njal.la/dns-query".to_string(),
                aura: "high".to_string(),
            },
            UpstreamConfig {
                provider: "Quad101".to_string(),
                url: "https://dns.twnic.tw/dns-query".to_string(),
                aura: "medium".to_string(),
            },
            UpstreamConfig {
                provider: "AliDNS".to_string(),
                url: "https://dns.alidns.com/dns-query".to_string(),
                aura: "low".to_string(),
            },
            UpstreamConfig {
                provider: "AA".to_string(),
                url: "https://dns.aa.net.uk/dns-query".to_string(),
                aura: "high".to_string(),
            },
            UpstreamConfig {
                provider: "Aquilenet".to_string(),
                url: "https://dns.aquilenet.fr/dns-query".to_string(),
                aura: "high".to_string(),
            },
            UpstreamConfig {
                provider: "Blokada".to_string(),
                url: "https://dns.blokada.org/dns-query".to_string(),
                aura: "high".to_string(),
            },
            UpstreamConfig {
                provider: "Belnet".to_string(),
                url: "https://dns.belnet.be/dns-query".to_string(),
                aura: "medium".to_string(),
            },
            UpstreamConfig {
                provider: "UncensoredDNS".to_string(),
                url: "https://anycast.uncensoreddns.org/dns-query".to_string(),
                aura: "medium".to_string(),
            },
        ]
    }

    /// 9 high-reliability fallback upstream DoH servers matching upstream JSON schema
    pub fn default_upstreams_config() -> Vec<UpstreamConfig> {
        Self::all_default_candidate_configs().into_iter().take(9).collect()
    }

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
            .user_agent("AmarDNS/1.0")
            .build()
            .unwrap_or_default();

        let default_upstreams: Vec<Arc<UpstreamNode>> = Self::default_upstreams_config()
            .into_iter()
            .map(|cfg| Arc::new(UpstreamNode::new(cfg)))
            .collect();

        let mut sorted = default_upstreams.clone();
        sorted.sort_by_key(|a| a.rank_key());

        Self {
            client,
            upstreams: RwLock::new(default_upstreams),
            cached_ranked: RwLock::new(Arc::new(sorted)),
            candidates: RwLock::new(Self::all_default_candidate_configs()),
            singleflight: Singleflight::new(),
            hedged_wins: AtomicU64::new(0),
        }
    }

    pub fn candidate_count(&self) -> usize {
        self.candidates.read().len()
    }

    #[allow(dead_code)]
    pub fn candidates(&self) -> Vec<UpstreamConfig> {
        self.candidates.read().clone()
    }

    #[allow(dead_code)]
    pub fn set_candidates(&self, cfgs: Vec<UpstreamConfig>) {
        *self.candidates.write() = cfgs;
    }

    /// Recomputes and caches the ranked list of upstreams based on latest latency and health.
    pub fn recompute_ranks(&self) {
        let guard = self.upstreams.read();
        let mut nodes = guard.clone();
        nodes.sort_by_key(|a| a.rank_key());
        *self.cached_ranked.write() = Arc::new(nodes);
    }

    /// Returns upstream nodes ordered by performance: lowest latency first (with priority tie-breaking), healthy first.
    /// Reads from pre-sorted cache with zero per-query sorting or allocation.
    pub fn ranked_nodes(&self) -> Vec<Arc<UpstreamNode>> {
        let guard = self.cached_ranked.read();
        guard.as_ref().clone()
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
            0x00, // Root label '.'
            0x00, 0x02, // QTYPE = NS (2)
            0x00, 0x01, // QCLASS = IN (1)
        ];

        let mut handles = Vec::new();
        for node in nodes.into_iter().take(4) {
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
        let key = match crate::dns::parser::parse_dns_query(query_wire).and_then(|p| p.question) {
            Some(q) => format!("{}:{}", q.name, q.qtype),
            None => {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                query_wire.hash(&mut hasher);
                format!("wire-{}", hasher.finish())
            }
        };

        self.singleflight.do_call(&key, || async {
            let nodes = self.ranked_nodes();
            if nodes.is_empty() {
                return None;
            }

            let first = nodes[0].clone();
            let second = if nodes.len() > 1 {
                Some(nodes[1].clone())
            } else {
                None
            };
            let third = if nodes.len() > 2 {
                Some(nodes[2].clone())
            } else {
                None
            };
            let client = self.client.clone();
            let wire = crate::dns::parser::ensure_edns0_do_bit(query_wire);
            // ECS privacy: strip client subnet from outbound queries (RFC 7871)
            let wire = crate::dns::parser::process_ecs_option(
                &wire,
                crate::dns::parser::EcsMode::Strip,
            );

            let execute_query = |node: Arc<UpstreamNode>, wire: Vec<u8>| {
                let client = client.clone();
                async move {
                    let start = std::time::Instant::now();
                    node.pulls.fetch_add(1, Ordering::Relaxed);
                    let mut resolved = None;

                    // 1. Fast POST attempt with 1500ms timeout
                    let res = client
                        .post(&node.url)
                        .header("content-type", "application/dns-message")
                        .header("accept", "application/dns-message")
                        .timeout(std::time::Duration::from_millis(1500))
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
                            .timeout(std::time::Duration::from_millis(1500))
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

            let hedge_sleep_1 = tokio::time::sleep(std::time::Duration::from_millis(8));
            tokio::pin!(hedge_sleep_1);

            tokio::select! {
                res1 = &mut fut1 => {
                    if let Some(res) = res1 {
                        return Some(res);
                    }
                }
                _ = &mut hedge_sleep_1 => {}
            }

            let on_hedged = |r: Option<(Vec<u8>, String)>| {
                if r.is_some() {
                    self.hedged_wins.fetch_add(1, Ordering::Relaxed);
                }
                r
            };

            if let Some(sec) = second {
                let fut2 = execute_query(sec, wire.clone());
                tokio::pin!(fut2);

                let hedge_sleep_2 = tokio::time::sleep(std::time::Duration::from_millis(12));
                tokio::pin!(hedge_sleep_2);

                tokio::select! {
                    res1 = &mut fut1 => {
                        if let Some(res) = res1 { return Some(res); }
                    }
                    res2 = &mut fut2 => {
                        if let Some(res) = res2 { return on_hedged(Some(res)); }
                    }
                    _ = &mut hedge_sleep_2 => {}
                }

                if let Some(thd) = third {
                    let fut3 = execute_query(thd, wire.clone());
                    tokio::pin!(fut3);

                    tokio::select! {
                        res1 = &mut fut1 => {
                            if let Some(res) = res1 { return Some(res); }
                            tokio::select! {
                                res2 = &mut fut2 => { if let Some(res) = res2 { return on_hedged(Some(res)); } on_hedged(fut3.await) }
                                res3 = &mut fut3 => { if let Some(res) = res3 { return on_hedged(Some(res)); } on_hedged(fut2.await) }
                            }
                        }
                        res2 = &mut fut2 => {
                            if let Some(res) = res2 { return on_hedged(Some(res)); }
                            tokio::select! {
                                res1 = &mut fut1 => { if let Some(res) = res1 { return Some(res); } on_hedged(fut3.await) }
                                res3 = &mut fut3 => { if let Some(res) = res3 { return on_hedged(Some(res)); } fut1.await }
                            }
                        }
                        res3 = &mut fut3 => {
                            if let Some(res) = res3 { return on_hedged(Some(res)); }
                            tokio::select! {
                                res1 = &mut fut1 => { if let Some(res) = res1 { return Some(res); } on_hedged(fut2.await) }
                                res2 = &mut fut2 => { if let Some(res) = res2 { return on_hedged(Some(res)); } fut1.await }
                            }
                        }
                    }
                } else {
                    tokio::select! {
                        res1 = &mut fut1 => {
                            if let Some(res) = res1 { return Some(res); }
                            on_hedged(fut2.await)
                        }
                        res2 = &mut fut2 => {
                            if let Some(res) = res2 { return on_hedged(Some(res)); }
                            fut1.await
                        }
                    }
                }
            } else {
                fut1.await
            }
        }).await
    }

    /// Autonomous IANA Root Server Hints Fallback (Zero-Upstream Recursion).
    /// If all configured DoH/DoT resolvers fail or are unreachable, query IANA root servers directly.
    pub async fn resolve_root_hints(&self, query_wire: &[u8]) -> Option<(Vec<u8>, String)> {
        let wire = crate::dns::parser::ensure_edns0_do_bit(query_wire);
        let wire =
            crate::dns::parser::process_ecs_option(&wire, crate::dns::parser::EcsMode::Strip);

        let mut tasks = Vec::with_capacity(3);
        let rng = ring::rand::SystemRandom::new();
        for &hint in IANA_ROOT_HINTS.iter().take(3) {
            let wire_c = wire.clone();
            let hint_str = hint.to_string();
            let mut rng_txid = [0u8; 2];
            if ring::rand::SecureRandom::fill(&rng, &mut rng_txid).is_err() {
                continue;
            }
            tasks.push(tokio::spawn(async move {
                // RFC 5452: Source port randomization via ephemeral UDP socket binding
                let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
                if let Ok(addr) = hint_str.parse::<std::net::SocketAddr>() {
                    // RFC 5452: Cryptographically random 16-bit query ID per outgoing request
                    let mut outgoing = wire_c;
                    if outgoing.len() >= 2 {
                        outgoing[0..2].copy_from_slice(&rng_txid);
                    }
                    // Connect socket directly to root server to reject spoofed UDP packets from other origins
                    if sock.connect(addr).await.is_ok() && sock.send(&outgoing).await.is_ok() {
                        let mut buf = [0u8; 4096];
                        if let Ok(Ok(len)) = tokio::time::timeout(
                            Duration::from_millis(1500),
                            sock.recv(&mut buf),
                        )
                        .await
                        {
                            // Strict RFC 5452 verification: 16-bit TxID must match outgoing random ID
                            if len >= 12 && buf[0..2] == rng_txid {
                                return Some((
                                    buf[..len].to_vec(),
                                    "Root".to_string(),
                                ));
                            }
                        }
                    }
                }
                None
            }));
        }

        for t in tasks {
            if let Ok(Some(res)) = t.await {
                return Some(res);
            }
        }
        None
    }

    pub async fn sync_and_rank(&self) -> Result<usize, String> {
        let feed_url = std::env::var("UPSTREAM_DNS_CONFIG_URL")
            .or_else(|_| std::env::var("UPSTREAM_FEED_URL"))
            .unwrap_or_else(|_| DEFAULT_UPSTREAM_URL.to_string());

        let mut cfgs = Self::default_upstreams_config();

        match self
            .client
            .get(&feed_url)
            .timeout(Duration::from_millis(4000))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(payload) = resp.json::<UpstreamPayload>().await {
                    let fetched = match payload {
                        UpstreamPayload::Wrapped { dns_over_https } => dns_over_https,
                        UpstreamPayload::Direct(list) => list,
                    };
                    let valid_fetched: Vec<_> = fetched
                        .into_iter()
                        .filter(|c| c.url.starts_with("https://"))
                        .collect();
                    if !valid_fetched.is_empty() {
                        tracing::info!(
                            "[upstream] Loaded {} candidate upstreams from {}",
                            valid_fetched.len(),
                            feed_url
                        );
                        cfgs = valid_fetched;
                    }
                }
            }
            Ok(resp) => {
                tracing::warn!(
                    "[upstream] Upstream feed URL {} returned HTTP {}; using default fallback upstreams",
                    feed_url,
                    resp.status()
                );
            }
            Err(e) => {
                tracing::warn!(
                    "[upstream] Failed to fetch upstreams from {}: {}; using default fallback upstreams",
                    feed_url,
                    e
                );
            }
        }

        *self.candidates.write() = cfgs.clone();

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
                    provider: normalize_provider_name(&cfg.provider),
                    url: cfg.url,
                    aura: cfg.aura,
                    latency_ms: AtomicU32::new(latency),
                    errors: AtomicU64::new(if ok { 0 } else { 1 }),
                    pulls: AtomicU64::new(1),
                    successes: AtomicU64::new(if ok { 1 } else { 0 }),
                    consecutive_successes: AtomicU64::new(if ok { 1 } else { 0 }),
                    recent_latencies: parking_lot::RwLock::new(if ok {
                        VecDeque::from([latency])
                    } else {
                        VecDeque::new()
                    }),
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
        // 1. ok (healthy / reachable) first
        // 2. Lowest latency first (with priority aura breaking ties within 5ms bracket)
        probed.sort_by_key(|(ok, node)| {
            let lat = node.latency_ms.load(Ordering::Relaxed);
            let bucket = lat / 5;
            let aura = node.aura_rank();
            (!*ok, bucket, std::cmp::Reverse(aura), lat)
        });

        // Exactly 9 upstreams loaded at a time according to their priority & low latency
        let count = probed.len().min(9);

        let active_nodes: Vec<Arc<UpstreamNode>> = probed
            .into_iter()
            .take(count)
            .map(|(_, node)| Arc::new(node))
            .collect();

        let final_count = active_nodes.len();
        *self.upstreams.write() = active_nodes;
        self.recompute_ranks();
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

        // Automatically demote degraded resolvers and promote fastest healthy candidates
        let _ = self.demote_degraded_and_promote_best().await;

        // Recompute cached ranks so fastest resolvers are always ranked #1
        self.recompute_ranks();
    }

    /// Evaluates current active upstreams, demotes degraded ones (errors >= 3 or latency >= 500ms or eff_lat >= 350ms),
    /// and promotes the best responsive candidates from candidate probes to maintain the qualified top 9 pool.
    pub fn apply_candidate_promotions(
        &self,
        candidate_probes: Vec<(bool, u32, UpstreamConfig)>,
    ) -> (usize, usize) {
        let (degraded_info, current_nodes) = {
            let guard = self.upstreams.read();
            let mut degraded = Vec::new();
            for (idx, node) in guard.iter().enumerate() {
                if node.is_degraded() {
                    degraded.push((
                        idx,
                        node.provider.clone(),
                        node.url.clone(),
                        node.errors.load(Ordering::Relaxed),
                        node.effective_latency(),
                    ));
                }
            }
            (degraded, guard.clone())
        };

        if degraded_info.is_empty() && current_nodes.len() >= 9 {
            return (0, 0);
        }

        let active_urls: std::collections::HashSet<String> =
            current_nodes.iter().map(|n| n.url.clone()).collect();

        let mut valid_candidates: Vec<(u32, UpstreamConfig)> = candidate_probes
            .into_iter()
            .filter(|(ok, _, cfg)| *ok && !active_urls.contains(&cfg.url))
            .map(|(_, lat, cfg)| (lat, cfg))
            .collect();

        if valid_candidates.is_empty() {
            return (0, 0);
        }

        valid_candidates.sort_by_key(|(lat, cfg)| {
            let aura_rank = match cfg.aura.to_lowercase().as_str() {
                "high" => 3,
                "medium" => 2,
                _ => 1,
            };
            (*lat / 5, std::cmp::Reverse(aura_rank), *lat)
        });

        let mut new_active = current_nodes;
        let mut demoted_count = 0;
        let mut promoted_count = 0;
        let mut cand_iter = valid_candidates.into_iter();

        for (idx, deg_name, deg_url, deg_errs, deg_eff_lat) in degraded_info {
            if let Some((cand_lat, cand_cfg)) = cand_iter.next() {
                let promoted_node = Arc::new(UpstreamNode {
                    provider: normalize_provider_name(&cand_cfg.provider),
                    url: cand_cfg.url.clone(),
                    aura: cand_cfg.aura.clone(),
                    latency_ms: AtomicU32::new(cand_lat),
                    errors: AtomicU64::new(0),
                    pulls: AtomicU64::new(1),
                    successes: AtomicU64::new(1),
                    consecutive_successes: AtomicU64::new(1),
                    recent_latencies: parking_lot::RwLock::new(VecDeque::from([cand_lat])),
                });

                tracing::info!(
                    "[upstream] Auto-demoted degraded upstream '{}' ({}, errors: {}, eff_lat: {}ms); promoted new best candidate '{}' ({}, latency: {}ms)",
                    deg_name, deg_url, deg_errs, deg_eff_lat, promoted_node.provider, cand_cfg.url, cand_lat
                );

                if idx < new_active.len() {
                    new_active[idx] = promoted_node;
                    demoted_count += 1;
                    promoted_count += 1;
                }
            }
        }

        while new_active.len() < 9 {
            if let Some((cand_lat, cand_cfg)) = cand_iter.next() {
                let promoted_node = Arc::new(UpstreamNode {
                    provider: normalize_provider_name(&cand_cfg.provider),
                    url: cand_cfg.url.clone(),
                    aura: cand_cfg.aura.clone(),
                    latency_ms: AtomicU32::new(cand_lat),
                    errors: AtomicU64::new(0),
                    pulls: AtomicU64::new(1),
                    successes: AtomicU64::new(1),
                    consecutive_successes: AtomicU64::new(1),
                    recent_latencies: parking_lot::RwLock::new(VecDeque::from([cand_lat])),
                });

                tracing::info!(
                    "[upstream] Promoted additional candidate '{}' ({}, latency: {}ms) to maintain qualified 9",
                    promoted_node.provider, cand_cfg.url, cand_lat
                );

                new_active.push(promoted_node);
                promoted_count += 1;
            } else {
                break;
            }
        }

        if demoted_count > 0 || promoted_count > 0 {
            *self.upstreams.write() = new_active;
            self.recompute_ranks();
        }

        (demoted_count, promoted_count)
    }

    /// Checks if any active upstreams are degraded and, if so, dynamically probes candidate upstreams and swaps them.
    pub async fn demote_degraded_and_promote_best(&self) -> (usize, usize) {
        let needs_check = {
            let guard = self.upstreams.read();
            guard.len() < 9 || guard.iter().any(|n| n.is_degraded())
        };

        if !needs_check {
            return (0, 0);
        }

        let active_urls: std::collections::HashSet<String> = {
            let guard = self.upstreams.read();
            guard.iter().map(|n| n.url.clone()).collect()
        };

        let available_candidates: Vec<UpstreamConfig> = {
            let guard = self.candidates.read();
            guard
                .iter()
                .filter(|c| !active_urls.contains(&c.url))
                .cloned()
                .collect()
        };

        if available_candidates.is_empty() {
            return (0, 0);
        }

        const PROBE_PACKET: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\ncloudflare\x03com\x00\x00\x01\x00\x01";
        const PROBE_B64: &str = "EjQBAAABAAAAAAAACmNsb3VkZmxhcmUDY29tAAABAAE";

        let mut tasks = Vec::new();
        for cfg in available_candidates {
            let client = self.client.clone();
            tasks.push(tokio::spawn(async move {
                let start = Instant::now();
                let mut ok = false;
                let mut latency = 9999;

                let res = client
                    .post(&cfg.url)
                    .header("content-type", "application/dns-message")
                    .header("accept", "application/dns-message")
                    .timeout(Duration::from_millis(2000))
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
                        .timeout(Duration::from_millis(2000))
                        .send()
                        .await
                    {
                        if r.status().is_success() {
                            ok = true;
                            latency = start.elapsed().as_millis().max(1) as u32;
                        }
                    }
                }

                (ok, latency, cfg)
            }));
        }

        let mut probed = Vec::new();
        for t in tasks {
            if let Ok(res) = t.await {
                probed.push(res);
            }
        }

        self.apply_candidate_promotions(probed)
    }

    pub fn reset_cb(&self) {
        let guard = self.upstreams.read();
        for u in guard.iter() {
            u.errors.store(0, Ordering::Relaxed);
        }
    }

    pub fn in_flight_count(&self) -> usize {
        self.singleflight.in_flight_count()
    }

    pub fn coalesced_count(&self) -> u64 {
        self.singleflight.coalesced.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> Vec<serde_json::Value> {
        let guard = self.upstreams.read();
        guard
            .iter()
            .enumerate()
            .map(|(idx, u)| {
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
                let score = u.score();
                let healthy = !u.is_degraded() && (errs < 5 || (err_pct < 25.0 && lat < 1000));
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
            })
            .collect()
    }

    /// Fires queries to all healthy upstreams simultaneously and returns the first valid response.
    /// This is the "turbo fallback" for worst-case latency scenarios.
    pub async fn resolve_race(&self, query_wire: &[u8]) -> Option<(Vec<u8>, String)> {
        let nodes = self.ranked_nodes();
        let healthy_nodes: Vec<_> = nodes
            .into_iter()
            .filter(|n| n.errors.load(Ordering::Relaxed) < 10)
            .collect();

        if healthy_nodes.is_empty() {
            return self.resolve(query_wire).await;
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<(Vec<u8>, String)>(1);
        let client = self.client.clone();
        let wire_do = crate::dns::parser::ensure_edns0_do_bit(query_wire);

        for node in healthy_nodes {
            let tx = tx.clone();
            let wire = wire_do.clone();
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
        let res = rx.recv().await;
        if res.is_some() {
            self.hedged_wins.fetch_add(1, Ordering::Relaxed);
        }
        res
    }
}

fn to_base64_url(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let cap = (input.len() * 4).div_ceil(3);
    let mut out = String::with_capacity(cap);
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() {
            input[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < input.len() {
            input[i + 2] as u32
        } else {
            0
        };
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

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_singleflight_deduplication() {
        let sf = Singleflight::new();
        let sf = std::sync::Arc::new(sf);
        let mut handles = vec![];
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        for _ in 0..10 {
            let sf2 = sf.clone();
            let cc = call_count.clone();
            handles.push(tokio::spawn(async move {
                sf2.do_call("example.com:1", || {
                    let cc = cc.clone();
                    async move {
                        cc.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        Some((vec![0u8; 12], "Mock Provider".to_string()))
                    }
                })
                .await
            }));
        }
        let mut results = vec![];
        for h in handles {
            results.push(h.await.unwrap());
        }
        assert!(results.iter().all(|r| r.is_some()));
        let count = call_count.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            count <= 3,
            "Expected at most 3 upstream calls due to singleflight, got {}",
            count
        );
        let coalesced = sf.coalesced.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            coalesced >= 7,
            "Expected at least 7 coalesced calls, got {}",
            coalesced
        );
    }

    #[tokio::test]
    async fn test_singleflight_cancellation_safe() {
        let sf = std::sync::Arc::new(Singleflight::new());
        let sf_clone = sf.clone();

        // 1. Spawn a task that starts singleflight and gets cancelled halfway
        let handle = tokio::spawn(async move {
            sf_clone
                .do_call("cancelled.com:1", || async {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    Some((vec![1u8, 2, 3], "Mock Provider".to_string()))
                })
                .await
        });

        // Give it 10ms to start and register in_flight
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        // Abort / drop the task
        handle.abort();
        let _ = handle.await;

        // 2. Subsequent query for the same key must NOT deadlock or hang on a dead channel
        let result = sf
            .do_call("cancelled.com:1", || async {
                Some((vec![4u8, 5, 6], "Mock Provider".to_string()))
            })
            .await;

        assert_eq!(result, Some((vec![4u8, 5, 6], "Mock Provider".to_string())));
    }

    use super::*;

    #[test]
    fn test_to_base64_url() {
        assert_eq!(to_base64_url(b""), "");
        assert_eq!(to_base64_url(b"f"), "Zg");
        assert_eq!(to_base64_url(b"fo"), "Zm8");
        assert_eq!(to_base64_url(b"foo"), "Zm9v");
        assert_eq!(to_base64_url(b"foob"), "Zm9vYg");
        assert_eq!(to_base64_url(b"fooba"), "Zm9vYmE");
        assert_eq!(to_base64_url(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_upstream_node_metrics_and_healing() {
        let node = UpstreamNode::new(UpstreamConfig {
            provider: "TestProvider".to_string(),
            url: "https://test.local/dns-query".to_string(),
            aura: "high".to_string(),
        });

        assert_eq!(node.aura_rank(), 3);

        // Record error
        node.record_error();
        assert_eq!(node.errors.load(Ordering::Relaxed), 1);
        assert_eq!(node.consecutive_successes.load(Ordering::Relaxed), 0);

        // Record 2 consecutive successes -> heals 1 error
        node.record_success(20);
        node.record_success(30);
        assert_eq!(node.errors.load(Ordering::Relaxed), 0);
        assert_eq!(node.consecutive_successes.load(Ordering::Relaxed), 2);
        assert_eq!(node.successes.load(Ordering::Relaxed), 2);

        let (p50, p95, p99) = node.get_percentiles();
        assert!(p50 > 0 && p95 >= p50 && p99 >= p95);
    }

    #[test]
    fn test_default_upstreams_config() {
        let upstreams = UpstreamPool::default_upstreams_config();
        assert_eq!(upstreams.len(), 9);
        let providers: Vec<&str> = upstreams.iter().map(|u| u.provider.as_str()).collect();
        assert!(providers.contains(&"Cloudflare"));
        assert!(providers.contains(&"Mullvad"));
        assert!(providers.contains(&"Quad9"));
        assert!(providers.contains(&"AdGuard"));
        assert!(providers.contains(&"ControlD"));
    }

    #[test]
    fn test_upstream_priority_and_latency_ranking_9_cap() {
        let json = r#"{
            "dns_over_https": [
                {"provider": "SlowHigh", "url": "https://slow.high/dns-query", "aura": "high"},
                {"provider": "FastHigh", "url": "https://fast.high/dns-query", "aura": "high"},
                {"provider": "OfflineHigh", "url": "https://offline.high/dns-query", "aura": "high"},
                {"provider": "FastMedium", "url": "https://fast.med/dns-query", "aura": "medium"},
                {"provider": "SlowMedium", "url": "https://slow.med/dns-query", "aura": "medium"},
                {"provider": "FastLow", "url": "https://fast.low/dns-query", "aura": "low"},
                {"provider": "Med1", "url": "https://m1/dns-query", "aura": "medium"},
                {"provider": "Med2", "url": "https://m2/dns-query", "aura": "medium"},
                {"provider": "Med3", "url": "https://m3/dns-query", "aura": "medium"},
                {"provider": "Med4", "url": "https://m4/dns-query", "aura": "medium"},
                {"provider": "Med5", "url": "https://m5/dns-query", "aura": "medium"},
                {"provider": "Med6", "url": "https://m6/dns-query", "aura": "medium"}
            ]
        }"#;

        let payload: UpstreamPayload = serde_json::from_str(json).expect("valid json");
        let list = match payload {
            UpstreamPayload::Wrapped { dns_over_https } => dns_over_https,
            UpstreamPayload::Direct(l) => l,
        };
        assert_eq!(list.len(), 12);

        // Simulate probing
        let mut probed: Vec<(bool, UpstreamNode)> = list
            .into_iter()
            .map(|cfg| {
                let (ok, lat) = match cfg.provider.as_str() {
                    "OfflineHigh" => (false, 9999),
                    "SlowHigh" => (true, 50),
                    "FastHigh" => (true, 10),
                    "FastMedium" => (true, 5),
                    "SlowMedium" => (true, 60),
                    "FastLow" => (true, 2),
                    _ => (true, 20),
                };
                let node = UpstreamNode {
                    provider: cfg.provider,
                    url: cfg.url,
                    aura: cfg.aura,
                    latency_ms: AtomicU32::new(lat),
                    errors: AtomicU64::new(if ok { 0 } else { 1 }),
                    pulls: AtomicU64::new(1),
                    successes: AtomicU64::new(if ok { 1 } else { 0 }),
                    consecutive_successes: AtomicU64::new(if ok { 1 } else { 0 }),
                    recent_latencies: parking_lot::RwLock::new(VecDeque::new()),
                };
                (ok, node)
            })
            .collect();

        // Sort by health (ok), lowest latency first (with aura breaking ties within 5ms bracket)
        probed.sort_by_key(|(ok, node)| {
            let lat = node.latency_ms.load(Ordering::Relaxed);
            let bucket = lat / 5;
            let aura = node.aura_rank();
            (!*ok, bucket, std::cmp::Reverse(aura), lat)
        });

        // Take exactly 9
        let top9: Vec<_> = probed.into_iter().take(9).collect();
        assert_eq!(top9.len(), 9);

        // #1 must be FastLow (2ms) (bucket 0)
        assert_eq!(top9[0].1.provider, "FastLow");
        assert_eq!(top9[0].1.latency_ms.load(Ordering::Relaxed), 2);
        // #2 must be FastMedium (5ms) (bucket 1)
        assert_eq!(top9[1].1.provider, "FastMedium");
        assert_eq!(top9[1].1.latency_ms.load(Ordering::Relaxed), 5);
        // #3 must be FastHigh (10ms) (bucket 2)
        assert_eq!(top9[2].1.provider, "FastHigh");
        assert_eq!(top9[2].1.latency_ms.load(Ordering::Relaxed), 10);
        // OfflineHigh must NOT be in top9 because it's unreachable (ok=false)
        assert!(!top9.iter().any(|(_, n)| n.provider == "OfflineHigh"));
    }

    #[test]
    fn test_upstream_node_degraded_and_score() {
        let cfg = UpstreamConfig {
            provider: "TestProvider".to_string(),
            url: "https://test.upstream/dns-query".to_string(),
            aura: "high".to_string(),
        };
        let node = UpstreamNode::new(cfg);
        assert!(!node.is_degraded());
        assert_eq!(node.score(), 0); // initial latency is 0

        // Latency 20ms -> score 50 (1000 / 20 = 50)
        node.record_success(20);
        assert!(!node.is_degraded());
        assert_eq!(node.score(), 50);

        // Accumulate 3 errors -> is_degraded must become true
        node.record_error();
        node.record_error();
        node.record_error();
        assert!(node.is_degraded());

        // 5 errors -> score drops to 0
        node.record_error();
        node.record_error();
        assert_eq!(node.score(), 0);
    }

    #[test]
    fn test_upstream_demote_degraded_and_promote_candidate() {
        let pool = UpstreamPool::new();
        assert_eq!(pool.upstreams.read().len(), 9);

        // Give existing nodes baseline latency of 50ms
        {
            let guard = pool.upstreams.read();
            for n in guard.iter() {
                n.latency_ms.store(50, Ordering::Relaxed);
            }
        }
        pool.recompute_ranks();

        // Degrade one active upstream (e.g. node index 2)
        {
            let guard = pool.upstreams.read();
            let degraded_node = &guard[2];
            degraded_node.errors.store(5, Ordering::Relaxed);
            degraded_node.latency_ms.store(600, Ordering::Relaxed);
            assert!(degraded_node.is_degraded());
        }

        let degraded_url = {
            let guard = pool.upstreams.read();
            guard[2].url.clone()
        };

        // Candidate probe simulating a fast, responsive candidate
        let candidate_probes = vec![
            (
                true,
                15,
                UpstreamConfig {
                    provider: "FreshFastDNS".to_string(),
                    url: "https://fresh.fast/dns-query".to_string(),
                    aura: "high".to_string(),
                },
            ),
        ];

        let (demoted, promoted) = pool.apply_candidate_promotions(candidate_probes);
        assert_eq!(demoted, 1);
        assert_eq!(promoted, 1);

        // Verify pool size is still 9
        let current = pool.upstreams.read();
        assert_eq!(current.len(), 9);

        // Degraded URL must NO LONGER be present in the active pool
        assert!(!current.iter().any(|n| n.url == degraded_url));

        // Promoted candidate must now be present in the active pool
        let promoted_in_pool = current.iter().find(|n| n.url == "https://fresh.fast/dns-query");
        assert!(promoted_in_pool.is_some());
        let promoted_node = promoted_in_pool.unwrap();
        assert_eq!(promoted_node.latency_ms.load(Ordering::Relaxed), 15);
        assert_eq!(promoted_node.errors.load(Ordering::Relaxed), 0);

        // Ranked nodes should rank the fresh fast node (15ms) at the top above 50ms nodes
        let ranked = pool.ranked_nodes();
        assert_eq!(ranked.len(), 9);
        assert_eq!(ranked[0].url, "https://fresh.fast/dns-query");
    }
}
