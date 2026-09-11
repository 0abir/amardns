use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::SystemTime;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::Config;
use crate::dns::cache::DnsCache;
use crate::dns::upstream::UpstreamPool;
use crate::dns::passive_dns::PassiveDnsStore;
use crate::dns::ttl_learner::TtlLearner;
use crate::security::bloom::BloomFilter;
use crate::security::rate_limit::RateLimiter;
use crate::security::safe_browsing::SafeBrowsingClient;
use crate::security::schedule::ScheduleStore;
use crate::security::feed_manager::FeedManager;
use crate::storage::wal::WalStorage;
use crate::telemetry::metrics::Metrics;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionLog {
    pub t: u64,
    pub action: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnomalyLog {
    pub t: u64,
    #[serde(rename = "type")]
    pub anomaly_type: String,
    pub err: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockEntry {
    pub domain: String,
    pub reason: String,
    pub source: String,
    pub tag: String,
    pub auto: bool,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeatmapRecord {
    pub hourly: [u16; 24],
    pub total: u64,
    #[serde(rename = "lastSeen")]
    pub last_seen: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigDecision {
    pub t: u64,
    pub decision: String,
    pub profile: String,
    pub stress: f64,
    pub rps: f64,
    #[serde(rename = "userEst")]
    pub user_est: u32,
    pub changed: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryLog {
    pub id: u64,
    pub t: u64,
    pub domain: String,
    pub qtype: String,
    pub client: String,
    pub proto: String,
    pub status: String,
    pub rcode: u16,
    pub lat: u32,
    pub reason: String,
    pub upstream: String,
}

pub struct AppState {
    pub config: Config,
    pub threat_bloom: RwLock<BloomFilter>,
    pub whitelist_bloom: RwLock<BloomFilter>,
    pub whitelist_exact: RwLock<HashSet<String>>,
    pub whitelist_wildcards: RwLock<HashSet<String>>,
    pub fingerprint: crate::security::heuristics::ClientFingerprintTracker,
    pub custom_blocklist: RwLock<HashMap<String, BlockEntry>>,
    pub custom_whitelist: RwLock<HashSet<String>>,
    pub custom_common: RwLock<HashSet<String>>,
    pub cache: DnsCache,
    pub upstreams: UpstreamPool,
    pub rate_limiter: RateLimiter,
    pub metrics: Metrics,
    pub wal: WalStorage,
    pub safe_browsing: SafeBrowsingClient,
    pub blocking_enabled: AtomicBool,
    pub is_private_mode: AtomicBool,
    pub recent_actions: RwLock<Vec<ActionLog>>,
    pub recent_anomalies: RwLock<Vec<AnomalyLog>>,
    pub recent_queries: RwLock<Vec<QueryLog>>,
    pub next_log_id: AtomicU64,
    pub heatmap: RwLock<HashMap<String, HeatmapRecord>>,
    pub config_decisions: RwLock<Vec<ConfigDecision>>,
    pub brain: crate::security::ai::AIBrain,
    pub expected_threat_total: AtomicUsize,
    pub expected_whitelist_total: AtomicUsize,
    pub feed_overlap_count: AtomicUsize,
    pub fast_neg_filter: moka::sync::Cache<String, (&'static str, bool)>,
    // Feature 4: Passive DNS Timeline
    pub passive_dns: PassiveDnsStore,
    // Feature 5: Canary Domain Detection
    pub canary_domain: String,
    pub canary_hits: AtomicU64,
    // Feature 6: TTL Manipulation Guard
    pub ttl_guard_enabled: AtomicBool,
    // Feature 9: Scheduled Blocking
    pub schedule_store: ScheduleStore,
    // Feature 10: Blocklist Feed Subscriptions
    pub feed_manager: FeedManager,
    // Feature 13: Smart TTL Learning
    pub ttl_learner: TtlLearner,
    // Feature 8: Real-Time SSE Log Stream broadcaster
    pub log_broadcaster: tokio::sync::broadcast::Sender<String>,
}

impl AppState {
    #[allow(dead_code)]
    pub fn seed_default_common(common: &mut HashSet<String>, whitelist: &mut HashSet<String>) {
        let roots = [
            "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
            "cloudflare.com", "cloudflare-dns.com", "one.one.one.one",
            "apple.com", "icloud.com", "aaplimg.com", "mzstatic.com",
            "microsoft.com", "azure.com", "windows.net", "office.com", "live.com",
            "github.com", "githubusercontent.com", "github.io",
            "amazon.com", "amazonaws.com", "aws.amazon.com",
            "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com", "whatsapp.net",
            "youtube.com", "ytimg.com", "googlevideo.com",
            "netflix.com", "nflxvideo.net", "nflximg.net",
            "twitter.com", "x.com", "twimg.com",
            "wikipedia.org", "wikimedia.org",
            "akamaized.net", "fastly.net", "fly.dev", "fly.io", "jsdelivr.net",
            "bing.com", "msn.com", "yahoo.com", "duckduckgo.com"
        ];
        for r in roots {
            let s = r.to_string();
            common.insert(s.clone());
            whitelist.insert(s);
        }
    }
    pub fn new(config: Config) -> Self {
        let wal = WalStorage::new(&config.db_path);
        let (raw_blocklist, raw_whitelist, raw_common) = wal.load_lists();
        let is_private = config.access_mode_is_private();
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut custom_blocklist = HashMap::new();
        for domain in raw_blocklist {
            custom_blocklist.insert(
                domain.clone(),
                BlockEntry {
                    domain: domain.clone(),
                    reason: "manual".to_string(),
                    source: "manual".to_string(),
                    tag: "MANUAL".to_string(),
                    auto: false,
                    created_at: now,
                },
            );
        }

        let custom_whitelist = raw_whitelist;
        let custom_common = raw_common;
        let heatmap = HashMap::new();

        let initial_decisions = Vec::new();

        let initial_actions = vec![
            ActionLog {
                t: now,
                action: "system_boot".to_string(),
                reason: "Zero-GC Rust core initialized".to_string(),
            },
        ];

        let initial_anomalies = Vec::new();

        let initial_queries = Vec::new();

        let safe_browsing = SafeBrowsingClient::new(config.safe_browsing_keys.clone());

        Self {
            config,
            threat_bloom: RwLock::new(BloomFilter::for_threat_feed()),
            whitelist_bloom: RwLock::new(BloomFilter::for_whitelist()),
            whitelist_exact: RwLock::new(HashSet::new()),
            whitelist_wildcards: RwLock::new(HashSet::new()),
            fingerprint: crate::security::heuristics::ClientFingerprintTracker::new(),
            custom_blocklist: RwLock::new(custom_blocklist),
            custom_whitelist: RwLock::new(custom_whitelist),
            custom_common: RwLock::new(custom_common),
            cache: DnsCache::new(150_000), // 150k entries ≈ 70-100 MB — dynamic expansion, governed under 200 MB hard cap
            upstreams: UpstreamPool::new(),
            rate_limiter: RateLimiter::new(100.0, 50.0, 500.0, 200.0), // 100 capacity, 50/sec refill; 500 IP ceiling, 200/sec refill
            metrics: Metrics::new(),
            wal,
            safe_browsing,
            blocking_enabled: AtomicBool::new(true),
            is_private_mode: AtomicBool::new(is_private),
            recent_actions: RwLock::new(initial_actions),
            recent_anomalies: RwLock::new(initial_anomalies),
            recent_queries: RwLock::new(initial_queries),
            next_log_id: AtomicU64::new(1),
            heatmap: RwLock::new(heatmap),
            config_decisions: RwLock::new(initial_decisions),
            brain: crate::security::ai::AIBrain::new(),
            expected_threat_total: AtomicUsize::new(0),
            expected_whitelist_total: AtomicUsize::new(0),
            feed_overlap_count: AtomicUsize::new(0),
            fast_neg_filter: moka::sync::Cache::builder()
                .max_capacity(20_000)  // 20k fast negative-cache entries ≈ 4 MB
                .time_to_live(std::time::Duration::from_secs(60))
                .build(),
            passive_dns: PassiveDnsStore::new(),
            canary_domain: {
                // Generate a unique canary domain using boot timestamp + process ID
                let ts = SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                format!("canary-{:x}.amardns.internal", ts & 0xFFFFFFFF)
            },
            canary_hits: AtomicU64::new(0),
            ttl_guard_enabled: AtomicBool::new(true),
            schedule_store: ScheduleStore::new(),
            feed_manager: FeedManager::new(),
            ttl_learner: TtlLearner::new(),
            log_broadcaster: {
                let (tx, _) = tokio::sync::broadcast::channel(256);
                tx
            },
        }
    }

    pub fn log_action(&self, action: &str, reason: &str) {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let mut guard = self.recent_actions.write();
        guard.push(ActionLog {
            t: now,
            action: action.to_string(),
            reason: reason.to_string(),
        });
        // Cap at 100, drain to 60 when full
        if guard.len() > 100 {
            guard.drain(0..40);
        }
    }

    pub fn log_anomaly(&self, anomaly_type: &str, err: &str) {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let mut guard = self.recent_anomalies.write();
        guard.push(AnomalyLog {
            t: now,
            anomaly_type: anomaly_type.to_string(),
            err: err.to_string(),
        });
        // Cap at 100, drain to 60 when full
        if guard.len() > 100 {
            guard.drain(0..40);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn log_query(
        &self,
        domain: &str,
        qtype: u16,
        client: &str,
        proto: &str,
        status: &str,
        rcode: u16,
        lat_ms: u32,
        reason: &str,
        upstream: &str,
    ) {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let id = self.next_log_id.fetch_add(1, Ordering::Relaxed);
        let qtype_str = crate::dns::parser::qtype_to_str(qtype).to_string();
        let qtype_str_sse = qtype_str.clone(); // keep a copy for SSE broadcast
        let mut guard = self.recent_queries.write();
        guard.push(QueryLog {
            id,
            t: now,
            domain: domain.to_string(),
            qtype: qtype_str,
            client: client.to_string(),
            proto: proto.to_string(),
            status: status.to_string(),
            rcode,
            lat: lat_ms,
            reason: reason.to_string(),
            upstream: upstream.to_string(),
        });
        // Cap at 150 entries (~52 KB), drain to 75 when full
        if guard.len() > 150 {
            guard.drain(0..75);
        }
        // Feature 8: Broadcast to live SSE stream subscribers (non-blocking)
        if self.log_broadcaster.receiver_count() > 0 {
            let log_json = serde_json::json!({
                "id": id, "t": now, "domain": domain, "qtype": qtype_str_sse,
                "client": client, "proto": proto, "status": status,
                "rcode": rcode, "lat": lat_ms, "reason": reason, "upstream": upstream
            }).to_string();
            let _ = self.log_broadcaster.send(log_json);
        }
    }

    /// Checks whether a domain is blocked:
    /// Returns (is_blocked, is_nxdomain, block_reason)
    pub fn check_domain(&self, domain: &str) -> (bool, bool, &'static str) {
        if !self.blocking_enabled.load(Ordering::Relaxed) {
            return (false, false, "none");
        }

        let clean = domain.trim_end_matches('.').to_ascii_lowercase();

        // 1. Exact Whitelist (Absolute highest priority: Explicit domain whitelist always wins)
        if self.is_exact_whitelisted(&clean) {
            self.record_detected_whitelist(&clean);
            return (false, false, "whitelisted");
        }

        // 2. Fast-Path Negative Absorber (Intercepts repeating ad/telemetry bursts in <10µs)
        if let Some((reason, is_nx)) = self.fast_neg_filter.get(&clean) {
            self.metrics.threat_blocks.fetch_add(1, Ordering::Relaxed);
            self.metrics.fast_neg_hits.fetch_add(1, Ordering::Relaxed);
            return (true, is_nx, reason);
        }

        // 2b. Feature 9: Scheduled Blocking — time-based rules
        if let Some(_reason) = self.schedule_store.is_blocked_now(&clean) {
            self.metrics.threat_blocks.fetch_add(1, Ordering::Relaxed);
            self.metrics.schedule_blocks.fetch_add(1, Ordering::Relaxed);
            self.fast_neg_filter.insert(clean.clone(), ("schedule_block", false));
            return (true, false, "schedule_block");
        }

        // 3. Exact Block (Punches a hole right through wildcard whitelists!)
        if let Some(reason) = self.is_exact_blocked(&clean) {
            self.fast_neg_filter.insert(clean.clone(), (reason, true));
            self.metrics.threat_blocks.fetch_add(1, Ordering::Relaxed);
            self.record_detected_block(&clean, reason);
            self.log_action(if reason == "threat_feed_abir" { "feed_block" } else { "custom_block" }, &clean);
            return (true, true, reason);
        }

        // 4. Wildcard Whitelist (Protects all other subdomains under *.whitelist)
        if self.is_wildcard_whitelisted(&clean) {
            self.record_detected_whitelist(&clean);
            return (false, false, "whitelist_feed");
        }

        // 5. Custom Wildcard Blocklist (e.g. *.tiktok.com)
        if let Some(reason) = self.is_wildcard_custom_blocked(&clean) {
            self.fast_neg_filter.insert(clean.clone(), (reason, true));
            self.metrics.threat_blocks.fetch_add(1, Ordering::Relaxed);
            self.record_detected_block(&clean, reason);
            self.log_action("custom_block", &clean);
            return (true, true, reason);
        }

        // 6. Global Threat Feed Bloom Filter (Ultra-fast ~30ns check before running heavy heuristics!)
        if self.is_threat_bloom(&clean) {
            self.fast_neg_filter.insert(clean.clone(), ("threat_feed_abir", true));
            self.metrics.threat_blocks.fetch_add(1, Ordering::Relaxed);
            self.record_detected_block(&clean, "threat_feed_abir");
            self.log_action("feed_block", &clean);
            return (true, true, "threat_feed_abir");
        }

        // 7. Heuristic Lookalike & Typosquat Detection
        if crate::security::heuristics::is_lookalike_threat(&clean) {
            self.fast_neg_filter.insert(clean.clone(), ("lookalike_threat", true));
            self.metrics.alike_blocks.fetch_add(1, Ordering::Relaxed);
            self.brain.typo_blocks.fetch_add(1, Ordering::Relaxed);
            let (feats, ent) = self.brain.extract_features(&clean);
            self.brain.record_decision(
                &clean,
                ent,
                0.95,
                feats,
                "HARD_BLOCK",
                "typosquat_lookalike",
                "Prevented brand impersonation phishing trap; blocked before credential theft",
            );
            self.record_detected_block(&clean, "lookalike_threat");
            self.log_action("alike_domain_block", &clean);
            self.log_anomaly("lookalike_threat", &format!("Brand impersonation phishing: {}", clean));
            return (true, true, "lookalike_threat");
        }

        // 8. Heuristic DGA Malware Detection
        if crate::security::heuristics::is_dga_threat(&clean) {
            self.fast_neg_filter.insert(clean.clone(), ("dga_threat", true));
            self.metrics.dga_blocks.fetch_add(1, Ordering::Relaxed);
            self.brain.zero_day_blocks.fetch_add(1, Ordering::Relaxed);
            let (feats, ent) = self.brain.extract_features(&clean);
            self.brain.record_decision(
                &clean,
                ent,
                0.98,
                feats,
                "HARD_BLOCK",
                "dga_algorithmic_threat",
                "Intercepted Zero-Day algorithmic DGA domain (Entropy > 3.8); not in static lists",
            );
            self.record_detected_block(&clean, "dga_threat");
            self.log_action("dga_block", &clean);
            self.log_anomaly("dga_algorithmic_threat", &format!("DGA botnet signature (Entropy {:.2}): {}", ent, clean));
            return (true, true, "dga_threat");
        }

        // 9. Neural Brain Online Evaluation
        let (score, verdict) = self.brain.evaluate(&clean);
        if score > 0.90 {
            self.fast_neg_filter.insert(clean.clone(), (verdict, true));
            self.metrics.dga_blocks.fetch_add(1, Ordering::Relaxed);
            self.brain.zero_day_blocks.fetch_add(1, Ordering::Relaxed);
            let (feats, ent) = self.brain.extract_features(&clean);
            self.brain.record_decision(
                &clean,
                ent,
                score,
                feats,
                "HARD_BLOCK",
                verdict,
                "Classified malicious domain via 8-layer neural weights; autonomous zero-day shield",
            );
            self.record_detected_block(&clean, verdict);
            self.log_action("neural_brain_block", &clean);
            self.log_anomaly("neural_zero_day", &format!("Autonomous Zero-Day Shield ({:.0}% score): {}", score * 100.0, clean));
            return (true, true, verdict);
        }

        (false, false, "none")
    }

    /// Read-only check for domain blocking without mutating any counters or triggering decisions_made increments
    pub fn is_domain_blocked(&self, domain: &str) -> bool {
        if !self.blocking_enabled.load(Ordering::Relaxed) {
            return false;
        }

        let clean = domain.trim_end_matches('.').to_ascii_lowercase();

        // 1. Exact Whitelist
        if self.is_exact_whitelisted(&clean) {
            return false;
        }

        // 2. Fast-Path Negative Filter
        if self.fast_neg_filter.get(&clean).is_some() {
            return true;
        }

        // 3. Exact Block (Punches a hole through wildcard whitelists!)
        if self.is_exact_blocked(&clean).is_some() {
            return true;
        }

        // 4. Wildcard Whitelist
        if self.is_wildcard_whitelisted(&clean) {
            return false;
        }

        // 5. Custom Wildcard Block
        if self.is_wildcard_custom_blocked(&clean).is_some() {
            return true;
        }

        // 6. Global Threat Feed Bloom Filter
        if self.is_threat_bloom(&clean) {
            return true;
        }

        // 7. Heuristics
        if crate::security::heuristics::is_lookalike_threat(&clean) {
            return true;
        }

        if crate::security::heuristics::is_dga_threat(&clean) {
            return true;
        }

        let (score, _) = self.brain.evaluate_internal(&clean);
        if score > 0.90 {
            return true;
        }

        false
    }

    pub fn is_exempt(&self, domain: &str) -> bool {
        let clean = domain.trim_end_matches('.').to_ascii_lowercase();
        // 1. Exact whitelist always wins and is exempt
        if self.is_exact_whitelisted(&clean) {
            return true;
        }
        // 2. An exact block or threat feed revokes exemption (punches through wildcard whitelist)
        if self.is_exact_blocked(&clean).is_some() || self.is_threat_bloom(&clean) {
            return false;
        }
        // 3. Dynamic wildcard whitelist exempts subdomains
        self.is_wildcard_whitelisted(&clean)
    }

    pub fn is_exact_whitelisted(&self, domain: &str) -> bool {
        if self.whitelist_exact.read().contains(domain) {
            return true;
        }
        let guard_wl = self.custom_whitelist.read();
        if guard_wl.contains(domain) && !domain.contains('*') {
            return true;
        }
        let guard_cm = self.custom_common.read();
        if guard_cm.contains(domain) && !domain.contains('*') {
            return true;
        }
        false
    }

    pub fn is_exact_blocked(&self, domain: &str) -> Option<&'static str> {
        let is_wl_apex = self.whitelist_wildcards.read().contains(domain);

        let guard = self.custom_blocklist.read();
        if let Some(entry) = guard.get(domain) {
            if !entry.domain.contains('*') {
                return Some(Self::block_reason_tag(&entry.reason));
            }
        }
        if !is_wl_apex {
            let g_bloom = self.threat_bloom.read();
            if g_bloom.contains(domain) {
                return Some("threat_feed_abir");
            }
        }
        None
    }

    pub fn is_whitelist_wildcard(&self, domain: &str) -> bool {
        let guard = self.whitelist_wildcards.read();
        if guard.is_empty() {
            return false;
        }
        let wc_self = format!("*.{}", domain);
        if guard.contains(domain) || guard.contains(&wc_self) {
            return true;
        }
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            let wc = format!("*.{}", parent);
            if guard.contains(&parent) || guard.contains(&wc) {
                return true;
            }
        }
        for key in guard.iter() {
            if key.contains('*') && domain_matches_pattern(key, domain) {
                return true;
            }
        }
        false
    }

    pub fn is_whitelist_bloom(&self, domain: &str) -> bool {
        let guard = self.whitelist_bloom.read();
        if guard.contains(domain) || guard.contains(&format!("*.{}", domain)) {
            return true;
        }
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let suffix = parts[i..].join(".");
            if guard.contains(&suffix) || guard.contains(&format!("*.{}", suffix)) {
                return true;
            }
        }
        false
    }

    pub fn is_wildcard_whitelisted(&self, domain: &str) -> bool {
        self.is_whitelist_wildcard(domain)
            || self.is_custom_wildcard_whitelisted(domain)
            || self.is_whitelist_bloom(domain)
    }

    pub fn is_custom_wildcard_whitelisted(&self, domain: &str) -> bool {
        let guard_wl = self.custom_whitelist.read();
        let guard_cm = self.custom_common.read();
        if guard_wl.is_empty() && guard_cm.is_empty() {
            return false;
        }
        let wc_self = format!("*.{}", domain);
        if guard_wl.contains(&wc_self) || guard_cm.contains(&wc_self) {
            return true;
        }
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            let wc = format!("*.{}", parent);
            if guard_wl.contains(&parent)
                || guard_wl.contains(&wc)
                || guard_cm.contains(&parent)
                || guard_cm.contains(&wc)
            {
                return true;
            }
        }
        for key in guard_wl.iter().chain(guard_cm.iter()) {
            if key.contains('*') && domain_matches_pattern(key, domain) {
                return true;
            }
        }
        false
    }

    pub fn is_wildcard_custom_blocked(&self, domain: &str) -> Option<&'static str> {
        let guard = self.custom_blocklist.read();
        if guard.is_empty() {
            return None;
        }
        let wc_self = format!("*.{}", domain);
        if let Some(entry) = guard.get(&wc_self) {
            return Some(Self::block_reason_tag(&entry.reason));
        }
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if let Some(entry) = guard.get(&parent) {
                return Some(Self::block_reason_tag(&entry.reason));
            }
            let wc = format!("*.{}", parent);
            if let Some(entry) = guard.get(&wc) {
                return Some(Self::block_reason_tag(&entry.reason));
            }
        }
        for (key, entry) in guard.iter() {
            if key.contains('*') && domain_matches_pattern(key, domain) {
                return Some(Self::block_reason_tag(&entry.reason));
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn is_whitelisted(&self, domain: &str) -> bool {
        self.is_exact_whitelisted(domain) || self.is_wildcard_whitelisted(domain)
    }

    #[allow(dead_code)]
    pub fn is_custom_blocked(&self, domain: &str) -> Option<&'static str> {
        self.is_exact_blocked(domain).or_else(|| self.is_wildcard_custom_blocked(domain))
    }

    #[inline(always)]
    fn block_reason_tag(reason: &str) -> &'static str {
        match reason {
            "threat_feed_abir" => "threat_feed_abir",
            "dga_threat" => "dga_threat",
            "lookalike_threat" => "lookalike_threat",
            _ => "custom_block",
        }
    }

    fn is_threat_bloom(&self, domain: &str) -> bool {
        let guard = self.threat_bloom.read();
        if guard.contains(domain) {
            return true;
        }
        let wc_self = format!("*.{}", domain);
        if guard.contains(&wc_self) {
            return true;
        }
        // Zero-allocation zero-copy subdomain traversal
        let mut sub = domain;
        while let Some(idx) = sub.find('.') {
            sub = &sub[idx + 1..];
            if !sub.contains('.') {
                break; // Skip TLD
            }
            if guard.contains(sub) {
                return true;
            }
            let wc = format!("*.{}", sub);
            if guard.contains(&wc) {
                return true;
            }
        }
        false
    }

    pub fn record_detected_whitelist(&self, domain: &str) {
        let clean = domain.trim_end_matches('.').to_ascii_lowercase();
        if clean.is_empty() {
            return;
        }
        let mut guard = self.custom_whitelist.write();
        // Cap at 500 to prevent memory growth from auto-whitelisting
        if guard.len() < 500 && !guard.contains(&clean) {
            guard.insert(clean);
        }
    }

    pub fn record_heatmap(&self, domain: &str) {
        let clean = domain.trim_end_matches('.').to_ascii_lowercase();
        if clean.is_empty() {
            return;
        }
        self.brain.train(&clean, false, 0);
        self.brain.fp_suppressions.fetch_add(1, Ordering::Relaxed);
        let cycles = self.brain.training_cycles.load(Ordering::Relaxed);
        if self.brain.recent_decisions.read().len() < 30 || cycles.is_multiple_of(10) {
            let (feats, ent) = self.brain.extract_features(&clean);
            let (score, _) = self.brain.evaluate_internal(&clean);
            self.brain.record_decision(
                &clean,
                ent,
                score,
                feats,
                "ALLOW_SAFE",
                "reputation_reinforced",
                "Safe domain resolution rewarded; threat score reduced; 0ms local response",
            );
        }
        let now_sec = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let hour = ((now_sec / 3600) % 24) as usize;

        let mut guard = self.heatmap.write();
        // Cap heatmap at 1000 domains to limit memory usage; evict oldest if over
        if guard.len() >= 1000 && !guard.contains_key(&clean) {
            if let Some(first_key) = guard.keys().next().cloned() {
                guard.remove(&first_key);
            }
        }
        let entry = guard.entry(clean).or_insert_with(|| HeatmapRecord {
            hourly: [0; 24],
            total: 0,
            last_seen: now_sec * 1000,
        });
        entry.hourly[hour] = entry.hourly[hour].saturating_add(1);
        entry.total = entry.total.saturating_add(1);
        entry.last_seen = now_sec * 1000;
    }

    pub fn record_detected_block(&self, domain: &str, reason: &str) {
        let clean = domain.trim_end_matches('.').to_ascii_lowercase();
        if clean.is_empty() {
            return;
        }
        self.brain.train(&clean, true, 3);
        // Do not pollute local custom blocklist with external cloud GSB threats
        if reason.contains("safe_browsing") || reason.contains("gsb") {
            return;
        }
        let mut guard = self.custom_blocklist.write();
        // Cap auto-detected blocks at 500 to limit memory growth
        if guard.len() >= 500 && !guard.contains_key(&clean) {
            return;
        }
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let (tag, source, auto) = if reason.contains("dga") || reason.contains("lookalike") || reason.contains("ai") {
            ("AI", "ai", true)
        } else if reason.contains("feed") || reason.contains("gsb") || reason.contains("threat") {
            ("FEED", "feed", false)
        } else {
            ("MANUAL", "manual", false)
        };

        guard.entry(clean.clone()).or_insert_with(|| BlockEntry {
            domain: clean,
            reason: reason.to_string(),
            source: source.to_string(),
            tag: tag.to_string(),
            auto,
            created_at: now,
        });
    }

    /// Convenience wrapper for the DNS hot-path: checks the rate limiter with an optional
    /// device/client identity hint. Always returns `true` in the current implementation
    /// (AmarDNS never hard-blocks), but calling this instead of `rate_limiter.check` directly
    /// keeps a single call-site for future per-identity throttling.
    pub fn check_rate_limit(&self, ip: std::net::IpAddr, identity: Option<&str>) -> bool {
        self.rate_limiter.check_with_identity(ip, identity)
    }
}

/// Zero-allocation, non-backtracking glob wildcard matching (supports '*' and '?')
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p_bytes = pattern.as_bytes();
    let t_bytes = text.as_bytes();
    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_idx = None;
    let mut match_idx = 0;

    while t_idx < t_bytes.len() {
        if p_idx < p_bytes.len() && (p_bytes[p_idx] == b'?' || p_bytes[p_idx] == t_bytes[t_idx]) {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < p_bytes.len() && p_bytes[p_idx] == b'*' {
            star_idx = Some(p_idx);
            match_idx = t_idx;
            p_idx += 1;
        } else if let Some(star) = star_idx {
            p_idx = star + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            return false;
        }
    }

    while p_idx < p_bytes.len() && p_bytes[p_idx] == b'*' {
        p_idx += 1;
    }

    p_idx == p_bytes.len()
}

/// Matches a domain against an exact domain, an apex/subdomain rule (*.domain.tld or domain.tld), or a glob pattern
pub fn domain_matches_pattern(pattern: &str, domain: &str) -> bool {
    let clean_pat = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let clean_dom = domain.trim().trim_end_matches('.').to_ascii_lowercase();

    if clean_pat == clean_dom {
        return true;
    }

    // Pattern "*.root.tld": matches both root.tld AND any subdomain (e.g. sub.root.tld)
    if let Some(root) = clean_pat.strip_prefix("*.") {
        if clean_dom == root || clean_dom.ends_with(&format!(".{}", root)) {
            return true;
        }
    } else if let Some(root) = clean_pat.strip_prefix('*') {
        if clean_dom == root || clean_dom.ends_with(&format!(".{}", root)) {
            return true;
        }
    }

    // Plain rule without wildcard: "root.tld" also inherently covers all subdomains in DNS filters
    if !clean_pat.contains('*')
        && clean_dom.ends_with(&format!(".{}", clean_pat)) {
            return true;
        }

    // Arbitrary glob matching (*tracker*, *.ads.*, ad.*, *.xyz)
    if clean_pat.contains('*') {
        return wildcard_match(&clean_pat, &clean_dom);
    }

    false
}

/// Normalizes raw blocklist feed lines, stripping wildcards, protocols, comments, and IP prefixes.
pub fn normalize_blocklist_line(raw: &str) -> Option<String> {
    let mut h = raw.trim().to_ascii_lowercase();
    if h.is_empty() {
        return None;
    }
    let first = h.as_bytes()[0];
    if matches!(first, b'#' | b'!' | b'@' | b';' | b'/' | b'[' | b'$') {
        return None;
    }
    if h.starts_with("@@") {
        return None;
    }
    if h.starts_with("||") {
        h = h[2..].to_string();
    }
    if h.starts_with('|') {
        h = h[1..].to_string();
    }
    if h.starts_with("*.") {
        h = h[2..].to_string();
    } else if h.starts_with('*') {
        h = h[1..].to_string();
    }
    if let Some(idx) = h.find('$') {
        h = h[..idx].to_string();
    }
    if h.ends_with('^') {
        h = h[..h.len() - 1].to_string();
    }
    if h.starts_with("local=/") {
        h = h[7..].to_string();
    }
    if h.ends_with('/') {
        h = h[..h.len() - 1].to_string();
    }
    if let Some(idx) = h.find(|c: char| c.is_whitespace()) {
        let ip = &h[..idx];
        if ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::1" || ip == "::" {
            h = h[idx..].trim().to_string();
        } else {
            return None;
        }
    }
    h = h.trim_end_matches('.').trim().to_string();
    if h.is_empty() || !h.contains('.') || h.contains(' ') || h.contains('/') || h.starts_with('-') || h.len() > 253 {
        return None;
    }
    if h.chars().any(|c| !c.is_ascii_alphanumeric() && c != '.' && c != '-' && c != '_' && c != '*') {
        return None;
    }
    Some(h)
}

impl AppState {
    /// Loads remote threat feeds into memory Bloom filters and wildcard sets
    pub async fn sync_threat_feeds(&self) -> Result<(usize, usize), String> {
        let now_sec = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(45))
            .build()
            .map_err(|e| e.to_string())?;

        // Cache-busting timestamp query to guarantee freshest CDN updates
        let block_url = format!("https://cdn.jsdelivr.net/gh/abir614/-@latest/blocklist.txt?_t={}", now_sec);
        let white_url = format!("https://cdn.jsdelivr.net/gh/abir614/-@latest/whitelist.txt?_t={}", now_sec);
        let total_block_url = format!("https://cdn.jsdelivr.net/gh/abir614/-@latest/total_blocked.txt?_t={}", now_sec);
        let total_white_url = format!("https://cdn.jsdelivr.net/gh/abir614/-@latest/total_whitelisted.txt?_t={}", now_sec);

        let (b_res, w_res, tb_res, tw_res) = tokio::join!(
            client.get(&block_url).send(),
            client.get(&white_url).send(),
            client.get(&total_block_url).send(),
            client.get(&total_white_url).send()
        );

        let mut expected_block = 0;
        if let Ok(resp) = tb_res {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
                    if let Ok(val) = digits.parse::<usize>() {
                        expected_block = val;
                        self.expected_threat_total.store(val, Ordering::Relaxed);
                    }
                }
            }
        }

        let mut expected_white = 0;
        if let Ok(resp) = tw_res {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
                    if let Ok(val) = digits.parse::<usize>() {
                        expected_white = val;
                        self.expected_whitelist_total.store(val, Ordering::Relaxed);
                    }
                }
            }
        }

        let mut block_count = 0;
        let mut new_threat_bloom = BloomFilter::for_threat_feed();
        if let Ok(resp) = b_res {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    for line in text.lines() {
                        if let Some(clean) = normalize_blocklist_line(line) {
                            new_threat_bloom.insert(&clean);
                            block_count += 1;
                        }
                    }
                }
            }
        }

        let mut white_count = 0;
        let mut crossmatched_overlap = 0;
        let mut new_whitelist_bloom = BloomFilter::for_whitelist();
        let mut new_exact = std::collections::HashSet::new();
        let mut new_wildcards = std::collections::HashSet::new();
        if let Ok(resp) = w_res {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    for line in text.lines() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
                            continue;
                        }
                        let mut d = trimmed.to_ascii_lowercase();
                        let is_wild = if d.starts_with("*.") {
                            d = d[2..].to_string();
                            true
                        } else if d.starts_with('*') {
                            d = d[1..].to_string();
                            true
                        } else {
                            false
                        };
                        let clean = d.trim_end_matches('.').to_string();
                        if !clean.is_empty() && clean.contains('.') {
                            if new_threat_bloom.contains(&clean) {
                                crossmatched_overlap += 1;
                            }
                            if is_wild {
                                new_wildcards.insert(clean.clone());
                            } else {
                                new_exact.insert(clean.clone());
                            }
                            new_whitelist_bloom.insert(&clean);
                            white_count += 1;
                        }
                    }
                }
            }
        }

        // Atomically swap in both Bloom filters and hash sets
        *self.threat_bloom.write() = new_threat_bloom;
        *self.whitelist_bloom.write() = new_whitelist_bloom;
        *self.whitelist_exact.write() = new_exact;
        *self.whitelist_wildcards.write() = new_wildcards;

        if expected_block == 0 && block_count > 0 {
            self.expected_threat_total.store(block_count, Ordering::Relaxed);
        }
        if expected_white == 0 && white_count > 0 {
            self.expected_whitelist_total.store(white_count, Ordering::Relaxed);
        }
        self.feed_overlap_count.store(crossmatched_overlap, Ordering::Relaxed);

        info!(
            "[threat_feed] Feed sync & crossmatch completed: {}/{} blocked rules, {}/{} whitelist rules (crossmatched: {}, {} overlap prioritized)",
            block_count,
            self.expected_threat_total.load(Ordering::Relaxed),
            white_count,
            self.expected_whitelist_total.load(Ordering::Relaxed),
            block_count >= expected_block && white_count >= expected_white,
            crossmatched_overlap
        );

        Ok((block_count, white_count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_record_heatmap() {
        let config = Config::from_env();
        let state = AppState::new(config);
        state.record_heatmap("example.com.");
        let guard = state.heatmap.read();
        assert!(guard.contains_key("example.com"));
        let rec = guard.get("example.com").unwrap();
        assert!(rec.total >= 1);
        let sum: u16 = rec.hourly.iter().sum();
        assert!(sum >= 1);
    }

    #[tokio::test]
    async fn test_record_detected_block() {
        let config = Config::from_env();
        let state = AppState::new(config);
        state.record_detected_block("malware-test.ru", "threat_feed_abir");
        {
            let guard = state.custom_blocklist.read();
            assert!(guard.contains_key("malware-test.ru"));
            let entry = guard.get("malware-test.ru").unwrap();
            assert_eq!(entry.tag, "FEED");
            assert_eq!(entry.source, "feed");
        }

        state.record_detected_block("dga-xyz123.com", "dga_threat");
        {
            let guard = state.custom_blocklist.read();
            let entry_ai = guard.get("dga-xyz123.com").unwrap();
            assert_eq!(entry_ai.tag, "AI");
            assert_eq!(entry_ai.source, "ai");
            assert!(entry_ai.auto);
        }
    }

    #[tokio::test]
    async fn test_whitelist_wildcards_and_detection() {
        let config = Config::from_env();
        let state = AppState::new(config);
        state.whitelist_wildcards.write().insert("adguard.com".to_string());
        state.whitelist_bloom.write().insert("adguard.com");

        assert!(state.is_whitelist_wildcard("sub.adguard.com"));
        assert!(state.is_whitelist_wildcard("deep.sub.adguard.com"));

        let (blocked, _, reason) = state.check_domain("tracker.adguard.com");
        assert!(!blocked);
        assert_eq!(reason, "whitelist_feed");

        let wl = state.custom_whitelist.read();
        assert!(wl.contains("tracker.adguard.com"));
    }

    #[test]
    fn test_normalize_blocklist_line() {
        assert_eq!(normalize_blocklist_line("*.000webhost.com"), Some("000webhost.com".to_string()));
        assert_eq!(normalize_blocklist_line("||doubleclick.net^"), Some("doubleclick.net".to_string()));
        assert_eq!(normalize_blocklist_line("0.0.0.0 bad-domain.ru"), Some("bad-domain.ru".to_string()));
        assert_eq!(normalize_blocklist_line("# A comment"), None);
        assert_eq!(normalize_blocklist_line("@@whitelist-syntax"), None);
        assert_eq!(normalize_blocklist_line("! Another comment"), None);
        assert_eq!(normalize_blocklist_line("malware.com/path"), None);
    }

    #[tokio::test]
    async fn test_threat_feed_subdomain_blocking() {
        let config = Config::from_env();
        let state = AppState::new(config);

        // Normalize and insert into threat_bloom
        let clean = normalize_blocklist_line("*.000webhost.com").unwrap();
        state.threat_bloom.write().insert(&clean);

        // Both apex and subdomain must be blocked!
        let (blocked_apex, is_nx, reason) = state.check_domain("000webhost.com");
        assert!(blocked_apex);
        assert!(is_nx);
        assert_eq!(reason, "threat_feed_abir");

        let (blocked_sub, is_nx_sub, reason_sub) = state.check_domain("login.000webhost.com");
        assert!(blocked_sub);
        assert!(is_nx_sub);
        assert_eq!(reason_sub, "threat_feed_abir");

        // Whitelist prioritization test: Whitelist takes precedence over threat bloom!
        state.custom_whitelist.write().insert("login.000webhost.com".to_string());
        let (blocked_wl, _, reason_wl) = state.check_domain("login.000webhost.com");
        assert!(!blocked_wl, "Whitelisted domain must bypass threat feed bloom filter!");
        assert_eq!(reason_wl, "whitelisted");

        // Other subdomains and apex still blocked by bloom
        assert!(state.check_domain("000webhost.com").0);
        assert!(state.check_domain("admin.000webhost.com").0);

        // Whitelist bloom filter with subdomain check
        state.whitelist_bloom.write().insert("internal-service.net");
        assert!(!state.check_domain("internal-service.net").0);
        assert!(!state.check_domain("api.internal-service.net").0);
    }

    #[test]
    fn test_wildcard_matching_and_patterns() {
        // 1. Basic wildcard_match
        assert!(wildcard_match("*.google.com", "sub.google.com"));
        assert!(wildcard_match("*doubleclick*", "ad.doubleclick.net"));
        assert!(wildcard_match("*.xyz", "malware.xyz"));
        assert!(wildcard_match("ad.*", "ad.network.com"));
        assert!(!wildcard_match("*.google.com", "notgoogle.com"));

        // 2. domain_matches_pattern
        // *.root.tld matches both root apex and any subdomain
        assert!(domain_matches_pattern("*.doubleclick.net", "doubleclick.net"));
        assert!(domain_matches_pattern("*.doubleclick.net", "ad.doubleclick.net"));
        assert!(domain_matches_pattern("*.doubleclick.net", "sub.ad.doubleclick.net"));
        assert!(!domain_matches_pattern("*.doubleclick.net", "notdoubleclick.net"));

        // root.tld (without asterisk) inherently covers all its subdomains in DNS
        assert!(domain_matches_pattern("doubleclick.net", "doubleclick.net"));
        assert!(domain_matches_pattern("doubleclick.net", "ad.doubleclick.net"));
        assert!(domain_matches_pattern("doubleclick.net", "deep.ad.doubleclick.net"));
        assert!(!domain_matches_pattern("doubleclick.net", "notdoubleclick.net"));
    }

    #[tokio::test]
    async fn test_custom_wildcard_and_whitelist_prioritization() {
        let config = Config::from_env();
        let state = AppState::new(config);

        // Add *.tiktok.com to custom blocklist
        state.custom_blocklist.write().insert(
            "*.tiktok.com".to_string(),
            BlockEntry {
                domain: "*.tiktok.com".to_string(),
                reason: "custom_block".to_string(),
                source: "manual".to_string(),
                tag: "MANUAL".to_string(),
                auto: false,
                created_at: 0,
            },
        );

        // Both apex and subdomains of *.tiktok.com must be blocked!
        assert!(state.check_domain("tiktok.com").0);
        assert!(state.check_domain("v16.tiktok.com").0);
        assert!(state.check_domain("deep.sub.tiktok.com").0);
        assert!(!state.check_domain("nottiktok.com").0);

        // Add *.evil.com to custom blocklist
        state.custom_blocklist.write().insert(
            "*.evil.com".to_string(),
            BlockEntry {
                domain: "*.evil.com".to_string(),
                reason: "custom_block".to_string(),
                source: "manual".to_string(),
                tag: "MANUAL".to_string(),
                auto: false,
                created_at: 0,
            },
        );

        // Add good.evil.com to custom whitelist
        state.custom_whitelist.write().insert("good.evil.com".to_string());

        // Whitelist MUST take ultimate priority!
        let (blocked_good, _, reason_good) = state.check_domain("good.evil.com");
        assert!(!blocked_good, "Whitelisted child must be prioritized over wildcard block!");
        assert_eq!(reason_good, "whitelisted");

        // Other subdomains and apex of evil.com must remain blocked
        assert!(state.check_domain("evil.com").0);
        assert!(state.check_domain("bad.evil.com").0);
        assert!(state.check_domain("other.evil.com").0);

        // Add *.apple.com to custom whitelist
        state.custom_whitelist.write().insert("*.apple.com".to_string());
        assert!(!state.check_domain("apple.com").0);
        assert!(!state.check_domain("music.apple.com").0);
    }

    #[tokio::test]
    async fn test_cdn_total_parsing_and_crossmatching() {
        let config = Config::from_env();
        let state = AppState::new(config);

        // Test parsing CDN number formats (e.g. with underscores and newlines)
        let sample_blocked_raw = "900_333\n";
        let sample_white_raw = "2_818\n";
        let parsed_b: usize = sample_blocked_raw.chars().filter(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap();
        let parsed_w: usize = sample_white_raw.chars().filter(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap();
        assert_eq!(parsed_b, 900333);
        assert_eq!(parsed_w, 2818);

        state.expected_threat_total.store(parsed_b, Ordering::Relaxed);
        state.expected_whitelist_total.store(parsed_w, Ordering::Relaxed);

        assert_eq!(state.expected_threat_total.load(Ordering::Relaxed), 900333);
        assert_eq!(state.expected_whitelist_total.load(Ordering::Relaxed), 2818);

        // Test feed overlap crossmatching
        let mut threat_bloom = BloomFilter::for_threat_feed();
        threat_bloom.insert("telemetry.dropbox.com");
        threat_bloom.insert("ad.tracker.com");

        let mut wl_bloom = BloomFilter::for_whitelist();
        let mut overlap = 0;
        let wl_candidates = vec!["telemetry.dropbox.com", "api.github.com"];
        for domain in wl_candidates {
            if threat_bloom.contains(domain) {
                overlap += 1;
            }
            wl_bloom.insert(domain);
        }
        assert_eq!(overlap, 1);
        state.feed_overlap_count.store(overlap, Ordering::Relaxed);
        assert_eq!(state.feed_overlap_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_exact_block_punches_hole_through_wildcard_whitelist() {
        let config = Config::from_env();
        let state = AppState::new(config);

        // 1. Add *.apple.com to custom whitelist
        state.custom_whitelist.write().insert("*.apple.com".to_string());

        // Apex and general subdomains are allowed by wildcard whitelist
        assert!(!state.check_domain("apple.com").0);
        assert!(!state.check_domain("music.apple.com").0);

        // 2. Add specific exact subdomain analytics.apple.com to blocklist
        state.custom_blocklist.write().insert(
            "analytics.apple.com".to_string(),
            BlockEntry {
                domain: "analytics.apple.com".to_string(),
                reason: "telemetry_tracker".to_string(),
                source: "manual".to_string(),
                tag: "MANUAL".to_string(),
                auto: false,
                created_at: 0,
            },
        );

        // Exact block MUST punch a hole right through *.apple.com!
        let (blocked, _, reason) = state.check_domain("analytics.apple.com");
        assert!(blocked, "Exact block must punch through wildcard whitelist!");
        assert_eq!(reason, "custom_block");
        assert!(!state.is_exempt("analytics.apple.com"), "Exact blocked domain must not be exempt");
        assert!(state.is_domain_blocked("analytics.apple.com"), "Exact blocked domain must be domain blocked");

        // Other subdomains and apex under *.apple.com MUST remain allowed!
        assert!(!state.check_domain("apple.com").0);
        assert!(!state.check_domain("music.apple.com").0);
        assert!(!state.check_domain("icloud.apple.com").0);
        assert!(state.is_exempt("music.apple.com"), "Other subdomains under wildcard whitelist must be exempt");

        // 3. Threat bloom filter exact subdomain also punches hole through wildcard whitelist
        state.threat_bloom.write().insert("telemetry.apple.com");
        let (blocked_feed, _, reason_feed) = state.check_domain("telemetry.apple.com");
        assert!(blocked_feed, "Threat bloom exact subdomain must punch through wildcard whitelist!");
        assert_eq!(reason_feed, "threat_feed_abir");
        assert!(!state.is_exempt("telemetry.apple.com"));
        assert!(state.is_domain_blocked("telemetry.apple.com"));

        // Non-threat subdomain remains allowed
        assert!(!state.check_domain("store.apple.com").0);

        // 4. If analytics.apple.com is explicitly added to exact whitelist, it overrides the exact block!
        state.custom_whitelist.write().insert("analytics.apple.com".to_string());
        let (blocked_now, _, reason_now) = state.check_domain("analytics.apple.com");
        assert!(!blocked_now, "Exact whitelist must override exact block!");
        assert_eq!(reason_now, "whitelisted");
        assert!(state.is_exempt("analytics.apple.com"));
        assert!(!state.is_domain_blocked("analytics.apple.com"));
    }
}
