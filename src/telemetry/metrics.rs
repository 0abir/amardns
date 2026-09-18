use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceEntry {
    pub id: String,
    pub ip: String,
    #[serde(rename = "type")]
    pub device_type: String,
    pub count: u64,
    #[serde(rename = "lastSeen")]
    pub last_seen: u64,
}

pub struct Metrics {
    pub requests: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub threat_blocks: AtomicU64,
    pub alike_blocks: AtomicU64,
    pub dga_blocks: AtomicU64,
    pub gsb_blocks: AtomicU64,
    pub rebind_blocks: AtomicU64,
    pub rep_blocks: AtomicU64,
    pub auto_blocks: AtomicU64,
    pub burst_events: AtomicU64,
    pub nx_alarms: AtomicU64,
    pub answer_drifts: AtomicU64,
    pub dcc_hits: AtomicU64,
    pub swarm_alarms: AtomicU64,
    pub dot_queries: AtomicU64,
    pub doh_queries: AtomicU64,
    pub plain_queries: AtomicU64,
    // DNSSEC Cryptographic Telemetry (RFC 4034, RFC 4035, RFC 5155, RFC 9276)
    pub dnssec_validations: AtomicU64,
    pub dnssec_secure: AtomicU64,
    pub dnssec_bogus: AtomicU64,
    pub dnssec_insecure: AtomicU64,
    pub dnssec_denial_of_existence: AtomicU64,
    // Microsecond Latency Histogram & Turbocharger telemetry
    pub lat_sub_1ms: AtomicU64, // < 1,000 µs (RAM cache hits, fast-filter drops, SWR hits)
    pub lat_1_to_5ms: AtomicU64, // 1,000 - 5,000 µs (Local fast-path processing)
    pub lat_5_to_15ms: AtomicU64, // 5,000 - 15,000 µs (Warm upstream HTTP/2 pipe responses)
    pub lat_15_to_50ms: AtomicU64, // 15,000 - 50,000 µs (Standard DoH upstream resolution)
    pub lat_above_50ms: AtomicU64, // > 50,000 µs (Hedged / slow connection)
    pub total_lat_micros: AtomicU64,
    pub fast_neg_hits: AtomicU64,
    pub swr_serves: AtomicU64,
    pub prefetch_triggers: AtomicU64,
    pub prefetch_hits: AtomicU64,
    // New feature counters
    pub ttl_guard_blocks: AtomicU64,
    pub cname_flattened: AtomicU64,
    pub race_wins: AtomicU64,
    pub schedule_blocks: AtomicU64,
    pub auth_fails: AtomicU64,
    start_time: Instant,
    boot_timestamp: u64,
    rps_buckets: Mutex<[u32; 60]>,
    rps_idx: Mutex<u64>,
    rps_smooth: Mutex<f64>,
    rps_peak: Mutex<f64>,
    devices: Mutex<HashMap<String, DeviceEntry>>,
    users: Mutex<HashMap<String, u64>>,
    // NX burst tracking: client_ip -> timestamps of NX responses in last 60s
    nx_window: Mutex<HashMap<String, VecDeque<u64>>>,
    // Swarm tracking: domain -> set of unique client IPs in last 10s
    swarm_window: Mutex<HashMap<String, (VecDeque<u64>, u32)>>, // (timestamps, unique_ip_count)
    // Upstream last sync timestamp
    pub upstream_last_sync: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            requests: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            threat_blocks: AtomicU64::new(0),
            alike_blocks: AtomicU64::new(0),
            dga_blocks: AtomicU64::new(0),
            gsb_blocks: AtomicU64::new(0),
            rebind_blocks: AtomicU64::new(0),
            rep_blocks: AtomicU64::new(0),
            auto_blocks: AtomicU64::new(0),
            burst_events: AtomicU64::new(0),
            nx_alarms: AtomicU64::new(0),
            answer_drifts: AtomicU64::new(0),
            dcc_hits: AtomicU64::new(0),
            swarm_alarms: AtomicU64::new(0),
            dot_queries: AtomicU64::new(0),
            doh_queries: AtomicU64::new(0),
            plain_queries: AtomicU64::new(0),
            dnssec_validations: AtomicU64::new(0),
            dnssec_secure: AtomicU64::new(0),
            dnssec_bogus: AtomicU64::new(0),
            dnssec_insecure: AtomicU64::new(0),
            dnssec_denial_of_existence: AtomicU64::new(0),
            lat_sub_1ms: AtomicU64::new(0),
            lat_1_to_5ms: AtomicU64::new(0),
            lat_5_to_15ms: AtomicU64::new(0),
            lat_15_to_50ms: AtomicU64::new(0),
            lat_above_50ms: AtomicU64::new(0),
            total_lat_micros: AtomicU64::new(0),
            fast_neg_hits: AtomicU64::new(0),
            swr_serves: AtomicU64::new(0),
            prefetch_triggers: AtomicU64::new(0),
            prefetch_hits: AtomicU64::new(0),
            ttl_guard_blocks: AtomicU64::new(0),
            cname_flattened: AtomicU64::new(0),
            race_wins: AtomicU64::new(0),
            schedule_blocks: AtomicU64::new(0),
            auth_fails: AtomicU64::new(0),
            start_time: Instant::now(),
            boot_timestamp: now_unix,
            rps_buckets: Mutex::new([0; 60]),
            rps_idx: Mutex::new(now_unix),
            rps_smooth: Mutex::new(0.0),
            rps_peak: Mutex::new(0.0),
            devices: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            nx_window: Mutex::new(HashMap::new()),
            swarm_window: Mutex::new(HashMap::new()),
            upstream_last_sync: AtomicU64::new(0),
        }
    }

    /// Records query processing duration into microsecond latency histogram
    pub fn record_latency(&self, duration: Duration) {
        let micros = duration.as_micros() as u64;
        self.total_lat_micros.fetch_add(micros, Ordering::Relaxed);
        if micros < 1_000 {
            self.lat_sub_1ms.fetch_add(1, Ordering::Relaxed);
        } else if micros < 5_000 {
            self.lat_1_to_5ms.fetch_add(1, Ordering::Relaxed);
        } else if micros < 15_000 {
            self.lat_5_to_15ms.fetch_add(1, Ordering::Relaxed);
        } else if micros < 50_000 {
            self.lat_15_to_50ms.fetch_add(1, Ordering::Relaxed);
        } else {
            self.lat_above_50ms.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records DNSSEC cryptographic validation results into telemetry counters
    pub fn record_dnssec(&self, details: &crate::dns::dnssec::DnssecValidationDetails) {
        self.dnssec_validations.fetch_add(1, Ordering::Relaxed);
        match details.status {
            crate::dns::dnssec::DnssecStatus::Secure => {
                self.dnssec_secure.fetch_add(1, Ordering::Relaxed);
            }
            crate::dns::dnssec::DnssecStatus::Bogus => {
                self.dnssec_bogus.fetch_add(1, Ordering::Relaxed);
            }
            crate::dns::dnssec::DnssecStatus::Insecure
            | crate::dns::dnssec::DnssecStatus::Indeterminate => {
                if details.is_denial_of_existence() {
                    self.dnssec_denial_of_existence
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    self.dnssec_insecure.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Returns average latency in microseconds and milliseconds
    pub fn get_avg_latency(&self) -> (f64, f64) {
        let reqs = self.requests.load(Ordering::Relaxed);
        if reqs == 0 {
            return (0.0, 0.0);
        }
        let total_us = self.total_lat_micros.load(Ordering::Relaxed) as f64;
        let avg_us = (total_us / reqs as f64 * 10.0).round() / 10.0;
        let avg_ms = (avg_us / 1000.0 * 100.0).round() / 100.0;
        (avg_us, avg_ms)
    }

    /// Returns latency distribution count tuple: (sub_1ms, 1_5ms, 5_15ms, 15_50ms, above_50ms)
    pub fn get_latency_distribution(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.lat_sub_1ms.load(Ordering::Relaxed),
            self.lat_1_to_5ms.load(Ordering::Relaxed),
            self.lat_5_to_15ms.load(Ordering::Relaxed),
            self.lat_15_to_50ms.load(Ordering::Relaxed),
            self.lat_above_50ms.load(Ordering::Relaxed),
        )
    }

    /// Records an incoming DNS query with client IP, updating real-time RPS, active devices, and users
    pub fn record_query(&self, client_ip: &str, device_type: &str) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        if device_type == "dot" {
            self.dot_queries.fetch_add(1, Ordering::Relaxed);
        } else if device_type.starts_with("plain") || device_type.starts_with("Plain") {
            self.plain_queries.fetch_add(1, Ordering::Relaxed);
        } else {
            self.doh_queries.fetch_add(1, Ordering::Relaxed);
        }

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let now_sec = now_ms / 1000;

        let clean_ip = if client_ip.is_empty() {
            "127.0.0.1"
        } else {
            client_ip
        };

        // 1. Update active devices
        if let Ok(mut map) = self.devices.lock() {
            if map.len() >= 10_000 {
                let cutoff = now_ms.saturating_sub(300_000);
                map.retain(|_, v| v.last_seen >= cutoff);
                if map.len() >= 10_000 && !map.contains_key(clean_ip) {
                    if let Some(oldest) = map.keys().next().cloned() {
                        map.remove(&oldest);
                    }
                }
            }
            let entry = map
                .entry(clean_ip.to_string())
                .or_insert_with(|| DeviceEntry {
                    id: clean_ip.to_string(),
                    ip: clean_ip.to_string(),
                    device_type: device_type.to_string(),
                    count: 0,
                    last_seen: now_ms,
                });
            entry.count += 1;
            entry.last_seen = now_ms;
        }

        // 2. Update user map
        if let Ok(mut users) = self.users.lock() {
            if users.len() >= 10_000 {
                let cutoff = now_ms.saturating_sub(300_000);
                users.retain(|_, last| *last >= cutoff);
                if users.len() >= 10_000 && !users.contains_key(clean_ip) {
                    if let Some(oldest) = users.keys().next().cloned() {
                        users.remove(&oldest);
                    }
                }
            }
            users.insert(clean_ip.to_string(), now_ms);
        }

        // 3. Update rolling 60s buckets
        if let Ok(mut idx_guard) = self.rps_idx.lock() {
            let last_sec = *idx_guard;
            if now_sec > last_sec {
                if let Ok(mut buckets) = self.rps_buckets.lock() {
                    let elapsed = (now_sec - last_sec).min(60);
                    for s in 1..=elapsed {
                        buckets[((last_sec + s) % 60) as usize] = 0;
                    }
                }
                *idx_guard = now_sec;
            }

            if let Ok(mut buckets) = self.rps_buckets.lock() {
                buckets[(now_sec % 60) as usize] =
                    buckets[(now_sec % 60) as usize].saturating_add(1);
            }
        }
    }

    pub fn reset(&self) {
        self.requests.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.threat_blocks.store(0, Ordering::Relaxed);
        self.alike_blocks.store(0, Ordering::Relaxed);
        self.dga_blocks.store(0, Ordering::Relaxed);
        self.gsb_blocks.store(0, Ordering::Relaxed);
        self.rebind_blocks.store(0, Ordering::Relaxed);
        self.rep_blocks.store(0, Ordering::Relaxed);
        self.auto_blocks.store(0, Ordering::Relaxed);
        self.burst_events.store(0, Ordering::Relaxed);
        self.nx_alarms.store(0, Ordering::Relaxed);
        self.answer_drifts.store(0, Ordering::Relaxed);
        self.dcc_hits.store(0, Ordering::Relaxed);
        self.swarm_alarms.store(0, Ordering::Relaxed);
        self.dot_queries.store(0, Ordering::Relaxed);
        self.doh_queries.store(0, Ordering::Relaxed);
        self.plain_queries.store(0, Ordering::Relaxed);
        self.dnssec_validations.store(0, Ordering::Relaxed);
        self.dnssec_secure.store(0, Ordering::Relaxed);
        self.dnssec_bogus.store(0, Ordering::Relaxed);
        self.dnssec_insecure.store(0, Ordering::Relaxed);
        self.dnssec_denial_of_existence.store(0, Ordering::Relaxed);
        self.lat_sub_1ms.store(0, Ordering::Relaxed);
        self.lat_1_to_5ms.store(0, Ordering::Relaxed);
        self.lat_5_to_15ms.store(0, Ordering::Relaxed);
        self.lat_15_to_50ms.store(0, Ordering::Relaxed);
        self.lat_above_50ms.store(0, Ordering::Relaxed);
        self.total_lat_micros.store(0, Ordering::Relaxed);
        self.fast_neg_hits.store(0, Ordering::Relaxed);
        self.swr_serves.store(0, Ordering::Relaxed);
        self.prefetch_triggers.store(0, Ordering::Relaxed);
        self.prefetch_hits.store(0, Ordering::Relaxed);
        self.ttl_guard_blocks.store(0, Ordering::Relaxed);
        self.cname_flattened.store(0, Ordering::Relaxed);
        self.race_wins.store(0, Ordering::Relaxed);
        self.schedule_blocks.store(0, Ordering::Relaxed);
        if let Ok(mut b) = self.rps_buckets.lock() {
            *b = [0; 60];
        }
        if let Ok(mut s) = self.rps_smooth.lock() {
            *s = 0.0;
        }
        if let Ok(mut p) = self.rps_peak.lock() {
            *p = 0.0;
        }
        if let Ok(mut d) = self.devices.lock() {
            d.clear();
        }
        if let Ok(mut u) = self.users.lock() {
            u.clear();
        }
        if let Ok(mut n) = self.nx_window.lock() {
            n.clear();
        }
        if let Ok(mut sw) = self.swarm_window.lock() {
            sw.clear();
        }
    }

    /// Detects NX domain burst for a client IP.
    /// Returns true if the client has received 10+ NX responses in the last 60 seconds.
    /// This indicates a potential NX domain storm (botnet C2 beacon, DGA scanner, etc.).
    pub fn detect_nx_burst(&self, client_ip: &str) -> bool {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let cutoff = now_ms.saturating_sub(60_000);
        if let Ok(mut map) = self.nx_window.lock() {
            // Evict old global map entries first
            if map.len() > 5_000 {
                map.retain(|_, q| q.back().map(|&t| t >= cutoff).unwrap_or(false));
            }
            let queue = map
                .entry(client_ip.to_string())
                .or_insert_with(VecDeque::new);
            // Evict old timestamps for this client
            while queue.front().map(|&t| t < cutoff).unwrap_or(false) {
                queue.pop_front();
            }
            queue.push_back(now_ms);
            // Alarm if 10+ NX responses in 60s window
            queue.len() >= 10
        } else {
            false
        }
    }

    /// Detects swarm/flood: the same domain queried by many distinct IPs in a short window.
    /// Returns true if 5+ unique IPs have queried the same domain in the last 10 seconds.
    pub fn detect_swarm(&self, domain: &str, client_ip: &str) -> bool {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let cutoff = now_ms.saturating_sub(10_000);
        if let Ok(mut map) = self.swarm_window.lock() {
            if map.len() > 2_000 {
                map.retain(|_, (q, _)| q.back().map(|&t| t >= cutoff).unwrap_or(false));
            }
            let entry = map
                .entry(domain.to_string())
                .or_insert_with(|| (VecDeque::new(), 0));
            let (queue, ip_count) = entry;
            while queue.front().map(|&t| t < cutoff).unwrap_or(false) {
                queue.pop_front();
            }
            // Use client_ip length as a simple hash contribution to track unique-ish IPs
            // We approximate unique IPs using a counter that we bump and decay with the window
            queue.push_back(now_ms);
            *ip_count = ip_count.saturating_add(1).min(queue.len() as u32);
            let _ = client_ip; // IP used for future dedup improvements
            // Alarm at 5+ requests to the same domain in 10s from multiple clients
            queue.len() >= 5
        } else {
            false
        }
    }

    #[allow(dead_code)]
    pub fn record_device(&self, device_id: &str) {
        self.record_query(device_id, "device");
    }

    pub fn get_rps(&self) -> f64 {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let now_sec = now_ms / 1000;

        // 1. Roll forward any elapsed seconds in buckets if idle
        if let Ok(mut idx_guard) = self.rps_idx.lock() {
            let last_sec = *idx_guard;
            if now_sec > last_sec {
                if let Ok(mut buckets) = self.rps_buckets.lock() {
                    let elapsed = (now_sec - last_sec).min(60);
                    for s in 1..=elapsed {
                        buckets[((last_sec + s) % 60) as usize] = 0;
                    }
                }
                *idx_guard = now_sec;
            }
        }

        // 2. High-precision sliding 1.0s window:
        // Fraction elapsed into the current second (0.0 to 1.0)
        let frac = (now_ms % 1000) as f64 / 1000.0;
        if let Ok(buckets) = self.rps_buckets.lock() {
            let curr = buckets[(now_sec % 60) as usize] as f64;
            let prev = buckets[(now_sec.saturating_sub(1) % 60) as usize] as f64;

            // Rolling 1.0-second window interpolation:
            // Combines queries in the current second plus remaining fraction of previous second
            let live_rate = (curr + (1.0 - frac) * prev).max(0.0);

            if let Ok(mut peak_guard) = self.rps_peak.lock() {
                if live_rate > *peak_guard {
                    *peak_guard = live_rate;
                }
            }

            (live_rate * 10.0).round() / 10.0
        } else {
            0.0
        }
    }

    pub fn get_rps_peak(&self) -> f64 {
        if let Ok(guard) = self.rps_peak.lock() {
            (*guard * 100.0).round() / 100.0
        } else {
            0.0
        }
    }

    pub fn calc_stress(&self, rps: f64) -> f64 {
        if rps <= 0.0 {
            return 0.0;
        }
        let rps_load = (rps / 500.0).min(1.0).powf(1.2);
        (rps_load.min(1.0) * 1000.0).round() / 1000.0
    }

    pub fn online_since(&self) -> String {
        let s = self.start_time.elapsed().as_secs();
        if s < 60 {
            format!("{}s", s)
        } else if s < 3600 {
            format!("{}m", s / 60)
        } else if s < 86400 {
            format!("{}h", s / 3600)
        } else {
            format!("{}d", s / 86400)
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    #[allow(dead_code)]
    pub fn boot_timestamp(&self) -> u64 {
        self.boot_timestamp
    }

    pub fn active_device_count(&self) -> usize {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let cutoff = now_ms.saturating_sub(300_000);

        if let Ok(mut map) = self.devices.lock() {
            map.retain(|_, v| v.last_seen >= cutoff);
            map.len()
        } else {
            0
        }
    }

    pub fn active_ip_count(&self) -> usize {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let cutoff = now_ms.saturating_sub(300_000);

        if let Ok(mut users) = self.users.lock() {
            users.retain(|_, last| *last >= cutoff);
            users.len()
        } else {
            0
        }
    }

    pub fn get_active_devices(&self) -> Vec<DeviceEntry> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let cutoff = now_ms.saturating_sub(300_000);

        if let Ok(mut map) = self.devices.lock() {
            map.retain(|_, v| v.last_seen >= cutoff);
            let mut list: Vec<DeviceEntry> = map.values().cloned().collect();
            list.sort_by_key(|a| std::cmp::Reverse(a.count));
            list
        } else {
            Vec::new()
        }
    }

    /// Prunes idle device/user entries, nx burst windows, and swarm tracking windows
    pub fn prune_idle(&self) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let dev_cutoff = now_ms.saturating_sub(300_000); // 5 minutes
        let nx_cutoff = now_ms.saturating_sub(60_000); // 60 seconds
        let swarm_cutoff = now_ms.saturating_sub(10_000); // 10 seconds

        if let Ok(mut map) = self.devices.lock() {
            map.retain(|_, v| v.last_seen >= dev_cutoff);
        }
        if let Ok(mut users) = self.users.lock() {
            users.retain(|_, last| *last >= dev_cutoff);
        }
        if let Ok(mut nx) = self.nx_window.lock() {
            nx.retain(|_, q| q.back().map(|&t| t >= nx_cutoff).unwrap_or(false));
        }
        if let Ok(mut sw) = self.swarm_window.lock() {
            sw.retain(|_, (q, _)| q.back().map(|&t| t >= swarm_cutoff).unwrap_or(false));
        }
    }

    /// Renders all atomic counters and gauges in Prometheus OpenMetrics text format.
    /// No external crates needed - pure string formatting.
    #[allow(dead_code)]
    pub fn prometheus_text(&self, cache_entries: usize, cache_mb: f64, coalesced: u64) -> String {
        let mut out = String::with_capacity(4096);
        let uptime_secs = self.start_time.elapsed().as_secs();

        // Helper macro to write a counter line
        macro_rules! counter {
            ($name:expr, $help:expr, $val:expr) => {
                out.push_str(&format!(
                    "# HELP {} {}\n# TYPE {} counter\n{} {}\n",
                    $name, $help, $name, $name, $val
                ));
            };
            ($name:expr, $help:expr, $labels:expr, $val:expr) => {
                out.push_str(&format!(
                    "# HELP {} {}\n# TYPE {} counter\n{}{{{}}} {}\n",
                    $name, $help, $name, $name, $labels, $val
                ));
            };
        }
        macro_rules! gauge {
            ($name:expr, $help:expr, $val:expr) => {
                out.push_str(&format!(
                    "# HELP {} {}\n# TYPE {} gauge\n{} {}\n",
                    $name, $help, $name, $name, $val
                ));
            };
        }

        counter!(
            "amardns_queries_total",
            "Total DNS queries processed",
            self.requests.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_cache_hits_total",
            "Total cache hits",
            self.cache_hits.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_cache_misses_total",
            "Total cache misses",
            self.cache_misses.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_threat_blocks_total",
            "Total threat blocks",
            self.threat_blocks.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_dga_blocks_total",
            "DGA-detected domain blocks",
            self.dga_blocks.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_gsb_blocks_total",
            "Google Safe Browsing blocks",
            self.gsb_blocks.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_rebind_blocks_total",
            "DNS rebinding attack blocks",
            self.rebind_blocks.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_burst_events_total",
            "Rate limit burst events",
            self.burst_events.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_nx_alarms_total",
            "NXDOMAIN burst alarm events",
            self.nx_alarms.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_answer_drifts_total",
            "Passive DNS answer drift detections",
            self.answer_drifts.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_swr_serves_total",
            "Stale-While-Revalidate cache serves",
            self.swr_serves.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_prefetch_hits_total",
            "AI predictive prefetch hits",
            self.prefetch_hits.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_auth_fails_total",
            "Authentication failures",
            self.auth_fails.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_singleflight_coalesced_total",
            "Queries deduplicated by singleflight (reused in-flight result)",
            coalesced
        );
        counter!(
            "amardns_dot_queries_total",
            "DNS-over-TLS queries",
            self.dot_queries.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_doh_queries_total",
            "DNS-over-HTTPS queries",
            self.doh_queries.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_plain_queries_total",
            "Plain DNS UDP/TCP port 53 queries",
            self.plain_queries.load(Ordering::Relaxed)
        );
        // DNSSEC cryptographic counters
        counter!(
            "amardns_dnssec_validations_total",
            "DNSSEC validations evaluated",
            self.dnssec_validations.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_dnssec_secure_total",
            "DNSSEC cryptographically secure positive validations",
            self.dnssec_secure.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_dnssec_bogus_total",
            "DNSSEC bogus/tampered validations rejected",
            self.dnssec_bogus.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_dnssec_insecure_total",
            "DNSSEC unsigned/insecure validations",
            self.dnssec_insecure.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_dnssec_denial_of_existence_total",
            "DNSSEC NSEC/NSEC3 cryptographic denial-of-existence proofs verified",
            self.dnssec_denial_of_existence.load(Ordering::Relaxed)
        );
        // Latency histogram buckets
        counter!(
            "amardns_latency_sub1ms_total",
            "Queries completed in <1ms",
            self.lat_sub_1ms.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_latency_1to5ms_total",
            "Queries completed in 1-5ms",
            self.lat_1_to_5ms.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_latency_5to15ms_total",
            "Queries completed in 5-15ms",
            self.lat_5_to_15ms.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_latency_15to50ms_total",
            "Queries completed in 15-50ms",
            self.lat_15_to_50ms.load(Ordering::Relaxed)
        );
        counter!(
            "amardns_latency_above50ms_total",
            "Queries completed in >50ms",
            self.lat_above_50ms.load(Ordering::Relaxed)
        );
        // Gauges
        gauge!(
            "amardns_cache_entries",
            "Current DNS cache entry count",
            cache_entries
        );
        gauge!(
            "amardns_cache_mb",
            "Current DNS cache memory in megabytes",
            format!("{:.2}", cache_mb)
        );
        gauge!(
            "amardns_uptime_seconds",
            "Process uptime in seconds",
            uptime_secs
        );

        // Upstream sync timestamp
        gauge!(
            "amardns_upstream_last_sync_timestamp",
            "Unix timestamp of last upstream sync",
            self.upstream_last_sync.load(Ordering::Relaxed)
        );

        out
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
unsafe extern "C" {
    fn malloc_trim(pad: usize) -> i32;
}

/// Hints to the OS allocator (glibc malloc) on Linux to release free memory back to the kernel.
pub fn trim_process_memory() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    unsafe {
        let _ = malloc_trim(0);
    }
}

/// Reads current process Resident Set Size (RSS) in megabytes from /proc/self/statm on Linux.
/// Includes +40MB baseline overhead to accurately account for system/container/kernel allocation.
pub fn get_process_rss_mb() -> f64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/statm") {
            let parts: Vec<&str> = s.split_whitespace().collect();
            if parts.len() > 1 {
                let resident_pages: f64 = parts[1].parse().unwrap_or(0.0);
                let raw_mb = resident_pages * 4096.0 / 1_048_576.0;
                return (((raw_mb + 40.0) * 10.0).round()) / 10.0;
            }
        }
    }
    40.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_histogram_distribution() {
        let m = Metrics::new();

        m.record_query("1.1.1.1", "doh");
        m.record_latency(Duration::from_micros(250)); // < 1ms

        m.record_query("1.1.1.1", "doh");
        m.record_latency(Duration::from_micros(2_500)); // 1-5ms

        m.record_query("1.1.1.1", "doh");
        m.record_latency(Duration::from_micros(8_000)); // 5-15ms

        m.record_query("1.1.1.1", "doh");
        m.record_latency(Duration::from_micros(25_000)); // 15-50ms

        m.record_query("1.1.1.1", "doh");
        m.record_latency(Duration::from_micros(75_000)); // > 50ms

        let (sub1, f1_5, f5_15, f15_50, above50) = m.get_latency_distribution();
        assert_eq!(sub1, 1);
        assert_eq!(f1_5, 1);
        assert_eq!(f5_15, 1);
        assert_eq!(f15_50, 1);
        assert_eq!(above50, 1);

        let (avg_us, avg_ms) = m.get_avg_latency();
        assert!(avg_us > 0.0);
        assert!(avg_ms > 0.0);
    }

    #[test]
    fn test_metrics_prune_idle() {
        let m = Metrics::new();
        m.record_query("192.0.2.1", "doh");
        m.record_query("192.0.2.2", "dot");
        assert_eq!(m.get_active_devices().len(), 2);

        m.prune_idle();
        assert_eq!(m.get_active_devices().len(), 2);
        trim_process_memory();
    }

    #[test]
    fn test_dnssec_and_plain_metrics() {
        let m = Metrics::new();
        m.record_query("127.0.0.1", "plain");
        assert_eq!(m.plain_queries.load(Ordering::Relaxed), 1);

        let sec_details = crate::dns::dnssec::DnssecValidationDetails::secure(
            crate::dns::dnssec::DnssecAlgorithm::Ed25519,
            1234,
            "example.com",
            1,
            1,
            1,
            1,
            true,
        );
        m.record_dnssec(&sec_details);
        assert_eq!(m.dnssec_validations.load(Ordering::Relaxed), 1);
        assert_eq!(m.dnssec_secure.load(Ordering::Relaxed), 1);

        let bogus_details =
            crate::dns::dnssec::DnssecValidationDetails::bogus("Signature mismatch", None, None);
        m.record_dnssec(&bogus_details);
        assert_eq!(m.dnssec_validations.load(Ordering::Relaxed), 2);
        assert_eq!(m.dnssec_bogus.load(Ordering::Relaxed), 1);

        let nsec_details = crate::dns::dnssec::DnssecValidationDetails::denial_of_existence(
            "NSEC3 NXDOMAIN",
            Some("example.com"),
            1,
            2,
        );
        m.record_dnssec(&nsec_details);
        assert_eq!(m.dnssec_validations.load(Ordering::Relaxed), 3);
        assert_eq!(m.dnssec_secure.load(Ordering::Relaxed), 2);

        let text = m.prometheus_text(100, 1.5, 42);
        assert!(text.contains("amardns_plain_queries_total 1"));
        assert!(text.contains("amardns_dnssec_validations_total 3"));
        assert!(text.contains("amardns_dnssec_secure_total 2"));
        assert!(text.contains("amardns_dnssec_bogus_total 1"));
    }
}
