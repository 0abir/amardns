// Copyright (c) 2026 AmarDNS Contributors.
// SPDX-License-Identifier: MIT
//
// src/security/rate_limit.rs
//
// Z+ Security Rate Limiter — Two-Level Composite-Identity Token Bucket
// =====================================================================
//
// Design:
//   • Identity = (IpAddr, Option<device_id>). Each distinct device/client ID
//     behind the same IP gets its OWN per-identity bucket, preventing a single
//     client from being unfairly capped by noisy neighbours sharing its IP.
//
//   • Two-level enforcement (BOTH must pass):
//       1. Per-identity bucket   — 60 tokens cap, 20 tok/s refill  (individual client)
//       2. Per-IP ceiling bucket — 500 tokens cap, 200 tok/s refill (entire IP/NAT)
//     A request is denied if either bucket is exhausted.
//
//   • Private / internal IP exemption — loopback, RFC-1918, and Fly.io fdaa::/16
//     addresses are ALWAYS allowed (return true immediately).
//
//   • Automatic pruning — when the identity-bucket map exceeds 50 000 entries,
//     entries idle for >120 seconds are evicted to bound memory.
//
//   • Thread-safe via `parking_lot::Mutex` (no poisoning, faster than std::Mutex).
//
// Public API:
//   RateLimiter::new(identity_cap, identity_refill, ip_cap, ip_refill) -> Self
//   .check(&self, ip: IpAddr) -> bool                              (IP-only identity)
//   .check_with_identity(&self, ip: IpAddr, device_id: Option<&str>) -> bool
//   .get_soft_limit_hits(&self) -> u64
//   .get_blocked_count(&self) -> u64

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::Mutex;

// ── Internal key type ──────────────────────────────────────────────────────────

/// Composite key: (IP address, optional device/client identifier).
/// Using `String` so we can own arbitrary client IDs without lifetime gymnastics.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct IdentityKey {
    ip: IpAddr,
    /// `None`  =>  no device ID provided; the key degenerates to IP-only.
    device_id: Option<String>,
}

impl IdentityKey {
    #[inline]
    fn new(ip: IpAddr, device_id: Option<&str>) -> Self {
        Self {
            ip,
            device_id: device_id.map(|d| {
                let trimmed = d.trim();
                if trimmed.len() > 64 {
                    trimmed[..64].to_string()
                } else {
                    trimmed.to_string()
                }
            }),
        }
    }
}


// ── Single token bucket ────────────────────────────────────────────────────────

/// A refilling token bucket updated lazily on each access.
#[derive(Debug)]
struct TokenBucket {
    /// Current token level (fractional).
    tokens: f64,
    /// Wall-clock instant of the last token-count update.
    last_refill: Instant,
    /// Maximum token level (burst capacity).
    capacity: f64,
    /// Token refill rate in tokens per second.
    refill_rate: f64,
}

impl TokenBucket {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            capacity,
            refill_rate,
        }
    }

    /// Lazily refills the bucket based on elapsed time, then attempts to consume
    /// one token.  Returns `true` if a token was available, `false` if exhausted.
    fn try_consume(&mut self, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Returns the wall-clock time of the last access (used for pruning).
    #[inline]
    fn last_seen(&self) -> Instant {
        self.last_refill
    }
}

// ── Rate-limiter configuration ─────────────────────────────────────────────────

/// Builder/configuration value for [`RateLimiter`].
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Max burst tokens for a single composite identity.
    pub identity_capacity: f64,
    /// Refill rate (tokens/s) for a single composite identity.
    pub identity_refill: f64,
    /// Max burst tokens shared across all identities from the same IP.
    pub ip_ceiling_capacity: f64,
    /// Refill rate (tokens/s) for the per-IP ceiling bucket.
    pub ip_ceiling_refill: f64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            identity_capacity: 60.0,
            identity_refill: 20.0,
            ip_ceiling_capacity: 500.0,
            ip_ceiling_refill: 200.0,
        }
    }
}

// ── Inner maps (held behind a Mutex each) ─────────────────────────────────────

struct IdentityMap {
    buckets: HashMap<IdentityKey, TokenBucket>,
}

struct IpCeilingMap {
    buckets: HashMap<IpAddr, TokenBucket>,
}

// ── Public RateLimiter ─────────────────────────────────────────────────────────

/// Two-level composite-identity token-bucket rate limiter.
///
/// Thread-safe via [`parking_lot::Mutex`].  Never panics on lock acquisition.
pub struct RateLimiter {
    config: RateLimitConfig,

    /// Per-identity (IP + device_id) buckets.
    identity_map: Mutex<IdentityMap>,

    /// Per-IP ceiling buckets (shared by all identities from that IP).
    ip_ceiling_map: Mutex<IpCeilingMap>,

    /// Counter: requests that were explicitly *blocked* (returned `false`).
    blocked_count: AtomicU64,

    /// Counter: requests where the per-identity bucket was exhausted.
    /// Incremented even if the request was ultimately blocked by the ceiling.
    soft_limit_hits: AtomicU64,
}

impl RateLimiter {
    // ── Construction ──────────────────────────────────────────────────────────

    /// Create a new `RateLimiter` with explicit capacity/refill parameters.
    ///
    /// # Parameters
    /// * `identity_capacity`   — burst cap per composite identity (tokens)
    /// * `identity_refill`     — refill rate per identity (tokens / second)
    /// * `ip_ceiling_capacity` — burst cap shared per IP (tokens)
    /// * `ip_ceiling_refill`   — refill rate per IP ceiling (tokens / second)
    pub fn new(
        identity_capacity: f64,
        identity_refill: f64,
        ip_ceiling_capacity: f64,
        ip_ceiling_refill: f64,
    ) -> Self {
        Self {
            config: RateLimitConfig {
                identity_capacity,
                identity_refill,
                ip_ceiling_capacity,
                ip_ceiling_refill,
            },
            identity_map: Mutex::new(IdentityMap {
                buckets: HashMap::new(),
            }),
            ip_ceiling_map: Mutex::new(IpCeilingMap {
                buckets: HashMap::new(),
            }),
            blocked_count: AtomicU64::new(0),
            soft_limit_hits: AtomicU64::new(0),
        }
    }

    /// Convenience constructor from a [`RateLimitConfig`].
    #[allow(dead_code)]
    pub fn from_config(cfg: RateLimitConfig) -> Self {
        Self::new(
            cfg.identity_capacity,
            cfg.identity_refill,
            cfg.ip_ceiling_capacity,
            cfg.ip_ceiling_refill,
        )
    }

    // ── Public check API ──────────────────────────────────────────────────────

    /// Backward-compatible check keyed solely on IP (no device identifier).
    ///
    /// Equivalent to `check_with_identity(ip, None)`.
    #[inline]
    #[allow(dead_code)]
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_with_identity(ip, None)
    }

    /// Full composite-identity check.
    ///
    /// Returns `true` if both the per-identity and per-IP ceiling buckets have
    /// at least one token; `false` (and increments [`blocked_count`]) otherwise.
    /// Private/loopback/Fly.io-internal addresses are always allowed.
    pub fn check_with_identity(&self, ip: IpAddr, device_id: Option<&str>) -> bool {
        // ── 1. Private / internal IP exemption ──────────────────────────────
        if is_exempt(ip) {
            return true;
        }

        let now = Instant::now();
        let key = IdentityKey::new(ip, device_id);
        let cfg = &self.config;

        // ── 2. Per-identity bucket ───────────────────────────────────────────
        let identity_ok = {
            let mut map = self.identity_map.lock();

            // Prune when the map grows too large to respect the 200MB memory cap.
            if map.buckets.len() > 25_000 {
                map.buckets
                    .retain(|_, b| now.duration_since(b.last_seen()).as_secs() < 60);
                if map.buckets.len() > 25_000 {
                    let to_remove = map.buckets.len() - 15_000;
                    let keys: Vec<_> = map.buckets.keys().take(to_remove).cloned().collect();
                    for k in keys {
                        map.buckets.remove(&k);
                    }
                }
            }

            let bucket = map
                .buckets
                .entry(key)
                .or_insert_with(|| TokenBucket::new(cfg.identity_capacity, cfg.identity_refill));

            let ok = bucket.try_consume(now);
            if !ok {
                self.soft_limit_hits.fetch_add(1, Ordering::Relaxed);
            }
            ok
        };

        // ── 3. Per-IP ceiling bucket ─────────────────────────────────────────
        //
        // Only consume from the ceiling when the identity check passed.
        // This prevents double-penalising an already-blocked identity but still
        // drains the ceiling for every IP-level attempt, so a flood of distinct
        // fake device IDs will exhaust the IP ceiling.
        let ceiling_ok = if identity_ok {
            let mut map = self.ip_ceiling_map.lock();

            if map.buckets.len() > 25_000 {
                map.buckets
                    .retain(|_, b| now.duration_since(b.last_seen()).as_secs() < 60);
                if map.buckets.len() > 25_000 {
                    let to_remove = map.buckets.len() - 15_000;
                    let keys: Vec<_> = map.buckets.keys().take(to_remove).cloned().collect();
                    for k in keys {
                        map.buckets.remove(&k);
                    }
                }
            }

            let bucket = map.buckets.entry(ip).or_insert_with(|| {
                TokenBucket::new(cfg.ip_ceiling_capacity, cfg.ip_ceiling_refill)
            });

            bucket.try_consume(now)
        } else {
            // Identity already failed — ceiling is irrelevant.
            false
        };

        let allowed = identity_ok && ceiling_ok;

        if !allowed {
            self.blocked_count.fetch_add(1, Ordering::Relaxed);
        }

        allowed
    }

    // ── Metrics ───────────────────────────────────────────────────────────────

    /// Returns the number of times a request exceeded the per-identity quota.
    ///
    /// This fires whenever the identity bucket is dry, regardless of whether
    /// the request was ultimately blocked by the ceiling.
    pub fn get_soft_limit_hits(&self) -> u64 {
        self.soft_limit_hits.load(Ordering::Relaxed)
    }

    /// Returns the total number of requests that were **denied** (returned `false`).
    pub fn get_blocked_count(&self) -> u64 {
        self.blocked_count.load(Ordering::Relaxed)
    }

    /// Prunes token buckets that have not been accessed in the last 60 seconds.
    pub fn prune_idle(&self) {
        let now = Instant::now();
        {
            let mut map = self.identity_map.lock();
            map.buckets.retain(|_, b| now.duration_since(b.last_seen()).as_secs() < 60);
        }
        {
            let mut map = self.ip_ceiling_map.lock();
            map.buckets.retain(|_, b| now.duration_since(b.last_seen()).as_secs() < 60);
        }
    }

    /// Clears all rate-limiter buckets to immediately release memory during pressure.
    pub fn clear(&self) {
        self.identity_map.lock().buckets.clear();
        self.ip_ceiling_map.lock().buckets.clear();
    }
}

// ── Private IP / exemption helpers ────────────────────────────────────────────

/// Returns `true` for IPs that must never be rate-limited:
///   - IPv4 loopback    (127.0.0.0/8)
///   - IPv4 RFC-1918    (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
///   - IPv4 link-local  (169.254.0.0/16)
///   - IPv6 loopback    (::1)
///   - IPv6 Unique Local (fc00::/7 — covers fd00::/8 and Fly.io fdaa::/16)
///   - IPv6 link-local  (fe80::/10)
#[inline]
fn is_exempt(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // 127.0.0.0/8  — loopback
            o[0] == 127
            // 10.0.0.0/8   — RFC-1918
            || o[0] == 10
            // 172.16.0.0/12 — RFC-1918
            || (o[0] == 172 && (16..=31).contains(&o[1]))
            // 192.168.0.0/16 — RFC-1918
            || (o[0] == 192 && o[1] == 168)
            // 169.254.0.0/16 — link-local (APIPA)
            || (o[0] == 169 && o[1] == 254)
        }
        IpAddr::V6(v6) => {
            // ::1 — loopback
            v6.is_loopback()
            // fc00::/7 — Unique Local (covers fd00::/8 and fdaa::/16 Fly.io internal)
            || (v6.segments()[0] & 0xfe00) == 0xfc00
            // fe80::/10 — link-local
            || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn public_ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// Limiter with zero refill so tokens are NOT replenished between calls.
    fn tight_limiter(identity_cap: f64, ip_cap: f64) -> RateLimiter {
        RateLimiter::new(identity_cap, 0.0, ip_cap, 0.0)
    }

    // ── Exemption tests ───────────────────────────────────────────────────────

    #[test]
    fn private_and_loopback_ips_always_pass() {
        // Capacity = 1, refill = 0 -> only 1 token; private IPs must ignore this.
        let limiter = tight_limiter(1.0, 1.0);

        let cases: &[IpAddr] = &[
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),      // IPv4 loopback
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),        // RFC-1918 /8
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),      // RFC-1918 /12 low boundary
            IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255)),  // RFC-1918 /12 high boundary
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),   // RFC-1918 /16
            IpAddr::V4(Ipv4Addr::new(169, 254, 10, 1)),    // APIPA link-local
            IpAddr::V6(Ipv6Addr::LOCALHOST),                // ::1
            // fdaa::/16 -- Fly.io internal (covered by fc00::/7)
            IpAddr::V6("fdaa:8b:56f6:a7b::2".parse().unwrap()),
            // fd00::/8 -- generic Unique Local
            IpAddr::V6("fd00::1".parse().unwrap()),
            // fe80::/10 -- link-local
            IpAddr::V6("fe80::1".parse().unwrap()),
        ];

        for &ip in cases {
            for _ in 0..200 {
                assert!(
                    limiter.check(ip),
                    "Expected exempt IP {ip} to always pass"
                );
            }
        }

        // No tokens consumed and no blocks recorded for exempt IPs.
        assert_eq!(limiter.get_blocked_count(), 0);
    }

    #[test]
    fn non_private_ips_outside_rfc1918_are_not_exempt() {
        // 172.15.x is NOT in the 172.16-31.x range -> public -> must be rate-limited.
        let limiter = tight_limiter(1.0, 10.0);
        let ip = IpAddr::V4(Ipv4Addr::new(172, 15, 0, 1));

        assert!(limiter.check(ip));  // first call consumes the 1 token
        assert!(!limiter.check(ip)); // second call: no tokens left -> blocked
        assert_eq!(limiter.get_blocked_count(), 1);
    }

    // ── Per-identity enforcement ──────────────────────────────────────────────

    #[test]
    fn single_identity_blocked_after_quota_exhausted() {
        // 5 identity tokens, no refill, large IP ceiling -> identity is the bottleneck.
        let limiter = RateLimiter::new(5.0, 0.0, 10_000.0, 0.0);
        let ip = public_ip(1, 2, 3, 4);

        for i in 0..5 {
            assert!(
                limiter.check(ip),
                "Call {i} should be allowed while tokens remain"
            );
        }

        // 6th call must be blocked.
        assert!(!limiter.check(ip), "6th call must be blocked");
        assert_eq!(limiter.get_blocked_count(), 1);
        // Identity bucket was exhausted once -> soft_limit_hits = 1.
        assert_eq!(limiter.get_soft_limit_hits(), 1);
    }

    #[test]
    fn distinct_device_ids_under_same_ip_get_independent_buckets() {
        // 3 identity tokens each, no refill, generous IP ceiling (50 >= 3 devices x 3 tokens).
        let limiter = RateLimiter::new(3.0, 0.0, 50.0, 0.0);
        let ip = public_ip(5, 6, 7, 8);

        let devices = ["device-A", "device-B", "device-C"];

        // Each device should be allowed its own independent 3-token quota.
        for dev in &devices {
            for i in 0..3 {
                assert!(
                    limiter.check_with_identity(ip, Some(dev)),
                    "Device {dev} call {i} should be allowed"
                );
            }
        }

        // Each device is now exhausted — next call per device must fail.
        for dev in &devices {
            assert!(
                !limiter.check_with_identity(ip, Some(dev)),
                "Device {dev} should be blocked after quota"
            );
        }

        assert_eq!(limiter.get_blocked_count(), 3);
    }

    #[test]
    fn device_id_none_and_device_id_some_are_separate_buckets() {
        // IP-only identity (None) and a named device must not share tokens.
        let limiter = RateLimiter::new(2.0, 0.0, 100.0, 0.0);
        let ip = public_ip(9, 9, 9, 9);

        // Exhaust the IP-only identity bucket.
        assert!(limiter.check_with_identity(ip, None));
        assert!(limiter.check_with_identity(ip, None));
        assert!(!limiter.check_with_identity(ip, None)); // blocked

        // Named device should have its own full 2-token quota untouched.
        assert!(limiter.check_with_identity(ip, Some("gadget-1")));
        assert!(limiter.check_with_identity(ip, Some("gadget-1")));
        assert!(!limiter.check_with_identity(ip, Some("gadget-1"))); // blocked

        assert_eq!(limiter.get_blocked_count(), 2);
    }

    // ── Per-IP ceiling enforcement ────────────────────────────────────────────

    #[test]
    fn ip_ceiling_hard_caps_even_when_identity_bucket_full() {
        // IP ceiling = 4 tokens. Each device identity has 10 tokens (plenty).
        // After 4 allowed requests across ALL devices, the IP ceiling blocks the rest.
        let limiter = RateLimiter::new(10.0, 0.0, 4.0, 0.0);
        let ip = public_ip(20, 20, 20, 20);

        let mut allowed = 0u32;
        let mut blocked = 0u32;

        // Issue 8 requests across 4 different devices (2 per device).
        let devices = ["d1", "d2", "d3", "d4"];
        for dev in &devices {
            for _ in 0..2 {
                if limiter.check_with_identity(ip, Some(dev)) {
                    allowed += 1;
                } else {
                    blocked += 1;
                }
            }
        }

        // Exactly 4 should be allowed (IP ceiling capacity), the remaining 4 blocked.
        assert_eq!(
            allowed, 4,
            "IP ceiling must allow exactly 4 requests total; got {allowed}"
        );
        assert_eq!(
            blocked, 4,
            "IP ceiling must block the remaining 4; got {blocked}"
        );
        assert_eq!(limiter.get_blocked_count(), 4);
    }

    #[test]
    fn ip_ceiling_shared_by_all_identities_under_same_ip() {
        // 1-token IP ceiling, many identity tokens -- every request after the first must fail.
        let limiter = RateLimiter::new(100.0, 0.0, 1.0, 0.0);
        let ip = public_ip(30, 30, 30, 30);

        assert!(limiter.check_with_identity(ip, Some("alpha")));  // ceiling token consumed
        assert!(!limiter.check_with_identity(ip, Some("beta")));  // ceiling empty
        assert!(!limiter.check_with_identity(ip, Some("gamma"))); // ceiling still empty
        assert!(!limiter.check(ip));                               // IP-only identity

        assert_eq!(limiter.get_blocked_count(), 3);
    }

    // ── Metrics ───────────────────────────────────────────────────────────────

    #[test]
    fn blocked_count_increments_on_each_rejection() {
        let limiter = tight_limiter(2.0, 100.0);
        let ip = public_ip(50, 0, 0, 1);

        assert_eq!(limiter.get_blocked_count(), 0);

        limiter.check(ip); // allowed
        limiter.check(ip); // allowed
        limiter.check(ip); // blocked -> count = 1
        assert_eq!(limiter.get_blocked_count(), 1);

        limiter.check(ip); // blocked -> count = 2
        assert_eq!(limiter.get_blocked_count(), 2);
    }

    #[test]
    fn soft_limit_hits_counts_identity_exhaustion() {
        let limiter = RateLimiter::new(2.0, 0.0, 10_000.0, 0.0);
        let ip = public_ip(60, 0, 0, 1);

        limiter.check(ip); // ok, 1 token left
        limiter.check(ip); // ok, 0 tokens left
        assert_eq!(limiter.get_soft_limit_hits(), 0);

        limiter.check(ip); // identity exhausted -> soft_limit_hits = 1
        assert_eq!(limiter.get_soft_limit_hits(), 1);

        limiter.check(ip); // again -> soft_limit_hits = 2
        assert_eq!(limiter.get_soft_limit_hits(), 2);
    }

    #[test]
    fn blocked_count_not_incremented_for_exempt_ips() {
        let limiter = tight_limiter(0.0, 0.0); // zero tokens -- would block any public IP
        let loopback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let private = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));

        for _ in 0..100 {
            assert!(limiter.check(loopback));
            assert!(limiter.check(private));
        }

        assert_eq!(limiter.get_blocked_count(), 0);
        assert_eq!(limiter.get_soft_limit_hits(), 0);
    }

    // ── is_exempt helper ──────────────────────────────────────────────────────

    #[test]
    fn is_exempt_covers_all_rfc1918_boundaries() {
        // 10.0.0.0/8
        assert!(is_exempt(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))));
        assert!(is_exempt(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));

        // 172.16.0.0/12 boundaries
        assert!(is_exempt(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0))));
        assert!(is_exempt(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
        assert!(!is_exempt(IpAddr::V4(Ipv4Addr::new(172, 15, 0, 1)))); // just outside low
        assert!(!is_exempt(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 0)))); // just outside high

        // 192.168.0.0/16
        assert!(is_exempt(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0))));
        assert!(is_exempt(IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255))));
        assert!(!is_exempt(IpAddr::V4(Ipv4Addr::new(192, 169, 0, 0)))); // just outside

        // Public IPs must NOT be exempt.
        assert!(!is_exempt(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_exempt(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_exempt(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    }

    #[test]
    fn is_exempt_covers_ipv6_ranges() {
        // ::1 loopback
        assert!(is_exempt(IpAddr::V6(Ipv6Addr::LOCALHOST)));

        // fc00::/7 -- Unique Local (includes fd::/8 and fdaa::/16)
        assert!(is_exempt("fc00::1".parse::<IpAddr>().unwrap()));
        assert!(is_exempt("fd00::1".parse::<IpAddr>().unwrap()));
        assert!(is_exempt("fdaa:8b:56f6:a7b::2".parse::<IpAddr>().unwrap()));

        // fe80::/10 -- link-local
        assert!(is_exempt("fe80::1".parse::<IpAddr>().unwrap()));

        // Public IPv6 must NOT be exempt.
        assert!(!is_exempt("2001:4860:4860::8888".parse::<IpAddr>().unwrap())); // Google DNS
        assert!(!is_exempt("2606:4700:4700::1111".parse::<IpAddr>().unwrap())); // Cloudflare DNS
    }
}
