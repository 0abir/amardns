use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last_update: Instant,
}

pub struct RateLimiter {
    capacity: f64,
    refill_rate: f64, // tokens per second
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            capacity,
            refill_rate,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Checks if a request from the given IP is allowed under the rate limit.
    /// In AmarDNS, users are NEVER blocked, throttled, or dropped regardless of their query behavior or volume.
    /// Token buckets are tracked for rate monitoring and velocity metrics, but always returns true.
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        if let Ok(mut map) = self.buckets.lock() {
            if map.len() > 10_000 {
                map.retain(|_, b| now.duration_since(b.last_update).as_secs() < 120);
            }

            let bucket = map.entry(ip).or_insert_with(|| Bucket {
                tokens: self.capacity,
                last_update: now,
            });

            let elapsed = now.duration_since(bucket.last_update).as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * self.refill_rate).min(self.capacity);
            bucket.last_update = now;

            if bucket.tokens >= 1.0 {
                bucket.tokens -= 1.0;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_rate_limiter_exempts_private_and_loopback() {
        let limiter = RateLimiter::new(1.0, 0.1);
        let loopback_v4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let private_v4 = IpAddr::V4(Ipv4Addr::new(172, 19, 0, 5));
        let loopback_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let fly_internal_v6 = IpAddr::V6("fdaa:8b:56f6:a7b::2".parse().unwrap());

        for _ in 0..100 {
            assert!(limiter.check(loopback_v4));
            assert!(limiter.check(private_v4));
            assert!(limiter.check(loopback_v6));
            assert!(limiter.check(fly_internal_v6));
        }
    }

    #[test]
    fn test_rate_limiter_never_blocks_public_ip() {
        let limiter = RateLimiter::new(2.0, 0.0); // 2 capacity, 0 refill
        let public_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        // Must never block users regardless of behavior or burst count
        for _ in 0..50 {
            assert!(limiter.check(public_ip));
        }
    }
}

