use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScheduleRule {
    pub id: u64,
    pub domain_pattern: String,
    /// 0-23 hour (local time using tz_offset_hours)
    pub start_hour: u8,
    /// 0-23 hour (exclusive end)
    pub end_hour: u8,
    /// UTC offset in hours (e.g. 6 for Asia/Dhaka)
    pub tz_offset_hours: i8,
    pub reason: String,
    pub created_at: u64,
}

impl ScheduleRule {
    /// Returns true if the current local hour falls within [start_hour, end_hour).
    /// Handles overnight rules (start > end, e.g. 22:00 to 06:00).
    pub fn is_active_now(&self) -> bool {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let local_secs = (now_unix as i64) + (self.tz_offset_hours as i64 * 3600);
        let hour = ((local_secs / 3600) % 24) as u8;

        if self.start_hour <= self.end_hour {
            // Normal window: e.g. 09:00 to 17:00
            hour >= self.start_hour && hour < self.end_hour
        } else {
            // Overnight window: e.g. 22:00 to 06:00 (wraps midnight)
            hour >= self.start_hour || hour < self.end_hour
        }
    }

    /// Returns true if the domain matches this rule's pattern (exact or suffix wildcard).
    pub fn matches_domain(&self, domain: &str) -> bool {
        let pat = self.domain_pattern.trim_start_matches('*').trim_start_matches('.');
        let clean = domain.trim_end_matches('.').to_ascii_lowercase();
        let pat_lower = pat.to_ascii_lowercase();
        clean == pat_lower || clean.ends_with(&format!(".{}", pat_lower))
    }
}

pub struct ScheduleStore {
    rules: RwLock<Vec<ScheduleRule>>,
    next_id: AtomicU64,
    #[allow(dead_code)]
    pub schedule_blocks: AtomicU64,
}

const MAX_SCHEDULE_RULES: usize = 500;

impl ScheduleStore {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            next_id: AtomicU64::new(1),
            schedule_blocks: AtomicU64::new(0),
        }
    }

    pub fn add_rule(&self, domain_pattern: String, start_hour: u8, end_hour: u8, tz_offset_hours: i8, reason: String) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let rule = ScheduleRule {
            id,
            domain_pattern,
            start_hour: start_hour % 24,
            end_hour: end_hour % 24,
            tz_offset_hours,
            reason,
            created_at: now,
        };
        let mut rules = self.rules.write();
        if rules.len() >= MAX_SCHEDULE_RULES {
            rules.remove(0);
        }
        rules.push(rule);
        id
    }

    pub fn remove_rule(&self, id: u64) -> bool {
        let mut rules = self.rules.write();
        let before = rules.len();
        rules.retain(|r| r.id != id);
        rules.len() < before
    }

    /// Returns true if the domain is currently blocked by any active schedule rule.
    pub fn is_blocked_now(&self, domain: &str) -> Option<&'static str> {
        let rules = self.rules.read();
        for rule in rules.iter() {
            if rule.is_active_now() && rule.matches_domain(domain) {
                // We can't return a reference to rule.reason since it's behind a lock guard.
                // Return a static sentinel and let callers use the rule list for details.
                return Some("SCHEDULE_BLOCK");
            }
        }
        None
    }

    /// Returns a snapshot of all rules.
    pub fn list_rules(&self) -> Vec<ScheduleRule> {
        self.rules.read().clone()
    }

    #[allow(dead_code)]
    pub fn rule_count(&self) -> usize {
        self.rules.read().len()
    }
}

impl Default for ScheduleStore {
    fn default() -> Self {
        Self::new()
    }
}
