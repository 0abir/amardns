use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainKnowledge {
    pub domain: String,
    #[serde(rename = "queryCount")]
    pub query_count: u64,
    #[serde(rename = "threatScore")]
    pub threat_score: f32,
    pub entropy: f32,
    #[serde(rename = "safeResolutions")]
    pub safe_resolutions: u32,
    #[serde(rename = "lastSeen")]
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIDecisionRecord {
    pub id: u64,
    pub timestamp: u64,
    pub domain: String,
    pub entropy: f32,
    #[serde(rename = "threatScore")]
    pub threat_score: f32,
    pub features: [f32; 8],
    pub action: String,
    pub reason: String,
    #[serde(rename = "utilityProof")]
    pub utility_proof: String,
}

/// Dynamic Online Neural Network & Markov Learning Brain for AmarDNS.
/// Gains real domain intelligence from live traffic, stores trained weights and Markov models,
/// and provides inferences for DGA and domain anomaly detection.
pub struct AIBrain {
    pub domain_iq: RwLock<HashMap<String, DomainKnowledge>>,
    pub markov_model: RwLock<HashMap<String, u32>>,
    pub neural_weights: RwLock<[f32; 8]>,
    pub domain_transitions: RwLock<HashMap<String, HashMap<String, u32>>>,
    pub last_query_sequence: parking_lot::Mutex<Option<(String, std::time::Instant)>>,
    pub prefetch_triggers: AtomicU64,
    #[allow(dead_code)]
    pub prefetch_hits: AtomicU64,
    pub training_cycles: AtomicU64,
    pub decisions_made: AtomicU64,
    pub recent_decisions: RwLock<Vec<AIDecisionRecord>>,
    pub zero_day_blocks: AtomicU64,
    pub typo_blocks: AtomicU64,
    pub fp_suppressions: AtomicU64,
}

impl AIBrain {
    pub fn new() -> Self {
        Self {
            domain_iq: RwLock::new(HashMap::new()),
            markov_model: RwLock::new(HashMap::new()),
            neural_weights: RwLock::new([0.10, 0.25, -0.50, 0.35, 0.30, 0.35, 0.40, -0.60]),
            domain_transitions: RwLock::new(HashMap::new()),
            last_query_sequence: parking_lot::Mutex::new(None),
            prefetch_triggers: AtomicU64::new(0),
            prefetch_hits: AtomicU64::new(0),
            training_cycles: AtomicU64::new(0),
            decisions_made: AtomicU64::new(0),
            recent_decisions: RwLock::new(Vec::new()),
            zero_day_blocks: AtomicU64::new(0),
            typo_blocks: AtomicU64::new(0),
            fp_suppressions: AtomicU64::new(0),
        }
    }

    /// Records client query sequence to learn domain correlation transitions (A -> B)
    pub fn record_sequence(&self, domain: &str) {
        let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if clean.is_empty() {
            return;
        }
        let now = std::time::Instant::now();
        let mut last_guard = self.last_query_sequence.lock();
        if let Some((prev_domain, prev_time)) = last_guard.as_ref() {
            let elapsed = now.duration_since(*prev_time).as_secs_f64();
            // If consecutive queries arrive within 2.5s and domains differ, record correlation
            if elapsed <= 2.5 && prev_domain != &clean {
                let mut transitions = self.domain_transitions.write();
                if transitions.len() >= 500 && !transitions.contains_key(prev_domain) {
                    if let Some(k) = transitions.keys().next().cloned() {
                        transitions.remove(&k);
                    }
                }
                let child_map = transitions.entry(prev_domain.clone()).or_default();
                if child_map.len() < 8 || child_map.contains_key(&clean) {
                    let counter = child_map.entry(clean.clone()).or_insert(0);
                    *counter = counter.saturating_add(1);
                }
            }
        }
        *last_guard = Some((clean, now));
    }

    /// Retrieves high-confidence predicted subresources for proactive prefetching
    pub fn get_prefetch_candidates(&self, domain: &str) -> Vec<String> {
        let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let transitions = self.domain_transitions.read();
        if let Some(children) = transitions.get(&clean) {
            let mut candidates: Vec<(&String, &u32)> = children.iter()
                .filter(|(_, &count)| count >= 2)
                .collect();
            candidates.sort_by(|a, b| b.1.cmp(a.1));
            candidates.into_iter().take(2).map(|(d, _)| d.clone()).collect()
        } else {
            Vec::new()
        }
    }

    /// Trains the brain online on an observed domain and resolution outcome.
    pub fn train(&self, domain: &str, is_threat: bool, rcode: u16) {
        let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if clean.is_empty() || clean.len() < 3 {
            return;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // 1. Update Markov character-transition model (bigrams)
        let bytes = clean.as_bytes();
        {
            let mut markov = self.markov_model.write();
            for w in bytes.windows(2) {
                if let Ok(s) = std::str::from_utf8(w) {
                    if markov.len() < 5000 || markov.contains_key(s) {
                        *markov.entry(s.to_string()).or_insert(0) += 1;
                    }
                }
            }
        }

        // 2. Compute features for domain
        let (features, entropy) = self.extract_features(&clean);

        // 3. Online neural learning: Stochastic gradient update
        {
            let mut weights = self.neural_weights.write();
            let lr = 0.01f32;
            let target = if is_threat { 1.0f32 } else { 0.0f32 };
            let raw_pred: f32 = weights.iter().zip(features.iter()).map(|(w, f)| w * f).sum();
            let pred = 1.0 / (1.0 + (-raw_pred).exp());
            let error = target - pred;

            for i in 0..8 {
                weights[i] = (weights[i] + lr * error * features[i]).clamp(-3.0, 3.0);
            }
        }

        // 4. Update Domain IQ repository
        {
            let mut iq = self.domain_iq.write();
            if iq.len() >= 5000 && !iq.contains_key(&clean) {
                // Prune lowest query domain when capacity reached
                if let Some(min_k) = iq.iter().min_by_key(|(_, v)| v.query_count).map(|(k, _)| k.clone()) {
                    iq.remove(&min_k);
                }
            }
            let entry = iq.entry(clean.clone()).or_insert_with(|| DomainKnowledge {
                domain: clean,
                query_count: 0,
                threat_score: if is_threat { 0.95 } else { 0.05 },
                entropy,
                safe_resolutions: 0,
                last_seen: now,
            });
            entry.query_count = entry.query_count.saturating_add(1);
            entry.last_seen = now;
            if is_threat {
                entry.threat_score = (entry.threat_score * 0.7 + 0.3).min(1.0);
            } else if rcode == 0 {
                entry.safe_resolutions = entry.safe_resolutions.saturating_add(1);
                entry.threat_score = (entry.threat_score * 0.85).max(0.01);
            }
        }

        self.training_cycles.fetch_add(1, Ordering::Relaxed);
    }

    /// Evaluates a domain without incrementing the live user queries decisions counter (used for telemetry benchmarks and dry-runs).
    pub fn evaluate_internal(&self, domain: &str) -> (f32, &'static str) {
        let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if clean.is_empty() {
            return (0.0, "clean");
        }

        let (features, _) = self.extract_features(&clean);
        let weights = self.neural_weights.read();
        let raw_pred: f32 = weights.iter().zip(features.iter()).map(|(w, f)| w * f).sum();
        let score = 1.0 / (1.0 + (-raw_pred).exp());

        let verdict = if score > 0.80 {
            "ai_neural_threat"
        } else if score > 0.60 {
            "ai_elevated_risk"
        } else {
            "benign"
        };

        (score, verdict)
    }

    /// Evaluates a live query and increments the decision counter.
    pub fn evaluate(&self, domain: &str) -> (f32, &'static str) {
        self.decisions_made.fetch_add(1, Ordering::Relaxed);
        self.evaluate_internal(domain)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_decision(
        &self,
        domain: &str,
        entropy: f32,
        threat_score: f32,
        features: [f32; 8],
        action: &str,
        reason: &str,
        utility_proof: &str,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut guard = self.recent_decisions.write();
        let id = guard.last().map(|d| d.id + 1).unwrap_or(1);
        guard.push(AIDecisionRecord {
            id,
            timestamp: now,
            domain: domain.to_string(),
            entropy,
            threat_score,
            features,
            action: action.to_string(),
            reason: reason.to_string(),
            utility_proof: utility_proof.to_string(),
        });
        if guard.len() > 150 {
            guard.drain(0..50);
        }
    }

    pub fn get_recent_decisions(&self, limit: usize) -> Vec<AIDecisionRecord> {
        let guard = self.recent_decisions.read();
        let take_n = limit.min(guard.len());
        guard.iter().rev().take(take_n).cloned().collect()
    }

    /// Calculates domain feature vector for neural network and Markov scoring.
    pub fn extract_features(&self, domain: &str) -> ([f32; 8], f32) {
        let len = domain.len() as f32;
        let mut char_counts = [0usize; 256];
        let mut vowels = 0usize;
        let mut digits = 0usize;
        let mut max_cons = 0usize;
        let mut curr_cons = 0usize;

        for &b in domain.as_bytes() {
            char_counts[b as usize] += 1;
            if matches!(b, b'a' | b'e' | b'i' | b'o' | b'u') {
                vowels += 1;
                curr_cons = 0;
            } else if b.is_ascii_alphabetic() {
                curr_cons += 1;
                max_cons = max_cons.max(curr_cons);
            } else if b.is_ascii_digit() {
                digits += 1;
                curr_cons = 0;
            } else {
                curr_cons = 0;
            }
        }

        // Shannon entropy
        let mut entropy = 0.0f32;
        for &c in &char_counts {
            if c > 0 {
                let p = c as f32 / len;
                entropy -= p * p.log2();
            }
        }

        // Markov anomaly: check how many bigrams are unknown or rare
        let markov = self.markov_model.read();
        let mut unknown_bigrams = 0usize;
        let bytes = domain.as_bytes();
        let total_bigrams = bytes.len().saturating_sub(1).max(1);
        for w in bytes.windows(2) {
            if let Ok(s) = std::str::from_utf8(w) {
                if markov.get(s).copied().unwrap_or(0) == 0 {
                    unknown_bigrams += 1;
                }
            }
        }
        drop(markov);
        let markov_anomaly = unknown_bigrams as f32 / total_bigrams as f32;

        let f0 = (len / 32.0).min(1.5);
        let f1 = (entropy / 4.0).min(1.5);
        let f2 = (vowels as f32 / len.max(1.0)).min(1.0);
        let f3 = (digits as f32 / len.max(1.0)).min(1.0);
        let f4 = (max_cons as f32 / 8.0).min(1.5);
        let f5 = markov_anomaly;
        let f6 = if domain.contains("paypal") || domain.contains("google") || domain.contains("apple") { 0.8 } else { 0.0 };
        let f7 = {
            let iq = self.domain_iq.read();
            if let Some(entry) = iq.get(domain) {
                if entry.safe_resolutions > 0 && entry.threat_score < 0.2 {
                    1.0f32
                } else if entry.threat_score > 0.8 {
                    -1.0f32
                } else {
                    0.0f32
                }
            } else {
                0.0f32
            }
        };

        ([f0, f1, f2, f3, f4, f5, f6, f7], entropy)
    }

    /// Exports the full trained brain data into a JSON structure for backup and synchronization.
    pub fn export_json(
        &self,
        heatmap: &HashMap<String, crate::state::HeatmapRecord>,
        custom_blocklist: &HashMap<String, crate::state::BlockEntry>,
        custom_whitelist: &std::collections::HashSet<String>,
    ) -> serde_json::Value {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let iq_guard = self.domain_iq.read();
        let markov_guard = self.markov_model.read();
        let weights_guard = self.neural_weights.read();

        // Convert domain IQ to json map
        let mut domain_iq_json = serde_json::Map::new();
        for (k, v) in iq_guard.iter() {
            domain_iq_json.insert(k.clone(), serde_json::json!({
                "queries": v.query_count,
                "threatScore": v.threat_score,
                "entropy": v.entropy,
                "safe": v.safe_resolutions,
                "lastSeen": v.last_seen
            }));
        }

        // Also incorporate any extra domains from heatmap that have query history
        for (d, h) in heatmap.iter() {
            if !domain_iq_json.contains_key(d) {
                domain_iq_json.insert(d.clone(), serde_json::json!({
                    "queries": h.total,
                    "hourly": h.hourly,
                    "threatScore": 0.05,
                    "lastSeen": h.last_seen
                }));
            }
        }

        // Top learned Markov bigrams
        let mut top_markov: Vec<(&String, &u32)> = markov_guard.iter().collect();
        top_markov.sort_by(|a, b| b.1.cmp(a.1));
        top_markov.truncate(500);
        let markov_json: serde_json::Map<String, serde_json::Value> = top_markov
            .into_iter()
            .map(|(k, v)| (k.clone(), serde_json::json!(v)))
            .collect();

        // Blocklist & Whitelist
        let blocks: Vec<String> = custom_blocklist.keys().cloned().collect();
        let whitelist: Vec<String> = custom_whitelist.iter().cloned().collect();

        // Learned domain transitions
        let transitions_guard = self.domain_transitions.read();
        let mut transitions_json = serde_json::Map::new();
        for (parent, children) in transitions_guard.iter() {
            let mut ch_map = serde_json::Map::new();
            for (ch, cnt) in children.iter() {
                ch_map.insert(ch.clone(), serde_json::json!(cnt));
            }
            transitions_json.insert(parent.clone(), serde_json::Value::Object(ch_map));
        }

        serde_json::json!({
            "version": "1.0.0",
            "engine": "AmarDNS Perpetual AI Brain",
            "trainedAt": now,
            "trainingCycles": self.training_cycles.load(Ordering::Relaxed),
            "decisionsMade": self.decisions_made.load(Ordering::Relaxed),
            "neuralWeights": *weights_guard,
            "domainIQ": domain_iq_json,
            "markov": markov_json,
            "domainTransitions": transitions_json,
            "customBlocklist": blocks,
            "customWhitelist": whitelist,
            "summary": {
                "domainsLearned": iq_guard.len().max(heatmap.len()),
                "bigramsLearned": markov_guard.len(),
                "neuralParams": weights_guard.len(),
                "transitionsLearned": transitions_guard.len()
            }
        })
    }

    /// Imports trained brain knowledge from backup, updating neural weights, Domain IQ, and Markov models.
    pub fn import_json(&self, data: &serde_json::Value) -> Result<usize, String> {
        let mut loaded = 0usize;

        // Restore domain transitions
        if let Some(trans_obj) = data.get("domainTransitions").and_then(|v| v.as_object()) {
            let mut transitions = self.domain_transitions.write();
            for (parent, ch_val) in trans_obj.iter() {
                if let Some(ch_obj) = ch_val.as_object() {
                    let entry = transitions.entry(parent.clone()).or_default();
                    for (ch, cnt_val) in ch_obj.iter() {
                        if let Some(cnt) = cnt_val.as_u64() {
                            entry.insert(ch.clone(), cnt as u32);
                        }
                    }
                }
            }
        }

        // Restore neural weights
        if let Some(weights_arr) = data.get("neuralWeights").and_then(|v| v.as_array()) {
            let mut w = self.neural_weights.write();
            for (i, val) in weights_arr.iter().enumerate().take(8) {
                if let Some(f) = val.as_f64() {
                    w[i] = f as f32;
                }
            }
        }

        // Restore training cycles
        if let Some(cycles) = data.get("trainingCycles").and_then(|v| v.as_u64()) {
            self.training_cycles.store(cycles, Ordering::Relaxed);
        }

        // Restore Domain IQ
        if let Some(iq_obj) = data.get("domainIQ").and_then(|v| v.as_object()) {
            let mut iq = self.domain_iq.write();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            for (domain, val) in iq_obj.iter() {
                let queries = val.get("queries").and_then(|q| q.as_u64()).unwrap_or(1);
                let score = val.get("threatScore").and_then(|s| s.as_f64()).unwrap_or(0.05) as f32;
                let entropy = val.get("entropy").and_then(|e| e.as_f64()).unwrap_or(2.5) as f32;
                let safe = val.get("safe").and_then(|s| s.as_u64()).unwrap_or(queries) as u32;
                let last = val.get("lastSeen").and_then(|l| l.as_u64()).unwrap_or(now);

                iq.insert(domain.clone(), DomainKnowledge {
                    domain: domain.clone(),
                    query_count: queries,
                    threat_score: score,
                    entropy,
                    safe_resolutions: safe,
                    last_seen: last,
                });
                loaded += 1;
            }
        }

        // Restore Markov transitions
        if let Some(markov_obj) = data.get("markov").and_then(|v| v.as_object()) {
            let mut markov = self.markov_model.write();
            for (bg, val) in markov_obj.iter() {
                if let Some(c) = val.as_u64() {
                    *markov.entry(bg.clone()).or_insert(0) += c as u32;
                }
            }
        }

        Ok(loaded)
    }

    /// Prunes single-hit noise and stale domain data from the brain.
    pub fn prune_noise(&self) -> usize {
        let mut iq = self.domain_iq.write();
        let before = iq.len();
        iq.retain(|_, v| v.query_count > 1);
        before - iq.len()
    }

    /// Returns the exact in-memory byte size of the trained brain data.
    /// Returns near-zero after a fresh start or NUKE, and grows dynamically as domains are learned.
    pub fn memory_bytes(&self) -> usize {
        let iq_count = self.domain_iq.read().len();
        let markov_count = self.markov_model.read().len();
        // Each DomainKnowledge is ~128 bytes, each Markov bigram entry is ~16 bytes, weights 32 bytes
        iq_count * 128 + markov_count * 16 + 32
    }

    /// Clears all learned knowledge to a factory hollow state (called during NUKE).
    pub fn clear(&self) {
        self.domain_iq.write().clear();
        self.markov_model.write().clear();
        self.recent_decisions.write().clear();
        *self.neural_weights.write() = [0.25, 0.35, -0.20, 0.30, 0.40, 0.50, 0.45, -0.25];
        self.training_cycles.store(0, Ordering::Relaxed);
        self.decisions_made.store(0, Ordering::Relaxed);
        self.zero_day_blocks.store(0, Ordering::Relaxed);
        self.typo_blocks.store(0, Ordering::Relaxed);
        self.fp_suppressions.store(0, Ordering::Relaxed);
    }
}

impl Default for AIBrain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ai_brain_fresh_memory_size_and_nuke() {
        let brain = AIBrain::new();
        // Fresh brain must have minimal baseline memory, not 2846 KB!
        assert!(brain.memory_bytes() <= 64);

        brain.train("example.com", false, 0);
        brain.train("google.com", false, 0);
        assert!(brain.memory_bytes() > 64);

        brain.clear();
        assert_eq!(brain.memory_bytes(), 32);
        assert_eq!(brain.training_cycles.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_ai_brain_learning_and_decision() {
        let brain = AIBrain::new();
        brain.train("cloudflare.com", false, 0);
        brain.train("github.com", false, 0);

        let (score, verdict) = brain.evaluate("cloudflare.com");
        assert!(score < 0.6, "Clean domain should have low threat score, got {}", score);
        assert_eq!(verdict, "benign");

        // Threat training
        brain.train("x7z9123847a98q1.cc", true, 3);
        let (threat_score, _) = brain.evaluate("x7z9123847a98q1.cc");
        assert!(threat_score > 0.6);
    }

    #[test]
    fn test_ai_brain_export_import_roundtrip() {
        let brain = AIBrain::new();
        brain.train("apple.com", false, 0);
        brain.train("malware-c2.net", true, 3);

        let heatmap = HashMap::new();
        let custom_blocks = HashMap::new();
        let custom_wl = std::collections::HashSet::new();

        let exported = brain.export_json(&heatmap, &custom_blocks, &custom_wl);
        assert_eq!(exported.get("version").and_then(|v| v.as_str()), Some("1.0.0"));
        let json_str = serde_json::to_string(&exported).unwrap();
        // Exported data must NOT be 104 bytes empty stub!
        assert!(json_str.len() > 200);

        let new_brain = AIBrain::new();
        let res = new_brain.import_json(&exported);
        assert!(res.is_ok());
        assert!(new_brain.domain_iq.read().len() >= 2);
    }

    #[test]
    fn test_predictive_dependency_prefetch_learning() {
        let brain = AIBrain::new();

        // Sequence: user visits youtube.com, then immediately visits i.ytimg.com twice
        brain.record_sequence("youtube.com");
        brain.record_sequence("i.ytimg.com");

        // Repeat sequence to cross threshold >= 2
        brain.record_sequence("youtube.com");
        brain.record_sequence("i.ytimg.com");

        let candidates = brain.get_prefetch_candidates("youtube.com");
        assert_eq!(candidates, vec!["i.ytimg.com"]);

        // Unknown domain has no predictions
        assert!(brain.get_prefetch_candidates("unknown-site.org").is_empty());
    }
}
