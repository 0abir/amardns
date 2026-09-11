use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::mpsc;

// ─── Record-integrity checksum ────────────────────────────────────────────────

/// Compute a simple additive checksum over the bytes of a line for integrity validation.
/// Uses FNV-1a-inspired mixing to give each byte position weight.
fn line_checksum(line: &str) -> u32 {
    let mut h: u32 = 2166136261u32; // FNV offset basis
    for b in line.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(16777619u32); // FNV prime
    }
    h
}

// ─── WAL Entry types sent through the background channel ─────────────────────

#[derive(Debug)]
enum WalEntry {
    Query {
        qname: String,
        qtype: u16,
        client_ip: String,
        rcode: u16,
        lat_ms: u32,
        action: &'static str,
    },
    Threat {
        domain: String,
        threat_type: String,
        client_ip: String,
    },
}

// ─── Public WAL struct ────────────────────────────────────────────────────────

pub struct WalStorage {
    file_path: Arc<String>,
    writer: Arc<Mutex<Option<File>>>,
    total_records: Arc<AtomicU64>,
    /// Background write queue — DNS hot path sends here, never blocks.
    /// Bounded at 4096 entries (~400 KB peak backlog). Drops on full channel.
    queue_tx: mpsc::Sender<WalEntry>,
    /// Count of dropped telemetry entries when queue is full.
    pub dropped_entries: Arc<AtomicU64>,
    /// Set to `true` while compaction is in progress.  The background writer
    /// checks this flag before every flush and skips the flush if set, so that
    /// compaction can hold the writer lock without contention.
    compacting: Arc<AtomicBool>,
}

impl WalStorage {
    pub fn new(path: &str) -> Self {
        let parent = Path::new(path).parent();
        if let Some(p) = parent {
            let _ = std::fs::create_dir_all(p);
        }

        let file = match OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)
        {
            Ok(f) => Some(f),
            Err(e) => {
                tracing::error!("[wal] Failed to open WAL file at {}: {}", path, e);
                None
            }
        };

        let writer = Arc::new(Mutex::new(file));
        let total_records = Arc::new(AtomicU64::new(0));
        let dropped_entries = Arc::new(AtomicU64::new(0));
        let compacting = Arc::new(AtomicBool::new(false));

        // Bounded channel: 4096 entries × ~100 bytes avg = ~400 KB peak backlog
        let (tx, rx) = mpsc::channel::<WalEntry>(4096);

        // Spawn the background writer if running inside a Tokio runtime
        let writer_clone = Arc::clone(&writer);
        let total_clone = Arc::clone(&total_records);
        let compacting_clone = Arc::clone(&compacting);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(Self::background_writer(rx, writer_clone, total_clone, compacting_clone));
        }

        Self {
            file_path: Arc::new(path.to_string()),
            writer,
            total_records,
            queue_tx: tx,
            dropped_entries,
            compacting,
        }
    }

    /// Returns a cheaply cloneable reference (shares all Arc internals).
    pub fn clone_ref(&self) -> Self {
        Self {
            file_path: Arc::clone(&self.file_path),
            writer: Arc::clone(&self.writer),
            total_records: Arc::clone(&self.total_records),
            queue_tx: self.queue_tx.clone(),
            dropped_entries: Arc::clone(&self.dropped_entries),
            compacting: Arc::clone(&self.compacting),
        }
    }

    // ─── Background writer task ────────────────────────────────────────────────
    //
    // Batches WAL entries and flushes every 100ms OR every 50 entries.
    // Runs entirely on the Tokio thread pool — never blocks the async executor.
    //
    // Before each flush the task checks the `compacting` flag.  When compaction
    // is running it holds the writer Mutex for a potentially long time (disk I/O
    // + fsync).  By skipping the flush we avoid spinning on the lock and avoid
    // the compacted file being reopened while we are still trying to write old
    // batched entries into it.  Entries remain in `batch` and will be flushed
    // on the next tick once compaction finishes and the flag is cleared.
    async fn background_writer(
        mut rx: mpsc::Receiver<WalEntry>,
        writer: Arc<Mutex<Option<File>>>,
        total_records: Arc<AtomicU64>,
        compacting: Arc<AtomicBool>,
    ) {
        let mut batch: Vec<WalEntry> = Vec::with_capacity(64);
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                entry = rx.recv() => {
                    match entry {
                        Some(e) => {
                            batch.push(e);
                            // Drain the channel greedily up to batch_size=50 without waiting
                            while batch.len() < 50 {
                                match rx.try_recv() {
                                    Ok(e2) => batch.push(e2),
                                    Err(_) => break,
                                }
                            }
                            if batch.len() >= 50 {
                                // Skip flush while compaction holds the writer lock.
                                if !compacting.load(Ordering::Acquire) {
                                    Self::flush_batch(&mut batch, &writer, &total_records);
                                }
                            }
                        }
                        None => {
                            // Channel closed (app shutting down) — flush remaining entries
                            if !batch.is_empty() {
                                Self::flush_batch(&mut batch, &writer, &total_records);
                            }
                            break;
                        }
                    }
                }
                // Time-based flush: write whatever accumulated in the last 100ms
                _ = interval.tick() => {
                    if !batch.is_empty() {
                        // Skip flush while compaction holds the writer lock.
                        if !compacting.load(Ordering::Acquire) {
                            Self::flush_batch(&mut batch, &writer, &total_records);
                        }
                    }
                }
            }
        }
    }

    fn flush_batch(batch: &mut Vec<WalEntry>, writer: &Arc<Mutex<Option<File>>>, total: &Arc<AtomicU64>) {
        if let Ok(mut lock) = writer.lock() {
            if let Some(f) = lock.as_mut() {
                for entry in batch.iter() {
                    match entry {
                        WalEntry::Query { qname, qtype, client_ip, rcode, lat_ms, action } => {
                            let line = format!("Q:{}:{}:{}:{}:{}:{}", qname, qtype, client_ip, rcode, lat_ms, action);
                            let crc = line_checksum(&line);
                            let _ = writeln!(f, "{} #crc={:08x}", line, crc);
                        }
                        WalEntry::Threat { domain, threat_type, client_ip } => {
                            let line = format!("T:{}:{}:{}", domain, threat_type, client_ip);
                            let crc = line_checksum(&line);
                            let _ = writeln!(f, "{} #crc={:08x}", line, crc);
                        }
                    }
                }
                total.fetch_add(batch.len() as u64, Ordering::Relaxed);
                let _ = f.flush();
            }
        }
        batch.clear();
    }

    // ─── Hot-path append (non-blocking try_send) ───────────────────────────────

    /// Enqueues a DNS query log entry. Never blocks — drops on backpressure.
    pub fn append_query(&self, qname: &str, qtype: u16, client_ip: &str, rcode: u16, lat_ms: u32, action: &'static str) {
        let entry = WalEntry::Query {
            qname: qname.to_string(),
            qtype,
            client_ip: client_ip.to_string(),
            rcode,
            lat_ms,
            action,
        };
        if self.queue_tx.try_send(entry).is_err() {
            self.dropped_entries.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Enqueues a threat event. Never blocks — drops on backpressure.
    pub fn append_threat_event(&self, domain: &str, threat_type: &str, client_ip: &str) {
        let entry = WalEntry::Threat {
            domain: domain.to_string(),
            threat_type: threat_type.to_string(),
            client_ip: client_ip.to_string(),
        };
        if self.queue_tx.try_send(entry).is_err() {
            self.dropped_entries.fetch_add(1, Ordering::Relaxed);
        }
    }

    // ─── Config mutations (direct write — rare admin ops, must be durable) ─────

    pub fn append_block(&self, domain: &str) {
        if let Ok(mut lock) = self.writer.lock() {
            if let Some(f) = lock.as_mut() {
                let line = format!("+B:{}", domain);
                let crc = line_checksum(&line);
                let _ = writeln!(f, "{} #crc={:08x}", line, crc);
                let _ = f.flush();
                self.total_records.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn append_whitelist(&self, domain: &str) {
        if let Ok(mut lock) = self.writer.lock() {
            if let Some(f) = lock.as_mut() {
                let line = format!("+W:{}", domain);
                let crc = line_checksum(&line);
                let _ = writeln!(f, "{} #crc={:08x}", line, crc);
                let _ = f.flush();
                self.total_records.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn append_unblock(&self, domain: &str) {
        if let Ok(mut lock) = self.writer.lock() {
            if let Some(f) = lock.as_mut() {
                let line = format!("-B:{}", domain);
                let crc = line_checksum(&line);
                let _ = writeln!(f, "{} #crc={:08x}", line, crc);
                let _ = f.flush();
                self.total_records.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn append_unwhitelist(&self, domain: &str) {
        if let Ok(mut lock) = self.writer.lock() {
            if let Some(f) = lock.as_mut() {
                let line = format!("-W:{}", domain);
                let crc = line_checksum(&line);
                let _ = writeln!(f, "{} #crc={:08x}", line, crc);
                let _ = f.flush();
                self.total_records.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn append_common(&self, domain: &str) {
        if let Ok(mut lock) = self.writer.lock() {
            if let Some(f) = lock.as_mut() {
                let line = format!("+C:{}", domain);
                let crc = line_checksum(&line);
                let _ = writeln!(f, "{} #crc={:08x}", line, crc);
                let _ = f.flush();
                self.total_records.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn append_uncommon(&self, domain: &str) {
        if let Ok(mut lock) = self.writer.lock() {
            if let Some(f) = lock.as_mut() {
                let line = format!("-C:{}", domain);
                let crc = line_checksum(&line);
                let _ = writeln!(f, "{} #crc={:08x}", line, crc);
                let _ = f.flush();
                self.total_records.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    // ─── Stats and maintenance ─────────────────────────────────────────────────

    pub fn total_records(&self) -> u64 {
        self.total_records.load(Ordering::Relaxed)
    }

    pub fn load_lists(&self) -> (HashSet<String>, HashSet<String>, HashSet<String>) {
        let mut custom_blocks = HashSet::new();
        let mut custom_whitelists = HashSet::new();
        let mut custom_common = HashSet::new();
        let mut lines_count = 0u64;

        if let Ok(file) = File::open(self.file_path.as_str()) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                lines_count += 1;
                // Strip and verify checksum if present
                let (payload, crc_ok) = if let Some(idx) = line.rfind(" #crc=") {
                    let (body, crc_part) = line.split_at(idx);
                    let stored_crc = u32::from_str_radix(crc_part.trim_start_matches(" #crc="), 16).unwrap_or(0);
                    let computed = line_checksum(body);
                    if stored_crc != computed {
                        tracing::warn!("[wal] Skipping corrupt record (CRC mismatch): {:?}", &line[..line.len().min(60)]);
                        continue;
                    }
                    (body, true)
                } else {
                    // Legacy lines without CRC — accept as-is
                    (line.as_str(), false)
                };
                let _ = crc_ok; // suppress unused warning
                let trimmed = payload.trim();
                if let Some(domain) = trimmed.strip_prefix("+B:") {
                    custom_blocks.insert(domain.to_string());
                } else if let Some(domain) = trimmed.strip_prefix("-B:") {
                    custom_blocks.remove(domain);
                } else if let Some(domain) = trimmed.strip_prefix("+W:") {
                    custom_whitelists.insert(domain.to_string());
                } else if let Some(domain) = trimmed.strip_prefix("-W:") {
                    custom_whitelists.remove(domain);
                } else if let Some(domain) = trimmed.strip_prefix("+C:") {
                    custom_common.insert(domain.to_string());
                    custom_whitelists.insert(domain.to_string());
                } else if let Some(domain) = trimmed.strip_prefix("-C:") {
                    custom_common.remove(domain);
                    custom_whitelists.remove(domain);
                }
            }
        }

        self.total_records.store(lines_count, Ordering::Relaxed);
        (custom_blocks, custom_whitelists, custom_common)
    }

    pub fn get_stats(&self) -> (u64, f64) {
        if let Ok(meta) = std::fs::metadata(self.file_path.as_str()) {
            let bytes = meta.len();
            let mb = (bytes as f64 / (1024.0 * 1024.0) * 1000.0).round() / 1000.0;
            (bytes, mb)
        } else {
            (0, 0.0)
        }
    }

    pub fn maybe_compact(&self) {
        let (bytes, _) = self.get_stats();
        if bytes > 15 * 1024 * 1024 || self.total_records.load(Ordering::Relaxed) > 50_000 {
            self.compact();
        }
    }

    pub fn compact(&self) {
        // ── Step 1: Signal the background writer to back off ──────────────────
        //
        // Setting this flag *before* acquiring the lock means the background
        // writer will stop trying to flush (and therefore stop competing for
        // the Mutex) as soon as it notices the flag on its next iteration.
        // We use Release ordering so the store is visible to the background
        // writer's Acquire load before we take the lock.
        self.compacting.store(true, Ordering::Release);

        // ── Step 2: Acquire the writer lock ───────────────────────────────────
        let mut lock = match self.writer.lock() {
            Ok(l) => l,
            Err(_) => {
                // Poisoned mutex — clear the flag and bail.
                self.compacting.store(false, Ordering::Release);
                return;
            }
        };

        // Temp file is in the same directory as the WAL file so that
        // `rename()` is guaranteed to be an atomic OS-level operation
        // (same filesystem).
        let temp_path = format!("{}.tmp", self.file_path.as_str());
        let mut config_lines = Vec::new();
        let mut recent_events = std::collections::VecDeque::with_capacity(3000);

        if let Ok(file) = File::open(self.file_path.as_str()) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let trimmed = line.trim();
                if trimmed.starts_with("+B:")
                    || trimmed.starts_with("-B:")
                    || trimmed.starts_with("+W:")
                    || trimmed.starts_with("-W:")
                    || trimmed.starts_with("+C:")
                    || trimmed.starts_with("-C:")
                {
                    config_lines.push(line);
                } else if trimmed.starts_with("Q:") || trimmed.starts_with("T:") {
                    if recent_events.len() >= 3000 {
                        recent_events.pop_front();
                    }
                    recent_events.push_back(line);
                }
            }
        }

        // ── Step 3: Write compacted data to the temp file ─────────────────────
        let write_res: Result<(), std::io::Error> = (|| {
            let mut out = File::create(&temp_path)?;
            for cl in &config_lines {
                writeln!(out, "{}", cl)?;
            }
            for re in &recent_events {
                writeln!(out, "{}", re)?;
            }
            // Flush userspace buffers then call fsync so all data is durably
            // on disk before we rename.  If the process crashes after rename
            // the new WAL file is complete and consistent.
            out.flush()?;
            out.sync_all()?;
            Ok(())
        })();

        match write_res {
            Ok(()) => {
                // ── Step 4: Atomic rename ─────────────────────────────────────
                //
                // Close the current WAL before renaming so Windows (if ever
                // ported) doesn't complain about open file handles; on Linux
                // this is not strictly necessary but is tidy.
                *lock = None;
                if let Err(e) = std::fs::rename(&temp_path, self.file_path.as_str()) {
                    tracing::error!(
                        "[wal] compact: rename failed ({} -> {}): {}",
                        temp_path,
                        self.file_path.as_str(),
                        e
                    );
                    // The temp file is still intact; leave it for operator
                    // inspection.  Re-open the original (which still exists).
                }
                // Re-open the WAL file (now the compacted version) for appending.
                *lock = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .read(true)
                    .open(self.file_path.as_str())
                    .ok();
                let new_count = (config_lines.len() + recent_events.len()) as u64;
                self.total_records.store(new_count, Ordering::Relaxed);
            }
            Err(e) => {
                // ── Step 4 (error path): clean up orphan temp file ────────────
                tracing::error!(
                    "[wal] compact: failed to write/sync temp file {}: {}",
                    temp_path,
                    e
                );
                if let Err(re) = std::fs::remove_file(&temp_path) {
                    tracing::warn!(
                        "[wal] compact: could not remove orphan temp file {}: {}",
                        temp_path,
                        re
                    );
                }
                // The original WAL file is untouched; nothing to do for lock.
            }
        }

        // ── Step 5: Let the background writer resume ──────────────────────────
        self.compacting.store(false, Ordering::Release);
    }

    pub fn clear(&self) {
        if let Ok(mut lock) = self.writer.lock() {
            *lock = None;
            let _ = std::fs::write(self.file_path.as_str(), "");
            *lock = OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(self.file_path.as_str())
                .ok();
            self.total_records.store(0, Ordering::Relaxed);
        }
    }
}
