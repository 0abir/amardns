use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub struct WalStorage {
    file_path: String,
    writer: Mutex<Option<File>>,
    total_records: AtomicU64,
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

        Self {
            file_path: path.to_string(),
            writer: Mutex::new(file),
            total_records: AtomicU64::new(0),
        }
    }

    pub fn load_lists(&self) -> (HashSet<String>, HashSet<String>, HashSet<String>) {
        let mut custom_blocks = HashSet::new();
        let mut custom_whitelists = HashSet::new();
        let mut custom_common = HashSet::new();
        let mut lines_count = 0u64;

        if let Ok(file) = File::open(&self.file_path) {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                lines_count += 1;
                let trimmed = line.trim();
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

    pub fn append_query(&self, qname: &str, qtype: u16, client_ip: &str, rcode: u16, lat_ms: u32, action: &str) {
        if let Ok(mut lock) = self.writer.lock() {
            if let Some(f) = lock.as_mut() {
                let _ = writeln!(f, "Q:{}:{}:{}:{}:{}:{}", qname, qtype, client_ip, rcode, lat_ms, action);
                let rec = self.total_records.fetch_add(1, Ordering::Relaxed) + 1;
                if rec % 20 == 0 {
                    let _ = f.flush();
                }
            }
        }
    }

    pub fn append_threat_event(&self, domain: &str, threat_type: &str, client_ip: &str) {
        if let Ok(mut lock) = self.writer.lock() {
            if let Some(f) = lock.as_mut() {
                let _ = writeln!(f, "T:{}:{}:{}", domain, threat_type, client_ip);
                let _ = f.flush();
                self.total_records.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn append_block(&self, domain: &str) {
        if let Ok(mut lock) = self.writer.lock() {
            if let Some(f) = lock.as_mut() {
                let _ = writeln!(f, "+B:{}", domain);
                let _ = f.flush();
                self.total_records.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn append_whitelist(&self, domain: &str) {
        if let Ok(mut lock) = self.writer.lock() {
            if let Some(f) = lock.as_mut() {
                let _ = writeln!(f, "+W:{}", domain);
                let _ = f.flush();
                self.total_records.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn append_unblock(&self, domain: &str) {
        if let Ok(mut lock) = self.writer.lock() {
            if let Some(f) = lock.as_mut() {
                let _ = writeln!(f, "-B:{}", domain);
                let _ = f.flush();
                self.total_records.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn append_unwhitelist(&self, domain: &str) {
        if let Ok(mut lock) = self.writer.lock() {
            if let Some(f) = lock.as_mut() {
                let _ = writeln!(f, "-W:{}", domain);
                let _ = f.flush();
                self.total_records.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn append_common(&self, domain: &str) {
        if let Ok(mut lock) = self.writer.lock() {
            if let Some(f) = lock.as_mut() {
                let _ = writeln!(f, "+C:{}", domain);
                let _ = f.flush();
                self.total_records.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn append_uncommon(&self, domain: &str) {
        if let Ok(mut lock) = self.writer.lock() {
            if let Some(f) = lock.as_mut() {
                let _ = writeln!(f, "-C:{}", domain);
                let _ = f.flush();
                self.total_records.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn total_records(&self) -> u64 {
        self.total_records.load(Ordering::Relaxed)
    }

    pub fn get_stats(&self) -> (u64, f64) {
        if let Ok(meta) = std::fs::metadata(&self.file_path) {
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
        let mut lock = match self.writer.lock() {
            Ok(l) => l,
            Err(_) => return,
        };

        let temp_path = format!("{}.tmp", self.file_path);
        let mut config_lines = Vec::new();
        let mut recent_events = std::collections::VecDeque::with_capacity(3000);

        if let Ok(file) = File::open(&self.file_path) {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
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

        let write_res: Result<(), std::io::Error> = (|| {
            let mut out = File::create(&temp_path)?;
            for cl in &config_lines {
                writeln!(out, "{}", cl)?;
            }
            for re in &recent_events {
                writeln!(out, "{}", re)?;
            }
            out.flush()?;
            Ok(())
        })();

        if write_res.is_ok() {
            *lock = None;
            let _ = std::fs::rename(&temp_path, &self.file_path);
            *lock = OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(&self.file_path)
                .ok();
            let new_count = (config_lines.len() + recent_events.len()) as u64;
            self.total_records.store(new_count, Ordering::Relaxed);
        } else {
            let _ = std::fs::remove_file(&temp_path);
        }
    }

    pub fn clear(&self) {
        if let Ok(mut lock) = self.writer.lock() {
            *lock = None;
            let _ = std::fs::write(&self.file_path, "");
            *lock = OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(&self.file_path)
                .ok();
            self.total_records.store(0, Ordering::Relaxed);
        }
    }
}
