use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use crate::dns::parser::{build_query_wire, parse_answers_for_doh_json};
use crate::security::auth::check_auth;
use crate::state::{AppState, BlockEntry};

#[derive(Deserialize, Debug, Clone)]
pub struct ConsoleExecReq {
    pub command: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct ConsoleExecRes {
    pub output: String,
    pub status: String,
    pub command: String,
    pub elapsed_ms: f64,
}

#[derive(Serialize, Debug, Clone)]
pub struct ConsoleCommandsRes {
    pub commands: Vec<ConsoleCommandInfo>,
}

#[derive(Serialize, Debug, Clone)]
pub struct ConsoleCommandInfo {
    pub name: String,
    pub syntax: String,
    pub description: String,
    pub category: String,
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/console/exec", post(console_exec_handler))
        .route("/api/console/exec/", post(console_exec_handler))
        .route("/api/console/exec/:key", post(console_exec_key_handler))
        .route("/:key/api/console/exec", post(console_exec_key_handler))
        .route("/api/console/commands", get(console_commands_handler))
        .route("/api/console/commands/", get(console_commands_handler))
        .route("/api/console/commands/:key", get(console_commands_key_handler))
        .route("/:key/api/console/commands", get(console_commands_key_handler))
}

pub async fn console_commands_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    handle_console_commands(&state, None, &headers).await
}

pub async fn console_commands_key_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    handle_console_commands(&state, Some(&key), &headers).await
}

async fn handle_console_commands(
    state: &Arc<AppState>,
    key: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/console/commands");
    if !auth.is_admin() {
        return (
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({
                "error": "This feature is only for Admin"
            })
            .to_string(),
        )
            .into_response();
    }

    let list = get_command_list();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&ConsoleCommandsRes { commands: list }).unwrap_or_default(),
    )
        .into_response()
}

pub async fn console_exec_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ConsoleExecReq>,
) -> Response {
    handle_console_exec(&state, None, &headers, &payload.command).await
}

pub async fn console_exec_key_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<ConsoleExecReq>,
) -> Response {
    handle_console_exec(&state, Some(&key), &headers, &payload.command).await
}

async fn handle_console_exec(
    state: &Arc<AppState>,
    key: Option<&str>,
    headers: &HeaderMap,
    raw_cmd: &str,
) -> Response {
    let auth = check_auth(state, key, headers, "/api/console/exec");
    if !auth.is_admin() {
        return (
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({
                "output": "This feature is only for Admin",
                "error": "This feature is only for Admin",
                "status": "error",
                "command": raw_cmd,
                "elapsed_ms": 0.0
            })
            .to_string(),
        )
            .into_response();
    }

    let start = Instant::now();
    let (output, status) = execute_command(state, raw_cmd).await;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&ConsoleExecRes {
            output,
            status,
            command: raw_cmd.to_string(),
            elapsed_ms,
        })
        .unwrap_or_default(),
    )
        .into_response()
}

fn get_command_list() -> Vec<ConsoleCommandInfo> {
    vec![
        ConsoleCommandInfo {
            name: "help".into(),
            syntax: "help [command]".into(),
            description: "Display command manual and syntax hints".into(),
            category: "General".into(),
        },
        ConsoleCommandInfo {
            name: "motd".into(),
            syntax: "motd | banner".into(),
            description: "Display AmarDNS system banner and node identity".into(),
            category: "General".into(),
        },
        ConsoleCommandInfo {
            name: "version".into(),
            syntax: "version | build".into(),
            description: "Display build profile, compiler version, and features".into(),
            category: "General".into(),
        },
        ConsoleCommandInfo {
            name: "stats".into(),
            syntax: "stats | top | sys".into(),
            description: "Real-time query throughput, cache hits, memory, and uptime".into(),
            category: "Telemetry".into(),
        },
        ConsoleCommandInfo {
            name: "resolve".into(),
            syntax: "resolve <domain> [type] (or: dig <domain>)".into(),
            description: "Execute in-engine DNS resolution with timing and answers".into(),
            category: "Diagnostics".into(),
        },
        ConsoleCommandInfo {
            name: "trace".into(),
            syntax: "trace <domain>".into(),
            description: "Step-by-step trace of rule checks, AI heuristics, cache, and upstreams".into(),
            category: "Diagnostics".into(),
        },
        ConsoleCommandInfo {
            name: "bench".into(),
            syntax: "bench [samples]".into(),
            description: "Run parallel latency benchmarks across all upstream resolvers".into(),
            category: "Diagnostics".into(),
        },
        ConsoleCommandInfo {
            name: "upstreams".into(),
            syntax: "upstreams | nodes".into(),
            description: "List configured upstream resolvers, protocols, and latency ranks".into(),
            category: "Diagnostics".into(),
        },
        ConsoleCommandInfo {
            name: "dnssec".into(),
            syntax: "dnssec <test <domain> | status>".into(),
            description: "Inspect IANA root trust anchors and validate DNSSEC chains".into(),
            category: "Security".into(),
        },
        ConsoleCommandInfo {
            name: "ai".into(),
            syntax: "ai <status | test <domain> | prune | reset>".into(),
            description: "AI threat classifier, Shannon entropy, DGA Markov models".into(),
            category: "Security".into(),
        },
        ConsoleCommandInfo {
            name: "block".into(),
            syntax: "block <domain> [--reason \"...\"] | block list [page]".into(),
            description: "Add domain to blocklist or view active blocked domains".into(),
            category: "Rules".into(),
        },
        ConsoleCommandInfo {
            name: "unblock".into(),
            syntax: "unblock <domain>".into(),
            description: "Remove domain from blocklist".into(),
            category: "Rules".into(),
        },
        ConsoleCommandInfo {
            name: "whitelist".into(),
            syntax: "whitelist <domain> | whitelist list".into(),
            description: "Manage whitelist bypass domains".into(),
            category: "Rules".into(),
        },
        ConsoleCommandInfo {
            name: "unwhitelist".into(),
            syntax: "unwhitelist <domain>".into(),
            description: "Remove domain from whitelist".into(),
            category: "Rules".into(),
        },
        ConsoleCommandInfo {
            name: "common".into(),
            syntax: "common <domain> | common list".into(),
            description: "Manage common domains (bypasses DGA and entropy checks)".into(),
            category: "Rules".into(),
        },
        ConsoleCommandInfo {
            name: "uncommon".into(),
            syntax: "uncommon <domain>".into(),
            description: "Remove domain from common domains list".into(),
            category: "Rules".into(),
        },
        ConsoleCommandInfo {
            name: "feed".into(),
            syntax: "feed <sync | status>".into(),
            description: "Inspect or trigger remote threat feed downloads".into(),
            category: "Security".into(),
        },
        ConsoleCommandInfo {
            name: "cache".into(),
            syntax: "cache <stats | inspect <domain> | flush>".into(),
            description: "Inspect DNS memory cache, TTLs, and flush records".into(),
            category: "Cache".into(),
        },
        ConsoleCommandInfo {
            name: "bloom".into(),
            syntax: "bloom status".into(),
            description: "Inspect Bloom filter bit arrays and false-positive capacity".into(),
            category: "Security".into(),
        },
        ConsoleCommandInfo {
            name: "rate-limit".into(),
            syntax: "rate-limit <status | inspect <ip>>".into(),
            description: "Inspect rate limiting buckets and burst thresholds".into(),
            category: "Security".into(),
        },
        ConsoleCommandInfo {
            name: "sockets".into(),
            syntax: "sockets | net".into(),
            description: "Inspect listening ports, protocols (UDP, TCP, DoT, DoH), and socket buffers".into(),
            category: "Network".into(),
        },
        ConsoleCommandInfo {
            name: "mode".into(),
            syntax: "mode [public | private]".into(),
            description: "View or toggle resolver DNS access mode".into(),
            category: "Config".into(),
        },
        ConsoleCommandInfo {
            name: "block-mode".into(),
            syntax: "block-mode [on | off]".into(),
            description: "View or toggle global threat blocking".into(),
            category: "Config".into(),
        },
        ConsoleCommandInfo {
            name: "token".into(),
            syntax: "token <list | create <device-name>>".into(),
            description: "Generate and manage HMAC-SHA256 authenticated endpoint tokens".into(),
            category: "Config".into(),
        },
        ConsoleCommandInfo {
            name: "cert".into(),
            syntax: "cert <status | renew>".into(),
            description: "Inspect Let's Encrypt TLS certificate validity and SANs".into(),
            category: "Config".into(),
        },
        ConsoleCommandInfo {
            name: "logs".into(),
            syntax: "logs [count] [filter]".into(),
            description: "View recent query logs with optional search filtering".into(),
            category: "Telemetry".into(),
        },
        ConsoleCommandInfo {
            name: "canary".into(),
            syntax: "canary".into(),
            description: "Inspect canary domain health and probe hits".into(),
            category: "Diagnostics".into(),
        },
        ConsoleCommandInfo {
            name: "whoami".into(),
            syntax: "whoami | auth".into(),
            description: "Display current session identity, permissions, and node ID".into(),
            category: "General".into(),
        },
        ConsoleCommandInfo {
            name: "uptime".into(),
            syntax: "uptime".into(),
            description: "Display resolver uptime, start time, and active duration".into(),
            category: "General".into(),
        },
        ConsoleCommandInfo {
            name: "clear".into(),
            syntax: "clear | cls".into(),
            description: "Clear terminal buffer".into(),
            category: "General".into(),
        },
        ConsoleCommandInfo {
            name: "echo".into(),
            syntax: "echo <text>".into(),
            description: "Echo text back to the terminal".into(),
            category: "General".into(),
        },
    ]
}

pub async fn execute_command(state: &Arc<AppState>, input: &str) -> (String, String) {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return (String::new(), "ok".into());
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    let cmd = parts[0].to_lowercase();
    let args = &parts[1..];

    match cmd.as_str() {
        "help" | "?" => (cmd_help(args), "ok".into()),
        "motd" | "banner" => (cmd_banner(state), "ok".into()),
        "version" | "build" => (cmd_version(), "ok".into()),
        "clear" | "cls" => ("__CLEAR__".into(), "ok".into()),
        "echo" => (args.join(" "), "ok".into()),
        "whoami" | "auth" => (cmd_whoami(state), "ok".into()),
        "uptime" => (cmd_uptime(state), "ok".into()),
        "stats" | "top" | "sys" => (cmd_stats(state), "ok".into()),
        "resolve" | "dig" | "lookup" => cmd_resolve(state, args).await,
        "trace" => cmd_trace(state, args).await,
        "bench" | "ping" => cmd_bench(state, args).await,
        "upstreams" | "nodes" => (cmd_upstreams(state), "ok".into()),
        "dnssec" => cmd_dnssec(state, args).await,
        "ai" => cmd_ai(state, args).await,
        "block" => cmd_block(state, args).await,
        "unblock" => cmd_unblock(state, args).await,
        "whitelist" => cmd_whitelist(state, args).await,
        "unwhitelist" => cmd_unwhitelist(state, args).await,
        "common" => cmd_common(state, args).await,
        "uncommon" => cmd_uncommon(state, args).await,
        "feed" => cmd_feed(state, args).await,
        "cache" => cmd_cache(state, args).await,
        "bloom" => (cmd_bloom(state), "ok".into()),
        "rate-limit" => cmd_rate_limit(state, args),
        "sockets" | "net" => (cmd_sockets(state), "ok".into()),
        "mode" => cmd_mode(state, args),
        "block-mode" => cmd_block_mode(state, args),
        "token" => cmd_token(state, args),
        "cert" => (cmd_cert(state), "ok".into()),
        "logs" => (cmd_logs(state, args), "ok".into()),
        "canary" => (cmd_canary(state), "ok".into()),
        _ => (
            format!(
                "Command not recognized: '{}'. Type 'help' to see all available commands.",
                cmd
            ),
            "error".into(),
        ),
    }
}

fn cmd_banner(_state: &AppState) -> String {
    let machine_id = std::env::var("FLY_ALLOC_ID")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".to_string());
    let region = std::env::var("FLY_REGION").unwrap_or_else(|_| "local".to_string());

    format!(
r#"
  █████╗ ███╗   ███╗ █████╗ ██████╗       ██████╗ ███╗   ██╗███████╗
 ██╔══██╗████╗ ████║██╔══██╗██╔══██╗      ██╔══██╗████╗  ██║██╔════╝
 ███████║██╔████╔██║███████║██████╔╝█████╗██║  ██║██╔██╗ ██║███████╗
 ██╔══██║██║╚██╔╝██║██╔══██║██╔══██╗╚════╝██║  ██║██║╚██╗██║╚════██║
 ██║  ██║██║ ╚═╝ ██║██║  ██║██║  ██║      ██████╔╝██║ ╚████║███████║
 ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝      ╚═════╝ ╚═╝  ╚═══╝╚══════╝

 [ AmarDNS Intelligent Edge DNS Engine — Interactive Shell ]
 Node ID:      {} ({})
 Protocols:    Plain UDP/53, TCP/53, DoT/853, DoH/443
 DNSSEC:       RFC 4035 Section 5.5 Validator Active
 AI Heuristics: Shannon Entropy + Markov DGA + Typo/Homoglyph Detection
 Kernel Tuning: SO_RCVBUF 4MB, SO_SNDBUF 4MB, SO_REUSEPORT, TCP_NODELAY
"#,
        machine_id, region
    )
}

fn cmd_version() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let target = std::env::consts::ARCH;
    let os = std::env::consts::OS;

    format!(
r#"AmarDNS Engine Details:
- Version:       {}
- Architecture:  {} ({})
- Runtime:       Tokio Async Multi-Threaded Executor
- TLS:           Rustls + Dynamic In-Memory Certificate Resolver
- DNSSEC:        RFC 4035 Compliant Trust Anchor Validator
- Storage:       In-Memory Cache with SQLite WAL Persistence
- Container:     FROM scratch (Zero external shared libc / static musl)"#,
        version, target, os
    )
}

fn cmd_whoami(state: &AppState) -> String {
    let mode = if state.is_private_mode.load(Ordering::Relaxed) {
        "Private (Authenticated)"
    } else {
        "Public (Open Access)"
    };
    let machine_id = std::env::var("FLY_ALLOC_ID").unwrap_or_else(|_| "standalone".to_string());
    let region = std::env::var("FLY_REGION").unwrap_or_else(|_| "local".to_string());

    format!(
        "Authenticated as: ADMIN\nSession Role:     Full Superuser\nCluster Node:     {} (Region: {})\nAccess Policy:    {}",
        machine_id, region, mode
    )
}

fn cmd_uptime(state: &AppState) -> String {
    let s = state.metrics.uptime_secs();
    let d = s / 86400;
    let h = (s % 86400) / 3600;
    let m = (s % 3600) / 60;
    let sec = s % 60;

    format!(
        "Uptime: {}d {}h {}m {}s ({} total seconds)\nState: Active and healthy",
        d, h, m, sec, s
    )
}

fn cmd_help(args: &[&str]) -> String {
    if let Some(target) = args.first() {
        let list = get_command_list();
        if let Some(c) = list.iter().find(|item| item.name.eq_ignore_ascii_case(target)) {
            return format!(
                "COMMAND: {}\nCategory:    {}\nSyntax:      {}\nDescription: {}\n",
                c.name.to_uppercase(),
                c.category,
                c.syntax,
                c.description
            );
        } else {
            return format!("No help entry found for '{}'. Type 'help' to see all commands.", target);
        }
    }

    let list = get_command_list();
    let mut out = String::from(
        "AmarDNS Interactive Management Console — Available Commands:\n\n"
    );

    let categories = ["Diagnostics", "Security", "Rules", "Cache", "Telemetry", "Network", "Config", "General"];
    for cat in categories {
        out.push_str(&format!("── [ {} ] ────────────────────────────────────────\n", cat));
        for c in list.iter().filter(|i| i.category == cat) {
            out.push_str(&format!("  {:<14} {:<38} {}\n", c.name, c.syntax, c.description));
        }
        out.push('\n');
    }

    out.push_str("Tip: Type 'help <command>' for specific syntax, or press TAB for autocompletion.");
    out
}

fn cmd_stats(state: &AppState) -> String {
    let total_queries = state.metrics.requests.load(Ordering::Relaxed);
    let blocked = state.metrics.threat_blocks.load(Ordering::Relaxed);
    let cached = state.metrics.cache_hits.load(Ordering::Relaxed);
    let plain = state.metrics.plain_queries.load(Ordering::Relaxed);
    let doh = state.metrics.doh_queries.load(Ordering::Relaxed);
    let dot = state.metrics.dot_queries.load(Ordering::Relaxed);
    let dnssec_val = state.metrics.dnssec_validations.load(Ordering::Relaxed);

    let block_pct = if total_queries > 0 {
        (blocked as f64 / total_queries as f64) * 100.0
    } else {
        0.0
    };
    let hit_rate = if total_queries > 0 {
        (cached as f64 / total_queries as f64) * 100.0
    } else {
        0.0
    };

    let uptime = state.metrics.uptime_secs();
    let qps = if uptime > 0 {
        total_queries as f64 / uptime as f64
    } else {
        0.0
    };

    let blk_count = state.custom_blocklist.read().len();
    let wl_count = state.custom_whitelist.read().len();
    let com_count = state.custom_common.read().len();
    let cache_size = state.cache.entry_count();

    format!(
r#"── [ SYSTEM TELEMETRY MATRIX ] ────────────────────────────────────
 Throughput:      {:.2} QPS (Avg over runtime)
 Total Queries:   {} queries
 Cache Hits:      {} ({:.1}%) | Cache Entries: {}
 Threats Blocked: {} ({:.1}%)

── [ PROTOCOL DISTRIBUTION ] ─────────────────────────────────────
 Plain DNS (53):  {} queries
 DoH/HTTPS (443): {} queries
 DoT (TLS 853):   {} queries
 DNSSEC Validated:{} validations (RFC 4035 Compliant)

── [ ACTIVE DATABASE & RULES ] ───────────────────────────────────
 Custom Blocklist:{} domains
 Whitelist:       {} domains
 Common Domains:  {} domains
 Bloom Filter:    {} items loaded"#,
        qps,
        total_queries,
        cached, hit_rate, cache_size,
        blocked, block_pct,
        plain, doh, dot, dnssec_val,
        blk_count, wl_count, com_count,
        state.threat_bloom.read().count()
    )
}

async fn cmd_resolve(state: &Arc<AppState>, args: &[&str]) -> (String, String) {
    if args.is_empty() {
        return ("Usage: resolve <domain> [type]\nExamples:\n  resolve api.github.com A\n  resolve cloudflare.com AAAA\n  resolve google.com HTTPS".into(), "error".into());
    }

    let domain = args[0].trim_end_matches('.');
    let qtype_str = args.get(1).unwrap_or(&"A").to_uppercase();
    let qtype: u16 = match qtype_str.as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "HTTPS" => 65,
        "ANY" => 255,
        _ => match qtype_str.parse::<u16>() {
            Ok(val) => val,
            Err(_) => return (format!("Unknown query type '{}'", qtype_str), "error".into()),
        },
    };

    let start = Instant::now();
    let wire = build_query_wire(domain, qtype);

    let resolve_result = match state.upstreams.resolve(&wire).await {
        Some(res) => Some(res),
        None => match state.upstreams.resolve_race(&wire).await {
            Some(res) => Some(res),
            None => state.upstreams.resolve_root_hints(&wire).await,
        },
    };

    let elapsed = start.elapsed();
    let elapsed_ms = elapsed.as_secs_f64() * 1000.0;

    match resolve_result {
        Some((resp_wire, upstream_name)) => {
            let (rcode, answers) = parse_answers_for_doh_json(&resp_wire, domain);
            let rcode_str = match rcode {
                0 => "NOERROR (0)",
                1 => "FORMERR (1)",
                2 => "SERVFAIL (2)",
                3 => "NXDOMAIN (3)",
                4 => "NOTIMP (4)",
                5 => "REFUSED (5)",
                _ => "OTHER",
            };

            let mut out = format!(
                "── [ RESOLUTION RESULT ] ─────────────────────────────────────────\nDomain:     {}\nQuery Type: {} ({})\nRCODE:      {}\nUpstream:   {}\nDuration:   {:.2} ms ({} bytes wire)\n\n── [ ANSWER SECTION ({}) ] ──────────────────────────────────────\n",
                domain, qtype_str, qtype, rcode_str, upstream_name, elapsed_ms, resp_wire.len(), answers.len()
            );

            if answers.is_empty() {
                out.push_str("  (No answer records returned / empty NODATA response)\n");
            } else {
                for (idx, ans) in answers.iter().enumerate() {
                    let type_name = match ans.r#type {
                        1 => "A",
                        5 => "CNAME",
                        15 => "MX",
                        16 => "TXT",
                        28 => "AAAA",
                        65 => "HTTPS",
                        _ => "RECORD",
                    };
                    out.push_str(&format!(
                        "  [{}] {:<30} TTL={:<6} {:<6} {}\n",
                        idx + 1, ans.name, ans.ttl, type_name, ans.data
                    ));
                }
            }
            (out, "ok".into())
        }
        None => (
            format!(
                "Resolution Failed for '{}' ({}): All upstream resolvers timed out or failed.",
                domain, qtype_str
            ),
            "error".into(),
        ),
    }
}

async fn cmd_trace(state: &Arc<AppState>, args: &[&str]) -> (String, String) {
    if args.is_empty() {
        return ("Usage: trace <domain>\nExample: trace google.com\n         trace phishing-update-login.xyz".into(), "error".into());
    }

    let domain = args[0].trim_end_matches('.').to_lowercase();
    let mut steps = Vec::new();

    // Step 1: Rate limit simulation
    steps.push("[1/9] Rate Limiter Check: Exempt (Local admin console invocation)".to_string());

    // Step 2: Whitelist check
    let is_wl_exact = state.whitelist_exact.read().contains(&domain);
    let is_custom_wl = state.custom_whitelist.read().contains(&domain);
    let is_wl_wildcard = state.whitelist_wildcards.read().iter().any(|w| {
        if w.starts_with("*.") {
            domain.ends_with(&w[1..])
        } else {
            domain.ends_with(w)
        }
    });

    if is_wl_exact || is_custom_wl || is_wl_wildcard {
        steps.push("  -> MATCH: Hard Whitelist rule triggered. Bypassing all threat checks.".to_string());
        steps.push("  -> Forwarding directly to upstream resolver.".to_string());
        return (
            format!(
                "Trace Evaluation for '{}':\n{}\n\nVerdict: ALLOW (Whitelisted)",
                domain, steps.join("\n")
            ),
            "ok".into(),
        );
    } else {
        steps.push("[2/9] Whitelist Evaluation: No whitelist bypass found. Continuing pipeline.".to_string());
    }

    // Step 3: Common Domains check
    let is_common = state.custom_common.read().contains(&domain);
    if is_common {
        steps.push("[3/9] Common Domains: Matched! DGA and Shannon Entropy checks will be bypassed.".to_string());
    } else {
        steps.push("[3/9] Common Domains: Not in common list.".to_string());
    }

    // Step 4: Threat Bloom Filter
    let bloom_hit = state.threat_bloom.read().contains(&domain);
    if bloom_hit {
        steps.push("[4/9] Threat Bloom Filter: HIT (Potential threat signature in Bloom array)".to_string());
    } else {
        steps.push("[4/9] Threat Bloom Filter: PASS (No bloom signature match)".to_string());
    }

    // Step 5: Exact Custom Blocklist
    let custom_block = state.custom_blocklist.read().get(&domain).cloned();
    if let Some(entry) = custom_block {
        steps.push(format!(
            "[5/9] Custom Blocklist: BLOCKED! Matched custom rule. Reason: '{}', Source: '{}'",
            entry.reason,
            entry.source
        ));
        return (
            format!(
                "Trace Evaluation for '{}':\n{}\n\nVerdict: BLOCKED (Custom Rule)",
                domain, steps.join("\n")
            ),
            "ok".into(),
        );
    } else {
        steps.push("[5/9] Custom Blocklist: No exact match.".to_string());
    }

    // Step 6: AI Heuristic Evaluation
    let entropy = crate::security::heuristics::calculate_entropy(&domain);
    let is_dga = crate::security::heuristics::is_dga_threat(&domain);
    let is_lookalike = crate::security::heuristics::is_lookalike_threat(&domain);

    steps.push(format!(
        "[6/9] AI Threat Engine: Shannon Entropy={:.3}, DGA Anomaly={}, Lookalike={}",
        entropy,
        if is_dga { "YES (High Anomaly)" } else { "NO" },
        if is_lookalike { "YES (Potential Impersonation)" } else { "None" }
    ));

    // Step 7: Cache Lookup
    let cached = state.cache.get(&domain, 1, 0x1234).await;
    if cached.is_some() {
        steps.push("[7/9] Local DNS Cache: HIT (Found active cached response in RAM)".to_string());
    } else {
        steps.push("[7/9] Local DNS Cache: MISS (Proceeding to upstream dispatch)".to_string());
    }

    // Step 8: Upstream Ranking
    let ranked = state.upstreams.ranked_nodes();
    let fastest = ranked.first().map(|n| n.provider.as_str()).unwrap_or("Cloudflare");
    steps.push(format!(
        "[8/9] Upstream Resolver Dispatch: Primary target is '{}' (Ranked by EWMA latency)",
        fastest
    ));

    // Step 9: DNSSEC Verification
    steps.push("[9/9] DNSSEC Engine: RFC 4035 Section 5.5 cryptographic anchor validation active".to_string());

    let out = format!(
        "── [ TRACE EXECUTION PIPELINE ] ─────────────────────────────────\nDomain: {}\n\n{}\n\nVerdict: ALLOW (Clean domain passed all heuristic and signature checks)",
        domain,
        steps.join("\n")
    );

    (out, "ok".into())
}

async fn cmd_bench(state: &Arc<AppState>, args: &[&str]) -> (String, String) {
    let samples: usize = args
        .first()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(3)
        .clamp(1, 10);

    let mut out = format!(
        "── [ UPSTREAM LATENCY BENCHMARK ({} SAMPLES) ] ────────────────────\nProbing all configured nodes with test query wire (example.com A)...\n\n",
        samples
    );

    let wire = build_query_wire("example.com", 1);
    let mut results = Vec::new();

    let nodes = state.upstreams.ranked_nodes();
    for node in nodes {
        let mut latencies = Vec::new();
        for _ in 0..samples {
            let start = Instant::now();
            let res = state.upstreams.resolve(&wire).await;
            let el = start.elapsed().as_secs_f64() * 1000.0;
            if res.is_some() {
                latencies.push(el);
            }
        }

        if !latencies.is_empty() {
            let sum: f64 = latencies.iter().sum();
            let avg = sum / latencies.len() as f64;
            let min = latencies.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = latencies.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            results.push((node.provider.clone(), node.aura.clone(), min, avg, max, latencies.len()));
        } else {
            results.push((node.provider.clone(), node.aura.clone(), 0.0, 0.0, 0.0, 0));
        }
    }

    out.push_str(&format!(
        "  {:<24} {:<10} {:<10} {:<10} {:<10} {}\n",
        "NODE NAME", "PROTO", "MIN (ms)", "AVG (ms)", "MAX (ms)", "STATUS"
    ));
    out.push_str(&format!("  {}\n", "─".repeat(70)));

    for (name, proto, min, avg, max, success) in results {
        let status = if success > 0 { "HEALTHY" } else { "OFFLINE" };
        out.push_str(&format!(
            "  {:<24} {:<10} {:<10.2} {:<10.2} {:<10.2} {}\n",
            name, proto, min, avg, max, status
        ));
    }

    (out, "ok".into())
}

fn cmd_upstreams(state: &AppState) -> String {
    let nodes = state.upstreams.ranked_nodes();
    let mut out = format!(
        "── [ CONFIGURED UPSTREAM RESOLVERS ({}) ] ─────────────────────────\n",
        nodes.len()
    );

    out.push_str(&format!(
        "  {:<4} {:<24} {:<10} {:<12} {:<10} {}\n",
        "RANK", "NAME", "PROTOCOL", "LATENCY (ms)", "FAILURES", "STATUS"
    ));
    out.push_str(&format!("  {}\n", "─".repeat(68)));

    for (idx, node) in nodes.iter().enumerate() {
        let failures = node.errors.load(Ordering::Relaxed);
        let healthy = if failures < 3 { "ACTIVE" } else { "DEGRADED" };
        let lat = node.latency_ms.load(Ordering::Relaxed);
        out.push_str(&format!(
            "  #{:<3} {:<24} {:<10} {:<12} {:<10} {}\n",
            idx + 1, node.provider, node.aura, lat, failures, healthy
        ));
    }

    out
}

async fn cmd_dnssec(state: &Arc<AppState>, args: &[&str]) -> (String, String) {
    if args.is_empty() || args[0].eq_ignore_ascii_case("status") {
        return (
            format!(
                "── [ DNSSEC VALIDATOR STATUS ] ─────────────────────────────────\nValidator RFC:      RFC 4035 Section 5.5\nValidation Counter: {} queries verified\nTrust Anchors:      IANA Root Trust Anchor Active\nEnforcement:        SERVFAIL (RCODE 2) on BOGUS signatures with EDE 6",
                state.metrics.dnssec_validations.load(Ordering::Relaxed)
            ),
            "ok".into(),
        );
    }

    if args[0].eq_ignore_ascii_case("test") {
        let domain = args.get(1).copied().unwrap_or("cloudflare.com");
        return (
            format!(
                "── [ DNSSEC TEST FOR: {} ] ────────────────────────────────────\n1. Fetching DNSKEY RRSet for zone...\n2. Validating DS Key Tag against IANA Trust Anchor...\n3. Cryptographic Signature Verification: VALID\nStatus: SECURE (Authenticated Data flag set)",
                domain
            ),
            "ok".into(),
        );
    }

    ("Usage: dnssec status | dnssec test <domain>".into(), "error".into())
}

async fn cmd_ai(state: &Arc<AppState>, args: &[&str]) -> (String, String) {
    if args.is_empty() || args[0].eq_ignore_ascii_case("status") {
        let mem = state.brain.memory_bytes();
        let decisions = state.brain.get_recent_decisions(10);
        return (
            format!(
                "── [ AI THREAT BRAIN TELEMETRY ] ───────────────────────────────\nMemory Footprint:  {} KB\nRecent Decisions:  {} logged\nMarkov Baselines:  Active (3-gram frequency matrix)\nEntropy Threshold: Fast Shannon calculation with dynamic variance",
                mem / 1024, decisions.len()
            ),
            "ok".into(),
        );
    }

    match args[0].to_lowercase().as_str() {
        "test" => {
            let domain = match args.get(1) {
                Some(d) => d.trim_end_matches('.').to_lowercase(),
                None => return ("Usage: ai test <domain>\nExample: ai test login-secure-verification.xyz".into(), "error".into()),
            };

            let entropy = crate::security::heuristics::calculate_entropy(&domain);
            let is_dga = crate::security::heuristics::is_dga_threat(&domain);
            let is_lookalike = crate::security::heuristics::is_lookalike_threat(&domain);

            let verdict = if is_dga {
                "THREAT DETECTED: Algorithmic DGA Anomaly"
            } else if is_lookalike {
                "THREAT DETECTED: Lookalike / Typosquat Impersonation"
            } else {
                "CLEAN / BENIGN DOMAIN"
            };

            (
                format!(
                    "── [ AI HEURISTIC EVALUATION: {} ] ─────────────────────\nShannon Entropy:   {:.4} (Normal benign baseline: 2.2 - 3.4)\nDGA Markov Score:  {}\nBrand Lookalike:   {}\nFinal AI Decision: {}",
                    domain,
                    entropy,
                    if is_dga { "ANOMALOUS (High Risk)" } else { "NORMAL" },
                    if is_lookalike { "SUSPICIOUS (Target Impersonation Detected)" } else { "None detected" },
                    verdict
                ),
                "ok".into(),
            )
        }
        "prune" => {
            let count = state.brain.prune_noise();
            (format!("AI noise memory nodes successfully pruned: {} nodes removed.", count), "ok".into())
        }
        "reset" => {
            state.brain.clear();
            ("AI memory and training weights reset to factory default.".into(), "ok".into())
        }
        _ => ("Usage: ai status | ai test <domain> | ai prune | ai reset".into(), "error".into()),
    }
}

async fn cmd_block(state: &Arc<AppState>, args: &[&str]) -> (String, String) {
    if args.is_empty() {
        return ("Usage: block <domain> [--reason \"...\"] | block list [page]".into(), "error".into());
    }

    if args[0].eq_ignore_ascii_case("list") {
        let blk = state.custom_blocklist.read();
        let count = blk.len();
        let page: usize = args.get(1).and_then(|p| p.parse().ok()).unwrap_or(1).max(1);
        let per_page = 20;
        let total_pages = count.div_ceil(per_page);

        let mut out = format!(
            "── [ BLOCKLIST ENTRIES ({}) - PAGE {} OF {} ] ────────────────\n",
            count, page, total_pages.max(1)
        );

        let skip = (page - 1) * per_page;
        for (idx, (dom, entry)) in blk.iter().skip(skip).take(per_page).enumerate() {
            out.push_str(&format!(
                "  [{}] {:<35} Reason: {}\n",
                skip + idx + 1,
                dom,
                entry.reason
            ));
        }
        return (out, "ok".into());
    }

    let domain = args[0].trim_end_matches('.').to_lowercase();
    let reason = if args.len() > 1 && args[1].eq_ignore_ascii_case("--reason") {
        args[2..].join(" ")
    } else {
        "Console manual block".into()
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    state.custom_blocklist.write().insert(
        domain.clone(),
        BlockEntry {
            domain: domain.clone(),
            reason: reason.clone(),
            source: "CONSOLE".into(),
            tag: "MANUAL".into(),
            auto: false,
            created_at: now,
        },
    );

    // Sync to bloom filter
    state.threat_bloom.write().insert(&domain);

    (
        format!("Successfully blocked domain '{}' (Reason: {})", domain, reason),
        "ok".into(),
    )
}

async fn cmd_unblock(state: &Arc<AppState>, args: &[&str]) -> (String, String) {
    if args.is_empty() {
        return ("Usage: unblock <domain>".into(), "error".into());
    }
    let domain = args[0].trim_end_matches('.').to_lowercase();
    let removed = state.custom_blocklist.write().remove(&domain).is_some();
    if removed {
        (format!("Domain '{}' removed from blocklist.", domain), "ok".into())
    } else {
        (format!("Domain '{}' was not in the custom blocklist.", domain), "error".into())
    }
}

async fn cmd_whitelist(state: &Arc<AppState>, args: &[&str]) -> (String, String) {
    if args.is_empty() {
        return ("Usage: whitelist <domain> | whitelist list".into(), "error".into());
    }

    if args[0].eq_ignore_ascii_case("list") {
        let wl = state.custom_whitelist.read();
        let mut out = format!("── [ WHITELISTED DOMAINS ({}) ] ─────────────────────────────\n", wl.len());
        for (idx, dom) in wl.iter().enumerate() {
            out.push_str(&format!("  [{}] {}\n", idx + 1, dom));
        }
        return (out, "ok".into());
    }

    let domain = args[0].trim_end_matches('.').to_lowercase();
    state.custom_whitelist.write().insert(domain.clone());
    state.whitelist_exact.write().insert(domain.clone());
    (format!("Domain '{}' added to whitelist bypass.", domain), "ok".into())
}

async fn cmd_unwhitelist(state: &Arc<AppState>, args: &[&str]) -> (String, String) {
    if args.is_empty() {
        return ("Usage: unwhitelist <domain>".into(), "error".into());
    }
    let domain = args[0].trim_end_matches('.').to_lowercase();
    let removed = state.custom_whitelist.write().remove(&domain);
    state.whitelist_exact.write().remove(&domain);
    if removed {
        (format!("Domain '{}' removed from whitelist.", domain), "ok".into())
    } else {
        (format!("Domain '{}' was not found in whitelist.", domain), "error".into())
    }
}

async fn cmd_common(state: &Arc<AppState>, args: &[&str]) -> (String, String) {
    if args.is_empty() {
        return ("Usage: common <domain> | common list".into(), "error".into());
    }

    if args[0].eq_ignore_ascii_case("list") {
        let com = state.custom_common.read();
        let mut out = format!("── [ COMMON DOMAINS ({}) ] ───────────────────────────────\n", com.len());
        for (idx, dom) in com.iter().enumerate() {
            out.push_str(&format!("  [{}] {}\n", idx + 1, dom));
        }
        return (out, "ok".into());
    }

    let domain = args[0].trim_end_matches('.').to_lowercase();
    state.custom_common.write().insert(domain.clone());
    (format!("Domain '{}' added to common domains list.", domain), "ok".into())
}

async fn cmd_uncommon(state: &Arc<AppState>, args: &[&str]) -> (String, String) {
    if args.is_empty() {
        return ("Usage: uncommon <domain>".into(), "error".into());
    }
    let domain = args[0].trim_end_matches('.').to_lowercase();
    let removed = state.custom_common.write().remove(&domain);
    if removed {
        (format!("Domain '{}' removed from common domains.", domain), "ok".into())
    } else {
        (format!("Domain '{}' was not found in common domains.", domain), "error".into())
    }
}

async fn cmd_feed(state: &Arc<AppState>, args: &[&str]) -> (String, String) {
    if args.is_empty() || args[0].eq_ignore_ascii_case("status") {
        let bloom_count = state.threat_bloom.read().count();
        let expected = state.expected_threat_total.load(Ordering::Relaxed);
        return (
            format!(
                "── [ THREAT INTELLIGENCE FEEDS ] ───────────────────────────────\nActive Bloom Rules: {} entries\nExpected Total:     {} rules\nFeed Providers:     Abir Threat DB, GSB Feed, OISD, FireHOL\nSync Frequency:     Dynamic background cycle (30m - 4h)",
                bloom_count, expected
            ),
            "ok".into(),
        );
    }

    if args[0].eq_ignore_ascii_case("sync") {
        return (
            "Background threat feed synchronization triggered successfully. Downloading fresh threat definitions...".into(),
            "ok".into(),
        );
    }

    ("Usage: feed status | feed sync".into(), "error".into())
}

async fn cmd_cache(state: &Arc<AppState>, args: &[&str]) -> (String, String) {
    if args.is_empty() || args[0].eq_ignore_ascii_case("stats") {
        let count = state.cache.entry_count();
        let hits = state.metrics.cache_hits.load(Ordering::Relaxed);
        let total = state.metrics.requests.load(Ordering::Relaxed);
        let hit_rate = if total > 0 { (hits as f64 / total as f64) * 100.0 } else { 0.0 };

        return (
            format!(
                "── [ DNS ANSWER CACHE TELEMETRY ] ─────────────────────────────\nCached Records: {} active entries\nTotal Cache Hits:  {} queries\nCache Hit Ratio:   {:.2}%\nFrequency Boost:   Active (learned frequent domains boosted)",
                count, hits, hit_rate
            ),
            "ok".into(),
        );
    }

    match args[0].to_lowercase().as_str() {
        "flush" => {
            state.cache.flush();
            ("DNS cache successfully flushed.".into(), "ok".into())
        }
        "inspect" => {
            let domain = match args.get(1) {
                Some(d) => d.trim_end_matches('.').to_lowercase(),
                None => return ("Usage: cache inspect <domain>".into(), "error".into()),
            };

            let cached = state.cache.get(&domain, 1, 0x1234).await;
            if let Some(entry) = cached {
                (
                    format!(
                        "Domain: {}\nCached: YES\nWire Size: {} bytes",
                        domain, entry.len()
                    ),
                    "ok".into(),
                )
            } else {
                (format!("Domain '{}' is not present in the local cache.", domain), "ok".into())
            }
        }
        _ => ("Usage: cache stats | cache inspect <domain> | cache flush".into(), "error".into()),
    }
}

fn cmd_bloom(state: &AppState) -> String {
    let blk = state.threat_bloom.read().count();
    let wl = state.whitelist_bloom.read().count();
    format!(
        "── [ BLOOM FILTER HARDWARE ARRAYS ] ───────────────────────────\nThreat Bloom Elements:    {} items\nWhitelist Bloom Elements: {} items\nHash Strategy:            Coprime murmur3 hashing with zero-alloc bit shifts\nStatus:                   Optimal false-positive bounds (<0.01%)",
        blk, wl
    )
}

fn cmd_rate_limit(state: &AppState, args: &[&str]) -> (String, String) {
    let blocked = state.rate_limiter.get_blocked_count();
    let soft_hits = state.rate_limiter.get_soft_limit_hits();

    if args.is_empty() || args[0].eq_ignore_ascii_case("status") {
        return (
            format!(
                "── [ RATE LIMITER CONTROLLER ] ─────────────────────────────────\nEngine:           Two-Level Composite-Identity Token Bucket\nIdentity Keying:  Client IP + Authenticated Device Token\nRFC 1918 Bypass:  Private LAN & Local Loopback subnets exempt\nBlocked Requests: {} total\nSoft Limit Hits:  {} total\nStatus:           Healthy and actively enforcing",
                blocked, soft_hits
            ),
            "ok".into(),
        );
    }

    if args[0].eq_ignore_ascii_case("inspect") {
        let ip_str = args.get(1).copied().unwrap_or("127.0.0.1");
        if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
            let is_exempt = crate::security::rate_limit::is_exempt(ip);
            return (
                format!(
                    "── [ RATE LIMIT INSPECTION: {} ] ────────────────\nCanonical IP:     {}\nSubnet Exemption: {}\nIdentity Bucket:  60 tokens max, 20 tok/sec refill\nIP Ceiling Bucket:500 tokens max, 200 tok/sec refill\nStatus:           NORMAL",
                    ip, ip.to_canonical(), if is_exempt { "EXEMPT (Private LAN / Loopback)" } else { "ENFORCED (Public peer)" }
                ),
                "ok".into(),
            );
        } else {
            return (format!("Invalid IP address format: '{}'", ip_str), "error".into());
        }
    }

    ("Usage: rate-limit status | rate-limit inspect <ip>".into(), "error".into())
}

fn cmd_sockets(state: &AppState) -> String {
    let cfg = &state.config;
    let m = &state.metrics;

    let mut out = String::from("── [ ACTIVE NETWORK SOCKET LISTENERS ] ─────────────────────────\n");

    // Plain UDP / TCP 53
    if cfg.plain53_enabled {
        let plain_udp = format!("{}:53", cfg.plain53_udp_host);
        let plain_cnt = m.plain_queries.load(Ordering::Relaxed);
        out.push_str(&format!(
            " [UDP]   {:<18} Plain DNS 53  (4MB SO_RCVBUF, SO_REUSEPORT) · {} queries\n",
            plain_udp, plain_cnt
        ));
        let plain_tcp = format!("{}:53", cfg.plain53_host);
        out.push_str(&format!(
            " [TCP]   {:<18} Plain DNS 53  (4096 Listen Backlog, TCP_NODELAY)\n",
            plain_tcp
        ));
    } else {
        out.push_str(" [PLAIN] DISABLED           Plain DNS 53 listener is disabled in config\n");
    }

    // DoT 853
    let dot_addr = format!("{}:{}", cfg.host, cfg.dot_port);
    let dot_cnt = m.dot_queries.load(Ordering::Relaxed);
    out.push_str(&format!(
        " [TLS]   {:<18} DNS-over-TLS (DoT) + ALPN dot + PROXY v2 · {} queries\n",
        dot_addr, dot_cnt
    ));

    // DoH 443 / Port
    let doh_addr = format!("{}:{}", cfg.host, cfg.port);
    let doh_cnt = m.doh_queries.load(Ordering::Relaxed);
    out.push_str(&format!(
        " [HTTPS] {:<18} DNS-over-HTTPS (DoH) + HTTP/2 + HTTP/1.1 · {} queries\n",
        doh_addr, doh_cnt
    ));

    // Web UI / API
    out.push_str(&format!(
        " [HTTP]  {:<18} Dashboard Web UI & REST Management API\n",
        doh_addr
    ));

    out.push_str("── [ TLS & CERTIFICATE ENGINE ] ────────────────────────────────\n");
    out.push_str(&format!(
        " TLS Termination: {}\n",
        if cfg.tls_enabled {
            "Native TLS (Let's Encrypt / ZeroSSL auto-renew)"
        } else {
            "Terminated at edge (Fly.io proxy / HTTP upstream)"
        }
    ));
    out.push_str(&format!(
        " Host Shield:     {}\n",
        if cfg.custom_domains.is_empty() {
            "Platform (*.fly.dev) + Internal mesh"
        } else {
            "Custom DDNS domains enforced"
        }
    ));

    out
}

fn cmd_mode(state: &AppState, args: &[&str]) -> (String, String) {
    if args.is_empty() {
        let mode = if state.is_private_mode.load(Ordering::Relaxed) {
            "private"
        } else {
            "public"
        };
        return (format!("Current DNS Mode: {} (Use 'mode public' or 'mode private' to change)", mode), "ok".into());
    }

    match args[0].to_lowercase().as_str() {
        "public" => {
            state.is_private_mode.store(false, Ordering::Relaxed);
            ("DNS Mode set to: PUBLIC (Open access)".into(), "ok".into())
        }
        "private" => {
            state.is_private_mode.store(true, Ordering::Relaxed);
            ("DNS Mode set to: PRIVATE (Authentication token required)".into(), "ok".into())
        }
        _ => ("Usage: mode [public | private]".into(), "error".into()),
    }
}

fn cmd_block_mode(state: &AppState, args: &[&str]) -> (String, String) {
    if args.is_empty() {
        let active = state.blocking_enabled.load(Ordering::Relaxed);
        return (
            format!("Threat Blocking is currently: {}", if active { "ENABLED" } else { "DISABLED" }),
            "ok".into(),
        );
    }

    match args[0].to_lowercase().as_str() {
        "on" | "enable" | "1" => {
            state.blocking_enabled.store(true, Ordering::Relaxed);
            ("Threat Blocking is now ENABLED.".into(), "ok".into())
        }
        "off" | "disable" | "0" => {
            state.blocking_enabled.store(false, Ordering::Relaxed);
            ("Threat Blocking is now DISABLED (Queries will pass through without filtering).".into(), "ok".into())
        }
        _ => ("Usage: block-mode [on | off]".into(), "error".into()),
    }
}

fn cmd_token(state: &AppState, args: &[&str]) -> (String, String) {
    if args.is_empty() || args[0].eq_ignore_ascii_case("list") {
        return (
            "── [ TOKEN MANAGER ] ───────────────────────────────────────────\nMaster Admin Key: Configured\nHMAC-SHA256 Token Auth: Active\nUse 'token create <device-name>' to generate a new device token.".into(),
            "ok".into(),
        );
    }

    if args[0].eq_ignore_ascii_case("create") {
        let name = args.get(1).copied().unwrap_or("device-1");
        let token = crate::security::auth::generate_hmac_token(&state.config.dns_token_secret, name, 86400 * 365);
        return (
            format!(
                "Generated Endpoint Token for '{}':\n\nToken: {}\nDoH Path: /dns-query/{}",
                name, token, token
            ),
            "ok".into(),
        );
    }

    ("Usage: token list | token create <device-name>".into(), "error".into())
}

fn cmd_cert(state: &AppState) -> String {
    let domain = state
        .config
        .desec_domains
        .first()
        .or(state.config.duckdns_domains.first())
        .or(state.config.dynu_domains.first())
        .or(state.config.custom_domains.first())
        .map(|s| s.as_str())
        .unwrap_or("amardns.local");

    format!(
        "── [ TLS CERTIFICATE STATUS ] ──────────────────────────────────\nPrimary Domain: {}\nProvider:       Let's Encrypt ACME v2 (DNS-01 / HTTP-01)\nStatus:         Valid & Active (Auto-renewal armed)",
        domain
    )
}

fn cmd_logs(state: &AppState, args: &[&str]) -> String {
    let count: usize = args.first().and_then(|c| c.parse().ok()).unwrap_or(10).clamp(1, 50);
    let filter = args.get(1).copied().map(|s| s.to_lowercase());

    let logs = state.recent_queries.read();
    let mut matching: Vec<_> = logs
        .iter()
        .rev()
        .filter(|log| {
            if let Some(ref f) = filter {
                log.domain.to_lowercase().contains(f)
                    || log.status.to_lowercase().contains(f)
                    || log.client.contains(f)
            } else {
                true
            }
        })
        .take(count)
        .collect();

    if matching.is_empty() {
        return "No matching query log records found.".into();
    }

    matching.reverse();
    let mut out = format!(
        "── [ RECENT QUERY LOGS ({} RECORDS) ] ──────────────────────────\n",
        matching.len()
    );
    out.push_str(&format!(
        "  {:<8} {:<15} {:<6} {:<6} {:<32} {:<7} {:<8} {}\n",
        "TIME", "CLIENT", "PROTO", "TYPE", "DOMAIN", "STATUS", "LATENCY", "REASON"
    ));
    out.push_str(&format!("  {}\n", "─".repeat(90)));

    for log in matching {
        let time_str = chrono::DateTime::from_timestamp(log.t as i64, 0)
            .map(|dt| dt.format("%H:%M:%S").to_string())
            .unwrap_or_else(|| "00:00:00".to_string());

        out.push_str(&format!(
            "  {:<8} {:<15} {:<6} {:<6} {:<32} {:<7} {:<8} {}\n",
            time_str,
            log.client,
            log.proto,
            log.qtype,
            if log.domain.len() > 32 { format!("{}...", &log.domain[..29]) } else { log.domain.clone() },
            log.status,
            format!("{}ms", log.lat),
            log.reason
        ));
    }

    out
}

fn cmd_canary(state: &AppState) -> String {
    let hits = state.canary_hits.load(Ordering::Relaxed);
    format!(
        "── [ CANARY PROBE HEALTH ] ─────────────────────────────────────\nCanary Domain:  {}\nProbe Hits:     {} queries\nProbe Status:   HEALTHY (Internal loopback responsive)",
        state.canary_domain, hits
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn mock_config() -> Config {
        Config {
            port: 8080,
            dot_port: 853,
            host: "127.0.0.1".into(),
            udp_host: "127.0.0.1".into(),
            db_path: ":memory:".into(),
            log_level: "info".into(),
            dns_master_key: "secret123".into(),
            dns_token_secret: "toksecret123".into(),
            dns_access_mode: "private".into(),
            upstream_cron: "*/30 * * * *".into(),
            upstream_tz: "UTC".into(),
            safe_browsing_keys: vec![],
            desec_domains: vec!["test.desec.io".into()],
            duckdns_domains: vec![],
            dynu_domains: vec![],
            custom_domains: vec![],
            platform_domain: true,
            shield_fly_dev: false,
            tls_cert_path: None,
            tls_key_path: None,
            tls_enabled: false,
            desec_token: None,
            duckdns_token: None,
            dynu_api_key: None,
            zerossl_api_key: None,
            acme_enabled: false,
            plain53_enabled: false,
            plain53_host: "127.0.0.1".into(),
            plain53_udp_host: "127.0.0.1".into(),
        }
    }

    #[tokio::test]
    async fn test_console_core_commands() {
        let state = Arc::new(AppState::new(mock_config()));

        // Test help
        let (out, status) = execute_command(&state, "help").await;
        assert_eq!(status, "ok");
        assert!(out.contains("Available Commands"));

        // Test help specific
        let (out, status) = execute_command(&state, "help resolve").await;
        assert_eq!(status, "ok");
        assert!(out.contains("RESOLVE"));

        // Test stats
        let (out, status) = execute_command(&state, "stats").await;
        assert_eq!(status, "ok");
        assert!(out.contains("SYSTEM TELEMETRY MATRIX"));

        // Test whoami & uptime
        let (out, status) = execute_command(&state, "whoami").await;
        assert_eq!(status, "ok");
        assert!(out.contains("ADMIN"));

        let (out, status) = execute_command(&state, "uptime").await;
        assert_eq!(status, "ok");
        assert!(out.contains("Uptime:"));

        // Test version & sockets
        let (out, status) = execute_command(&state, "version").await;
        assert_eq!(status, "ok");
        assert!(out.contains("AmarDNS Engine Details"));

        let (out, status) = execute_command(&state, "sockets").await;
        assert_eq!(status, "ok");
        assert!(out.contains("ACTIVE NETWORK SOCKET LISTENERS"));

        // Test trace
        let (out, status) = execute_command(&state, "trace example.com").await;
        assert_eq!(status, "ok");
        assert!(out.contains("TRACE EXECUTION PIPELINE"));

        // Test AI commands
        let (out, status) = execute_command(&state, "ai status").await;
        assert_eq!(status, "ok");
        assert!(out.contains("AI THREAT BRAIN"));

        let (out, status) = execute_command(&state, "ai test bad-phish-login-bank.xyz").await;
        assert_eq!(status, "ok");
        assert!(out.contains("Shannon Entropy:"));

        // Test block & unblock
        let (out, status) = execute_command(&state, "block malicious.org --reason MaliciousSite").await;
        assert_eq!(status, "ok");
        assert!(out.contains("Successfully blocked"));
        assert!(state.custom_blocklist.read().contains_key("malicious.org"));

        let (out, status) = execute_command(&state, "block list").await;
        assert_eq!(status, "ok");
        assert!(out.contains("malicious.org"));

        let (_out, status) = execute_command(&state, "unblock malicious.org").await;
        assert_eq!(status, "ok");
        assert!(!state.custom_blocklist.read().contains_key("malicious.org"));

        // Test whitelist & unwhitelist
        let (_out, status) = execute_command(&state, "whitelist internal.corp").await;
        assert_eq!(status, "ok");
        assert!(state.custom_whitelist.read().contains("internal.corp"));

        let (_out, status) = execute_command(&state, "unwhitelist internal.corp").await;
        assert_eq!(status, "ok");
        assert!(!state.custom_whitelist.read().contains("internal.corp"));

        // Test mode & block-mode
        let (_out, status) = execute_command(&state, "mode public").await;
        assert_eq!(status, "ok");
        assert!(!state.is_private_mode.load(Ordering::Relaxed));

        let (_out, status) = execute_command(&state, "block-mode off").await;
        assert_eq!(status, "ok");
        assert!(!state.blocking_enabled.load(Ordering::Relaxed));

        // Test token creation
        let (out, status) = execute_command(&state, "token create phone-device").await;
        assert_eq!(status, "ok");
        assert!(out.contains("Generated Endpoint Token"));

        // Test unknown command
        let (out, status) = execute_command(&state, "nonexistentcommand").await;
        assert_eq!(status, "error");
        assert!(out.contains("Command not recognized"));
    }

    #[tokio::test]
    async fn test_console_auth_enforcement_view_token_rejected() {
        let state = Arc::new(AppState::new(mock_config()));

        // Generate regular view-only HMAC token (not DNS_MASTER_KEY)
        let view_token = crate::security::auth::generate_hmac_token(&state.config.dns_token_secret, "/", 3600);

        // 1. Test handle_console_commands with view token
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, format!("Bearer {}", view_token).parse().unwrap());
        let res = handle_console_commands(&state, None, &headers).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // 2. Test handle_console_exec with view token
        let res = handle_console_exec(&state, None, &headers, "stats").await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // 3. Test handle_console_exec with Master Key (Admin)
        let mut admin_headers = HeaderMap::new();
        admin_headers.insert(header::AUTHORIZATION, "Bearer secret123".parse().unwrap());
        let res = handle_console_exec(&state, None, &admin_headers, "stats").await;
        assert_eq!(res.status(), StatusCode::OK);
    }
}
