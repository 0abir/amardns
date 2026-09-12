pub mod ai;
pub mod rules;
pub mod status;
pub mod system;

use std::sync::Arc;
use axum::{http::HeaderMap, Router};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct DnsQueryParam {
    pub dns: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub qtype: Option<String>,
    pub device: Option<String>,
    pub client: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DomainReq {
    pub domain: Option<String>,
    pub domains: Option<Vec<String>>,
    #[allow(dead_code)]
    pub reason: Option<String>,
    #[allow(dead_code)]
    pub source: Option<String>,
    #[allow(dead_code)]
    pub ttl: Option<u32>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct BoolSetting {
    pub enabled: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ModeSetting {
    pub mode: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct NuclearWipeReq {
    pub confirm: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "nukeToken")]
    pub nuke_token: Option<String>,
}

/// Multi-Machine Cluster Peer Sync Broadcaster
pub fn broadcast_peer_sync(
    headers: &HeaderMap,
    master_key: &str,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) {
    if headers.contains_key("x-peer-sync") {
        return;
    }
    let app_name = match std::env::var("FLY_APP_NAME") {
        Ok(name) if !name.is_empty() => name,
        _ => return,
    };
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let path = path.to_string();
    let auth_header = format!("Bearer {}", master_key);

    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(2000))
            .build()
            .unwrap_or_default();

        let host = format!("{}.internal:{}", app_name, port);
        if let Ok(iter) = tokio::net::lookup_host(host).await {
            let addrs: Vec<std::net::SocketAddr> = iter.collect();
            for addr in addrs {
                let url = format!("http://{}/{}", addr, path.trim_start_matches('/'));
                let mut req = client.request(method.clone(), &url)
                    .header("x-peer-sync", "1")
                    .header("authorization", &auth_header);
                if let Some(ref b) = body {
                    req = req.json(b);
                }
                let _ = req.send().await;
            }
        }
    });
}

/// Aggregates all REST API subrouters.
pub fn api_routes() -> Router<Arc<AppState>> {
    Router::new()
        .merge(status::routes())
        .merge(rules::routes())
        .merge(ai::routes())
        .merge(system::routes())
}
