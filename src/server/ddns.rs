use std::net::IpAddr;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::server::acme::is_dynu_domain;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublicIps {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

/// Discovers the public Anycast IPv4 and IPv6 addresses assigned to the application.
/// Queries DoH for `{app_name}.fly.dev` (Google and Cloudflare), falling back to IP echo services.
pub async fn discover_public_ips(http: &reqwest::Client, app_name_hint: Option<&str>) -> PublicIps {
    let mut ips = PublicIps::default();

    let app_name = std::env::var("FLY_APP_NAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| app_name_hint.map(|s| s.to_string()))
        .unwrap_or_else(|| "amardns".to_string());

    let fly_hostname = format!("{}.fly.dev", app_name);

    // 1. Google DoH
    if ips.ipv4.is_none() {
        let url = format!("https://dns.google/resolve?name={}&type=A", fly_hostname);
        if let Ok(resp) = http.get(&url).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(answers) = json["Answer"].as_array() {
                    for a in answers {
                        if let Some(data) = a["data"].as_str() {
                            if let Ok(IpAddr::V4(v4)) = data.trim().parse::<IpAddr>() {
                                ips.ipv4 = Some(v4.to_string());
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    if ips.ipv6.is_none() {
        let url = format!("https://dns.google/resolve?name={}&type=AAAA", fly_hostname);
        if let Ok(resp) = http.get(&url).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(answers) = json["Answer"].as_array() {
                    for a in answers {
                        if let Some(data) = a["data"].as_str() {
                            if let Ok(IpAddr::V6(v6)) = data.trim().parse::<IpAddr>() {
                                ips.ipv6 = Some(v6.to_string());
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Cloudflare DoH Fallback
    if ips.ipv4.is_none() {
        let url = format!(
            "https://cloudflare-dns.com/dns-query?name={}&type=A",
            fly_hostname
        );
        if let Ok(resp) = http
            .get(&url)
            .header("Accept", "application/dns-json")
            .send()
            .await
        {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(answers) = json["Answer"].as_array() {
                    for a in answers {
                        if let Some(data) = a["data"].as_str() {
                            if let Ok(IpAddr::V4(v4)) = data.trim().parse::<IpAddr>() {
                                ips.ipv4 = Some(v4.to_string());
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    if ips.ipv6.is_none() {
        let url = format!(
            "https://cloudflare-dns.com/dns-query?name={}&type=AAAA",
            fly_hostname
        );
        if let Ok(resp) = http
            .get(&url)
            .header("Accept", "application/dns-json")
            .send()
            .await
        {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(answers) = json["Answer"].as_array() {
                    for a in answers {
                        if let Some(data) = a["data"].as_str() {
                            if let Ok(IpAddr::V6(v6)) = data.trim().parse::<IpAddr>() {
                                ips.ipv6 = Some(v6.to_string());
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Fallback to public IP echo services
    if ips.ipv4.is_none() {
        for echo_url in &[
            "https://api4.ipify.org",
            "https://v4.ident.me",
            "https://checkip.amazonaws.com",
        ] {
            if let Ok(resp) = http.get(*echo_url).send().await {
                if let Ok(text) = resp.text().await {
                    let cleaned = text.trim();
                    if let Ok(IpAddr::V4(v4)) = cleaned.parse::<IpAddr>() {
                        ips.ipv4 = Some(v4.to_string());
                        break;
                    }
                }
            }
        }
    }

    if ips.ipv6.is_none() {
        for echo_url in &["https://api6.ipify.org", "https://v6.ident.me"] {
            if let Ok(resp) = http.get(*echo_url).send().await {
                if let Ok(text) = resp.text().await {
                    let cleaned = text.trim();
                    if let Ok(IpAddr::V6(v6)) = cleaned.parse::<IpAddr>() {
                        ips.ipv6 = Some(v6.to_string());
                        break;
                    }
                }
            }
        }
    }

    ips
}

/// Updates deSEC A and AAAA records for a domain via the REST API.
pub async fn update_desec_ip(
    http: &reqwest::Client,
    token: &str,
    domain: &str,
    ips: &PublicIps,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut rrsets = Vec::new();

    if let Some(ref ipv4) = ips.ipv4 {
        rrsets.push(serde_json::json!({
            "subname": "",
            "type": "A",
            "records": [ipv4],
            "ttl": 900
        }));
    }

    if let Some(ref ipv6) = ips.ipv6 {
        rrsets.push(serde_json::json!({
            "subname": "",
            "type": "AAAA",
            "records": [ipv6],
            "ttl": 900
        }));
    }

    if rrsets.is_empty() {
        return Ok(());
    }

    let url = format!("https://desec.io/api/v1/domains/{}/rrsets/", domain);
    let resp = http
        .patch(&url)
        .header("Authorization", format!("Token {}", token))
        .header("Content-Type", "application/json")
        .json(&rrsets)
        .send()
        .await?;

    if resp.status().is_success() {
        info!(
            "[ddns/desec] Successfully synchronized IP records for '{}' (IPv4: {:?}, IPv6: {:?})",
            domain, ips.ipv4, ips.ipv6
        );
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err(format!("deSEC IP update failed: HTTP {} - {}", status, body).into())
    }
}

/// Updates DuckDNS IPv4 and IPv6 records for a domain.
pub async fn update_duckdns_ip(
    http: &reqwest::Client,
    token: &str,
    domain: &str,
    ips: &PublicIps,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sub = domain
        .trim_end_matches(".duckdns.org")
        .trim_end_matches('.');

    let mut query = vec![("domains", sub), ("token", token)];

    let ip_str;
    if let Some(ref ipv4) = ips.ipv4 {
        ip_str = ipv4.as_str();
        query.push(("ip", ip_str));
    }

    let ipv6_str;
    if let Some(ref ipv6) = ips.ipv6 {
        ipv6_str = ipv6.as_str();
        query.push(("ipv6", ipv6_str));
    }

    let resp = http
        .get("https://www.duckdns.org/update")
        .query(&query)
        .send()
        .await?;

    let text = resp.text().await.unwrap_or_default();
    if text.trim() == "OK" {
        info!(
            "[ddns/duckdns] Successfully synchronized IP records for '{}' (IPv4: {:?}, IPv6: {:?})",
            domain, ips.ipv4, ips.ipv6
        );
        Ok(())
    } else {
        Err(format!(
            "DuckDNS IP update failed for '{}': response='{}'",
            domain, text
        )
        .into())
    }
}

/// Updates Dynu domain IPv4 and IPv6 addresses via the Dynu REST API v2.
pub async fn update_dynu_ip(
    http: &reqwest::Client,
    api_key: &str,
    domain: &str,
    ips: &PublicIps,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Resolve Dynu Domain ID
    let root_url = format!("https://api.dynu.com/v2/dns/getroot/{}", domain);
    let root_resp = http
        .get(&root_url)
        .header("API-Key", api_key)
        .header("Accept", "application/json")
        .send()
        .await?;

    let domain_id = if root_resp.status().is_success() {
        let json: serde_json::Value = root_resp.json().await?;
        json["id"].as_u64()
    } else {
        // Fallback: list all domains
        let list_resp = http
            .get("https://api.dynu.com/v2/dns")
            .header("API-Key", api_key)
            .header("Accept", "application/json")
            .send()
            .await?;
        if list_resp.status().is_success() {
            let json: serde_json::Value = list_resp.json().await?;
            json["domains"]
                .as_array()
                .and_then(|arr| {
                    arr.iter().find(|d| {
                        d["name"]
                            .as_str()
                            .map(|s| s.eq_ignore_ascii_case(domain))
                            .unwrap_or(false)
                    })
                })
                .and_then(|d| d["id"].as_u64())
        } else {
            None
        }
    };

    let id = domain_id.ok_or_else(|| format!("Could not find Dynu domain ID for '{}'", domain))?;

    // 2. Update IPv4 and IPv6
    let mut payload = serde_json::json!({
        "name": domain,
        "ttl": 60,
        "ipv4": ips.ipv4.is_some(),
        "ipv6": ips.ipv6.is_some(),
    });

    if let Some(ref ipv4) = ips.ipv4 {
        payload["ipv4Address"] = serde_json::Value::String(ipv4.clone());
    }
    if let Some(ref ipv6) = ips.ipv6 {
        payload["ipv6Address"] = serde_json::Value::String(ipv6.clone());
    }

    let update_url = format!("https://api.dynu.com/v2/dns/{}", id);
    let resp = http
        .post(&update_url)
        .header("API-Key", api_key)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&payload)
        .send()
        .await?;

    if resp.status().is_success() {
        info!(
            "[ddns/dynu] Successfully synchronized IP records for '{}' (IPv4: {:?}, IPv6: {:?})",
            domain, ips.ipv4, ips.ipv6
        );
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err(format!(
            "Dynu IP update failed for '{}': HTTP {} - {}",
            domain, status, body
        )
        .into())
    }
}

/// Resolves current public A and AAAA records for a domain via Google and Cloudflare DoH.
pub async fn resolve_current_ips(
    http: &reqwest::Client,
    domain: &str,
) -> (Option<String>, Option<String>) {
    let mut current_v4 = None;
    let mut current_v6 = None;

    // 1. Google DoH
    let v4_url = format!("https://dns.google/resolve?name={}&type=A", domain);
    if let Ok(resp) = http.get(&v4_url).send().await {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            if let Some(answers) = json["Answer"].as_array() {
                for a in answers {
                    if let Some(data) = a["data"].as_str() {
                        if let Ok(IpAddr::V4(v4)) = data.trim().parse::<IpAddr>() {
                            current_v4 = Some(v4.to_string());
                            break;
                        }
                    }
                }
            }
        }
    }

    let v6_url = format!("https://dns.google/resolve?name={}&type=AAAA", domain);
    if let Ok(resp) = http.get(&v6_url).send().await {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            if let Some(answers) = json["Answer"].as_array() {
                for a in answers {
                    if let Some(data) = a["data"].as_str() {
                        if let Ok(IpAddr::V6(v6)) = data.trim().parse::<IpAddr>() {
                            current_v6 = Some(v6.to_string());
                            break;
                        }
                    }
                }
            }
        }
    }

    // 2. Cloudflare DoH Fallback
    if current_v4.is_none() {
        let cf_v4 = format!(
            "https://cloudflare-dns.com/dns-query?name={}&type=A",
            domain
        );
        if let Ok(resp) = http
            .get(&cf_v4)
            .header("Accept", "application/dns-json")
            .send()
            .await
        {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(answers) = json["Answer"].as_array() {
                    for a in answers {
                        if let Some(data) = a["data"].as_str() {
                            if let Ok(IpAddr::V4(v4)) = data.trim().parse::<IpAddr>() {
                                current_v4 = Some(v4.to_string());
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    if current_v6.is_none() {
        let cf_v6 = format!(
            "https://cloudflare-dns.com/dns-query?name={}&type=AAAA",
            domain
        );
        if let Ok(resp) = http
            .get(&cf_v6)
            .header("Accept", "application/dns-json")
            .send()
            .await
        {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(answers) = json["Answer"].as_array() {
                    for a in answers {
                        if let Some(data) = a["data"].as_str() {
                            if let Ok(IpAddr::V6(v6)) = data.trim().parse::<IpAddr>() {
                                current_v6 = Some(v6.to_string());
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    (current_v4, current_v6)
}

/// Checks whether a domain already points to the discovered public IPs.
/// Returns true if no DDNS update is necessary, preventing unnecessary API hammering.
pub async fn is_domain_ip_up_to_date(
    http: &reqwest::Client,
    domain: &str,
    target_ips: &PublicIps,
) -> bool {
    let (cur_v4, cur_v6) = resolve_current_ips(http, domain).await;

    let v4_match = match (&target_ips.ipv4, &cur_v4) {
        (Some(target), Some(current)) => target == current,
        (None, _) => true,
        (Some(_), None) => false,
    };

    let v6_match = match (&target_ips.ipv6, &cur_v6) {
        (Some(target), Some(current)) => target == current,
        (None, _) => true,
        (Some(_), None) => false,
    };

    if v4_match && v6_match {
        info!(
            "[ddns] Domain '{}' already resolves to target IP(s) (A: {:?}, AAAA: {:?}). Skipping redundant DDNS API call.",
            domain, cur_v4, cur_v6
        );
        true
    } else {
        info!(
            "[ddns] Domain '{}' requires IP update (Current -> A: {:?}, AAAA: {:?}; Target -> A: {:?}, AAAA: {:?})",
            domain, cur_v4, cur_v6, target_ips.ipv4, target_ips.ipv6
        );
        false
    }
}

/// Orchestrates automated public IP discovery and synchronizes DNS A/AAAA records across all configured DDNS providers.
pub async fn sync_all_ddns_records(config: &Config) {
    if config.desec_token.is_none()
        && config.duckdns_token.is_none()
        && config.dynu_api_key.is_none()
    {
        return;
    }

    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!("[ddns] Failed to build HTTP client for DDNS sync: {}", e);
            return;
        }
    };

    info!("[ddns] Discovering public Anycast IPv4 and IPv6 addresses for application...");
    let ips = discover_public_ips(&http, Some("amardns")).await;
    info!(
        "[ddns] Discovered public IPs — IPv4: {:?}, IPv6: {:?}",
        ips.ipv4, ips.ipv6
    );

    if ips.ipv4.is_none() && ips.ipv6.is_none() {
        warn!("[ddns] Could not discover public IPv4 or IPv6 address. Skipping DDNS update.");
        return;
    }

    // 1. Sync deSEC domains
    if let Some(ref token) = config.desec_token {
        let mut domains_to_sync = config.desec_domains.clone();
        for d in &config.custom_domains {
            if d.ends_with(".dedyn.io") && !domains_to_sync.contains(d) {
                domains_to_sync.push(d.clone());
            }
        }
        for domain in &domains_to_sync {
            if is_domain_ip_up_to_date(&http, domain, &ips).await {
                continue;
            }
            if let Err(e) = update_desec_ip(&http, token, domain, &ips).await {
                warn!("[ddns/desec] Error updating '{}': {}", domain, e);
            }
        }
    }

    // 2. Sync DuckDNS domains
    if let Some(ref token) = config.duckdns_token {
        let mut domains_to_sync = config.duckdns_domains.clone();
        for d in &config.custom_domains {
            if d.ends_with(".duckdns.org") && !domains_to_sync.contains(d) {
                domains_to_sync.push(d.clone());
            }
        }
        for domain in &domains_to_sync {
            if is_domain_ip_up_to_date(&http, domain, &ips).await {
                continue;
            }
            if let Err(e) = update_duckdns_ip(&http, token, domain, &ips).await {
                warn!("[ddns/duckdns] Error updating '{}': {}", domain, e);
            }
        }
    }

    // 3. Sync Dynu domains
    if let Some(ref api_key) = config.dynu_api_key {
        let mut domains_to_sync = config.dynu_domains.clone();
        for d in &config.custom_domains {
            if (is_dynu_domain(d) || !config.dynu_domains.is_empty())
                && !domains_to_sync.contains(d)
                && !d.ends_with(".dedyn.io")
                && !d.ends_with(".duckdns.org")
            {
                domains_to_sync.push(d.clone());
            }
        }
        for domain in &domains_to_sync {
            if is_domain_ip_up_to_date(&http, domain, &ips).await {
                continue;
            }
            if let Err(e) = update_dynu_ip(&http, api_key, domain, &ips).await {
                warn!("[ddns/dynu] Error updating '{}': {}", domain, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_ips_default() {
        let ips = PublicIps::default();
        assert!(ips.ipv4.is_none());
        assert!(ips.ipv6.is_none());
    }
}
