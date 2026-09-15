// src/ui/pages.rs
// SEO-friendly, modern public documentation and policy pages for AmarDNS.
// Matches the dark glassmorphic neon cyberpunk aesthetic with Zero Emojis.

pub fn render_robots_txt(host: &str) -> String {
    let clean_host = if host.is_empty() || host == "localhost" {
        "amardns.fly.dev"
    } else {
        host
    };

    format!(
        r#"User-agent: *
Allow: /
Allow: /health
Allow: /help
Allow: /docs
Allow: /security
Allow: /privacy
Allow: /terms
Allow: /sitemap.xml
Allow: /manifest.json
Allow: /favicon.ico

# Disallow private and administrative control paths
Disallow: /api/
Disallow: /metrics
Disallow: /console
Disallow: /dns-query
Disallow: /resolve
Disallow: /*?*dns=
Disallow: /*?*key=
Disallow: /*?*token=

# Sitemap index
Sitemap: https://{clean_host}/sitemap.xml
"#
    )
}

pub fn render_sitemap_xml(host: &str) -> String {
    let clean_host = if host.is_empty() || host == "localhost" {
        "amardns.fly.dev"
    } else {
        host
    };

    let base_url = format!("https://{}", clean_host);

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9
        http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">
  <url>
    <loc>{base_url}/</loc>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>{base_url}/help</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>{base_url}/security</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>{base_url}/privacy</loc>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>
  <url>
    <loc>{base_url}/terms</loc>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>
  <url>
    <loc>{base_url}/health</loc>
    <changefreq>always</changefreq>
    <priority>0.3</priority>
  </url>
</urlset>"#
    )
}

pub fn render_manifest_json() -> String {
    r##"{
  "name": "AmarDNS Secure Resolver",
  "short_name": "AmarDNS",
  "description": "Autonomous AI-Shielded Zero-GC Private DNS Resolver Gateway",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#000508",
  "theme_color": "#000508",
  "icons": [
    {
      "src": "/favicon.ico",
      "sizes": "64x64 32x32 24x24 16x16",
      "type": "image/x-icon"
    }
  ],
  "categories": ["utilities", "security", "developer tools"]
}"##
    .to_string()
}

fn page_shell(title: &str, description: &str, path: &str, content_html: &str, host: &str, region: &str, machine_id: &str) -> String {
    let clean_host = if host.is_empty() || host == "localhost" {
        "amardns.fly.dev"
    } else {
        host
    };
    let canonical = format!("https://{}{}", clean_host, path);
    let safe_region = region.to_ascii_uppercase();
    let short_machine = if machine_id.len() > 14 {
        &machine_id[..14]
    } else {
        machine_id
    };

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#000508">
<meta name="robots" content="index, follow">
<title>AmarDNS • {title}</title>
<meta name="description" content="{description}">
<link rel="canonical" href="{canonical}">
<link rel="manifest" href="/manifest.json">
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect width=%22100%22 height=%22100%22 rx=%2224%22 fill=%22%2300e5cc%22/><path d=%22M50 20 L75 32 V52 C75 68 50 80 50 80 C50 80 25 68 25 52 V32 Z%22 fill=%22%23000508%22/></svg>">

<!-- Open Graph / Facebook -->
<meta property="og:type" content="website">
<meta property="og:url" content="{canonical}">
<meta property="og:title" content="AmarDNS • {title}">
<meta property="og:description" content="{description}">
<meta property="og:site_name" content="AmarDNS">

<!-- Twitter Cards -->
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="AmarDNS • {title}">
<meta name="twitter:description" content="{description}">

<!-- Schema.org Structured Data -->
<script type="application/ld+json">
{{
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  "name": "AmarDNS",
  "applicationCategory": "SecurityApplication",
  "operatingSystem": "All",
  "url": "{canonical}",
  "description": "{description}",
  "offers": {{
    "@type": "Offer",
    "price": "0",
    "priceCurrency": "USD"
  }}
}}
</script>

<style>
:root {{
  --bg: #000508;
  --bg2: #050d14;
  --card: rgba(5, 16, 26, 0.85);
  --brd: rgba(0, 229, 204, 0.18);
  --brd2: rgba(0, 229, 204, 0.38);
  --txt: #e2f1f8;
  --mut: #628296;
  --sub: #8faec2;
  --acc: #00e5cc;
  --acc2: #39ff14;
  --acc3: #9d4edd;
  --bad: #ff2d6b;
  --fm: "JetBrains Mono", "Fira Code", "Courier New", monospace;
  --fh: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
html, body {{
  min-height: 100vh;
  min-height: -webkit-fill-available;
  background-color: var(--bg);
  background-image:
    radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0, 229, 204, 0.12), transparent),
    radial-gradient(ellipse 60% 40% at 80% 90%, rgba(157, 78, 221, 0.08), transparent),
    linear-gradient(rgba(0, 229, 204, 0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0, 229, 204, 0.03) 1px, transparent 1px);
  background-size: 100% 100%, 100% 100%, 36px 36px, 36px 36px;
  color: var(--txt);
  font-family: var(--fh);
  font-size: 14px;
  line-height: 1.6;
  padding: 16px;
  display: flex;
  flex-direction: column;
  align-items: center;
}}
.container {{
  width: 100%;
  max-width: 820px;
  margin: auto;
  display: flex;
  flex-direction: column;
  gap: 18px;
}}
header.site-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-bottom: 14px;
  border-bottom: 1px solid var(--brd);
  flex-wrap: wrap;
  gap: 10px;
}}
.brand {{
  display: flex;
  align-items: baseline;
  gap: 3px;
  text-decoration: none;
}}
.brand-a {{ font-family: var(--fh); font-size: 22px; font-weight: 900; color: #00e5cc; }}
.brand-b {{ font-family: var(--fh); font-size: 22px; font-weight: 700; color: #ffffff; }}
.brand-badge {{
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.1em;
  padding: 2px 6px;
  border-radius: 2px;
  background: rgba(0, 229, 204, 0.1);
  color: #00e5cc;
  border: 1px solid rgba(0, 229, 204, 0.25);
  margin-left: 6px;
}}
nav.nav-links {{
  display: flex;
  gap: 14px;
  font-size: 12px;
  font-family: var(--fm);
}}
nav.nav-links a {{
  color: var(--sub);
  text-decoration: none;
  transition: color 0.15s;
}}
nav.nav-links a:hover, nav.nav-links a.active {{
  color: var(--acc);
}}
.node-pill {{
  font-size: 11px;
  color: var(--sub);
  letter-spacing: 0.06em;
  display: flex;
  align-items: center;
  gap: 6px;
  background: rgba(0, 0, 0, 0.4);
  padding: 4px 10px;
  border-radius: 3px;
  border: 1px solid var(--brd);
  font-family: var(--fm);
}}
.node-dot {{
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--acc2);
  box-shadow: 0 0 8px var(--acc2);
}}
main.content-card {{
  background: var(--card);
  border: 1px solid var(--brd);
  backdrop-filter: blur(18px);
  -webkit-backdrop-filter: blur(18px);
  border-radius: 8px;
  padding: 32px 28px;
  box-shadow: 0 12px 40px rgba(0, 0, 0, 0.6);
  position: relative;
  overflow: hidden;
}}
main.content-card::before {{
  content: "";
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--acc), transparent);
}}
h1.page-title {{
  font-size: clamp(24px, 4vw, 30px);
  font-weight: 800;
  color: #ffffff;
  margin-bottom: 8px;
  letter-spacing: -0.01em;
}}
p.page-sub {{
  color: var(--sub);
  font-size: 14px;
  margin-bottom: 24px;
}}
h2.sec-heading {{
  font-size: 18px;
  font-weight: 700;
  color: var(--acc);
  margin-top: 28px;
  margin-bottom: 12px;
  letter-spacing: 0.02em;
  border-left: 3px solid var(--acc);
  padding-left: 10px;
}}
h3.sub-heading {{
  font-size: 15px;
  font-weight: 700;
  color: #ffffff;
  margin-top: 18px;
  margin-bottom: 8px;
}}
.code-block {{
  background: rgba(0, 5, 8, 0.85);
  border: 1px solid var(--brd);
  border-radius: 6px;
  padding: 14px 16px;
  font-family: var(--fm);
  font-size: 12.5px;
  color: var(--acc);
  margin: 12px 0;
  overflow-x: auto;
  user-select: all;
}}
.grid-2 {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 14px;
  margin: 16px 0;
}}
.card-box {{
  background: rgba(0, 0, 0, 0.45);
  border: 1px solid var(--brd);
  border-radius: 6px;
  padding: 16px;
}}
.card-box h4 {{
  font-size: 13px;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 6px;
  font-family: var(--fm);
}}
.card-box p {{
  font-size: 12px;
  color: var(--sub);
  line-height: 1.5;
}}
ul.feat-list {{
  list-style: none;
  margin: 10px 0;
}}
ul.feat-list li {{
  padding-left: 16px;
  position: relative;
  margin-bottom: 8px;
  color: var(--sub);
  font-size: 13px;
}}
ul.feat-list li::before {{
  content: "•";
  position: absolute;
  left: 0;
  color: var(--acc);
  font-weight: 700;
}}
.btn {{
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 8px 16px;
  font-family: var(--fm);
  font-size: 12px;
  font-weight: 700;
  border-radius: 4px;
  text-decoration: none;
  cursor: pointer;
  transition: all 0.15s ease;
  border: 1px solid;
}}
.btn-p {{
  background: var(--acc);
  color: #000508;
  border-color: var(--acc);
}}
.btn-p:hover {{
  filter: brightness(1.15);
  box-shadow: 0 0 16px var(--acc);
}}
.btn-s {{
  background: rgba(0, 0, 0, 0.4);
  color: var(--txt);
  border-color: var(--brd);
}}
.btn-s:hover {{
  border-color: var(--acc);
  color: #ffffff;
}}
footer.site-footer {{
  font-size: 11px;
  color: var(--mut);
  text-align: center;
  padding-top: 14px;
  letter-spacing: 0.04em;
  display: flex;
  flex-direction: column;
  gap: 8px;
  align-items: center;
}}
footer.site-footer a {{
  color: var(--sub);
  text-decoration: none;
}}
footer.site-footer a:hover {{
  color: var(--acc);
}}
.footer-links {{
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
  justify-content: center;
  font-family: var(--fm);
}}
</style>
</head>
<body>
<div class="container">
  <header class="site-header">
    <a href="/" class="brand">
      <span class="brand-a">Amar</span><span class="brand-b">DNS</span>
      <span class="brand-badge">EDGE</span>
    </a>
    <nav class="nav-links">
      <a href="/" {nav_home}>Gateway</a>
      <a href="/help" {nav_help}>Setup Guide</a>
      <a href="/security" {nav_sec}>Security</a>
      <a href="/privacy" {nav_priv}>Privacy</a>
      <a href="/terms" {nav_terms}>Terms</a>
    </nav>
    <div class="node-pill">
      <div class="node-dot"></div>
      <span>{safe_region} {short_machine}</span>
    </div>
  </header>

  <main class="content-card">
    {content_html}
  </main>

  <footer class="site-footer">
    <div class="footer-links">
      <a href="/">Gateway</a>
      <a href="/help">Documentation</a>
      <a href="/security">Security Architecture</a>
      <a href="/privacy">Privacy Policy</a>
      <a href="/terms">Terms of Service</a>
      <a href="/health">System Health</a>
      <a href="/sitemap.xml">Sitemap</a>
    </div>
    <div>AmarDNS • Autonomous AI-Shielded Zero-GC Private DNS Gateway</div>
  </footer>
</div>
</body>
</html>"##,
        title = title,
        description = description,
        canonical = canonical,
        safe_region = safe_region,
        short_machine = short_machine,
        content_html = content_html,
        nav_home = if path == "/" { "class=\"active\"" } else { "" },
        nav_help = if path == "/help" || path == "/docs" { "class=\"active\"" } else { "" },
        nav_sec = if path == "/security" { "class=\"active\"" } else { "" },
        nav_priv = if path == "/privacy" { "class=\"active\"" } else { "" },
        nav_terms = if path == "/terms" { "class=\"active\"" } else { "" },
    )
}

pub fn render_help_page(host: &str, region: &str, machine_id: &str) -> String {
    let clean_host = if host.is_empty() || host == "localhost" {
        "amardns.fly.dev"
    } else {
        host
    };

    let content = format!(
        r##"
<h1 class="page-title">Client Setup &amp; Configuration Guide</h1>
<p class="page-sub">Connect your devices to AmarDNS for multi-layer ad-blocking, anti-tracking, DNSSEC validation, and real-time AI zero-day threat defense.</p>

<h2 class="sec-heading">1. Core Connection Endpoints</h2>
<div class="grid-2">
  <div class="card-box">
    <h4>DNS-over-HTTPS (DoH)</h4>
    <p>Standard encrypted DNS over HTTPS (Port 443) with HTTP/2 and TLS 1.3 support.</p>
    <div class="code-block">https://{clean_host}/dns-query</div>
  </div>
  <div class="card-box">
    <h4>DNS-over-TLS (DoT)</h4>
    <p>Dedicated encrypted DNS over TLS on Port 853 with ALPN dot negotiation.</p>
    <div class="code-block">{clean_host}</div>
  </div>
  <div class="card-box">
    <h4>Plain Standard DNS (UDP/TCP 53)</h4>
    <p>Universal fallback listener powered by kernel SO_REUSEPORT multi-workers.</p>
    <div class="code-block">Port 53 (UDP &amp; TCP)</div>
  </div>
</div>

<h2 class="sec-heading">2. Device Configuration Instructions</h2>

<h3 class="sub-heading">Android (Private DNS)</h3>
<ul class="feat-list">
  <li>Open <strong>Settings</strong> &rarr; <strong>Network &amp; internet</strong> &rarr; <strong>Private DNS</strong>.</li>
  <li>Select <strong>Private DNS provider hostname</strong>.</li>
  <li>Enter <code style="color:var(--acc)">{clean_host}</code> and tap <strong>Save</strong>.</li>
</ul>

<h3 class="sub-heading">Apple iOS &amp; macOS</h3>
<ul class="feat-list">
  <li>For Safari and system-wide encrypted DNS, install an encrypted DNS mobileconfig profile or configure in <strong>System Settings &rarr; Network &rarr; DNS</strong>.</li>
  <li>For DoH in browsers, enter <code style="color:var(--acc)">https://{clean_host}/dns-query</code> under browser privacy settings.</li>
</ul>

<h3 class="sub-heading">Google Chrome / Brave / Microsoft Edge</h3>
<ul class="feat-list">
  <li>Open <strong>Settings</strong> &rarr; <strong>Privacy and security</strong> &rarr; <strong>Security</strong>.</li>
  <li>Enable <strong>Use secure DNS</strong> and select <strong>Custom</strong>.</li>
  <li>Enter: <code style="color:var(--acc)">https://{clean_host}/dns-query</code></li>
</ul>

<h3 class="sub-heading">Mozilla Firefox</h3>
<ul class="feat-list">
  <li>Open <strong>Settings</strong> &rarr; <strong>Privacy &amp; Security</strong> &rarr; <strong>DNS over HTTPS</strong>.</li>
  <li>Select <strong>Max Protection</strong> or <strong>Increased Protection</strong>.</li>
  <li>Choose <strong>Custom Provider</strong> and enter: <code style="color:var(--acc)">https://{clean_host}/dns-query</code></li>
</ul>

<h3 class="sub-heading">Linux (systemd-resolved)</h3>
<div class="code-block"># Edit /etc/systemd/resolved.conf
[Resolve]
DNS={clean_host}
DNSOverTLS=yes
DNSSEC=yes</div>
<p style="font-size:12px;color:var(--sub)">Then run: <code style="color:var(--acc)">sudo systemctl restart systemd-resolved</code></p>

<h2 class="sec-heading">3. Testing &amp; Verification</h2>
<p style="color:var(--sub);margin-bottom:12px">Verify your secure connection using our browser-testable JSON resolver API:</p>
<div class="code-block"><a href="/resolve?name=google.com&type=A" style="color:var(--acc);text-decoration:none">https://{clean_host}/resolve?name=google.com&amp;type=A</a></div>
<p style="font-size:12px;color:var(--sub)">If you receive a JSON response with status code 0 (NOERROR) and AD=true, your encrypted DNSSEC pipeline is fully operational.</p>
"##,
        clean_host = clean_host
    );

    page_shell(
        "Client Setup & Configuration Guide",
        "Step-by-step setup guides for configuring DoH, DoT, and Plain DNS on Android, iOS, Windows, macOS, Linux, and web browsers.",
        "/help",
        &content,
        host,
        region,
        machine_id,
    )
}

pub fn render_security_page(host: &str, region: &str, machine_id: &str) -> String {
    let content = r##"
<h1 class="page-title">Security Architecture &amp; Cryptographic Model</h1>
<p class="page-sub">AmarDNS is engineered in bare-metal Rust with zero garbage collection, cryptographic DNSSEC verification, and in-memory Bloom filter hardware bit arrays.</p>

<h2 class="sec-heading">1. Cryptographic DNSSEC Engine (RFC 4034, 4035, 5155, 9276)</h2>
<ul class="feat-list">
  <li><strong>Direct IANA Root Trust Anchor Sync:</strong> Authenticated against official root-anchors.xml with S/MIME PKCS#7 signature verification.</li>
  <li><strong>Zero Upstream Trust:</strong> Cryptographic RRSIG signatures (ECDSA P-256, Ed25519, RSA/SHA-256) are validated locally on-node before setting Authenticated Data (AD=1).</li>
  <li><strong>NSEC / NSEC3 Denial-of-Existence Proofs:</strong> Validates cryptographic non-existence hashes with salt and iteration limits (RFC 5155).</li>
  <li><strong>RFC 9276 DoS Iteration Guard:</strong> Enforces a strict ceiling of &le; 150 iterations to eliminate CPU exhaustion attacks.</li>
</ul>

<h2 class="sec-heading">2. Multi-Layer Threat Mitigation Pipeline</h2>
<div class="grid-2">
  <div class="card-box">
    <h4>Bloom Filter Hardware Bitsets</h4>
    <p>Zero-allocation in-memory membership filter holding 1.5M+ threat signatures in 4MB RAM with power-of-two bitwise masking and coprime double-hashing.</p>
  </div>
  <div class="card-box">
    <h4>Perpetual AI Neural Engine</h4>
    <p>8-dimensional feature vector extraction and Markov transition bigram anomaly scoring to detect zero-day DGA malware before blocklists update.</p>
  </div>
  <div class="card-box">
    <h4>DNS Rebinding Interceptor</h4>
    <p>Blocks malicious public domain resolutions attempting to return RFC 1918 private IPv4 or loopback subnets.</p>
  </div>
  <div class="card-box">
    <h4>Brand Typosquatting Defense</h4>
    <p>Levenshtein distance and homoglyph inspection protecting users from phishing traps targeting banking and cloud portals.</p>
  </div>
</div>

<h2 class="sec-heading">3. Memory Governor &amp; Rate Limiter Architecture</h2>
<ul class="feat-list">
  <li><strong>Dynamic Memory Governor:</strong> Operates under a 200MB hard RSS ceiling. At 140MB, proactive eviction runs; at 175MB, emergency cache shedding instantly resets memory to ~30MB.</li>
  <li><strong>Token-Bucket Rate Limiter:</strong> Enforces per-IP and per-device burst limits with automatic CIDR exemptions for private RFC 1918 networks and Carrier-Grade NAT.</li>
  <li><strong>Singleflight Concurrency Coalescing:</strong> Merges identical concurrent queries into a single upstream request, eliminating thundering-herd surges.</li>
</ul>
"##;

    page_shell(
        "Security Architecture & Cryptographic Model",
        "Overview of AmarDNS cryptographic DNSSEC verification, AI threat heuristics, Bloom filter engine, and zero-day defense pipeline.",
        "/security",
        content,
        host,
        region,
        machine_id,
    )
}

pub fn render_privacy_page(host: &str, region: &str, machine_id: &str) -> String {
    let content = r##"
<h1 class="page-title">Privacy Policy &amp; Zero-Log Guarantee</h1>
<p class="page-sub">AmarDNS is committed to absolute privacy. Your DNS queries belong strictly to you.</p>

<h2 class="sec-heading">1. Zero-Log Architecture</h2>
<p style="color:var(--sub);margin-bottom:12px">We operate under a strict zero-logging architecture:</p>
<ul class="feat-list">
  <li><strong>No Query IP Logging:</strong> DNS query logs are stored strictly in volatile, ephemeral RAM ring buffers and compressed PulseDB WAL files for real-time live diagnostics.</li>
  <li><strong>No User Profiling:</strong> We do not build advertising profiles, track browsing habits, or fingerprint individuals.</li>
  <li><strong>No Data Monetization:</strong> We never sell, lease, or share resolver telemetry with data brokers, ISPs, or government agencies.</li>
  <li><strong>Encrypted Transports:</strong> All DoH and DoT queries are encrypted with TLS 1.3, shielding queries from local network eavesdroppers.</li>
</ul>

<h2 class="sec-heading">2. Cache &amp; Ephemeral Memory</h2>
<p style="color:var(--sub);margin-bottom:12px">Cached DNS records in AeroCache (W-TinyLFU) contain only canonical domain-to-IP mappings provided by authoritative nameservers with standard TTL counters. No client identity is attached to cached records.</p>

<h2 class="sec-heading">3. Third-Party Upstream Resolution</h2>
<p style="color:var(--sub);margin-bottom:12px">When a domain is not present in the local cache, AmarDNS queries privacy-respecting upstream providers (e.g. Mullvad DNS, Quad9, Cloudflare) via encrypted DoH channels. We do not transmit EDNS Client Subnet (ECS) headers, preserving your exact IP location.</p>
"##;

    page_shell(
        "Privacy Policy & Zero-Log Guarantee",
        "AmarDNS zero-log privacy policy: absolute encryption, ephemeral RAM processing, and zero tracking or data monetization.",
        "/privacy",
        content,
        host,
        region,
        machine_id,
    )
}

pub fn render_terms_page(host: &str, region: &str, machine_id: &str) -> String {
    let content = r##"
<h1 class="page-title">Terms of Service &amp; Acceptable Use Policy</h1>
<p class="page-sub">Guidelines for accessing and utilizing the AmarDNS resolver network.</p>

<h2 class="sec-heading">1. Permitted Use</h2>
<p style="color:var(--sub);margin-bottom:12px">AmarDNS is provided as a high-performance DNS resolution and threat-filtering gateway for personal, family, development, and organizational use across authorized devices.</p>

<h2 class="sec-heading">2. Prohibited Activities</h2>
<ul class="feat-list">
  <li>Attempting Denial of Service (DoS) or Distributed Denial of Service (DDoS) amplification attacks against the resolver infrastructure.</li>
  <li>Using the service for automated scanning, dictionary attacks, or DNS tunneling exploitation.</li>
  <li>Attempting to bypass administrative access controls, tamper with TLS certificates, or exploit edge API endpoints.</li>
</ul>

<h2 class="sec-heading">3. Availability &amp; Disclaimer</h2>
<p style="color:var(--sub);margin-bottom:12px">AmarDNS is provided on an "as-is" and "as-available" basis. While we maintain autonomous self-healing mechanisms and high availability across multi-region edge nodes, we do not guarantee uninterrupted service under extreme upstream network disruptions.</p>
"##;

    page_shell(
        "Terms of Service & Acceptable Use Policy",
        "Terms and conditions for utilizing the AmarDNS edge DNS resolution and security network.",
        "/terms",
        content,
        host,
        region,
        machine_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_robots_txt() {
        let robots = render_robots_txt("amardns.fly.dev");
        assert!(robots.contains("User-agent: *"));
        assert!(robots.contains("Allow: /help"));
        assert!(robots.contains("Disallow: /api/"));
        assert!(robots.contains("Sitemap: https://amardns.fly.dev/sitemap.xml"));
    }

    #[test]
    fn test_render_sitemap_xml() {
        let sitemap = render_sitemap_xml("amardns.fly.dev");
        assert!(sitemap.contains("<loc>https://amardns.fly.dev/</loc>"));
        assert!(sitemap.contains("<loc>https://amardns.fly.dev/help</loc>"));
        assert!(sitemap.contains("<loc>https://amardns.fly.dev/security</loc>"));
    }

    #[test]
    fn test_render_help_page() {
        let help = render_help_page("amardns.fly.dev", "sin", "m_12345");
        assert!(help.contains("Client Setup &amp; Configuration Guide"));
        assert!(help.contains("https://amardns.fly.dev/dns-query"));
        assert!(help.contains("SIN"));
    }

    #[test]
    fn test_render_security_page() {
        let sec = render_security_page("amardns.fly.dev", "fra", "m_67890");
        assert!(sec.contains("Security Architecture"));
        assert!(sec.contains("DNSSEC"));
    }
}
