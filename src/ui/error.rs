// src/ui/error.rs
// Modern, high-performance error page generator for AmarDNS.
// Matches the dark glassmorphic neon cyberpunk aesthetic with Zero Emojis.

#[allow(clippy::too_many_arguments)]
pub fn render_error_page(
    status_code: u16,
    error_code: &str,
    status_title: &str,
    description: &str,
    path: &str,
    client_ip: &str,
    region: &str,
    machine_id: &str,
) -> String {
    let safe_path = html_escape(path);
    let safe_ip = html_escape(client_ip);
    let safe_region = html_escape(&region.to_ascii_uppercase());
    let safe_machine = html_escape(machine_id);
    let short_machine = if safe_machine.len() > 14 {
        &safe_machine[..14]
    } else {
        &safe_machine
    };

    let accent_color = match status_code {
        404 => "#00ffe7",       // Cyan
        401 | 403 => "#ff2d6b", // Neon Red/Pink
        405 => "#ffcc00",       // Yellow / Warning
        500..=599 => "#f97316", // Orange
        _ => "#a78bfa",         // Purple
    };

    let border_color = match status_code {
        404 => "rgba(0, 255, 231, 0.22)",
        401 | 403 => "rgba(255, 45, 107, 0.3)",
        405 => "rgba(255, 204, 0, 0.25)",
        500..=599 => "rgba(249, 115, 22, 0.3)",
        _ => "rgba(167, 139, 250, 0.25)",
    };

    let show_auth_box = status_code == 401 || status_code == 403;

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#000508">
<title>AmarDNS • {status_code} {status_title}</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect width=%22100%22 height=%22100%22 rx=%2224%22 fill=%22%2300e5cc%22/><path d=%22M50 20 L75 32 V52 C75 68 50 80 50 80 C50 80 25 68 25 52 V32 Z%22 fill=%22%23000508%22/></svg>">
<style>
:root {{
  --bg: #000508;
  --bg2: #050d14;
  --bg3: #0a1622;
  --card: rgba(5, 16, 26, 0.82);
  --brd: rgba(0, 255, 231, 0.14);
  --brd2: {border_color};
  --txt: #e2f1f8;
  --mut: #628296;
  --sub: #8faec2;
  --acc: {accent_color};
  --bad: #ff2d6b;
  --good: #39ff14;
  --warn: #ffcc00;
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
  font-family: var(--fm);
  font-size: 13px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  align-items: center;
  padding: 16px;
}}
.container {{
  width: 100%;
  max-width: 720px;
  margin: auto;
  display: flex;
  flex-direction: column;
  gap: 16px;
}}
.header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--brd);
}}
.brand {{
  display: flex;
  align-items: baseline;
  gap: 3px;
  text-decoration: none;
}}
.brand-a {{ font-family: var(--fh); font-size: 20px; font-weight: 900; color: #00e5cc; }}
.brand-b {{ font-family: var(--fh); font-size: 20px; font-weight: 700; color: #ffffff; }}
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
}}
.node-dot {{
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--good);
  box-shadow: 0 0 8px var(--good);
}}
.error-card {{
  background: var(--card);
  border: 1px solid var(--brd2);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border-radius: 6px;
  padding: 32px 28px;
  box-shadow: 0 12px 40px rgba(0, 0, 0, 0.6);
  position: relative;
  overflow: hidden;
}}
.error-card::before {{
  content: "";
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--acc), transparent);
}}
.status-row {{
  display: flex;
  align-items: baseline;
  gap: 14px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}}
.status-code {{
  font-family: var(--fh);
  font-size: clamp(52px, 10vw, 76px);
  font-weight: 900;
  line-height: 1;
  background: linear-gradient(135deg, #ffffff, var(--acc));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  letter-spacing: -0.02em;
}}
.status-tag {{
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.12em;
  color: var(--acc);
  padding: 4px 10px;
  border: 1px solid var(--brd2);
  border-radius: 3px;
  background: rgba(0, 0, 0, 0.35);
  text-transform: uppercase;
}}
.status-title {{
  font-family: var(--fh);
  font-size: 22px;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 10px;
  letter-spacing: 0.02em;
}}
.status-desc {{
  font-size: 13px;
  color: var(--sub);
  line-height: 1.6;
  margin-bottom: 24px;
}}
.diag-panel {{
  background: rgba(0, 0, 0, 0.45);
  border: 1px solid var(--brd);
  border-radius: 4px;
  padding: 14px 16px;
  margin-bottom: 24px;
}}
.diag-header {{
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.12em;
  color: var(--mut);
  text-transform: uppercase;
  margin-bottom: 10px;
  display: flex;
  justify-content: space-between;
}}
.diag-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 8px 16px;
}}
.diag-item {{
  display: flex;
  flex-direction: column;
  gap: 2px;
}}
.diag-key {{
  font-size: 10px;
  color: var(--mut);
  letter-spacing: 0.04em;
}}
.diag-val {{
  font-size: 12px;
  color: var(--txt);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}}
.auth-box {{
  margin-bottom: 24px;
  background: rgba(255, 45, 107, 0.05);
  border: 1px solid rgba(255, 45, 107, 0.25);
  border-radius: 4px;
  padding: 14px 16px;
}}
.auth-title {{
  font-size: 11px;
  font-weight: 700;
  color: #ff2d6b;
  letter-spacing: 0.06em;
  margin-bottom: 6px;
}}
.auth-form {{
  display: flex;
  gap: 8px;
  margin-top: 8px;
  flex-wrap: wrap;
}}
.fld {{
  flex: 1;
  min-width: 200px;
  background: rgba(0, 0, 0, 0.5);
  border: 1px solid var(--brd);
  color: #ffffff;
  padding: 8px 12px;
  font-family: var(--fm);
  font-size: 12px;
  border-radius: 3px;
  outline: none;
}}
.fld:focus {{
  border-color: var(--acc);
}}
.btn {{
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 9px 18px;
  font-family: var(--fm);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.04em;
  border-radius: 3px;
  text-decoration: none;
  cursor: pointer;
  transition: all 0.15s ease;
  border: 1px solid;
}}
.btn-primary {{
  background: var(--acc);
  color: #000508;
  border-color: var(--acc);
}}
.btn-primary:hover {{
  filter: brightness(1.15);
  box-shadow: 0 0 16px var(--acc);
}}
.btn-secondary {{
  background: rgba(0, 0, 0, 0.4);
  color: var(--txt);
  border-color: var(--brd);
}}
.btn-secondary:hover {{
  background: rgba(0, 255, 231, 0.08);
  border-color: var(--acc);
  color: #ffffff;
}}
.btn-row {{
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}}
.footer {{
  font-size: 11px;
  color: var(--mut);
  text-align: center;
  padding-top: 16px;
  letter-spacing: 0.04em;
}}
</style>
</head>
<body>
<div class="container">
  <header class="header">
    <a href="/" class="brand">
      <span class="brand-a">Amar</span><span class="brand-b">DNS</span>
      <span class="brand-badge">EDGE</span>
    </a>
    <div class="node-pill">
      <div class="node-dot"></div>
      <span>{safe_region} {short_machine}</span>
    </div>
  </header>

  <main class="error-card">
    <div class="status-row">
      <div class="status-code">{status_code}</div>
      <div class="status-tag">[{error_code}]</div>
    </div>
    <div class="status-title">{status_title}</div>
    <p class="status-desc">{description}</p>

    <div class="diag-panel">
      <div class="diag-header">
        <span>Node Diagnostics</span>
        <span>Zero-GC Core</span>
      </div>
      <div class="diag-grid">
        <div class="diag-item">
          <span class="diag-key">REQUESTED PATH</span>
          <span class="diag-val" title="{safe_path}">{safe_path}</span>
        </div>
        <div class="diag-item">
          <span class="diag-key">CLIENT IP</span>
          <span class="diag-val">{safe_ip}</span>
        </div>
        <div class="diag-item">
          <span class="diag-key">EDGE REGION</span>
          <span class="diag-val">{safe_region}</span>
        </div>
        <div class="diag-item">
          <span class="diag-key">NODE UID</span>
          <span class="diag-val">{safe_machine}</span>
        </div>
      </div>
    </div>

    "##,
        status_code = status_code,
        error_code = error_code,
        status_title = status_title,
        description = description,
        safe_path = safe_path,
        safe_ip = safe_ip,
        safe_region = safe_region,
        safe_machine = safe_machine,
        short_machine = short_machine,
    ) + if show_auth_box {
        r##"
    <div class="auth-box">
      <div class="auth-title">AUTHENTICATE ACCESS</div>
      <div style="font-size:11px;color:var(--sub);margin-bottom:8px">Enter Master Key or HMAC token to unlock telemetry and configuration controls.</div>
      <form class="auth-form" onsubmit="event.preventDefault(); var k=document.getElementById('auth-key').value.trim(); if(k) window.location.href='/'+encodeURIComponent(k); return false;">
        <input type="password" id="auth-key" class="fld" placeholder="Enter DNS Master Key or View Token" required />
        <button type="submit" class="btn btn-primary">Authenticate</button>
      </form>
    </div>
    "##
    } else {
        ""
    } + r##"
    <div class="btn-row">
      <a href="/" class="btn btn-primary">Return to Dashboard</a>
      <a href="/resolve?name=google.com&type=A" class="btn btn-secondary">Test DoH Resolver</a>
      <a href="/health" class="btn btn-secondary">Node Health Check</a>
    </div>
  </main>

  <footer class="footer">
    AmarDNS v1.0 • Autonomous Zero-GC Edge DNS Gateway
  </footer>
</div>
</body>
</html>"##
}

pub fn render_404(path: &str, client_ip: &str, region: &str, machine_id: &str) -> String {
    render_error_page(
        404,
        "EDGE_404_NOT_FOUND",
        "Resource Not Located",
        "The requested route or asset does not exist on this edge resolver node. If you were attempting to resolve a DNS query, please use the /dns-query or /resolve endpoints.",
        path,
        client_ip,
        region,
        machine_id,
    )
}

#[allow(dead_code)]
pub fn render_401(path: &str, client_ip: &str, region: &str, machine_id: &str) -> String {
    render_error_page(
        401,
        "EDGE_401_UNAUTHORIZED",
        "Authentication Required",
        "This endpoint requires valid authorization. In private mode, DNS queries and telemetry endpoints require a configured Master Key or signed HMAC view token.",
        path,
        client_ip,
        region,
        machine_id,
    )
}

pub fn render_403(path: &str, client_ip: &str, region: &str, machine_id: &str) -> String {
    render_error_page(
        403,
        "EDGE_403_FORBIDDEN",
        "Access Restricted by Policy",
        "Access to this resource is prohibited by active edge shielding or client rate-limiting policies. Ensure you are connecting via an authorized custom domain.",
        path,
        client_ip,
        region,
        machine_id,
    )
}

#[allow(dead_code)]
pub fn render_400(path: &str, client_ip: &str, region: &str, machine_id: &str) -> String {
    render_error_page(
        400,
        "EDGE_400_BAD_REQUEST",
        "Malformed Client Request",
        "The edge resolver node could not process the request due to invalid syntax, missing query parameters, or malformed DNS wire format.",
        path,
        client_ip,
        region,
        machine_id,
    )
}

#[allow(dead_code)]
pub fn render_405(path: &str, client_ip: &str, region: &str, machine_id: &str) -> String {
    render_error_page(
        405,
        "EDGE_405_METHOD_NOT_ALLOWED",
        "HTTP Method Not Allowed",
        "The requested HTTP method is not permitted for this route. Use GET for web inspection or POST/GET for DNS wire payloads.",
        path,
        client_ip,
        region,
        machine_id,
    )
}

#[allow(dead_code)]
pub fn render_429(path: &str, client_ip: &str, region: &str, machine_id: &str) -> String {
    render_error_page(
        429,
        "EDGE_429_TOO_MANY_REQUESTS",
        "Query Rate Limit Exceeded",
        "Your client IP has exceeded the allowed query rate ceiling or token-bucket quota. Please wait a brief moment before sending subsequent queries.",
        path,
        client_ip,
        region,
        machine_id,
    )
}

#[allow(dead_code)]
pub fn render_500(
    path: &str,
    error_msg: &str,
    client_ip: &str,
    region: &str,
    machine_id: &str,
) -> String {
    render_error_page(
        500,
        "EDGE_500_INTERNAL_ERROR",
        "Edge Processing Error",
        &format!(
            "An internal exception was encountered during query processing: {}",
            html_escape(error_msg)
        ),
        path,
        client_ip,
        region,
        machine_id,
    )
}

#[allow(dead_code)]
pub fn render_502(path: &str, client_ip: &str, region: &str, machine_id: &str) -> String {
    render_error_page(
        502,
        "EDGE_502_BAD_GATEWAY",
        "Upstream Resolver Gateway Failure",
        "The edge node encountered an invalid or unreachable response from configured upstream DNS nameservers. Self-healing circuit breakers are rerouting traffic.",
        path,
        client_ip,
        region,
        machine_id,
    )
}

#[allow(dead_code)]
pub fn render_503(path: &str, client_ip: &str, region: &str, machine_id: &str) -> String {
    render_error_page(
        503,
        "EDGE_503_SERVICE_UNAVAILABLE",
        "Service Temporarily Unavailable",
        "The edge DNS resolver node is currently synchronizing threat databases or undergoing brief maintenance. Normal resolution will resume momentarily.",
        path,
        client_ip,
        region,
        machine_id,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_404_error_page() {
        let html = render_404("/nonexistent/route", "192.0.2.1", "sin", "d8d0150a114498");
        assert!(html.contains("404"));
        assert!(html.contains("EDGE_404_NOT_FOUND"));
        assert!(html.contains("/nonexistent/route"));
        assert!(html.contains("SIN"));
        assert!(html.contains("d8d0150a114498"));
    }

    #[test]
    fn test_render_401_error_page_with_auth_box() {
        let html = render_401("/api/admin/config", "10.0.0.1", "fra", "48e0e33ce1de28");
        assert!(html.contains("401"));
        assert!(html.contains("EDGE_401_UNAUTHORIZED"));
        assert!(html.contains("AUTHENTICATE ACCESS"));
    }

    #[test]
    fn test_render_429_and_503() {
        let html429 = render_429("/dns-query", "203.0.113.5", "iad", "m_429test");
        assert!(html429.contains("429"));
        assert!(html429.contains("EDGE_429_TOO_MANY_REQUESTS"));

        let html503 = render_503("/dns-query", "203.0.113.5", "iad", "m_503test");
        assert!(html503.contains("503"));
        assert!(html503.contains("EDGE_503_SERVICE_UNAVAILABLE"));
    }
}
