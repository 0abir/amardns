// src/core/gateway-html.js
// Public-facing AmarDNS Gateway & Unlock Portal (returned instead of plain "Not Found")

export const GATEWAY_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#000508">
<meta name="description" content="AmarDNS Autonomous AI-Shielded Private DNS Gateway">
<title>AmarDNS • Secure Resolver Gateway</title>
<style>
:root {
  --bg: #000508;
  --card: rgba(4, 15, 23, 0.75);
  --border: rgba(0, 229, 204, 0.18);
  --border-hover: rgba(0, 229, 204, 0.5);
  --txt: #e2f1f8;
  --mut: #628296;
  --acc1: #00e5cc;
  --acc2: #39ff14;
  --acc3: #9d4edd;
  --glow: 0 0 24px rgba(0, 229, 204, 0.25);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background-color: var(--bg);
  background-image: 
    radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0, 229, 204, 0.12), transparent),
    radial-gradient(ellipse 60% 40% at 80% 90%, rgba(157, 78, 221, 0.08), transparent),
    linear-gradient(rgba(0, 229, 204, 0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0, 229, 204, 0.03) 1px, transparent 1px);
  background-size: 100% 100%, 100% 100%, 36px 36px, 36px 36px;
  color: var(--txt);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  padding: 24px 16px;
}
.shell {
  width: 100%;
  max-width: 640px;
  display: flex;
  flex-direction: column;
  gap: 20px;
}
.brand {
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}
.logo-badge {
  width: 54px;
  height: 54px;
  border-radius: 14px;
  background: linear-gradient(135deg, rgba(0,229,204,0.2), rgba(157,78,221,0.2));
  border: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 26px;
  box-shadow: var(--glow);
  animation: pulse 3s infinite ease-in-out;
}
@keyframes pulse {
  0%, 100% { box-shadow: 0 0 16px rgba(0,229,204,0.2); }
  50% { box-shadow: 0 0 28px rgba(0,229,204,0.45); }
}
h1 {
  font-size: 26px;
  font-weight: 800;
  letter-spacing: 0.5px;
  background: linear-gradient(135deg, #ffffff, var(--acc1));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.tagline {
  font-size: 12px;
  color: var(--mut);
  display: flex;
  align-items: center;
  gap: 8px;
}
.live-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--acc2);
  box-shadow: 0 0 8px var(--acc2);
}
.card {
  background: var(--card);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 24px;
  transition: border-color 0.2s;
}
.card:hover {
  border-color: var(--border-hover);
}
.card-title {
  font-size: 13px;
  font-weight: 700;
  color: var(--acc1);
  text-transform: uppercase;
  letter-spacing: 1px;
  margin-bottom: 6px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.card-desc {
  font-size: 12px;
  color: var(--mut);
  line-height: 1.5;
  margin-bottom: 16px;
}
.unlock-form {
  display: flex;
  gap: 10px;
}
.key-input {
  flex: 1;
  background: rgba(0, 5, 8, 0.85);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px 14px;
  color: #fff;
  font-size: 13px;
  font-family: monospace;
  outline: none;
  transition: all 0.2s;
}
.key-input:focus {
  border-color: var(--acc1);
  box-shadow: 0 0 12px rgba(0,229,204,0.3);
}
.btn {
  background: linear-gradient(135deg, #00e5cc, #00b8a3);
  color: #000;
  font-weight: 700;
  font-size: 13px;
  border: none;
  border-radius: 8px;
  padding: 12px 20px;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
}
.btn:hover {
  filter: brightness(1.15);
  transform: translateY(-1px);
  box-shadow: 0 4px 16px rgba(0,229,204,0.4);
}
.btn:active {
  transform: translateY(0);
}
.grid-cols {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}
@media (max-width: 540px) {
  .grid-cols { grid-template-columns: 1fr; }
  .unlock-form { flex-direction: column; }
  .btn { justify-content: center; }
}
.proto-box {
  background: rgba(0, 5, 8, 0.6);
  border: 1px solid rgba(0,229,204,0.12);
  border-radius: 8px;
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.proto-hdr {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 11px;
  font-weight: 700;
}
.proto-val {
  font-size: 11px;
  font-family: monospace;
  color: var(--acc1);
  word-break: break-all;
  background: rgba(0,0,0,0.4);
  padding: 6px 8px;
  border-radius: 4px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.copy-btn {
  background: transparent;
  border: none;
  color: var(--mut);
  cursor: pointer;
  font-size: 11px;
  padding: 2px 4px;
  border-radius: 3px;
  transition: color 0.15s;
}
.copy-btn:hover { color: #fff; }
.features {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: center;
}
.feat-pill {
  font-size: 10px;
  color: var(--mut);
  background: rgba(4, 15, 23, 0.8);
  border: 1px solid rgba(0,229,204,0.1);
  padding: 4px 10px;
  border-radius: 20px;
  display: flex;
  align-items: center;
  gap: 4px;
}
.footer {
  text-align: center;
  font-size: 10px;
  color: #3e5668;
}
.error-msg {
  color: #ff2d6b;
  font-size: 11px;
  margin-top: 8px;
  display: none;
}
</style>
</head>
<body>
<div class="shell">
  <div class="brand">
    <div class="logo-badge">🛡️</div>
    <h1>AmarDNS</h1>
    <div class="tagline">
      <span class="live-dot"></span>
      <span>Autonomous AI-Shielded DNS Resolver</span>
      <span>•</span>
      <span style="color:#22d3ee">Online</span>
    </div>
  </div>

  <div class="card">
    <div class="card-title">🔐 Unlock Dashboard</div>
    <div class="card-desc">
      Enter your <strong>Master Key</strong> for administrative controls, or a signed <strong>Access Token</strong> for real-time view-only telemetry.
    </div>
    <form class="unlock-form" id="unlock-form">
      <input type="password" class="key-input" id="key-input" placeholder="Paste Master Key or Token..." autocomplete="off" autofocus required>
      <button type="submit" class="btn" id="unlock-btn">Unlock ➔</button>
    </form>
    <div class="error-msg" id="error-msg">Please enter a valid key or token.</div>
  </div>

  <div class="card">
    <div class="card-title">🌐 Client Setup & Endpoints</div>
    <div class="card-desc">
      Connect your devices to AmarDNS for automated ad-blocking, anti-tracking, and ML-powered phishing defense.
    </div>
    <div class="grid-cols">
      <div class="proto-box">
        <div class="proto-hdr">
          <span>DNS-over-HTTPS (DoH)</span>
          <span style="color:var(--acc2);font-size:9px">Port 443</span>
        </div>
        <div class="proto-val">
          <span id="doh-url">/dns-query</span>
          <button class="copy-btn" id="copy-doh" title="Copy URL">📋</button>
        </div>
        <div style="font-size:9px;color:var(--mut);line-height:1.3">
          Browser & iOS Secure DNS: Settings → Privacy → Custom Provider.
        </div>
      </div>
      <div class="proto-box">
        <div class="proto-hdr">
          <span>DNS-over-TLS (DoT)</span>
          <span style="color:var(--acc2);font-size:9px">Port 853</span>
        </div>
        <div class="proto-val">
          <span id="dot-host">hostname</span>
          <button class="copy-btn" id="copy-dot" title="Copy Hostname">📋</button>
        </div>
        <div style="font-size:9px;color:var(--mut);line-height:1.3">
          Android: Settings → Network & Internet → Private DNS.
        </div>
      </div>
    </div>
  </div>

  <div class="features">
    <div class="feat-pill">⚡ Multi-Cloud Anycast Pool</div>
    <div class="feat-pill">🧠 Transformer Threat Classification</div>
    <div class="feat-pill">🛡️ 400k+ Threat Feeds</div>
    <div class="feat-pill">🗄️ PulseDB WAL + AeroCache</div>
    <div class="feat-pill">🔒 Zero Logging</div>
  </div>

  <div class="footer">
    AmarDNS • High-Performance Private Resolver
  </div>
</div>

<script>
(function() {
  var host = window.location.hostname || 'localhost';
  var origin = window.location.origin || ('https://' + host);
  var dohEl = document.getElementById('doh-url');
  var dotEl = document.getElementById('dot-host');
  if (dohEl) dohEl.textContent = origin + '/dns-query';
  if (dotEl) dotEl.textContent = host;

  function copy(text, btn) {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(function() {
        btn.textContent = '✓';
        setTimeout(function(){ btn.textContent = '📋'; }, 1500);
      });
    }
  }

  var cDoh = document.getElementById('copy-doh');
  var cDot = document.getElementById('copy-dot');
  if (cDoh) cDoh.addEventListener('click', function() { copy(origin + '/dns-query', this); });
  if (cDot) cDot.addEventListener('click', function() { copy(host, this); });

  var form = document.getElementById('unlock-form');
  var input = document.getElementById('key-input');
  var errMsg = document.getElementById('error-msg');

  if (form && input) {
    form.addEventListener('submit', function(e) {
      e.preventDefault();
      var val = (input.value || '').trim();
      if (!val) {
        if (errMsg) errMsg.style.display = 'block';
        return;
      }
      if (val.startsWith('http://') || val.startsWith('https://')) {
        try {
          var u = new URL(val);
          val = u.pathname.replace(/^\\/+/, '');
        } catch(_) {}
      }
      val = val.replace(/^\\/+/, '');
      window.location.href = '/' + val;
    });
  }
})();
</script>
</body>
</html>`;
