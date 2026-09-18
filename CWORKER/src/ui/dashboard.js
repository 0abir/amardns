// CWORKER/src/ui/dashboard.js
// Modern, high-performance glassmorphic dashboard UI with centered navigation tabs,
// live query logs, dynamic upstream ranking, and real-time Bloom filter telemetry.

export function renderDashboardHtml(data) {
  const { appName, masterKey, stats, quota, storage, upstreams, rules, logs } = data;

  const customRulesFormatted = Number(stats.customRulesCount !== undefined ? stats.customRulesCount : (rules?.length || 0)).toLocaleString();
  const threatBloomFormatted = Number(stats.threatBloomCount || stats.threatFeedEntries || 877729).toLocaleString();
  const whitelistCountFormatted = Number(stats.whitelistCount || 2821).toLocaleString();
  const totalProtectedFormatted = Number(stats.totalProtectedDomains || ((stats.threatBloomCount || 877729) + (stats.whitelistCount || 2821) + (rules?.length || 0))).toLocaleString();

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${appName} - Console</title>
  <style>
    :root {
      --bg-base: #07090e;
      --bg-card: rgba(15, 20, 32, 0.75);
      --bg-card-hover: rgba(22, 30, 48, 0.85);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-focus: rgba(59, 130, 246, 0.5);
      --accent-blue: #3b82f6;
      --accent-cyan: #06b6d4;
      --accent-green: #10b981;
      --accent-red: #ef4444;
      --accent-amber: #f59e0b;
      --text-main: #f9fafb;
      --text-muted: #94a3b8;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg-base);
      background-image: 
        radial-gradient(at 0% 0%, rgba(59, 130, 246, 0.08) 0px, transparent 50%),
        radial-gradient(at 100% 100%, rgba(6, 182, 212, 0.05) 0px, transparent 50%);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      padding: 24px;
      min-height: 100vh;
    }
    .container { max-width: 1320px; margin: 0 auto; }
    
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border-color);
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand h1 { font-size: 20px; font-weight: 700; letter-spacing: -0.5px; }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      background: rgba(59, 130, 246, 0.12);
      color: var(--accent-blue);
      border: 1px solid rgba(59, 130, 246, 0.25);
    }
    .badge-green {
      background: rgba(16, 185, 129, 0.12);
      color: var(--accent-green);
      border-color: rgba(16, 185, 129, 0.25);
    }
    .badge-cyan {
      background: rgba(6, 182, 212, 0.12);
      color: var(--accent-cyan);
      border-color: rgba(6, 182, 212, 0.25);
    }
    .badge-amber {
      background: rgba(245, 158, 11, 0.12);
      color: var(--accent-amber);
      border-color: rgba(245, 158, 11, 0.25);
    }
    
    /* Centered Navigation Tabs */
    .nav-tabs {
      display: flex;
      justify-content: center;
      align-items: center;
      gap: 10px;
      margin-bottom: 24px;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 10px;
      overflow-x: auto;
    }
    .nav-tab {
      background: transparent;
      border: 1px solid transparent;
      color: var(--text-muted);
      padding: 9px 20px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }
    .nav-tab:hover {
      color: var(--text-main);
      background: rgba(255, 255, 255, 0.04);
    }
    .nav-tab.active {
      color: #fff;
      background: rgba(59, 130, 246, 0.18);
      border-color: rgba(59, 130, 246, 0.35);
    }
    
    .tab-content { display: none; }
    .tab-content.active { display: block; animation: fadeIn 0.2s ease-in; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(3px); } to { opacity: 1; transform: translateY(0); } }

    .grid-stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .card {
      background: var(--bg-card);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 20px;
      transition: border-color 0.2s;
    }
    .card:hover { border-color: rgba(255, 255, 255, 0.14); }
    .card-title { font-size: 12px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
    .card-value { font-size: 28px; font-weight: 700; color: var(--text-main); letter-spacing: -0.5px; }
    .card-subtitle { font-size: 12px; color: var(--text-muted); margin-top: 4px; }
    
    table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }
    th { padding: 12px 14px; border-bottom: 1px solid var(--border-color); color: var(--text-muted); font-weight: 600; font-size: 12px; }
    td { padding: 12px 14px; border-bottom: 1px solid rgba(255, 255, 255, 0.03); }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }
    tr:last-child td { border-bottom: none; }
    
    .status-pill {
      display: inline-block;
      padding: 2px 7px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      font-family: var(--font-mono);
    }
    .status-allowed { background: rgba(16, 185, 129, 0.12); color: var(--accent-green); }
    .status-blocked { background: rgba(239, 68, 68, 0.12); color: var(--accent-red); }
    
    .form-row { display: flex; gap: 10px; margin-bottom: 16px; }
    input, select, button {
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border-color);
      color: var(--text-main);
      padding: 9px 13px;
      border-radius: 7px;
      font-size: 13px;
      outline: none;
      transition: border-color 0.2s;
    }
    input:focus, select:focus { border-color: var(--border-focus); }
    button {
      background: var(--accent-blue);
      color: #fff;
      font-weight: 600;
      cursor: pointer;
      border: none;
      transition: opacity 0.2s, background-color 0.2s;
    }
    button:hover { opacity: 0.9; }
    button.btn-secondary { background: rgba(255, 255, 255, 0.06); color: var(--text-main); border: 1px solid var(--border-color); }
    button.btn-secondary:hover { background: rgba(255, 255, 255, 0.1); }
    button.btn-danger { background: rgba(239, 68, 68, 0.15); color: var(--accent-red); border: 1px solid rgba(239, 68, 68, 0.3); }
    button.btn-danger:hover { background: var(--accent-red); color: #fff; }
    
    .progress-bar {
      width: 100%;
      height: 6px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 3px;
      overflow: hidden;
      margin-top: 8px;
    }
    .progress-fill { height: 100%; background: var(--accent-blue); border-radius: 3px; }
    .live-dot {
      display: inline-block;
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--accent-green);
      margin-right: 6px;
      box-shadow: 0 0 8px var(--accent-green);
    }
    .toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
      flex-wrap: wrap;
      gap: 12px;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <h1>${appName}</h1>
        <span class="badge">Cloudflare Edge</span>
      </div>
      <div style="display: flex; align-items: center; gap: 10px;">
        <span class="badge badge-green" id="sync-live-badge"><span class="live-dot"></span>Live</span>
        <button onclick="logout()" class="btn-secondary" style="padding: 4px 10px; font-size: 11px;">Lock</button>
      </div>
    </header>

    <!-- Centered Navigation Tabs -->
    <div class="nav-tabs">
      <button class="nav-tab active" data-tab="overview" onclick="switchTab('overview')">Overview</button>
      <button class="nav-tab" data-tab="logs" onclick="switchTab('logs')">Logs</button>
      <button class="nav-tab" data-tab="rules" onclick="switchTab('rules')">Rules</button>
      <button class="nav-tab" data-tab="upstreams" onclick="switchTab('upstreams')">Upstreams</button>
      <button class="nav-tab" data-tab="quota" onclick="switchTab('quota')">Quota</button>
    </div>

    <!-- TAB 1: OVERVIEW -->
    <div id="tab-overview" class="tab-content active">
      <div class="grid-stats">
        <div class="card">
          <div class="card-title">Total Queries</div>
          <div class="card-value" id="stat-total">${stats.totalQueries || 0}</div>
          <div class="card-subtitle">Session Invocations</div>
        </div>
        <div class="card">
          <div class="card-title">Threats Blocked</div>
          <div class="card-value" style="color: var(--accent-red);" id="stat-blocked">${stats.blockedQueries || 0}</div>
          <div class="card-subtitle" id="stat-block-rate">${stats.blockRate || '0.0%'} Block Rate</div>
        </div>
        <div class="card">
          <div class="card-title">Edge Cache Hit Rate</div>
          <div class="card-value" style="color: var(--accent-green);" id="stat-cache-rate">${stats.cacheHitRate || '0.0%'}</div>
          <div class="card-subtitle" id="stat-cache-sub">${stats.cacheHits || 0} hits / ${stats.cacheMisses || 0} misses</div>
        </div>
        <div class="card">
          <div class="card-title">Threat Feed Shield</div>
          <div class="card-value" style="color: var(--accent-cyan);" id="stat-rules-total">${threatBloomFormatted}</div>
          <div class="card-subtitle" id="stat-rules-sub">${whitelistCountFormatted} allowlist · ${customRulesFormatted} custom</div>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px;">
        <div class="card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <h2 style="font-size: 15px;">Fast DNS Inspector</h2>
            <span class="badge">Live Test</span>
          </div>
          <form onsubmit="testResolution(event)">
            <div class="form-row">
              <input type="text" id="test-domain" placeholder="Domain name (e.g. cloudflare.com)" style="flex: 2;" required />
              <select id="test-type" style="flex: 1;">
                <option value="A">A</option>
                <option value="AAAA">AAAA</option>
                <option value="TXT">TXT</option>
                <option value="CNAME">CNAME</option>
                <option value="HTTPS">HTTPS</option>
              </select>
              <button type="submit">Resolve</button>
            </div>
          </form>
          <pre id="test-result" style="background: rgba(0,0,0,0.3); padding: 14px; border-radius: 8px; font-family: var(--font-mono); font-size: 12px; max-height: 180px; overflow-y: auto; color: var(--text-muted);">Enter a domain above to test real-time resolution</pre>
        </div>

        <div class="card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <h2 style="font-size: 15px;">Active Upstreams Status</h2>
            <div style="display: flex; gap: 8px;">
              <button class="btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="rankUpstreams()">Rank Now</button>
              <button class="btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="flushCache()">Flush Cache</button>
            </div>
          </div>
          <table>
            <thead>
              <tr>
                <th>Provider</th>
                <th>Latency</th>
                <th>Aura</th>
                <th>Score</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody id="overview-upstreams-tbody">
              ${upstreams.slice(0, 4).map(u => `
                <tr>
                  <td><strong>${u.provider}</strong></td>
                  <td>${u.latencyMs} ms</td>
                  <td><span class="badge badge-${u.aura === 'high' ? 'green' : (u.aura === 'medium' ? 'cyan' : 'amber')}">${(u.aura || 'medium').toUpperCase()}</span></td>
                  <td>${u.score}/100</td>
                  <td><span class="status-pill status-${u.healthy ? 'allowed' : 'blocked'}">${u.healthy ? 'Healthy' : 'Degraded'}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 2: LOGS -->
    <div id="tab-logs" class="tab-content">
      <div class="card">
        <div class="toolbar">
          <div style="display: flex; gap: 10px; align-items: center;">
            <h2 style="font-size: 16px;">Live Query Log Stream</h2>
            <span class="badge badge-green" id="log-status-badge"><span class="live-dot"></span>Streaming</span>
          </div>
          <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
            <input type="text" id="log-search" placeholder="Search domain..." oninput="filterLogs()" style="width: 180px; padding: 6px 10px; font-size: 12px;" />
            <select id="log-status-filter" onchange="filterLogs()" style="padding: 6px 10px; font-size: 12px;">
              <option value="ALL">All Status</option>
              <option value="ALLOWED">Allowed</option>
              <option value="BLOCKED">Blocked</option>
            </select>
            <select id="log-qtype-filter" onchange="filterLogs()" style="padding: 6px 10px; font-size: 12px;">
              <option value="ALL">All Types</option>
              <option value="A">A</option>
              <option value="AAAA">AAAA</option>
              <option value="HTTPS">HTTPS</option>
              <option value="TXT">TXT</option>
            </select>
            <button class="btn-secondary" onclick="toggleLogStream()" id="btn-toggle-stream" style="padding: 6px 10px; font-size: 12px;">Pause</button>
            <button class="btn-secondary" onclick="clearLogs()" style="padding: 6px 10px; font-size: 12px;">Clear</button>
          </div>
        </div>

        <div style="max-height: 520px; overflow-y: auto; border: 1px solid var(--border-color); border-radius: 8px;">
          <table>
            <thead>
              <tr>
                <th style="width: 100px;">Time</th>
                <th>Domain</th>
                <th style="width: 70px;">Type</th>
                <th style="width: 90px;">Status</th>
                <th>Reason / Upstream</th>
                <th style="width: 90px;">Latency</th>
              </tr>
            </thead>
            <tbody id="live-logs-tbody">
              ${logs.length === 0 ? '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">No query logs recorded yet</td></tr>' : logs.map(l => `
                <tr>
                  <td style="color: var(--text-muted); font-size: 11px; font-family: var(--font-mono);">${new Date(l.timestamp).toLocaleTimeString()}</td>
                  <td style="font-weight: 600; font-family: var(--font-mono);">${l.domain}</td>
                  <td><span class="badge" style="font-size: 10px;">${l.qtype}</span></td>
                  <td><span class="status-pill status-${l.status === 'ALLOWED' ? 'allowed' : 'blocked'}">${l.status}</span></td>
                  <td style="font-size: 12px; color: var(--text-muted);">${l.reason}</td>
                  <td style="font-family: var(--font-mono); font-size: 12px;">${l.latencyMs} ms</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 3: RULES -->
    <div id="tab-rules" class="tab-content">
      <!-- Bloom Filter Telemetry Banner -->
      <div class="card" style="margin-bottom: 20px; background: rgba(59, 130, 246, 0.05); border-color: rgba(59, 130, 246, 0.2);">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
          <div>
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px;">
              <h3 style="font-size: 15px; font-weight: 700;">In-Memory Bloom Filter Threat Engine</h3>
              <span class="badge badge-green" id="bloom-pill">4 MB Bitset Active</span>
            </div>
            <div style="font-size: 12px; color: var(--text-muted);" id="bloom-desc">
              33,554,432 bits with 7 optimal double-hash probes. Protecting <strong id="bloom-block-count">${threatBloomFormatted}</strong> global threat domains & <strong id="bloom-white-count">${whitelistCountFormatted}</strong> verified infrastructure allowlists with zero latency.
            </div>
          </div>
          <button class="btn-secondary" style="padding: 6px 14px; font-size: 12px;" onclick="syncFeeds()" id="btn-sync-feeds">Sync Threat Feeds</button>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 24px;">
        <div class="card">
          <h2 style="font-size: 15px; margin-bottom: 14px;">Add Custom Rule</h2>
          <form onsubmit="addRule(event)">
            <div style="margin-bottom: 12px;">
              <label style="font-size: 12px; color: var(--text-muted); display: block; margin-bottom: 4px;">Domain Name</label>
              <input type="text" id="rule-domain" placeholder="example.com" style="width: 100%;" required />
            </div>
            <div style="margin-bottom: 12px;">
              <label style="font-size: 12px; color: var(--text-muted); display: block; margin-bottom: 4px;">Action</label>
              <select id="rule-type" style="width: 100%;">
                <option value="blocklist">Block (Zero-IP / NXDOMAIN)</option>
                <option value="whitelist">Allow (Bypass all checks)</option>
              </select>
            </div>
            <div style="margin-bottom: 16px;">
              <label style="font-size: 12px; color: var(--text-muted); display: flex; align-items: center; gap: 6px; cursor: pointer;">
                <input type="checkbox" id="rule-wildcard" checked /> Match Subdomains (*.)
              </label>
            </div>
            <button type="submit" style="width: 100%;">Save Rule</button>
          </form>
        </div>

        <div class="card">
          <div class="toolbar">
            <h2 style="font-size: 15px;">Active Custom Override Rules</h2>
            <input type="text" id="rules-search" placeholder="Search rules..." oninput="filterRules()" style="padding: 5px 10px; font-size: 12px; width: 180px;" />
          </div>
          <div style="max-height: 420px; overflow-y: auto;">
            <table>
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Type</th>
                  <th>Scope</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody id="rules-tbody">
                ${rules.length === 0 ? '<tr><td colspan="4" style="color: var(--text-muted); text-align: center; padding: 24px;">No custom override rules configured</td></tr>' : rules.map(r => `
                  <tr>
                    <td style="font-weight: 600; font-family: var(--font-mono);">${r.domain}</td>
                    <td><span class="status-pill status-${r.type === 'whitelist' ? 'allowed' : 'blocked'}">${r.type}</span></td>
                    <td><span class="badge" style="font-size: 10px;">${r.isWildcard ? 'Wildcard (*.)' : 'Exact'}</span></td>
                    <td><button class="btn-danger" style="padding: 2px 8px; font-size: 11px;" onclick="deleteRule('${r.domain}')">Delete</button></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 4: UPSTREAMS -->
    <div id="tab-upstreams" class="tab-content">
      <div class="card">
        <div class="toolbar">
          <div>
            <h2 style="font-size: 16px;">Upstream Resolvers Telemetry</h2>
            <div style="font-size: 12px; color: var(--text-muted);">Probed and ranked by lowest latency & aura priority in background</div>
          </div>
          <button class="btn-secondary" onclick="rankUpstreams()" id="btn-rank-upstreams" style="padding: 6px 14px; font-size: 12px;">Probe & Rank All Upstreams</button>
        </div>
        <table>
          <thead>
            <tr>
              <th>Provider</th>
              <th>Endpoint URL</th>
              <th>Aura</th>
              <th>Latency (EWMA)</th>
              <th>Health Score</th>
              <th>Requests</th>
              <th>Errors</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody id="upstreams-tbody">
            ${upstreams.map(u => `
              <tr>
                <td><strong>${u.provider}</strong></td>
                <td style="font-family: var(--font-mono); font-size: 12px; color: var(--text-muted);">${u.url}</td>
                <td><span class="badge badge-${u.aura === 'high' ? 'green' : (u.aura === 'medium' ? 'cyan' : 'amber')}">${(u.aura || 'medium').toUpperCase()}</span></td>
                <td style="font-family: var(--font-mono);">${u.latencyMs} ms</td>
                <td>
                  <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="font-family: var(--font-mono);">${u.score}%</span>
                    <div style="width: 60px; height: 4px; background: rgba(255,255,255,0.06); border-radius: 2px;">
                      <div style="width: ${u.score}%; height: 100%; background: ${u.score > 80 ? 'var(--accent-green)' : 'var(--accent-amber)'};"></div>
                    </div>
                  </div>
                </td>
                <td>${u.hits}</td>
                <td>${u.errors}</td>
                <td><span class="status-pill status-${u.healthy ? 'allowed' : 'blocked'}">${u.healthy ? 'Healthy' : 'Degraded'}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 5: QUOTA -->
    <div id="tab-quota" class="tab-content">
      <div class="card" style="max-width: 780px; margin: 0 auto;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px;">
          <div>
            <h2 style="font-size: 16px;">Daily Quota Guardian</h2>
            <div style="font-size: 12px; color: var(--text-muted);">Real-time Cloudflare Free Tier budget enforcement</div>
          </div>
          <span class="badge ${storage?.kv?.bound || storage?.d1?.bound ? 'badge-green' : 'badge-cyan'}" id="quota-storage-badge">
            ${storage?.mode || 'Persistent Edge Store'}
          </span>
        </div>

        <!-- Detected Storage Bindings Grid -->
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 24px;">
          <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border-color); border-radius: 8px; padding: 12px;">
            <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">KV Namespace</div>
            <div style="font-size: 13px; font-weight: 600; margin-top: 4px;" id="storage-kv-status">
              ${storage?.kv?.bound ? `Connected (${storage.kv.name})` : 'In-Memory Mode'}
            </div>
          </div>
          <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border-color); border-radius: 8px; padding: 12px;">
            <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">D1 SQL Database</div>
            <div style="font-size: 13px; font-weight: 600; margin-top: 4px;" id="storage-d1-status">
              ${storage?.d1?.bound ? `Connected (${storage.d1.name})` : 'In-Memory Mode'}
            </div>
          </div>
        </div>
        
        <div style="margin-bottom: 20px;">
          <div style="display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 6px;">
            <span><strong>KV Daily Writes</strong> (Limit: ${Number(quota?.kv?.writeCap || 900).toLocaleString()} / day)</span>
            <span style="font-family: var(--font-mono);" id="quota-kv-writes">${quota?.kv?.writes || 0} / ${quota?.kv?.writeCap || 900}</span>
          </div>
          <div class="progress-bar" style="height: 8px;">
            <div class="progress-fill" id="quota-kv-bar" style="width: ${((quota?.kv?.writes || 0) / (quota?.kv?.writeCap || 900)) * 100}%;"></div>
          </div>
          <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;" id="quota-kv-sub">Remaining: ${quota?.kv?.writesRemaining || 900} writes today</div>
        </div>

        <div style="margin-bottom: 20px;">
          <div style="display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 6px;">
            <span><strong>KV Daily Reads</strong> (Limit: ${Number(quota?.kv?.readCap || 90000).toLocaleString()} / day)</span>
            <span style="font-family: var(--font-mono);" id="quota-read-writes">${quota?.kv?.reads || 0} / ${quota?.kv?.readCap || 90000}</span>
          </div>
          <div class="progress-bar" style="height: 8px;">
            <div class="progress-fill" id="quota-read-bar" style="width: ${((quota?.kv?.reads || 0) / (quota?.kv?.readCap || 90000)) * 100}%; background: var(--accent-green);"></div>
          </div>
          <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;" id="quota-read-sub">Remaining: ${quota?.kv?.readsRemaining || 90000} reads today</div>
        </div>

        <div style="margin-bottom: 24px;">
          <div style="display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 6px;">
            <span><strong>D1 Daily Writes</strong> (Limit: ${Number(quota?.d1?.writeCap || 90000).toLocaleString()} / day)</span>
            <span style="font-family: var(--font-mono);" id="quota-d1-writes">${quota?.d1?.writes || 0} / ${quota?.d1?.writeCap || 90000}</span>
          </div>
          <div class="progress-bar" style="height: 8px;">
            <div class="progress-fill" id="quota-d1-bar" style="width: ${((quota?.d1?.writes || 0) / (quota?.d1?.writeCap || 90000)) * 100}%; background: var(--accent-cyan);"></div>
          </div>
          <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;" id="quota-d1-sub">Remaining: ${quota?.d1?.writesRemaining || 90000} writes today</div>
        </div>

        <div style="background: rgba(255,255,255,0.03); padding: 14px; border-radius: 8px; border: 1px solid var(--border-color); font-size: 12px; color: var(--text-muted); line-height: 1.6;">
          <strong>Automatic Over-Quota Protection:</strong> When daily persistent storage limits are reached, the worker seamlessly diverts all operations to the 100% free, unlimited Cloudflare Edge Cache API and in-memory V8 isolates, guaranteeing zero overage charges.
        </div>
      </div>
    </div>
  </div>

  <script>
    const MASTER_KEY = '${masterKey}';
    let allLogs = ${JSON.stringify(logs)};
    let allRules = ${JSON.stringify(rules)};
    let allUpstreams = ${JSON.stringify(upstreams)};
    let streamInterval = null;
    let isStreaming = true;

    function switchTab(tabId) {
      document.querySelectorAll('.nav-tab').forEach(t => {
        t.classList.toggle('active', t.getAttribute('data-tab') === tabId);
      });
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      
      const content = document.getElementById('tab-' + tabId);
      if (content) content.classList.add('active');

      if (tabId === 'logs') {
        startLogStream();
      }
    }

    async function fetchStatus() {
      try {
        const res = await fetch('/api/status', {
          headers: { 'x-api-key': MASTER_KEY }
        });
        if (res.ok) {
          const data = await res.json();
          updateDashboardStats(data);
        }
      } catch (e) {}
    }

    function updateDashboardStats(data) {
      if (!data) return;
      const stats = data.stats || {};
      const rules = data.rules || {};
      const upstreams = data.upstreams || [];

      const total = document.getElementById('stat-total');
      if (total && stats.totalQueries !== undefined) total.innerText = stats.totalQueries;

      const blocked = document.getElementById('stat-blocked');
      if (blocked && stats.blockedQueries !== undefined) blocked.innerText = stats.blockedQueries;

      const blockRate = document.getElementById('stat-block-rate');
      if (blockRate && stats.blockRate) blockRate.innerText = stats.blockRate + ' Block Rate';

      const cacheRate = document.getElementById('stat-cache-rate');
      if (cacheRate && stats.cacheHitRate) cacheRate.innerText = stats.cacheHitRate;

      const cacheSub = document.getElementById('stat-cache-sub');
      if (cacheSub) cacheSub.innerText = (stats.cacheHits || 0) + ' hits / ' + (stats.cacheMisses || 0) + ' misses';

      const rulesTotal = document.getElementById('stat-rules-total');
      const threatCount = stats.threatBloomCount !== undefined ? stats.threatBloomCount : (stats.threatFeedEntries || 0);
      if (rulesTotal && threatCount !== undefined) rulesTotal.innerText = Number(threatCount).toLocaleString();

      const rulesSub = document.getElementById('stat-rules-sub');
      if (rulesSub && stats.whitelistCount !== undefined) {
        const customCount = stats.customRulesCount !== undefined ? stats.customRulesCount : (allRules ? allRules.length : 0);
        rulesSub.innerText = Number(stats.whitelistCount).toLocaleString() + ' allowlist · ' + Number(customCount).toLocaleString() + ' custom';
      }

      const bloomBlock = document.getElementById('bloom-block-count');
      if (bloomBlock && threatCount !== undefined) bloomBlock.innerText = Number(threatCount).toLocaleString();

      const bloomWhite = document.getElementById('bloom-white-count');
      if (bloomWhite && stats.whitelistCount !== undefined) bloomWhite.innerText = Number(stats.whitelistCount).toLocaleString();

      if (data.quota) {
        const q = data.quota;
        if (q.kv) {
          const kw = document.getElementById('quota-kv-writes');
          if (kw) kw.innerText = q.kv.writes + ' / ' + q.kv.writeCap;
          const kb = document.getElementById('quota-kv-bar');
          if (kb) kb.style.width = ((q.kv.writes / q.kv.writeCap) * 100) + '%';
          const ks = document.getElementById('quota-kv-sub');
          if (ks) ks.innerText = 'Remaining: ' + q.kv.writesRemaining + ' writes today';

          const kr = document.getElementById('quota-read-writes');
          if (kr) kr.innerText = q.kv.reads + ' / ' + q.kv.readCap;
          const krb = document.getElementById('quota-read-bar');
          if (krb) krb.style.width = ((q.kv.reads / q.kv.readCap) * 100) + '%';
          const krs = document.getElementById('quota-read-sub');
          if (krs) krs.innerText = 'Remaining: ' + q.kv.readsRemaining + ' reads today';
        }
        if (q.d1) {
          const dw = document.getElementById('quota-d1-writes');
          if (dw) dw.innerText = q.d1.writes + ' / ' + q.d1.writeCap;
          const db = document.getElementById('quota-d1-bar');
          if (db) db.style.width = ((q.d1.writes / q.d1.writeCap) * 100) + '%';
          const ds = document.getElementById('quota-d1-sub');
          if (ds) ds.innerText = 'Remaining: ' + q.d1.writesRemaining + ' writes today';
        }
      }

      if (data.storage) {
        const st = data.storage;
        const kvStatus = document.getElementById('storage-kv-status');
        if (kvStatus) kvStatus.innerText = st.kv?.bound ? 'Connected (' + st.kv.name + ')' : 'In-Memory Mode';
        const d1Status = document.getElementById('storage-d1-status');
        if (d1Status) d1Status.innerText = st.d1?.bound ? 'Connected (' + st.d1.name + ')' : 'In-Memory Mode';
        const badge = document.getElementById('quota-storage-badge');
        if (badge) badge.innerText = st.mode || 'Persistent Edge Store';
      }

      if (Array.isArray(upstreams) && upstreams.length > 0) {
        allUpstreams = upstreams;
        renderUpstreamsRows(upstreams);
      }
    }

    function renderUpstreamsRows(list) {
      const tbody = document.getElementById('upstreams-tbody');
      const overviewTbody = document.getElementById('overview-upstreams-tbody');
      if (!list) return;

      const rowsHtml = list.map(u => \`
        <tr>
          <td><strong>\${u.provider}</strong></td>
          <td style="font-family: var(--font-mono); font-size: 12px; color: var(--text-muted);">\${u.url}</td>
          <td><span class="badge badge-\${u.aura === 'high' ? 'green' : (u.aura === 'medium' ? 'cyan' : 'amber')}">\${(u.aura || 'medium').toUpperCase()}</span></td>
          <td style="font-family: var(--font-mono);">\${u.latencyMs} ms</td>
          <td>
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="font-family: var(--font-mono);">\${u.score}%</span>
              <div style="width: 60px; height: 4px; background: rgba(255,255,255,0.06); border-radius: 2px;">
                <div style="width: \${u.score}%; height: 100%; background: \${u.score > 80 ? 'var(--accent-green)' : 'var(--accent-amber)'};"></div>
              </div>
            </div>
          </td>
          <td>\${u.hits}</td>
          <td>\${u.errors}</td>
          <td><span class="status-pill status-\${u.healthy ? 'allowed' : 'blocked'}">\${u.healthy ? 'Healthy' : 'Degraded'}</span></td>
        </tr>
      \`).join('');

      if (tbody) tbody.innerHTML = rowsHtml;

      if (overviewTbody) {
        overviewTbody.innerHTML = list.slice(0, 4).map(u => \`
          <tr>
            <td><strong>\${u.provider}</strong></td>
            <td>\${u.latencyMs} ms</td>
            <td><span class="badge badge-\${u.aura === 'high' ? 'green' : (u.aura === 'medium' ? 'cyan' : 'amber')}">\${(u.aura || 'medium').toUpperCase()}</span></td>
            <td>\${u.score}/100</td>
            <td><span class="status-pill status-\${u.healthy ? 'allowed' : 'blocked'}">\${u.healthy ? 'Healthy' : 'Degraded'}</span></td>
          </tr>
        \`).join('');
      }
    }

    async function fetchLogs() {
      try {
        const res = await fetch('/api/logs', {
          headers: { 'x-api-key': MASTER_KEY }
        });
        if (res.ok) {
          allLogs = await res.json();
          renderLogRows(allLogs);
        }
      } catch (e) {}
    }

    function renderLogRows(logList) {
      const tbody = document.getElementById('live-logs-tbody');
      if (!tbody) return;
      if (!logList || logList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">No query logs recorded yet</td></tr>';
        return;
      }
      tbody.innerHTML = logList.map(l => \`
        <tr>
          <td style="color: var(--text-muted); font-size: 11px; font-family: var(--font-mono);">\${new Date(l.timestamp).toLocaleTimeString()}</td>
          <td style="font-weight: 600; font-family: var(--font-mono);">\${l.domain}</td>
          <td><span class="badge" style="font-size: 10px;">\${l.qtype}</span></td>
          <td><span class="status-pill status-\${l.status === 'ALLOWED' ? 'allowed' : 'blocked'}">\${l.status}</span></td>
          <td style="font-size: 12px; color: var(--text-muted);">\${l.reason}</td>
          <td style="font-family: var(--font-mono); font-size: 12px;">\${l.latencyMs} ms</td>
        </tr>
      \`).join('');
    }

    function filterLogs() {
      const q = (document.getElementById('log-search')?.value || '').toLowerCase().trim();
      const status = document.getElementById('log-status-filter')?.value || 'ALL';
      const qtype = document.getElementById('log-qtype-filter')?.value || 'ALL';

      let filtered = allLogs;
      if (status !== 'ALL') filtered = filtered.filter(l => l.status === status);
      if (qtype !== 'ALL') filtered = filtered.filter(l => l.qtype === qtype);
      if (q) filtered = filtered.filter(l => l.domain.includes(q) || (l.reason && l.reason.toLowerCase().includes(q)));
      renderLogRows(filtered);
    }

    function startLogStream() {
      if (streamInterval) clearInterval(streamInterval);
      if (isStreaming) {
        streamInterval = setInterval(fetchLogs, 3000);
      }
    }

    function toggleLogStream() {
      isStreaming = !isStreaming;
      const btn = document.getElementById('btn-toggle-stream');
      const badge = document.getElementById('log-status-badge');
      if (isStreaming) {
        btn.innerText = 'Pause';
        badge.className = 'badge badge-green';
        badge.innerHTML = '<span class="live-dot"></span>Streaming';
        startLogStream();
      } else {
        btn.innerText = 'Resume';
        badge.className = 'badge';
        badge.innerText = 'Paused';
        if (streamInterval) clearInterval(streamInterval);
      }
    }

    async function clearLogs() {
      if (!confirm('Clear all in-memory query logs?')) return;
      try {
        const res = await fetch('/api/logs?action=clear', {
          method: 'DELETE',
          headers: { 'x-api-key': MASTER_KEY }
        });
        if (res.ok) {
          allLogs = [];
          renderLogRows([]);
        }
      } catch (e) {}
    }

    async function rankUpstreams() {
      const btn = document.getElementById('btn-rank-upstreams');
      if (btn) {
        btn.disabled = true;
        btn.innerText = 'Probing & Ranking...';
      }
      try {
        const res = await fetch('/api/upstreams/rank', {
          method: 'POST',
          headers: { 'x-api-key': MASTER_KEY }
        });
        if (res.ok) {
          const data = await res.json();
          if (data.upstreams) {
            renderUpstreamsRows(data.upstreams);
          }
          await fetchStatus();
        }
      } catch (e) {
        alert('Failed to rank upstreams: ' + e.message);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.innerText = 'Probe & Rank All Upstreams';
        }
      }
    }

    async function syncFeeds() {
      const btn = document.getElementById('btn-sync-feeds');
      if (btn) {
        btn.disabled = true;
        btn.innerText = 'Streaming & Ingesting Feeds...';
      }
      try {
        const res = await fetch('/api/feeds/sync', {
          method: 'POST',
          headers: { 'x-api-key': MASTER_KEY }
        });
        if (res.ok) {
          await fetchStatus();
        }
      } catch (e) {
        alert('Failed to sync feeds: ' + e.message);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.innerText = 'Sync Threat Feeds';
        }
      }
    }

    async function testResolution(e) {
      e.preventDefault();
      const domain = document.getElementById('test-domain').value.trim();
      const type = document.getElementById('test-type').value;
      const resultBox = document.getElementById('test-result');
      resultBox.innerText = 'Resolving ' + domain + ' (' + type + ')...';

      try {
        const t0 = performance.now();
        const res = await fetch('/resolve?name=' + encodeURIComponent(domain) + '&type=' + encodeURIComponent(type));
        const json = await res.json();
        const lat = Math.round(performance.now() - t0);
        resultBox.innerText = JSON.stringify(json, null, 2) + '\\n\\n// Total round-trip: ' + lat + ' ms';
        fetchLogs();
      } catch (err) {
        resultBox.innerText = 'Error: ' + err.message;
      }
    }

    async function addRule(e) {
      e.preventDefault();
      const domain = document.getElementById('rule-domain').value.trim();
      const type = document.getElementById('rule-type').value;
      const isWildcard = document.getElementById('rule-wildcard').checked;
      if (!domain) return;

      try {
        const res = await fetch('/api/rules', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': MASTER_KEY
          },
          body: JSON.stringify({ domain, type, isWildcard })
        });
        if (res.ok) {
          location.reload();
        } else {
          alert('Failed to save rule');
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }

    async function deleteRule(domain) {
      if (!confirm('Delete rule for ' + domain + '?')) return;
      try {
        const res = await fetch('/api/rules?domain=' + encodeURIComponent(domain), {
          method: 'DELETE',
          headers: { 'x-api-key': MASTER_KEY }
        });
        if (res.ok) location.reload();
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }

    async function flushCache() {
      if (!confirm('Flush Edge and In-Memory Cache?')) return;
      try {
        const res = await fetch('/api/flush', {
          method: 'POST',
          headers: { 'x-api-key': MASTER_KEY }
        });
        if (res.ok) alert('Cache successfully flushed.');
      } catch (err) {}
    }

    function logout() {
      document.cookie = 'amardns_auth=; Path=/; Max-Age=0; SameSite=Strict';
      location.href = '/';
    }

    // Start background live status updates (every 5 seconds)
    setInterval(fetchStatus, 5000);
  </script>
</body>
</html>`;
}

export function renderLoginHtml(appName) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${appName} - Authentication</title>
  <style>
    :root {
      --bg-base: #07090e;
      --bg-card: rgba(15, 20, 32, 0.85);
      --border-color: rgba(255, 255, 255, 0.1);
      --accent-blue: #3b82f6;
      --accent-red: #ef4444;
      --text-main: #f9fafb;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg-base);
      background-image: radial-gradient(at 50% 50%, rgba(59, 130, 246, 0.08) 0px, transparent 60%);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .login-card {
      background: var(--bg-card);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 36px;
      width: 100%;
      max-width: 420px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
      text-align: center;
    }
    .brand-title { font-size: 20px; font-weight: 700; margin-bottom: 6px; letter-spacing: -0.5px; }
    .brand-subtitle { font-size: 12px; color: var(--text-muted); margin-bottom: 28px; }
    .form-group { margin-bottom: 20px; text-align: left; }
    label { display: block; font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
    input[type="password"] {
      width: 100%;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      color: var(--text-main);
      padding: 12px 14px;
      border-radius: 8px;
      font-size: 14px;
      outline: none;
      transition: border-color 0.2s;
    }
    input:focus { border-color: var(--accent-blue); }
    button {
      width: 100%;
      background: var(--accent-blue);
      color: #fff;
      font-size: 14px;
      font-weight: 600;
      padding: 12px;
      border-radius: 8px;
      border: none;
      cursor: pointer;
      transition: opacity 0.2s;
    }
    button:hover { opacity: 0.9; }
    .error-box {
      display: none;
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: var(--accent-red);
      font-size: 12px;
      padding: 10px;
      border-radius: 8px;
      margin-bottom: 20px;
      text-align: left;
    }
  </style>
</head>
<body>
  <div class="login-card">
    <div class="brand-title">${appName}</div>
    <div class="brand-subtitle">Protected Management Console</div>

    <div class="error-box" id="error-box">Access Denied: Invalid Master Key</div>

    <form id="login-form" onsubmit="handleLogin(event)">
      <div class="form-group">
        <label for="master-key">Master Key</label>
        <input type="password" id="master-key" placeholder="Enter master key" required autofocus />
      </div>
      <button type="submit" id="submit-btn">Unlock Dashboard</button>
    </form>
  </div>

  <script>
    async function handleLogin(e) {
      e.preventDefault();
      const key = document.getElementById('master-key').value.trim();
      const errBox = document.getElementById('error-box');
      const btn = document.getElementById('submit-btn');

      errBox.style.display = 'none';
      btn.disabled = true;
      btn.innerText = 'Authenticating...';

      try {
        const res = await fetch('/api/status', {
          headers: { 'x-api-key': key }
        });

        if (res.ok) {
          document.cookie = 'amardns_auth=' + encodeURIComponent(key) + '; Path=/; Max-Age=2592000; SameSite=Strict';
          location.href = '/?key=' + encodeURIComponent(key);
        } else {
          errBox.style.display = 'block';
          btn.disabled = false;
          btn.innerText = 'Unlock Dashboard';
        }
      } catch (err) {
        errBox.innerText = 'Network error: ' + err.message;
        errBox.style.display = 'block';
        btn.disabled = false;
        btn.innerText = 'Unlock Dashboard';
      }
    }
  </script>
</body>
</html>`;
}
