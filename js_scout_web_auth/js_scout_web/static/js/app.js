/**
 * JS Scout Web — Frontend Application
 * macOS-style JavaScript reconnaissance tool UI
 */

// ─── State ───────────────────────────────────────────────────────────────────
let socket = null;
let currentScanId = null;
let currentResults = null;
let allScans = [];

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initClock();
  initSocket();
  loadScans();

  // Enter key on target input
  document.getElementById('target-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') startScan();
  });
});

// ─── Clock ───────────────────────────────────────────────────────────────────
function initClock() {
  const el = document.getElementById('menubar-time');
  const update = () => {
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  };
  update();
  setInterval(update, 10000);
}

// ─── Socket.IO ───────────────────────────────────────────────────────────────
function initSocket() {
  socket = io({ transports: ['websocket', 'polling'] });

  socket.on('connect', () => console.log('[socket] connected'));
  socket.on('disconnect', () => console.log('[socket] disconnected'));

  socket.on('scan_log', (data) => {
    if (data.scan_id === currentScanId) {
      appendTerminalLine(data.msg, data.level, data.time);
    }
  });

  socket.on('scan_progress', (data) => {
    if (data.scan_id === currentScanId) {
      updateProgress(data.progress, data.phase);
    }
  });

  socket.on('scan_complete', (data) => {
    if (data.scan_id === currentScanId) {
      onScanComplete(data.results);
    }
  });
}

// ─── View Switching ───────────────────────────────────────────────────────────
function switchView(viewName) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.dock-item').forEach(d => d.classList.remove('active'));

  const view = document.getElementById(`view-${viewName}`);
  if (view) view.classList.add('active');

  const navItem = document.querySelector(`[data-view="${viewName}"]`);
  if (navItem) navItem.classList.add('active');

  // Dock active state
  const dockIdx = { scanner: 0, scans: 1 };
  const docks = document.querySelectorAll('.dock-item');
  if (dockIdx[viewName] !== undefined && docks[dockIdx[viewName]]) {
    docks[dockIdx[viewName]].classList.add('active');
  }

  if (viewName === 'scans') refreshScansTable();
}

// ─── Tab Switching ────────────────────────────────────────────────────────────
function switchTab(tabId) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));

  const panel = document.getElementById(tabId);
  if (panel) panel.classList.add('active');

  const tab = document.querySelector(`[data-tab="${tabId}"]`);
  if (tab) tab.classList.add('active');
}

// ─── Start Scan ───────────────────────────────────────────────────────────────
async function startScan() {
  const target = document.getElementById('target-input').value.trim();
  if (!target) {
    shakeElement(document.getElementById('target-input'));
    return;
  }

  const options = {
    deep: document.getElementById('opt-deep').checked,
    headless: document.getElementById('opt-headless').checked,
    use_gau: document.getElementById('opt-gau').checked,
    use_katana: document.getElementById('opt-katana').checked,
    rate_limit: parseFloat(document.getElementById('opt-rate').value) || 10,
  };

  // UI state
  const scanBtn = document.getElementById('scan-btn');
  scanBtn.disabled = true;
  scanBtn.innerHTML = `<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2"><circle cx="10" cy="10" r="7"/><path class="spin-path" d="M10 3a7 7 0 017 7"/></svg> Scanning...`;

  // Show progress card
  const progressCard = document.getElementById('progress-card');
  progressCard.style.display = 'block';
  progressCard.classList.add('fade-in');
  document.getElementById('progress-target').textContent = target;
  document.getElementById('progress-status-badge').textContent = 'Running';
  document.getElementById('progress-status-badge').className = 'progress-status-badge';
  document.getElementById('terminal-body').innerHTML = '';

  // Hide stats
  document.getElementById('quick-stats').style.display = 'none';

  // Update menubar
  document.getElementById('menubar-status').textContent = `Scanning ${target}...`;

  try {
    const auth = collectAuthData();
    const resp = await fetch('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, options, auth }),
    });
    const data = await resp.json();

    if (data.error) {
      showError(data.error);
      resetScanBtn();
      return;
    }

    currentScanId = data.scan_id;
    appendTerminalLine(`[*] Scan started — ID: ${data.scan_id}`, 'info', new Date().toLocaleTimeString());

    // Poll as fallback in case websocket misses
    pollScanStatus();

  } catch (err) {
    showError('Failed to start scan: ' + err.message);
    resetScanBtn();
  }
}

// ─── Poll Status (fallback) ──────────────────────────────────────────────────
function pollScanStatus() {
  if (!currentScanId) return;
  let done = false;

  const interval = setInterval(async () => {
    if (done) { clearInterval(interval); return; }
    try {
      const resp = await fetch(`/api/scan/${currentScanId}/status`);
      const data = await resp.json();

      updateProgress(data.progress, data.phase);

      if (data.status === 'complete') {
        done = true;
        clearInterval(interval);
        // Fetch full results
        const rResp = await fetch(`/api/scan/${currentScanId}/results`);
        const results = await rResp.json();
        onScanComplete(results);
      } else if (data.status === 'error') {
        done = true;
        clearInterval(interval);
        onScanError(data.phase);
      }
    } catch (e) {
      console.warn('poll error', e);
    }
  }, 2000);
}

// ─── Progress Update ─────────────────────────────────────────────────────────
function updateProgress(pct, phase) {
  document.getElementById('progress-fill').style.width = pct + '%';
  document.getElementById('progress-pct').textContent = pct + '%';
  document.getElementById('progress-phase').textContent = phase;
}

// ─── Terminal Log ─────────────────────────────────────────────────────────────
function appendTerminalLine(msg, level, time) {
  const body = document.getElementById('terminal-body');
  const line = document.createElement('span');
  line.className = `log-line ${level || 'info'}`;
  line.innerHTML = `<span class="log-time">${time || ''}</span>${escapeHtml(msg)}`;
  body.appendChild(line);
  body.scrollTop = body.scrollHeight;
}

// ─── Scan Complete ────────────────────────────────────────────────────────────
function onScanComplete(results) {
  currentResults = results;

  // Update progress UI
  document.getElementById('progress-status-badge').textContent = 'Complete';
  document.getElementById('progress-status-badge').className = 'progress-status-badge success';
  updateProgress(100, 'Scan complete!');

  // Reset scan button
  resetScanBtn();

  // Update menubar
  document.getElementById('menubar-status').textContent = `Scan complete — ${results.target}`;

  // Show quick stats
  const statsEl = document.getElementById('quick-stats');
  statsEl.style.display = 'grid';
  statsEl.classList.add('fade-in');

  document.getElementById('stat-js').textContent = results.unique_files || 0;
  document.getElementById('stat-ep').textContent = results.endpoints?.length || 0;
  document.getElementById('stat-sec').textContent = results.secrets?.length || 0;

  const riskEl = document.getElementById('stat-risk');
  riskEl.textContent = results.risk_level || 'INFO';
  riskEl.style.color = riskColor(results.risk_level);

  // Show results nav item
  const resultsNav = document.getElementById('results-nav');
  resultsNav.style.display = 'flex';

  const riskBadge = document.getElementById('result-badge');
  riskBadge.style.display = 'inline';
  riskBadge.textContent = results.risk_level;
  riskBadge.style.background = riskBgColor(results.risk_level);
  riskBadge.style.color = riskColor(results.risk_level);

  // Add to recent
  addRecentScan(results.target, results.scan_id);

  // Refresh scans list
  loadScans();

  // Populate results view
  populateResults(results);

  // Auto-switch to results
  setTimeout(() => {
    switchView('results');
  }, 800);
}

function onScanError(msg) {
  document.getElementById('progress-status-badge').textContent = 'Error';
  document.getElementById('progress-status-badge').className = 'progress-status-badge error';
  document.getElementById('progress-phase').textContent = msg;
  document.getElementById('menubar-status').textContent = 'Scan failed';
  resetScanBtn();
}

function resetScanBtn() {
  const btn = document.getElementById('scan-btn');
  btn.disabled = false;
  btn.innerHTML = `<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2"><circle cx="10" cy="10" r="7"/><path d="M10 6v4l3 2"/></svg> Scan`;
}

// ─── Populate Results ─────────────────────────────────────────────────────────
function populateResults(results) {
  // Header
  document.getElementById('results-title').textContent = `Results: ${results.target}`;
  const rBadge = document.getElementById('results-risk-badge');
  rBadge.textContent = results.risk_level;
  rBadge.className = `risk-badge ${results.risk_level}`;

  // Download report button
  document.getElementById('download-report-btn').onclick = () => {
    window.location.href = `/api/scan/${results.scan_id}/report`;
  };

  // Tab counts
  document.getElementById('tc-endpoints').textContent = results.endpoints?.length || 0;
  document.getElementById('tc-secrets').textContent = results.secrets?.length || 0;
  document.getElementById('tc-jsfiles').textContent = results.js_files?.length || 0;
  document.getElementById('tc-keywords').textContent = Object.keys(results.keywords || {}).length;
  document.getElementById('tc-urls').textContent = results.urls?.length || 0;

  // Alert on secrets
  if (results.secrets?.length > 0) {
    document.getElementById('tc-secrets').className = 'tab-count alert';
  }

  // Populate each tab
  populateOverview(results);
  populateEndpoints(results.endpoints || []);
  populateSecrets(results.secrets || []);
  populateJsFiles(results.js_files || [], results.scan_id);
  populateKeywords(results.keywords || {});
  populateUrls(results.urls || []);

  // Reset to overview tab
  switchTab('tab-overview');
}

// Overview
function populateOverview(r) {
  const grid = document.getElementById('overview-grid');
  grid.innerHTML = '';

  const cards = [
    {
      label: 'Total JS Files',
      value: r.unique_files || 0,
      sub: `${r.total_discovered || 0} discovered, ${r.duplicates || 0} duplicates`,
    },
    {
      label: 'API Endpoints',
      value: r.endpoints?.length || 0,
      sub: 'Unique paths found',
    },
    {
      label: 'Secrets Found',
      value: r.secrets?.length || 0,
      sub: `${r.high_risk_secrets?.length || 0} high-risk`,
      alert: (r.secrets?.length || 0) > 0,
    },
    {
      label: 'Risk Level',
      value: r.risk_level || 'INFO',
      valueStyle: `color: ${riskColor(r.risk_level)}`,
      sub: `Scan duration: ${r.duration}s`,
    },
    {
      label: 'Top Endpoints',
      isList: true,
      items: (r.endpoints || []).slice(0, 8).map(e => e.path),
    },
    {
      label: 'URLs Extracted',
      value: r.urls?.length || 0,
      sub: 'External references',
    },
  ];

  cards.forEach(c => {
    const div = document.createElement('div');
    div.className = 'overview-card fade-in';
    if (c.alert) div.style.borderColor = 'rgba(255,59,48,0.25)';

    if (c.isList) {
      div.innerHTML = `
        <div class="ov-label">${c.label}</div>
        <ul class="ov-list">
          ${(c.items || []).map(i => `<li>${escapeHtml(i)}</li>`).join('') || '<li style="color:var(--text-tertiary)">None found</li>'}
        </ul>`;
    } else {
      div.innerHTML = `
        <div class="ov-label">${c.label}</div>
        <div class="ov-value-big" style="${c.valueStyle || ''}">${c.value}</div>
        <div class="ov-sub">${c.sub || ''}</div>`;
    }
    grid.appendChild(div);
  });
}

// Endpoints
function populateEndpoints(endpoints) {
  const container = document.getElementById('ep-list');
  container.innerHTML = '';

  if (!endpoints.length) {
    container.innerHTML = '<div class="empty-row" style="padding:40px;text-align:center;color:var(--text-tertiary)">No endpoints found</div>';
    return;
  }

  endpoints.forEach(ep => {
    const div = document.createElement('div');
    div.className = 'list-item';
    div.dataset.text = ep.path.toLowerCase();

    const methodBadge = guessMethod(ep.path);
    const files = ep.files?.slice(0, 2).join(', ') || '';

    div.innerHTML = `
      <span class="list-item-badge">${methodBadge}</span>
      <span class="list-item-path">${escapeHtml(ep.path)}</span>
      <span class="list-item-meta">${escapeHtml(files)}</span>`;
    container.appendChild(div);
  });
}

// Secrets
function populateSecrets(secrets) {
  const container = document.getElementById('secrets-list');
  container.innerHTML = '';

  if (!secrets.length) {
    container.innerHTML = `
      <div class="no-secrets">
        <svg fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
          <path d="M12 2l7 3v5c0 4-3 7-7 8-4-1-7-4-7-8V5l7-3z"/>
          <path d="M9 12l2 2 4-4"/>
        </svg>
        <p>No secrets detected</p>
      </div>`;
    return;
  }

  secrets.forEach(s => {
    const div = document.createElement('div');
    div.className = 'secret-item fade-in';
    div.innerHTML = `
      <div class="secret-header">
        <span class="secret-type-badge">${escapeHtml(s.type)}</span>
        <span class="secret-file">${escapeHtml(s.file)}</span>
      </div>
      <div class="secret-value-row">
        <span class="secret-val-label">VALUE</span>
        <span class="secret-val">${escapeHtml(s.value)}</span>
      </div>
      <div class="secret-value-row">
        <span class="secret-val-label">CONTEXT</span>
        <span class="secret-context">${escapeHtml(s.context)}</span>
      </div>`;
    container.appendChild(div);
  });
}

// JS Files
function populateJsFiles(files, scanId) {
  const container = document.getElementById('js-list');
  container.innerHTML = '';

  if (!files.length) {
    container.innerHTML = '<div class="empty-row" style="padding:40px;text-align:center;color:var(--text-tertiary)">No JS files found</div>';
    return;
  }

  files.forEach(f => {
    const div = document.createElement('div');
    div.className = 'js-file-item';
    div.dataset.text = f.name.toLowerCase();

    div.innerHTML = `
      <div class="js-file-icon ${f.minified ? 'minified' : ''}">
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M14 3H6a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2z"/>
          <path d="M8 12V8M12 8v4" stroke-linecap="round"/>
        </svg>
      </div>
      <div class="js-file-info">
        <div class="js-file-name">${escapeHtml(f.name)}</div>
        <div class="js-file-meta">${f.size_human || f.size + ' B'} · ${f.urls?.length || 0} source URL(s)</div>
      </div>
      <span class="js-badge ${f.minified ? 'minified-badge' : 'readable-badge'}">${f.minified ? 'min' : 'src'}</span>
      <button class="btn btn-secondary btn-sm" onclick="downloadFile('${escapeHtml(scanId)}','${escapeHtml(f.name)}')">↓</button>`;
    container.appendChild(div);
  });
}

// Keywords
function populateKeywords(keywords) {
  const container = document.getElementById('keywords-list');
  container.innerHTML = '';

  const keys = Object.keys(keywords);
  if (!keys.length) {
    container.innerHTML = '<div class="empty-row" style="padding:40px;text-align:center;color:var(--text-tertiary);grid-column:1/-1">No interesting keywords found</div>';
    return;
  }

  keys.forEach(kw => {
    const matches = keywords[kw] || [];
    const div = document.createElement('div');
    div.className = 'keyword-card fade-in';
    div.innerHTML = `
      <div class="keyword-header">
        <span class="keyword-name">${escapeHtml(kw)}</span>
        <span class="keyword-count">${matches.length}</span>
      </div>
      <div class="keyword-matches">
        ${matches.slice(0, 4).map(m => `
          <div class="keyword-match">
            <span class="match-file">${escapeHtml(m.file)}</span>:${m.line || '?'} — ${escapeHtml((m.content || '').slice(0, 80))}
          </div>`).join('')}
      </div>`;
    container.appendChild(div);
  });
}

// URLs
function populateUrls(urls) {
  const container = document.getElementById('url-list');
  container.innerHTML = '';

  if (!urls.length) {
    container.innerHTML = '<div class="empty-row" style="padding:40px;text-align:center;color:var(--text-tertiary)">No URLs found</div>';
    return;
  }

  urls.forEach(url => {
    const div = document.createElement('div');
    div.className = 'list-item';
    div.dataset.text = url.toLowerCase();
    div.innerHTML = `
      <span class="list-item-path" style="color:var(--mac-blue)">${escapeHtml(url)}</span>
      <button class="btn btn-secondary btn-sm" onclick="window.open('${escapeHtml(url)}','_blank')">↗</button>`;
    container.appendChild(div);
  });
}

// ─── Filter ───────────────────────────────────────────────────────────────────
function filterList(containerId, query) {
  const q = query.toLowerCase();
  const container = document.getElementById(containerId);
  container.querySelectorAll('.list-item, .js-file-item').forEach(item => {
    const text = (item.dataset.text || item.textContent || '').toLowerCase();
    item.style.display = text.includes(q) ? '' : 'none';
  });
}

// ─── Load / Refresh Scans ─────────────────────────────────────────────────────
async function loadScans() {
  try {
    const resp = await fetch('/api/scans');
    allScans = await resp.json();
    updateScanCount();
    refreshRecentList();
    refreshScansTable();
  } catch (e) {
    console.warn('loadScans error', e);
  }
}

function updateScanCount() {
  document.getElementById('scan-count').textContent = allScans.length;
}

function refreshRecentList() {
  const container = document.getElementById('recent-scans');
  container.innerHTML = '';

  const recent = allScans.slice(0, 6);
  if (!recent.length) {
    container.innerHTML = '<div class="empty-recent">No recent scans</div>';
    return;
  }

  recent.forEach(scan => {
    const div = document.createElement('div');
    div.className = 'recent-item';
    div.textContent = scan.target;
    div.title = scan.target;
    div.onclick = () => loadScanResults(scan.id);
    container.appendChild(div);
  });
}

function refreshScansTable() {
  const tbody = document.getElementById('scans-tbody');
  tbody.innerHTML = '';

  if (!allScans.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-row">No scans yet. Start a new scan!</td></tr>';
    return;
  }

  allScans.forEach(scan => {
    const tr = document.createElement('tr');
    const date = scan.started_at ? new Date(scan.started_at).toLocaleString() : '—';
    const authMode = scan.auth_mode || 'none';
    tr.innerHTML = `
      <td class="target-cell">${escapeHtml(scan.target)}</td>
      <td><span class="status-dot ${scan.status}">${scan.status}</span></td>
      <td>
        <span class="auth-badge ${authMode}">${authMode}</span>
      </td>
      <td style="color:var(--text-tertiary);font-size:12px">${date}</td>
      <td>
        <div class="tbl-progress">
          <div class="tbl-progress-bar"><div class="tbl-progress-fill" style="width:${scan.progress}%"></div></div>
          <span style="font-size:11px;color:var(--text-tertiary);font-family:var(--font-mono)">${scan.progress}%</span>
        </div>
      </td>
      <td>
        ${scan.status === 'complete'
          ? `<button class="btn btn-secondary btn-sm" onclick="loadScanResults('${scan.id}')">View Results</button>`
          : scan.status === 'running'
          ? `<button class="btn btn-secondary btn-sm" onclick="watchScan('${scan.id}')">Watch</button>`
          : '—'
        }
      </td>`;
    tbody.appendChild(tr);
  });
}

async function loadScanResults(scanId) {
  try {
    const resp = await fetch(`/api/scan/${scanId}/results`);
    if (!resp.ok) { alert('Results not available yet'); return; }
    const results = await resp.json();
    currentResults = results;
    currentScanId = scanId;
    populateResults(results);
    switchView('results');
    document.getElementById('results-nav').style.display = 'flex';
  } catch (e) {
    alert('Failed to load results: ' + e.message);
  }
}

function watchScan(scanId) {
  currentScanId = scanId;
  switchView('scanner');
  document.getElementById('progress-card').style.display = 'block';
  pollScanStatus();
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function downloadFile(scanId, filename) {
  window.location.href = `/api/scan/${scanId}/file/${filename}`;
}

function addRecentScan(target, scanId) {
  allScans = allScans.filter(s => s.id !== scanId);
  allScans.unshift({ id: scanId, target, status: 'complete', progress: 100 });
  refreshRecentList();
  updateScanCount();
}

function guessMethod(path) {
  if (path.includes('login') || path.includes('register') || path.includes('create')) return 'POST';
  if (path.includes('delete') || path.includes('remove')) return 'DELETE';
  return 'GET';
}

function riskColor(level) {
  const map = { CRITICAL: '#FF3B30', HIGH: '#FF9500', MEDIUM: '#FFCC00', LOW: '#34C759', INFO: '#8E8E93' };
  return map[level] || '#8E8E93';
}

function riskBgColor(level) {
  const map = {
    CRITICAL: 'rgba(255,59,48,0.15)',
    HIGH: 'rgba(255,149,0,0.15)',
    MEDIUM: 'rgba(255,196,0,0.12)',
    LOW: 'rgba(52,199,89,0.12)',
    INFO: 'rgba(255,255,255,0.07)'
  };
  return map[level] || 'rgba(255,255,255,0.07)';
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function shakeElement(el) {
  el.style.animation = 'none';
  el.offsetHeight;
  el.style.animation = 'shake 0.3s ease';
  el.addEventListener('animationend', () => el.style.animation = '', { once: true });
}

function showError(msg) {
  console.error(msg);
  document.getElementById('progress-phase').textContent = '⚠ ' + msg;
}

function minimizeApp() { /* macOS close button - could add window toggle */ }
function toggleSettings() { /* placeholder for settings panel */ }

// Add shake animation
const style = document.createElement('style');
style.textContent = `
  @keyframes shake {
    0%, 100% { transform: translateX(0); }
    20% { transform: translateX(-8px); }
    40% { transform: translateX(8px); }
    60% { transform: translateX(-6px); }
    80% { transform: translateX(6px); }
  }
`;
document.head.appendChild(style);

// ─── Auth Panel Logic ──────────────────────────────────────────────────────────

let authPanelOpen = false;
let currentAuthTab = 'cookie';

function toggleAuthPanel() {
  authPanelOpen = !authPanelOpen;
  const body = document.getElementById('auth-body');
  const chevron = document.getElementById('auth-chevron');
  body.style.display = authPanelOpen ? 'block' : 'none';
  chevron.classList.toggle('open', authPanelOpen);
}

function switchAuthTab(tab) {
  currentAuthTab = tab;
  document.querySelectorAll('.auth-tab').forEach(t => {
    t.classList.toggle('active', t.dataset.authTab === tab);
  });
  document.querySelectorAll('.auth-panel').forEach(p => {
    p.classList.remove('active');
  });
  const panel = document.getElementById(`auth-panel-${tab}`);
  if (panel) panel.classList.add('active');
}

function updateAuthMode() {
  const cookies   = document.getElementById('auth-cookies')?.value.trim() || '';
  const token     = document.getElementById('auth-token')?.value.trim() || '';
  const username  = document.getElementById('auth-username')?.value.trim() || '';
  const password  = document.getElementById('auth-password')?.value.trim() || '';

  const pill = document.getElementById('auth-mode-pill');
  const lockIcon = document.getElementById('auth-lock-icon');
  const authCard = document.getElementById('auth-card');

  const hasCookie = cookies || token;
  const hasCreds  = username && password;

  let mode = 'none';
  let label = 'None';

  if (hasCookie && hasCreds) {
    mode = 'both'; label = 'Both';
  } else if (hasCreds) {
    mode = 'credentials'; label = 'Auto-Login';
  } else if (hasCookie) {
    mode = 'cookies'; label = 'Cookie Auth';
  }

  pill.textContent = label;
  pill.className = `auth-mode-pill ${mode !== 'none' ? (mode === 'both' ? 'both' : 'active') : ''}`;
  lockIcon.classList.toggle('active', mode !== 'none');
  authCard.classList.toggle('has-auth', mode !== 'none');

  // Auto-enable headless if credentials provided
  if (hasCreds) {
    document.getElementById('opt-headless').checked = true;
  }
}

function syncBothFields() {
  // Keep single-tab fields in sync with both-tab fields
  const b_cookies  = document.getElementById('auth-cookies-b')?.value || '';
  const b_token    = document.getElementById('auth-token-b')?.value || '';
  const b_username = document.getElementById('auth-username-b')?.value || '';
  const b_password = document.getElementById('auth-password-b')?.value || '';

  if (document.getElementById('auth-cookies'))  document.getElementById('auth-cookies').value  = b_cookies;
  if (document.getElementById('auth-token'))    document.getElementById('auth-token').value    = b_token;
  if (document.getElementById('auth-username')) document.getElementById('auth-username').value = b_username;
  if (document.getElementById('auth-password')) document.getElementById('auth-password').value = b_password;
  updateAuthMode();
}

function togglePasswordVisibility() {
  const pw = document.getElementById('auth-password');
  const eye = document.getElementById('pw-eye');
  if (!pw) return;
  const isHidden = pw.type === 'password';
  pw.type = isHidden ? 'text' : 'password';
  eye.innerHTML = isHidden
    ? `<path d="M2 2l12 12M6.5 6.6A4 4 0 0111.4 11M1 8s2.5-5 7-5c1.2 0 2.3.3 3.3.8M15 8s-1 2-3.3 3.8"/>`
    : `<path d="M1 8s2.5-5 7-5 7 5 7 5-2.5 5-7 5-7-5-7-5z"/><circle cx="8" cy="8" r="2"/>`;
}

function toggleAdvancedSelectors() {
  const el = document.getElementById('auth-advanced');
  if (!el) return;
  el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

function collectAuthData() {
  // Collect auth from whichever tab is active (or both tab)
  const tab = currentAuthTab;

  if (tab === 'both') {
    return {
      cookies:          document.getElementById('auth-cookies-b')?.value.trim() || '',
      auth_token:       document.getElementById('auth-token-b')?.value.trim() || '',
      username:         document.getElementById('auth-username-b')?.value.trim() || '',
      password:         document.getElementById('auth-password-b')?.value.trim() || '',
      login_url:        document.getElementById('auth-login-url-b')?.value.trim() || '',
      username_selector: '',
      password_selector: '',
    };
  }

  if (tab === 'creds') {
    return {
      cookies:          '',
      auth_token:       '',
      username:         document.getElementById('auth-username')?.value.trim() || '',
      password:         document.getElementById('auth-password')?.value.trim() || '',
      login_url:        document.getElementById('auth-login-url')?.value.trim() || '',
      username_selector: document.getElementById('auth-usr-selector')?.value.trim() || '',
      password_selector: document.getElementById('auth-pwd-selector')?.value.trim() || '',
    };
  }

  // cookie tab (default)
  return {
    cookies:          document.getElementById('auth-cookies')?.value.trim() || '',
    auth_token:       document.getElementById('auth-token')?.value.trim() || '',
    username:         '',
    password:         '',
    login_url:        '',
    username_selector: '',
    password_selector: '',
  };
}
