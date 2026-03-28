/* Diverg Console — Professional UI */

const CFG = { apiUrl: localStorage.getItem('diverg_api') || 'http://127.0.0.1:5000' };
const api = p => CFG.apiUrl + p;

const State = { scope: 'full', scanId: null, report: null, allFindings: [], historyData: [] };

// ── Navigation ─────────────────────────────────────────────────────────────
const PAGES = {
  home: 'Home',
  scanner: 'Scanner',
  history: 'History',
  findings: 'Findings',
  results: 'Results',
  'attack-paths': 'Attack Paths',
  investigation: 'Investigation',
  settings: 'Settings',
};

function navigate(page, data) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const pg = document.getElementById('page-' + page);
  if (pg) pg.classList.add('active');

  const ni = document.querySelector(`.nav-item[data-page="${page}"]`);
  if (ni) ni.classList.add('active');

  document.getElementById('pageTitle').textContent = PAGES[page] || page;
  document.getElementById('pageActions').innerHTML = '';

  if (page === 'home') loadHome();
  if (page === 'scanner') resetScanner();
  if (page === 'history') loadHistory();
  if (page === 'findings') loadFindings();
  if (page === 'attack-paths') loadAllAttackPaths();
  if (page === 'settings') loadSettings();
  if (page === 'results' && data) showResults(data);

  window.scrollTo(0, 0);
}

// Nav click handlers
document.querySelectorAll('.nav-item[data-page]').forEach(el =>
  el.addEventListener('click', () => navigate(el.dataset.page)));

// Tab handlers
document.querySelectorAll('.tab[data-tab]').forEach(btn =>
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    const panel = document.getElementById('tab-' + btn.dataset.tab);
    if (panel) panel.classList.add('active');
  }));

// Scope handlers
document.querySelectorAll('.scope-btn').forEach(btn =>
  btn.addEventListener('click', () => {
    State.scope = btn.dataset.scope;
    document.querySelectorAll('.scope-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
  }));

// ── Toast ───────────────────────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.getElementById('toastContainer').appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

// ── API helpers ─────────────────────────────────────────────────────────────
async function get(path) {
  const r = await fetch(api(path));
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}
async function post(path, body) {
  const r = await fetch(api(path), {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}
async function del(path) {
  const r = await fetch(api(path), { method: 'DELETE' });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}

// ── Helpers ─────────────────────────────────────────────────────────────────
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function riskClass(v) {
  if (!v) return 'unknown';
  const l = v.toLowerCase();
  if (l.includes('critical')) return 'critical';
  if (l.includes('high')) return 'high';
  if (l.includes('medium')) return 'medium';
  if (l.includes('low')) return 'low';
  if (l.includes('clean') || l.includes('safe')) return 'clean';
  return 'unknown';
}

function badgeHtml(verdict, score) {
  const c = riskClass(verdict);
  const s = score != null ? ` · ${score}` : '';
  return `<span class="badge ${c}">${esc(verdict || 'Unknown')}${s}</span>`;
}

function sevClass(s) {
  const l = (s || '').toLowerCase();
  if (l === 'critical') return 'Critical';
  if (l === 'high') return 'High';
  if (l === 'medium') return 'Medium';
  if (l === 'low') return 'Low';
  return 'Info';
}

function ago(iso) {
  if (!iso) return '—';
  const m = Math.floor((Date.now() - new Date(iso)) / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function fmtDate(iso) {
  return iso ? new Date(iso).toLocaleString() : '—';
}

function shortUrl(u) {
  try {
    const x = new URL(u.startsWith('http') ? u : 'https://' + u);
    return x.hostname + (x.pathname !== '/' ? x.pathname : '');
  } catch { return u; }
}

// ── HOME ────────────────────────────────────────────────────────────────────
async function loadHome() {
  try {
    const s = await get('/api/stats');
    document.getElementById('statScans').textContent = s.total_scans ?? '0';
    document.getElementById('statCritical').textContent = s.total_critical ?? '0';
    document.getElementById('statTargets').textContent = s.unique_targets ?? '0';
    document.getElementById('statAvgRisk').textContent = s.avg_risk_score > 0 ? s.avg_risk_score : '—';

    const recent = document.getElementById('recentScans');
    if (!s.recent_scans?.length) {
      recent.innerHTML = `
        <div class="empty">
          <div class="empty-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div>
          <div class="empty-title">No scans yet</div>
          <div class="empty-desc">Run your first scan to see results here</div>
        </div>`;
    } else {
      recent.innerHTML = `<div class="scan-list">${s.recent_scans.map(miniRow).join('')}</div>`;
    }
  } catch { document.getElementById('statScans').textContent = 'API offline'; }
}

function miniRow(s) {
  return `
    <div class="scan-item" onclick="openScan('${s.id}')">
      <div class="scan-info">
        <div class="scan-url">${esc(shortUrl(s.target_url))}</div>
        <div class="scan-meta">${ago(s.scanned_at)}</div>
      </div>
      ${badgeHtml(s.risk_verdict, s.risk_score)}
      ${s.critical ? `<span style="font-size:0.75rem; color:var(--red); font-weight:600">${s.critical}C</span>` : ''}
    </div>`;
}

function quickLaunch() {
  const url = document.getElementById('quickUrl').value.trim();
  if (!url) { toast('Enter a target URL', 'error'); return; }
  const scope = document.getElementById('quickScope').value;
  navigate('scanner');
  setTimeout(() => {
    document.getElementById('scanUrl').value = url;
    State.scope = scope;
    document.querySelectorAll('.scope-btn').forEach(b => b.classList.toggle('active', b.dataset.scope === scope));
    launchScan();
  }, 100);
}

// ── SCANNER ─────────────────────────────────────────────────────────────────
function resetScanner() {
  document.getElementById('progressContainer').classList.remove('show');
  document.getElementById('launchBtn').disabled = false;
  document.getElementById('launchBtn').textContent = 'Launch Scan';
}

async function launchScan() {
  let url = document.getElementById('scanUrl').value.trim();
  if (!url) { toast('Enter a target URL', 'error'); return; }
  if (!url.startsWith('http')) url = 'https://' + url;

  const goal = document.getElementById('scanGoal').value.trim();
  const scope = State.scope;

  const btn = document.getElementById('launchBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner" style="width:16px;height:16px;border-color:var(--border);border-top-color:currentColor"></span> Launching…';

  const container = document.getElementById('progressContainer');
  container.classList.add('show');
  document.getElementById('progressTitle').textContent = 'Scanning…';
  document.getElementById('progressTarget').textContent = url;
  document.getElementById('skillsList').innerHTML = '';
  document.getElementById('liveFindings').innerHTML = '';
  document.getElementById('progressComplete').style.display = 'none';

  const skills = {};
  let lastReport = null;

  try {
    const resp = await fetch(api('/api/scan/stream'), {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, goal, scope }),
    });
    if (!resp.ok) throw new Error('API error ' + resp.status);

    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    let buf = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const lines = buf.split('\n'); buf = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const e = JSON.parse(line);
          handleEvent(e, skills);
          if (e.event === 'done') lastReport = e.report;
        } catch {}
      }
    }
  } catch (e) { toast('Scan error: ' + e.message, 'error'); }

  btn.disabled = false;
  btn.textContent = 'Launch Scan';

  if (lastReport) {
    State.report = lastReport;
    State.scanId = lastReport.id;
    document.getElementById('progressComplete').style.display = 'block';
    toast(`Scan complete — ${lastReport.findings?.length || 0} findings`, 'success');
    if (document.getElementById('toggleAutoNav')?.checked) {
      setTimeout(() => navigate('results', lastReport), 600);
    }
  }
}

function viewProgressResults() {
  if (State.report) navigate('results', State.report);
}

function handleEvent(e, skills) {
  const list = document.getElementById('skillsList');
  const live = document.getElementById('liveFindings');

  if (e.event === 'scan_start') {
    document.getElementById('progressTitle').textContent = `Scanning (${e.scope})`;
    return;
  }
  if (e.event === 'skill_start') {
    skills[e.skill] = { status: 'running', count: 0 };
    renderSkills(list, skills);
    return;
  }
  if (e.event === 'skill_done') {
    if (skills[e.skill]) { skills[e.skill].status = 'done'; skills[e.skill].count = e.findings_count || 0; }
    renderSkills(list, skills);
    return;
  }
  if (e.event === 'finding') {
    const f = e.finding || {};
    const s = sevClass(f.severity);
    if (s === 'Critical' && document.getElementById('toggleCritical')?.checked) {
      toast('Critical: ' + (f.title || 'Finding'), 'error');
    }
    const row = document.createElement('div');
    row.className = 'live-finding';
    row.innerHTML = `<span class="live-severity ${s}">${s}</span><span class="live-text">${esc(f.title || 'Finding')}</span>`;
    live.appendChild(row);
  }
  if (e.event === 'error') toast('Error: ' + e.error, 'error');
}

function renderSkills(el, skills) {
  el.innerHTML = Object.entries(skills).map(([name, info]) => `
    <div class="skill-row">
      <div class="skill-name ${info.status === 'running' ? 'active' : ''}">${esc(name)}</div>
      <div class="skill-status ${info.status}">${info.status === 'running' ? 'Running' : 'Done'}</div>
      <div style="font-size:0.75rem; color:var(--muted); font-family:var(--mono)">${info.count} found</div>
    </div>
  `).join('');
}

// ── HISTORY ─────────────────────────────────────────────────────────────────
async function loadHistory() {
  const scope = document.getElementById('historyScope')?.value || '';
  const verdict = document.getElementById('historyVerdict')?.value || '';
  let url = '/api/history?limit=50';
  if (scope) url += '&scope=' + encodeURIComponent(scope);
  if (verdict) url += '&verdict=' + encodeURIComponent(verdict);

  try {
    const data = await get(url);
    State.historyData = data.scans;
    document.getElementById('historyCount').textContent = `${data.total} scan${data.total !== 1 ? 's' : ''}`;
    renderHistory(data.scans);
  } catch (e) { toast('Could not load history', 'error'); }
}

function filterHistory() {
  const q = (document.getElementById('historySearch')?.value || '').toLowerCase();
  const f = q ? State.historyData.filter(s => (s.target_url + (s.label || '')).toLowerCase().includes(q)) : State.historyData;
  renderHistory(f);
}

function renderHistory(scans) {
  const el = document.getElementById('historyList');
  if (!scans?.length) {
    el.innerHTML = `
      <div class="empty">
        <div class="empty-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div>
        <div class="empty-title">No scans found</div>
        <div class="empty-desc">Try adjusting filters or run a new scan</div>
      </div>`;
    return;
  }
  el.innerHTML = scans.map(s => `
    <div class="scan-item" onclick="openScan('${s.id}')">
      <div class="scan-info">
        <div class="scan-url">${esc(shortUrl(s.target_url))}</div>
        <div class="scan-meta">${s.label ? esc(s.label) + ' · ' : ''}${fmtDate(s.scanned_at)}</div>
      </div>
      <span class="scan-scope">${s.scope || 'full'}</span>
      ${badgeHtml(s.risk_verdict, s.risk_score)}
      <span style="font-size:0.8125rem; color:var(--muted)">${s.total || 0} findings</span>
      <span style="font-size:0.8125rem; color:var(--muted)">${ago(s.scanned_at)}</span>
      <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation(); deleteScan('${s.id}')">Delete</button>
    </div>
  `).join('');
}

async function openScan(id) {
  try {
    const data = await get(`/api/history/${id}`);
    State.scanId = id;
    State.report = data.report || data;
    navigate('results', State.report);
  } catch (e) { toast('Could not load scan', 'error'); }
}

async function deleteScan(id) {
  if (!confirm('Delete this scan?')) return;
  try { await del(`/api/history/${id}`); toast('Scan deleted', 'success'); loadHistory(); }
  catch (e) { toast('Delete failed', 'error'); }
}

async function deleteCurrentScan() {
  if (State.scanId) { await deleteScan(State.scanId); navigate('history'); }
}

// ── FINDINGS ────────────────────────────────────────────────────────────────
async function loadFindings() {
  try {
    const data = await get('/api/history?limit=100');
    const all = [];
    for (const scan of (data.scans || [])) {
      if (scan.total > 0) {
        try {
          const full = await get(`/api/history/${scan.id}`);
          (full.report?.findings || []).forEach(f => all.push({ ...f, _scan: scan }));
        } catch {}
      }
    }
    State.allFindings = all;
    document.getElementById('findingsCount').textContent = `${all.length} findings across ${data.total} scans`;
    renderFindings(all, 'findingsList');
  } catch (e) { toast('Could not load findings', 'error'); }
}

function filterFindings() {
  const q = (document.getElementById('findingsSearch')?.value || '').toLowerCase();
  const sev = document.getElementById('findingsSev')?.value || '';
  let f = State.allFindings;
  if (q) f = f.filter(x => (x.title + (x.category || '')).toLowerCase().includes(q));
  if (sev) f = f.filter(x => sevClass(x.severity) === sev);
  renderFindings(f, 'findingsList');
  document.getElementById('findingsCount').textContent = `${f.length} of ${State.allFindings.length} findings`;
}

// ── RESULTS ─────────────────────────────────────────────────────────────────
function showResults(report) {
  if (!report) return;
  const findings = report.findings || [];
  const cls = riskClass(report.risk_verdict);

  document.getElementById('resultsUrl').textContent = report.target_url || '—';
  document.getElementById('resultsMeta').textContent = `Scope: ${report.scope || '—'} · ${fmtDate(report.scanned_at)}`;
  document.getElementById('resultsBadge').innerHTML = badgeHtml(report.risk_verdict, report.risk_score);

  document.getElementById('scoreRing').className = 'score-ring ' + cls;
  document.getElementById('scoreValue').textContent = report.risk_score != null ? report.risk_score : '—';

  document.getElementById('rc').textContent = findings.filter(f => sevClass(f.severity) === 'Critical').length;
  document.getElementById('rh').textContent = findings.filter(f => sevClass(f.severity) === 'High').length;
  document.getElementById('rm').textContent = findings.filter(f => sevClass(f.severity) === 'Medium').length;
  document.getElementById('rl').textContent = findings.filter(f => sevClass(f.severity) === 'Low').length;

  const sorted = [...findings].sort((a, b) => {
    const o = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    return (o[sevClass(a.severity)] ?? 5) - (o[sevClass(b.severity)] ?? 5);
  });
  renderFindings(sorted, 'resultsFindingsList');

  document.getElementById('resultsSummary').textContent = report.summary || 'No summary available.';
  document.getElementById('resultsEvidence').textContent = report.evidence_summary || 'No evidence summary.';
  document.getElementById('resultsSkills').innerHTML = (report.skills_run || []).map(s =>
    `<span style="font-size:0.75rem; background:var(--surface); padding:0.25rem 0.625rem; border-radius:6px; border:1px solid var(--border); color:var(--muted)">${esc(s)}</span>`
  ).join('');

  renderPaths(report.attack_paths || [], 'resultsPaths');
  document.getElementById('resultsRemediation').textContent = report.remediation_plan || 'No remediation plan available.';

  const sugg = report.suggested_next_tests;
  const el = document.getElementById('resultsSuggested');
  if (Array.isArray(sugg)) {
    el.innerHTML = sugg.map(t => `<div style="padding:0.25rem 0">• ${esc(String(t))}</div>`).join('');
  } else {
    el.textContent = sugg || 'No suggestions.';
  }

  // Reset tabs
  document.querySelectorAll('.tab').forEach((b, i) => b.classList.toggle('active', i === 0));
  document.querySelectorAll('.tab-content').forEach((c, i) => c.classList.toggle('active', i === 0));

  // Header actions
  document.getElementById('pageActions').innerHTML = `
    <button class="btn btn-secondary btn-sm" onclick="exportReport()">Export JSON</button>
    <button class="btn btn-danger btn-sm" onclick="deleteCurrentScan()">Delete</button>
  `;
}

function renderFindings(findings, containerId) {
  const el = document.getElementById(containerId);
  if (!findings?.length) {
    el.innerHTML = `
      <div class="empty">
        <div class="empty-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
        <div class="empty-title">No findings</div>
        <div class="empty-desc">Nothing detected in this scan</div>
      </div>`;
    return;
  }
  el.innerHTML = findings.map((f, i) => {
    const s = sevClass(f.severity);
    const uid = `f-${containerId}-${i}`;
    const ev = f.evidence || f.proof || f.url || '';
    return `
      <div class="finding" id="${uid}">
        <div class="finding-header" onclick="toggleFinding('${uid}')">
          <span class="live-severity ${s}">${s}</span>
          <div class="finding-title">${esc(f.title || f.type || 'Finding')}</div>
          <div class="finding-category">${esc(f.category || '')}</div>
          <svg class="finding-expand" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
        </div>
        <div class="finding-body">
          ${f.description ? `<div class="finding-section"><div class="finding-section-title">Description</div><div class="finding-content">${esc(f.description)}</div></div>` : ''}
          ${f.impact ? `<div class="finding-section"><div class="finding-section-title">Impact</div><div class="finding-content">${esc(f.impact)}</div></div>` : ''}
          ${ev ? `<div class="finding-section"><div class="finding-section-title">Evidence</div><pre class="finding-code">${esc(String(ev).substring(0, 500))}</pre></div>` : ''}
          ${f.remediation ? `<div class="finding-section"><div class="finding-section-title">Remediation</div><div class="finding-content">${esc(f.remediation)}</div></div>` : ''}
        </div>
      </div>`;
  }).join('');
}

function toggleFinding(uid) {
  document.getElementById(uid)?.classList.toggle('open');
}

// ── ATTACK PATHS ────────────────────────────────────────────────────────────
function renderPaths(paths, id) {
  const el = document.getElementById(id);
  if (!paths?.length) {
    el.innerHTML = `
      <div class="empty">
        <div class="empty-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg></div>
        <div class="empty-title">No attack paths</div>
        <div class="empty-desc">Run a full-scope scan to discover chained paths</div>
      </div>`;
    return;
  }
  el.innerHTML = paths.map(p => {
    const steps = Array.isArray(p.steps) ? p.steps : (p.chain || p.path || []);
    const chain = steps.length
      ? steps.map((s, i) => `${i ? '<span class="path-arrow">→</span>' : ''}<span class="path-step">${esc(String(s))}</span>`).join('')
      : esc(p.description || '');
    return `
      <div class="path-item">
        <div class="path-title">${esc(p.title || p.name || 'Attack Path')}</div>
        <div class="path-chain">${chain}</div>
        ${p.impact ? `<div style="font-size:0.875rem; color:var(--muted); margin-top:0.5rem">${esc(p.impact)}</div>` : ''}
      </div>`;
  }).join('');
}

async function loadAllAttackPaths() {
  try {
    const data = await get('/api/history?limit=100');
    const all = [];
    for (const scan of (data.scans || [])) {
      try {
        const full = await get(`/api/history/${scan.id}`);
        (full.report?.attack_paths || []).forEach(p => all.push(p));
      } catch {}
    }
    renderPaths(all, 'attackPathsList');
  } catch { toast('Could not load attack paths', 'error'); }
}

// ── INVESTIGATION ─────────────────────────────────────────────────────────────
async function runChainLookup() {
  const addr = document.getElementById('chainAddr').value.trim();
  if (!addr) { toast('Enter an address', 'error'); return; }
  const el = document.getElementById('chainResult');
  el.textContent = 'Looking up…';

  const heliusKey = localStorage.getItem('diverg_helius_key');

  // If it's a Solana address and we have Helius key, use it directly
  if (heliusKey && (addr.length === 32 || addr.length === 44 || addr.startsWith('sol:'))) {
    try {
      const r = await fetch(`https://mainnet.helius-rpc.com/?api-key=${heliusKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0', id: 1,
          method: 'getAccountInfo',
          params: [addr.replace('sol:', ''), { encoding: 'base58' }]
        }),
      });
      const data = await r.json();
      if (data.error) throw new Error(data.error.message);

      const balance = await fetch(`https://mainnet.helius-rpc.com/?api-key=${heliusKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0', id: 1,
          method: 'getBalance',
          params: [addr.replace('sol:', '')]
        }),
      }).then(r => r.json());

      el.textContent = `Solana Address: ${addr}\n\nBalance: ${(balance.result?.value / 1e9).toFixed(4)} SOL\nData Size: ${data.result?.value?.data ? data.result.value.data[0].length : 0} bytes\nExecutable: ${data.result?.value?.executable ? 'Yes' : 'No'}\nOwner: ${data.result?.value?.owner || 'Unknown'}\n\nVia Helius RPC`;
      el.style.color = 'var(--text)';
      return;
    } catch (e) {
      el.textContent = 'Helius lookup failed: ' + e.message + '\n\nFalling back to diverg-auto…';
    }
  }

  // Fallback to diverg-auto
  try {
    const r = await post('/api/scan', { url: 'https://etherscan.io', goal: `Blockchain lookup: ${addr}`, scope: 'passive' });
    el.textContent = `Address: ${addr}\n\nRisk: ${r.risk_verdict || '—'}\nFindings: ${(r.findings || []).length}\n\nNote: Add Helius API key in Settings for direct blockchain queries.`;
    el.style.color = 'var(--text)';
  } catch (e) {
    el.textContent = 'Error: ' + e.message;
    el.style.color = 'var(--red)';
  }
}

function runOsint() {
  const domain = document.getElementById('osintDomain').value.trim();
  if (!domain) { toast('Enter a domain', 'error'); return; }
  const el = document.getElementById('osintResult'); el.textContent = 'Investigating…';
  const url = domain.startsWith('http') ? domain : 'https://' + domain;
  post('/api/scan', { url, scope: 'recon' })
    .then(r => {
      const lines = [`OSINT: ${domain}`, `Verdict: ${r.risk_verdict || '—'}`, ''];
      (r.findings || []).forEach(f => { lines.push(`[${f.severity}] ${f.title}`); if (f.evidence) lines.push(`  → ${String(f.evidence).substring(0, 100)}`); });
      if (!r.findings?.length) lines.push('No significant findings.');
      el.textContent = lines.join('\n');
    }).catch(e => { el.textContent = 'Error: ' + e.message; });
}

async function runPoc() {
  const type = document.getElementById('pocType').value;
  const url = document.getElementById('pocUrl').value.trim();
  const el = document.getElementById('pocResult');
  if (!url) { toast('Enter a URL', 'error'); return; }
  el.textContent = 'Running…';
  const body = { type, url };
  if (type === 'idor') {
    body.param_to_change = document.getElementById('pocParam').value.trim() || 'id';
    body.new_value = document.getElementById('pocValue').value.trim() || '2';
  }
  try {
    const r = await post('/api/poc/simulate', body);
    el.textContent = `Conclusion: ${r.conclusion}\nSuccess: ${r.success} · Status: ${r.status_code || '—'}${r.body_preview ? '\n\n' + r.body_preview.substring(0, 400) : ''}`;
    el.style.color = r.success ? 'var(--green)' : 'var(--red)';
  } catch (e) { el.textContent = 'Error: ' + e.message; }
}

document.getElementById('pocType')?.addEventListener('change', function() {
  document.getElementById('pocIdorFields').style.display = this.value === 'idor' ? 'block' : 'none';
});

async function runReputation() {
  const target = document.getElementById('reputationTarget').value.trim();
  if (!target) { toast('Enter a target', 'error'); return; }
  const el = document.getElementById('reputationResult'); el.textContent = 'Checking…';
  const url = target.startsWith('http') ? target : 'https://' + target;
  try {
    const r = await post('/api/scan', { url, scope: 'passive', goal: `Entity reputation: ${target}` });
    const lines = [`Reputation: ${target}`, `Verdict: ${r.risk_verdict || '—'}`, ''];
    (r.findings || []).slice(0, 8).forEach(f => lines.push(`[${f.severity}] ${f.title}`));
    el.textContent = lines.join('\n');
  } catch (e) { el.textContent = 'Error: ' + e.message; }
}

// ── SETTINGS ─────────────────────────────────────────────────────────────────
function loadSettings() {
  document.getElementById('settingsApiUrl').value = CFG.apiUrl;
  const heliusKey = localStorage.getItem('diverg_helius_key') || '';
  const heliusNetwork = localStorage.getItem('diverg_helius_network') || 'mainnet';
  document.getElementById('heliusApiKey').value = heliusKey;
  const networkSelect = document.getElementById('heliusNetwork');
  if (networkSelect) networkSelect.value = heliusNetwork;
}

async function saveHeliusKey() {
  const key = document.getElementById('heliusApiKey').value.trim();
  const network = document.getElementById('heliusNetwork')?.value || 'mainnet';
  if (!key) { toast('Enter a Helius API key', 'error'); return; }
  localStorage.setItem('diverg_helius_key', key);
  localStorage.setItem('diverg_helius_network', network);
  toast('Helius settings saved', 'success');
}

async function testHeliusKey() {
  const key = document.getElementById('heliusApiKey').value.trim();
  const el = document.getElementById('heliusStatus');
  if (!key) { el.textContent = 'Please enter an API key'; el.style.color = 'var(--red)'; return; }

  el.textContent = 'Testing…'; el.style.color = 'var(--muted)';
  try {
    const r = await fetch(`https://mainnet.helius-rpc.com/?api-key=${key}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getHealth' }),
    });
    if (!r.ok) throw new Error('Invalid key');
    const data = await r.json();
    if (data.error) throw new Error(data.error.message);
    el.textContent = 'Key valid — Helius RPC connected';
    el.style.color = 'var(--green)';
    toast('Helius API key valid', 'success');
  } catch (e) {
    el.textContent = 'Key invalid: ' + e.message;
    el.style.color = 'var(--red)';
    toast('Helius API key invalid', 'error');
  }
}

function saveSettings() {
  const url = document.getElementById('settingsApiUrl').value.trim();
  if (url) { CFG.apiUrl = url; localStorage.setItem('diverg_api', url); toast('Settings saved', 'success'); }
}

async function testConnection() {
  const el = document.getElementById('connStatus');
  el.textContent = 'Testing…'; el.style.color = 'var(--muted)';
  try {
    const r = await get('/api/health');
    el.textContent = `Connected — ${r.service} v${r.version || '?'}`;
    el.style.color = 'var(--green)';
    toast('API connected', 'success');
  } catch (e) { el.textContent = 'Failed: ' + e.message; el.style.color = 'var(--red)'; toast('Connection failed', 'error'); }
}

async function exportHistory() {
  try {
    const d = await get('/api/history?limit=200');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([JSON.stringify(d, null, 2)], { type: 'application/json' }));
    a.download = `diverg-history-${Date.now()}.json`; a.click();
    toast('Exported', 'success');
  } catch (e) { toast('Export failed', 'error'); }
}

async function clearHistory() {
  if (!confirm('Delete ALL scan history? This cannot be undone.')) return;
  try {
    const d = await get('/api/history?limit=200');
    for (const s of (d.scans || [])) await del(`/api/history/${s.id}`);
    toast('History cleared', 'success'); loadHistory();
  } catch (e) { toast('Error: ' + e.message, 'error'); }
}

function exportReport() {
  if (!State.report) return;
  const a = document.createElement('a');
  const name = shortUrl(State.report.target_url || 'scan').replace(/[^a-z0-9]/gi, '-');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(State.report, null, 2)], { type: 'application/json' }));
  a.download = `diverg-${name}-${Date.now()}.json`; a.click();
}

// ── Init ────────────────────────────────────────────────────────────────────
loadHome();
