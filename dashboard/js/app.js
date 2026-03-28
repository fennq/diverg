/* Diverg Console — Minimal, intentional */

const CFG = { apiUrl: localStorage.getItem('diverg_api') || 'http://127.0.0.1:5000' };
const api = p => CFG.apiUrl + p;

const State = { scope: 'full', scanId: null, report: null, historyData: [], findings: [] };

// ── Navigation ───────────────────────────────────────────────────────────
function navigate(page, data) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  document.getElementById('page-' + page)?.classList.add('active');
  document.querySelector(`.nav-item[data-page="${page}"]`)?.classList.add('active');
  document.getElementById('pageTitle').textContent = page.charAt(0).toUpperCase() + page.slice(1);

  if (page === 'home') loadHome();
  if (page === 'analytics') loadAnalytics();
  if (page === 'history') loadHistory();
  if (page === 'findings') loadFindings();
  if (page === 'attack-paths') loadAttackPaths();
  if (page === 'settings') loadSettings();
  if (page === 'results' && data) showResults(data);

  window.scrollTo(0, 0);
}

document.querySelectorAll('.nav-item[data-page]').forEach(el =>
  el.addEventListener('click', () => navigate(el.dataset.page)));

// ── Scope handling ─────────────────────────────────────────────────────────
document.querySelectorAll('.scope-opt').forEach(opt =>
  opt.addEventListener('click', () => {
    State.scope = opt.dataset.scope;
    document.querySelectorAll('.scope-opt').forEach(o => o.classList.remove('active'));
    opt.classList.add('active');
  }));

function setQuickScope(el) {
  State.scope = el.dataset.scope;
  document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
}

// ── Toast ─────────────────────────────────────────────────────────────────
function toast(msg, type = 'ok') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.getElementById('toastContainer').appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

// ── API helpers ────────────────────────────────────────────────────────────
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

// ── Helpers ───────────────────────────────────────────────────────────────
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function riskClass(v) {
  const l = (v || '').toLowerCase();
  if (l.includes('critical')) return 'critical';
  if (l.includes('high')) return 'high';
  if (l.includes('medium')) return 'medium';
  if (l.includes('low')) return 'low';
  if (l.includes('clean') || l.includes('safe')) return 'clean';
  return 'unknown';
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

function shortUrl(u) {
  try {
    const x = new URL(u.startsWith('http') ? u : 'https://' + u);
    return x.hostname;
  } catch { return u; }
}

// ── HOME ───────────────────────────────────────────────────────────────────
async function loadHome() {
  try {
    const s = await get('/api/stats');
    document.getElementById('statScans').textContent = s.total_scans ?? '0';
    document.getElementById('statCritical').textContent = s.total_critical ?? '0';
    document.getElementById('statTargets').textContent = s.unique_targets ?? '0';
    document.getElementById('statAvgRisk').textContent = s.avg_risk_score > 0 ? s.avg_risk_score : '—';

    const recent = document.getElementById('recentScans');
    if (!s.recent_scans?.length) {
      recent.innerHTML = `<div class="empty"><div class="empty-t">No scans yet</div><div class="empty-d">Enter a URL above to start</div></div>`;
    } else {
      recent.innerHTML = s.recent_scans.map(scanRow).join('');
    }
  } catch { document.getElementById('statScans').textContent = '—'; }
}

// ── ANALYTICS ──────────────────────────────────────────────────────────────
async function loadAnalytics() {
  try {
    const s = await get('/api/stats');
    const history = await get('/api/history?limit=100');
    const scans = history.scans || [];

    // Severity breakdown
    let critical = 0, high = 0, medium = 0, low = 0;
    scans.forEach(scan => {
      (scan.findings || []).forEach(f => {
        if (f.severity === 'Critical') critical++;
        else if (f.severity === 'High') high++;
        else if (f.severity === 'Medium') medium++;
        else low++;
      });
    });
    const max = Math.max(critical, high, medium, low, 1);
    document.getElementById('valCritical').textContent = critical;
    document.getElementById('barCritical').style.width = (critical / max * 100) + '%';
    document.getElementById('valHigh').textContent = high;
    document.getElementById('barHigh').style.width = (high / max * 100) + '%';
    document.getElementById('valMedium').textContent = medium;
    document.getElementById('barMedium').style.width = (medium / max * 100) + '%';
    document.getElementById('valLow').textContent = low;
    document.getElementById('barLow').style.width = (low / max * 100) + '%';

    // Donut chart - avg risk
    const avgRisk = s.avg_risk_score || 0;
    document.getElementById('donutValue').textContent = avgRisk > 0 ? avgRisk : '—';
    const donut = document.getElementById('riskDonut');
    if (avgRisk > 0) {
      const redPct = Math.min(avgRisk / 10 * 100, 100);
      donut.style.background = `conic-gradient(var(--red) 0% ${redPct}%, var(--elevated) ${redPct}% 100%)`;
    }

    // Trend chart (last 30 days)
    const days = 30;
    const counts = new Array(days).fill(0);
    const labels = [];
    const today = new Date();
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(today);
      d.setDate(d.getDate() - i);
      labels.push(d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
    }
    scans.forEach(scan => {
      const d = new Date(scan.created_at);
      const daysAgo = Math.floor((today - d) / (1000 * 60 * 60 * 24));
      if (daysAgo >= 0 && daysAgo < days) counts[days - 1 - daysAgo]++;
    });
    const maxCount = Math.max(...counts, 1);
    const trendBars = document.getElementById('trendBars');
    trendBars.innerHTML = counts.map(c =>
      `<div class="trend-bar" style="height:${Math.max(c / maxCount * 100, 4)}%"></div>`
    ).join('');
    const trendLabels = document.getElementById('trendLabels');
    trendLabels.innerHTML = `
      <span>${labels[0]}</span>
      <span>${labels[Math.floor(days/2)]}</span>
      <span>${labels[days-1]}</span>
    `;

    // Top categories
    const cats = {};
    scans.forEach(scan => {
      (scan.findings || []).forEach(f => {
        const cat = f.category || 'Other';
        cats[cat] = (cats[cat] || 0) + 1;
      });
    });
    const sortedCats = Object.entries(cats).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const topTotal = sortedCats[0]?.[1] || 1;
    const catsEl = document.getElementById('topCategories');
    if (sortedCats.length === 0) {
      catsEl.innerHTML = `<div class="empty" style="padding:2rem"><div class="empty-t">No data yet</div><div class="empty-d">Run scans to see analytics</div></div>`;
    } else {
      catsEl.innerHTML = sortedCats.map(([name, count]) => `
        <div class="category-row">
          <span class="category-name">${esc(name)}</span>
          <div class="category-bar-wrap"><div class="category-bar" style="width:${count / topTotal * 100}%"></div></div>
          <span class="category-count">${count}</span>
        </div>
      `).join('');
    }
  } catch (e) {
    console.error('Analytics load failed:', e);
  }
}

function scanRow(s) {
  const cls = riskClass(s.risk_verdict);
  return `
    <div class="scan-row" onclick="openScan('${s.id}')">
      <div class="scan-info">
        <div class="scan-url">${esc(shortUrl(s.target_url))}</div>
        <div class="scan-meta">${ago(s.scanned_at)}</div>
      </div>
      <span class="badge ${cls}">${s.risk_verdict || 'Unknown'}</span>
    </div>`;
}

async function quickLaunch() {
  let url = document.getElementById('quickUrl').value.trim();
  if (!url) { toast('Enter a URL', 'err'); return; }
  if (!url.startsWith('http')) url = 'https://' + url;

  const btn = document.getElementById('quickBtn');
  btn.disabled = true;
  btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10" stroke-dasharray="60" stroke-dashoffset="30"><animateTransform attributeName="transform" type="rotate" from="0 12 12" to="360 12 12" dur="1s" repeatCount="indefinite"/></circle></svg>`;

  try {
    toast('Starting scan…', 'ok');
    const resp = await fetch(api('/api/scan/stream'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url: url, scope: state.scope })
    });

    let result = null;
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const msg = JSON.parse(line);
          if (msg.event === 'scan:complete') result = msg;
        } catch {}
      }
    }

    if (result?.scan_id) {
      toast('Scan complete', 'ok');
      openScan(result.scan_id);
    } else {
      toast('Scan finished', 'ok');
      loadHome();
    }
  } catch (e) {
    toast('Scan failed: ' + (e.message || 'Error'), 'err');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"/></svg>`;
  }
}

// ── SCANNER ────────────────────────────────────────────────────────────────
async function launchScan() {
  let url = document.getElementById('scanUrl').value.trim();
  if (!url) { toast('Enter a URL', 'err'); return; }
  if (!url.startsWith('http')) url = 'https://' + url;

  const box = document.getElementById('progressBox');
  const btn = document.querySelector('.command-btn');
  box.classList.add('show');
  btn.disabled = true;

  document.getElementById('skillsList').innerHTML = '';
  document.getElementById('liveFindings').innerHTML = '';
  document.getElementById('progressText').textContent = 'Scanning…';

  const skills = {};

  try {
    const resp = await fetch(api('/api/scan/stream'), {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, scope: State.scope }),
    });
    if (!resp.ok) throw new Error('API error ' + resp.status);

    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    let buf = '', lastReport = null;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const lines = buf.split('\n'); buf = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const e = JSON.parse(line);
          if (e.event === 'skill_start') { skills[e.skill] = 'running'; renderSkills(skills); }
          if (e.event === 'skill_done') { skills[e.skill] = 'done'; renderSkills(skills); }
          if (e.event === 'finding') addLiveFinding(e.finding);
          if (e.event === 'done') lastReport = e.report;
        } catch {}
      }
    }

    if (lastReport) {
      State.report = lastReport;
      State.scanId = lastReport.id;
      document.getElementById('progressText').textContent = 'Complete';
      toast('Scan complete', 'ok');
      if (document.getElementById('toggleAutoNav')?.checked) {
        setTimeout(() => navigate('results', lastReport), 400);
      }
    }
  } catch (e) {
    toast('Scan failed: ' + e.message, 'err');
  }

  btn.disabled = false;
}

function renderSkills(skills) {
  const el = document.getElementById('skillsList');
  el.innerHTML = Object.entries(skills).map(([name, status]) => `
    <div style="display:flex; align-items:center; gap:0.5rem; padding:0.25rem 0; font-size:0.75rem; color:var(--dim)">
      <span style="width:6px; height:6px; border-radius:50%; background:${status === 'running' ? 'var(--accent)' : 'var(--green)'}"></span>
      ${esc(name)}
    </div>
  `).join('');
}

function addLiveFinding(f) {
  const s = sevClass(f.severity);
  const el = document.getElementById('liveFindings');
  const row = document.createElement('div');
  row.style.cssText = 'display:flex; align-items:center; gap:0.5rem; padding:0.375rem 0; font-size:0.8125rem;';
  row.innerHTML = `<span class="sev ${s}">${s}</span><span>${esc(f.title || 'Finding')}</span>`;
  el.appendChild(row);
  if (s === 'Critical' && document.getElementById('toggleCritical')?.checked) {
    toast('Critical finding!', 'err');
  }
}

// ── HISTORY ────────────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const data = await get('/api/history?limit=50');
    State.historyData = data.scans;
    const el = document.getElementById('historyList');
    if (!data.scans?.length) {
      el.innerHTML = `<div class="empty" style="padding:2rem"><div class="empty-t">No scans</div></div>`;
    } else {
      el.innerHTML = data.scans.map(scanRow).join('');
    }
  } catch { toast('Failed to load history', 'err'); }
}

async function openScan(id) {
  try {
    const data = await get(`/api/history/${id}`);
    State.scanId = id;
    State.report = data.report || data;
    navigate('results', State.report);
  } catch { toast('Failed to load scan', 'err'); }
}

async function deleteScan(id) {
  if (!confirm('Delete this scan?')) return;
  try { await del(`/api/history/${id}`); toast('Deleted', 'ok'); loadHistory(); }
  catch { toast('Delete failed', 'err'); }
}

// ── FINDINGS ────────────────────────────────────────────────────────────────
async function loadFindings() {
  try {
    const data = await get('/api/history?limit=100');
    const all = [];
    for (const s of data.scans || []) {
      if (s.total > 0) {
        try {
          const full = await get(`/api/history/${s.id}`);
          (full.report?.findings || []).forEach(f => all.push(f));
        } catch {}
      }
    }
    State.findings = all;
    const el = document.getElementById('findingsList');
    if (!all.length) {
      el.innerHTML = `<div class="empty" style="padding:2rem"><div class="empty-t">No findings</div></div>`;
    } else {
      el.innerHTML = all.map(f => findingRow(f)).join('');
    }
  } catch { toast('Failed to load findings', 'err'); }
}

function findingRow(f) {
  const s = sevClass(f.severity);
  return `
    <div class="finding">
      <div class="finding-h" onclick="this.parentElement.classList.toggle('open')">
        <span class="sev ${s}">${s}</span>
        <span class="finding-t">${esc(f.title || 'Finding')}</span>
        <span class="finding-cat">${esc(f.category || '')}</span>
      </div>
      <div class="finding-b">
        ${f.description ? `<p style="margin-bottom:0.5rem; color:var(--muted); font-size:0.8125rem">${esc(f.description)}</p>` : ''}
        ${f.evidence ? `<pre style="padding:0.75rem; background:var(--elevated); border-radius:4px; font-size:0.75rem; overflow:auto">${esc(String(f.evidence).substring(0, 300))}</pre>` : ''}
      </div>
    </div>`;
}

// ── RESULTS ────────────────────────────────────────────────────────────────
function showResults(report) {
  if (!report) return;
  const f = report.findings || [];

  document.getElementById('resultsTarget').textContent = shortUrl(report.target_url || 'Results');

  const cls = riskClass(report.risk_verdict);
  document.getElementById('resultsBadge').outerHTML = `<span class="badge ${cls}">${report.risk_verdict || 'Unknown'}</span>`;

  const counts = {
    c: f.filter(x => sevClass(x.severity) === 'Critical').length,
    h: f.filter(x => sevClass(x.severity) === 'High').length,
    m: f.filter(x => sevClass(x.severity) === 'Medium').length,
    l: f.filter(x => sevClass(x.severity) === 'Low').length,
  };

  document.getElementById('rcBadge').outerHTML = counts.c ? `<span class="badge critical">${counts.c} Critical</span>` : '';
  document.getElementById('rhBadge').outerHTML = counts.h ? `<span class="badge high">${counts.h} High</span>` : '';
  document.getElementById('rmBadge').outerHTML = counts.m ? `<span class="badge medium">${counts.m} Medium</span>` : '';
  document.getElementById('rlBadge').outerHTML = counts.l ? `<span class="badge low">${counts.l} Low</span>` : '';

  const sorted = [...f].sort((a, b) => {
    const o = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    return (o[sevClass(a.severity)] ?? 5) - (o[sevClass(b.severity)] ?? 5);
  });

  document.getElementById('resultsFindings').innerHTML = sorted.map(findingRow).join('') ||
    `<div class="empty" style="padding:2rem"><div class="empty-t">No findings</div></div>`;
}

// ── ATTACK PATHS ───────────────────────────────────────────────────────────
async function loadAttackPaths() {
  try {
    const data = await get('/api/history?limit=100');
    const paths = [];
    for (const s of data.scans || []) {
      try {
        const full = await get(`/api/history/${s.id}`);
        (full.report?.attack_paths || []).forEach(p => paths.push(p));
      } catch {}
    }
    const el = document.getElementById('attackPathsList');
    if (!paths.length) {
      el.innerHTML = `<div class="empty"><div class="empty-t">No attack paths</div><div class="empty-d">Run a full scan to discover chains</div></div>`;
    } else {
      el.innerHTML = paths.map(p => `
        <div style="padding:1rem; border-bottom:1px solid var(--border)">
          <div style="font-weight:500; margin-bottom:0.375rem">${esc(p.title || 'Path')}</div>
          <div style="font-size:0.75rem; color:var(--dim)">${(p.steps || []).join(' → ')}</div>
        </div>
      `).join('');
    }
  } catch {}
}

// ── INVESTIGATION ──────────────────────────────────────────────────────────
async function runChainLookup() {
  const addr = document.getElementById('chainAddr').value.trim();
  if (!addr) { toast('Enter an address', 'err'); return; }
  const el = document.getElementById('chainResult');
  el.textContent = 'Looking up…';
  try {
    const r = await post('/api/scan', { url: 'https://etherscan.io', goal: `Lookup: ${addr}`, scope: 'passive' });
    el.textContent = `Address: ${addr}\nRisk: ${r.risk_verdict || '—'}\nFindings: ${(r.findings || []).length}`;
  } catch (e) { el.textContent = 'Error: ' + e.message; }
}

async function runOsint() {
  const d = document.getElementById('osintDomain').value.trim();
  if (!d) { toast('Enter a domain', 'err'); return; }
  const el = document.getElementById('osintResult');
  el.textContent = 'Running…';
  try {
    const url = d.startsWith('http') ? d : 'https://' + d;
    const r = await post('/api/scan', { url, scope: 'recon' });
    el.textContent = `Domain: ${d}\nVerdict: ${r.risk_verdict || '—'}\nFindings: ${(r.findings || []).length}`;
  } catch (e) { el.textContent = 'Error: ' + e.message; }
}

async function runPoc() {
  const type = document.getElementById('pocType').value;
  const url = document.getElementById('pocUrl').value.trim();
  if (!url) { toast('Enter a URL', 'err'); return; }
  const el = document.getElementById('pocResult');
  el.textContent = 'Running…';
  try {
    const body = { type, url };
    if (type === 'idor') {
      body.param_to_change = 'id';
      body.new_value = '2';
    }
    const r = await post('/api/poc/simulate', body);
    el.textContent = `Result: ${r.conclusion}\nSuccess: ${r.success}\nStatus: ${r.status_code || '—'}`;
    el.style.color = r.success ? 'var(--green)' : 'var(--red)';
  } catch (e) { el.textContent = 'Error: ' + e.message; }
}

async function runReputation() {
  const t = document.getElementById('reputationTarget').value.trim();
  if (!t) { toast('Enter a target', 'err'); return; }
  const el = document.getElementById('reputationResult');
  el.textContent = 'Checking…';
  try {
    const url = t.startsWith('http') ? t : 'https://' + t;
    const r = await post('/api/scan', { url, scope: 'passive', goal: `Reputation: ${t}` });
    el.textContent = `Target: ${t}\nVerdict: ${r.risk_verdict || '—'}`;
  } catch (e) { el.textContent = 'Error: ' + e.message; }
}

// ── SETTINGS ────────────────────────────────────────────────────────────────
function loadSettings() {
  document.getElementById('settingsApiUrl').value = CFG.apiUrl;
  const hKey = localStorage.getItem('diverg_helius_key') || '';
  const hNet = localStorage.getItem('diverg_helius_network') || 'mainnet';
  document.getElementById('heliusApiKey').value = hKey;
  document.getElementById('heliusNetwork').value = hNet;
}

function saveSettings() {
  const url = document.getElementById('settingsApiUrl').value.trim();
  if (url) { CFG.apiUrl = url; localStorage.setItem('diverg_api', url); toast('Saved', 'ok'); }
}

async function testConnection() {
  const el = document.getElementById('connStatus');
  el.textContent = 'Testing…';
  try {
    const r = await get('/api/health');
    el.textContent = `Connected — ${r.service}`;
    el.style.color = 'var(--green)';
  } catch (e) {
    el.textContent = 'Failed';
    el.style.color = 'var(--red)';
  }
}

function saveHeliusKey() {
  const key = document.getElementById('heliusApiKey').value.trim();
  const net = document.getElementById('heliusNetwork').value;
  localStorage.setItem('diverg_helius_key', key);
  localStorage.setItem('diverg_helius_network', net);
  toast('Helius settings saved', 'ok');
}

async function testHeliusKey() {
  const key = document.getElementById('heliusApiKey').value.trim();
  const el = document.getElementById('heliusStatus');
  if (!key) { el.textContent = 'Enter a key'; el.style.color = 'var(--red)'; return; }
  el.textContent = 'Testing…';
  try {
    const r = await fetch(`https://mainnet.helius-rpc.com/?api-key=${key}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getHealth' }),
    });
    if (r.ok) {
      el.textContent = 'Connected';
      el.style.color = 'var(--green)';
    } else throw new Error('Invalid');
  } catch {
    el.textContent = 'Invalid key';
    el.style.color = 'var(--red)';
  }
}

async function exportHistory() {
  try {
    const d = await get('/api/history?limit=200');
    const blob = new Blob([JSON.stringify(d, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `diverg-${Date.now()}.json`;
    a.click();
    toast('Exported', 'ok');
  } catch { toast('Export failed', 'err'); }
}

async function clearHistory() {
  if (!confirm('Clear all scans?')) return;
  try {
    const d = await get('/api/history?limit=200');
    for (const s of d.scans || []) await del(`/api/history/${s.id}`);
    toast('Cleared', 'ok');
    loadHistory();
  } catch { toast('Failed', 'err'); }
}

function exportReport() {
  if (!State.report) return;
  const blob = new Blob([JSON.stringify(State.report, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `scan-${Date.now()}.json`;
  a.click();
}

// ── Init ──────────────────────────────────────────────────────────────────
loadHome();
