/* Diverg Console */

const CFG = { apiUrl: localStorage.getItem('diverg_api') || 'http://127.0.0.1:5000' };
const api = p => CFG.apiUrl + p;

const State = { scope: 'full', scanId: null, report: null, historyData: [], findings: [] };

// ── Auth ──────────────────────────────────────────────────────────────────
const Auth = {
  get token() { return localStorage.getItem('diverg_token') || ''; },
  get user() { try { return JSON.parse(localStorage.getItem('diverg_user') || 'null'); } catch { return null; } },
  get headers() { return this.token ? { 'Authorization': 'Bearer ' + this.token } : {}; },
  logout() {
    localStorage.removeItem('diverg_token');
    localStorage.removeItem('diverg_user');
    window.location.href = '/login';
  }
};

if (!Auth.token) { window.location.href = '/login'; }

// ── Navigation ───────────────────────────────────────────────────────────
function navigate(page, data) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  document.getElementById('page-' + page)?.classList.add('active');
  document.querySelector(`.nav-item[data-page="${page}"]`)?.classList.add('active');

  const titles = {
    home: 'Home', scanner: 'Scanner', analytics: 'Analytics', history: 'History',
    findings: 'Findings', results: 'Results', 'attack-paths': 'Attack Paths',
    investigation: 'Investigation', settings: 'Settings',
  };
  document.getElementById('pageTitle').textContent = titles[page] || page;

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
function authHeaders(extra) {
  return { ...Auth.headers, ...extra };
}

async function get(path) {
  const r = await fetch(api(path), { headers: authHeaders() });
  if (r.status === 401) { Auth.logout(); return; }
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}
async function post(path, body) {
  const r = await fetch(api(path), {
    method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify(body)
  });
  if (r.status === 401) { Auth.logout(); return; }
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}
async function del(path) {
  const r = await fetch(api(path), { method: 'DELETE', headers: authHeaders() });
  if (r.status === 401) { Auth.logout(); return; }
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

function scanRow(s) {
  const cls = riskClass(s.risk_verdict);
  return `
    <div class="scan-row" onclick="openScan('${s.id}')">
      <div class="scan-info">
        <div class="scan-url">${esc(shortUrl(s.target_url))}</div>
        <div class="scan-meta">${ago(s.scanned_at)}</div>
      </div>
      <span class="badge ${cls}">${esc(s.risk_verdict || 'Unknown')}</span>
    </div>`;
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
      recent.innerHTML = `<div class="scan-list">${s.recent_scans.map(scanRow).join('')}</div>`;
    }
  } catch { document.getElementById('statScans').textContent = '—'; }
}

// ── QUICK LAUNCH (Home) ────────────────────────────────────────────────────
async function quickLaunch() {
  let url = document.getElementById('quickUrl').value.trim();
  if (!url) { toast('Enter a URL', 'err'); return; }
  if (!url.startsWith('http')) url = 'https://' + url;

  const btn = document.getElementById('quickBtn');
  btn.disabled = true;

  try {
    toast('Starting scan…', 'ok');
    const resp = await fetch(api('/api/scan/stream'), {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ url, scope: State.scope }),
    });
    if (resp.status === 401) { Auth.logout(); return; }
    if (!resp.ok) throw new Error('API error ' + resp.status);

    let lastReport = null;
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
          if (e.event === 'done') lastReport = e.report;
        } catch {}
      }
    }

    if (lastReport) {
      State.report = lastReport;
      State.scanId = lastReport.id;
      toast('Scan complete', 'ok');
      navigate('results', lastReport);
    } else {
      toast('Scan finished', 'ok');
      loadHome();
    }
  } catch (e) {
    toast('Scan failed: ' + e.message, 'err');
  } finally {
    btn.disabled = false;
  }
}

// ── SCANNER (dedicated page) ────────────────────────────────────────────────
async function launchScan() {
  let url = document.getElementById('scanUrl').value.trim();
  if (!url) { toast('Enter a URL', 'err'); return; }
  if (!url.startsWith('http')) url = 'https://' + url;

  const box = document.getElementById('progressBox');
  box.classList.add('show');

  document.getElementById('skillsList').innerHTML = '';
  document.getElementById('liveFindings').innerHTML = '';
  document.getElementById('progressText').textContent = 'Scanning…';

  const skills = {};

  try {
    const resp = await fetch(api('/api/scan/stream'), {
      method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ url, scope: State.scope }),
    });
    if (resp.status === 401) { Auth.logout(); return; }
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
          if (e.event === 'skill_done') {
            skills[e.skill] = e.error ? 'error' : 'done';
            renderSkills(skills);
            if (e.findings_count > 0) {
              document.getElementById('progressText').textContent = `Found ${e.findings_count} issue${e.findings_count > 1 ? 's' : ''} in ${e.skill}`;
            }
          }
          if (e.event === 'done') {
            lastReport = e.report;
            (lastReport.findings || []).forEach(f => addLiveFinding(f));
          }
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
}

function renderSkills(skills) {
  const el = document.getElementById('skillsList');
  const colors = { running: 'var(--accent)', done: 'var(--green)', error: 'var(--red)' };
  el.innerHTML = Object.entries(skills).map(([name, status]) => `
    <div style="display:flex; align-items:center; gap:0.5rem; padding:0.25rem 0; font-size:0.75rem; color:var(--dim)">
      <span style="width:6px; height:6px; border-radius:50%; background:${colors[status] || 'var(--dim)'}"></span>
      ${esc(name)}
    </div>
  `).join('');
}

function addLiveFinding(f) {
  if (!f) return;
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

// ── ANALYTICS ──────────────────────────────────────────────────────────────
async function loadAnalytics() {
  try {
    const s = await get('/api/stats');
    const history = await get('/api/history?limit=100');
    const scans = history.scans || [];

    // Use counts from the list data (not findings array)
    let critical = 0, high = 0, medium = 0, low = 0;
    scans.forEach(scan => {
      critical += scan.critical || 0;
      high += scan.high || 0;
      medium += scan.medium || 0;
      low += scan.low || 0;
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

    // Donut chart
    const avgRisk = s.avg_risk_score || 0;
    document.getElementById('donutValue').textContent = avgRisk > 0 ? avgRisk : '—';
    const donut = document.getElementById('riskDonut');
    if (avgRisk > 0) {
      const pct = Math.min(avgRisk / 10 * 100, 100);
      donut.style.background = `conic-gradient(var(--red) 0% ${pct}%, var(--elevated) ${pct}% 100%)`;
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
      if (!scan.created_at) return;
      const d = new Date(scan.created_at);
      const daysAgo = Math.floor((today - d) / (1000 * 60 * 60 * 24));
      if (daysAgo >= 0 && daysAgo < days) counts[days - 1 - daysAgo]++;
    });
    const maxCount = Math.max(...counts, 1);
    document.getElementById('trendBars').innerHTML = counts.map(c =>
      `<div class="trend-bar" style="height:${Math.max(c / maxCount * 100, 4)}%"></div>`
    ).join('');
    document.getElementById('trendLabels').innerHTML = `
      <span>${labels[0]}</span>
      <span>${labels[Math.floor(days / 2)]}</span>
      <span>${labels[days - 1]}</span>
    `;

    // Top categories — fetch full reports for scans with findings
    const cats = {};
    for (const scan of scans) {
      if ((scan.total || 0) > 0) {
        try {
          const full = await get(`/api/history/${scan.id}`);
          (full.report?.findings || []).forEach(f => {
            const cat = f.category || 'Other';
            cats[cat] = (cats[cat] || 0) + 1;
          });
        } catch {}
      }
    }
    const sorted = Object.entries(cats).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const topMax = sorted[0]?.[1] || 1;
    const catsEl = document.getElementById('topCategories');
    if (!sorted.length) {
      catsEl.innerHTML = `<div class="empty" style="padding:2rem"><div class="empty-t">No data yet</div><div class="empty-d">Run scans to see analytics</div></div>`;
    } else {
      catsEl.innerHTML = sorted.map(([name, count]) => `
        <div class="category-row">
          <span class="category-name">${esc(name)}</span>
          <div class="category-bar-wrap"><div class="category-bar" style="width:${count / topMax * 100}%"></div></div>
          <span class="category-count">${count}</span>
        </div>
      `).join('');
    }
  } catch (e) {
    console.error('Analytics load failed:', e);
  }
}

// ── HISTORY ────────────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const data = await get('/api/history?limit=50');
    State.historyData = data.scans || [];
    const el = document.getElementById('historyList');
    if (!State.historyData.length) {
      el.innerHTML = `<div class="empty" style="padding:2rem"><div class="empty-t">No scans</div><div class="empty-d">Run a scan from Home to see results here</div></div>`;
    } else {
      el.innerHTML = State.historyData.map(s => `
        <div class="scan-row" onclick="openScan('${s.id}')">
          <div class="scan-info">
            <div class="scan-url">${esc(shortUrl(s.target_url))}</div>
            <div class="scan-meta">${s.scope || 'full'} · ${ago(s.scanned_at)} · ${s.total || 0} findings</div>
          </div>
          <span class="badge ${riskClass(s.risk_verdict)}">${esc(s.risk_verdict || 'Unknown')}</span>
          <button class="btn btn-ghost" onclick="event.stopPropagation(); deleteScan('${s.id}')" style="font-size:0.75rem; color:var(--dim)">Delete</button>
        </div>
      `).join('');
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
      if ((s.total || 0) > 0) {
        try {
          const full = await get(`/api/history/${s.id}`);
          (full.report?.findings || []).forEach(f => all.push(f));
        } catch {}
      }
    }
    State.findings = all;
    const el = document.getElementById('findingsList');
    if (!all.length) {
      el.innerHTML = `<div class="empty" style="padding:2rem"><div class="empty-t">No findings</div><div class="empty-d">Run a scan to see vulnerability findings</div></div>`;
    } else {
      el.innerHTML = all.map(findingRow).join('');
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
        ${f.description ? `<p style="margin-bottom:0.5rem; color:var(--muted); font-size:0.8125rem; line-height:1.6">${esc(f.description)}</p>` : ''}
        ${f.impact ? `<p style="margin-bottom:0.5rem; color:var(--muted); font-size:0.8125rem"><strong style="color:var(--text)">Impact:</strong> ${esc(f.impact)}</p>` : ''}
        ${f.evidence ? `<pre style="margin-top:0.5rem; padding:0.75rem; background:var(--elevated); border-radius:4px; font-size:0.75rem; overflow-x:auto; white-space:pre-wrap; word-break:break-all">${esc(String(f.evidence).substring(0, 500))}</pre>` : ''}
        ${f.remediation ? `<p style="margin-top:0.5rem; color:var(--muted); font-size:0.8125rem"><strong style="color:var(--text)">Fix:</strong> ${esc(f.remediation)}</p>` : ''}
      </div>
    </div>`;
}

// ── RESULTS ────────────────────────────────────────────────────────────────
function showResults(report) {
  if (!report) return;
  const findings = report.findings || [];

  document.getElementById('resultsTarget').textContent = shortUrl(report.target_url || 'Results');

  const counts = {
    c: findings.filter(x => sevClass(x.severity) === 'Critical').length,
    h: findings.filter(x => sevClass(x.severity) === 'High').length,
    m: findings.filter(x => sevClass(x.severity) === 'Medium').length,
    l: findings.filter(x => sevClass(x.severity) === 'Low').length,
  };

  const cls = riskClass(report.risk_verdict);
  const badgesEl = document.getElementById('resultsBadges');
  const parts = [`<span class="badge ${cls}">${esc(report.risk_verdict || 'Unknown')}${report.risk_score != null ? ' · ' + report.risk_score : ''}</span>`];
  if (counts.c) parts.push(`<span class="badge critical">${counts.c} Critical</span>`);
  if (counts.h) parts.push(`<span class="badge high">${counts.h} High</span>`);
  if (counts.m) parts.push(`<span class="badge medium">${counts.m} Medium</span>`);
  if (counts.l) parts.push(`<span class="badge low">${counts.l} Low</span>`);
  badgesEl.innerHTML = parts.join('');

  const sorted = [...findings].sort((a, b) => {
    const o = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    return (o[sevClass(a.severity)] ?? 5) - (o[sevClass(b.severity)] ?? 5);
  });

  document.getElementById('resultsFindings').innerHTML = sorted.length
    ? sorted.map(findingRow).join('')
    : `<div class="empty" style="padding:2rem"><div class="empty-t">No findings</div></div>`;
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
      el.innerHTML = `<div class="empty"><div class="empty-t">No attack paths discovered</div><div class="empty-d">Run a full scan to find chained vulnerabilities</div></div>`;
    } else {
      el.innerHTML = `<div class="scan-list">${paths.map(p => {
        const steps = Array.isArray(p.steps) ? p.steps : (p.chain || p.path || []);
        return `<div style="padding:1rem 1.25rem; border-bottom:1px solid var(--border)">
          <div style="font-weight:500; margin-bottom:0.375rem">${esc(p.title || p.name || 'Attack Path')}</div>
          <div style="font-size:0.75rem; color:var(--dim); font-family:var(--mono)">${steps.map(s => esc(String(s))).join(' → ')}</div>
          ${p.impact ? `<div style="font-size:0.75rem; color:var(--muted); margin-top:0.25rem">${esc(p.impact)}</div>` : ''}
        </div>`;
      }).join('')}</div>`;
    }
  } catch { toast('Failed to load attack paths', 'err'); }
}

// ── INVESTIGATION ──────────────────────────────────────────────────────────
async function runChainLookup() {
  const addr = document.getElementById('chainAddr').value.trim();
  if (!addr) { toast('Enter an address', 'err'); return; }
  const el = document.getElementById('chainResult');
  el.textContent = 'Looking up…'; el.style.color = '';
  try {
    const r = await post('/api/scan', { url: 'https://etherscan.io', goal: `Blockchain lookup: ${addr}`, scope: 'passive' });
    const lines = [`Address: ${addr}`, `Risk: ${r.risk_verdict || '—'}`, `Score: ${r.risk_score ?? '—'}`, `Findings: ${(r.findings || []).length}`];
    (r.findings || []).slice(0, 5).forEach(f => lines.push(`  [${f.severity}] ${f.title}`));
    el.textContent = lines.join('\n');
  } catch (e) { el.textContent = 'Error: ' + e.message; el.style.color = 'var(--red)'; }
}

async function runOsint() {
  const d = document.getElementById('osintDomain').value.trim();
  if (!d) { toast('Enter a domain', 'err'); return; }
  const el = document.getElementById('osintResult');
  el.textContent = 'Investigating…'; el.style.color = '';
  try {
    const url = d.startsWith('http') ? d : 'https://' + d;
    const r = await post('/api/scan', { url, scope: 'recon' });
    const lines = [`Domain: ${d}`, `Verdict: ${r.risk_verdict || '—'}`, `Score: ${r.risk_score ?? '—'}`, `Findings: ${(r.findings || []).length}`, ''];
    (r.findings || []).slice(0, 8).forEach(f => {
      lines.push(`[${f.severity}] ${f.title}`);
      if (f.evidence) lines.push(`  ${String(f.evidence).substring(0, 80)}`);
    });
    el.textContent = lines.join('\n');
  } catch (e) { el.textContent = 'Error: ' + e.message; el.style.color = 'var(--red)'; }
}

async function runPoc() {
  const type = document.getElementById('pocType').value;
  const url = document.getElementById('pocUrl').value.trim();
  if (!url) { toast('Enter a URL', 'err'); return; }
  const el = document.getElementById('pocResult');
  el.textContent = 'Running…'; el.style.color = '';
  try {
    const body = { type, url };
    if (type === 'idor') {
      body.param_to_change = document.getElementById('pocParam')?.value.trim() || 'id';
      body.new_value = document.getElementById('pocValue')?.value.trim() || '2';
    }
    const r = await post('/api/poc/simulate', body);
    el.textContent = `Result: ${r.conclusion}\nSuccess: ${r.success}\nStatus: ${r.status_code || '—'}${r.body_preview ? '\n\n' + r.body_preview.substring(0, 300) : ''}`;
    el.style.color = r.success ? 'var(--green)' : 'var(--red)';
  } catch (e) { el.textContent = 'Error: ' + e.message; el.style.color = 'var(--red)'; }
}

async function runReputation() {
  const t = document.getElementById('reputationTarget').value.trim();
  if (!t) { toast('Enter a target', 'err'); return; }
  const el = document.getElementById('reputationResult');
  el.textContent = 'Checking…'; el.style.color = '';
  try {
    const url = t.startsWith('http') ? t : 'https://' + t;
    const r = await post('/api/scan', { url, scope: 'passive', goal: `Entity reputation: ${t}` });
    const lines = [`Target: ${t}`, `Verdict: ${r.risk_verdict || '—'}`, `Score: ${r.risk_score ?? '—'}`, ''];
    (r.findings || []).slice(0, 8).forEach(f => lines.push(`[${f.severity}] ${f.title}`));
    if (!(r.findings || []).length) lines.push('No significant findings.');
    el.textContent = lines.join('\n');
  } catch (e) { el.textContent = 'Error: ' + e.message; el.style.color = 'var(--red)'; }
}

// ── SETTINGS ────────────────────────────────────────────────────────────────
function loadSettings() {
  document.getElementById('settingsApiUrl').value = CFG.apiUrl;
  document.getElementById('heliusApiKey').value = localStorage.getItem('diverg_helius_key') || '';
  document.getElementById('heliusNetwork').value = localStorage.getItem('diverg_helius_network') || 'mainnet';
}

function saveSettings() {
  const url = document.getElementById('settingsApiUrl').value.trim();
  if (url) { CFG.apiUrl = url; localStorage.setItem('diverg_api', url); toast('Saved', 'ok'); }
}

async function testConnection() {
  const el = document.getElementById('connStatus');
  el.textContent = 'Testing…'; el.style.color = 'var(--dim)';
  try {
    const r = await get('/api/health');
    el.textContent = `Connected — ${r.service} v${r.version}`;
    el.style.color = 'var(--green)';
    toast('API connected', 'ok');
  } catch (e) {
    el.textContent = 'Failed: ' + e.message;
    el.style.color = 'var(--red)';
    toast('Connection failed', 'err');
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
  el.textContent = 'Testing…'; el.style.color = 'var(--dim)';
  try {
    const r = await fetch(`https://mainnet.helius-rpc.com/?api-key=${key}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getHealth' }),
    });
    if (r.ok) {
      el.textContent = 'Connected'; el.style.color = 'var(--green)';
      toast('Helius key valid', 'ok');
    } else throw new Error('Invalid');
  } catch {
    el.textContent = 'Invalid key'; el.style.color = 'var(--red)';
    toast('Invalid key', 'err');
  }
}

async function exportHistory() {
  try {
    const d = await get('/api/history?limit=200');
    const blob = new Blob([JSON.stringify(d, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = `diverg-${Date.now()}.json`;
    a.click(); toast('Exported', 'ok');
  } catch { toast('Export failed', 'err'); }
}

async function clearHistory() {
  if (!confirm('Clear all scans? This cannot be undone.')) return;
  try {
    const d = await get('/api/history?limit=200');
    for (const s of d.scans || []) await del(`/api/history/${s.id}`);
    toast('Cleared', 'ok'); loadHistory();
  } catch { toast('Failed', 'err'); }
}

function exportReport() {
  if (!State.report) return;
  const blob = new Blob([JSON.stringify(State.report, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = `scan-${Date.now()}.json`;
  a.click(); toast('Exported', 'ok');
}

// ── Init ──────────────────────────────────────────────────────────────────
(function initUser() {
  const u = Auth.user;
  if (u) {
    const nameEl = document.getElementById('userName');
    const avatarEl = document.getElementById('userAvatar');
    if (nameEl) nameEl.textContent = u.name || u.email.split('@')[0];
    if (avatarEl) avatarEl.textContent = (u.name || u.email)[0].toUpperCase();
  }
})();

loadHome();
