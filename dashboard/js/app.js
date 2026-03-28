/* Diverg Console */

const CFG = { apiUrl: localStorage.getItem('diverg_api') || window.location.origin };
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
  if (r.status === 401) { Auth.logout(); throw new Error('Session expired. Sign in again.'); }
  let data = {};
  try { data = await r.json(); } catch { /* non-json */ }
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
}
async function post(path, body) {
  const r = await fetch(api(path), {
    method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify(body)
  });
  if (r.status === 401) { Auth.logout(); throw new Error('Session expired. Sign in again.'); }
  let data = {};
  try { data = await r.json(); } catch { /* non-json */ }
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
}
async function del(path) {
  const r = await fetch(api(path), { method: 'DELETE', headers: authHeaders() });
  if (r.status === 401) { Auth.logout(); throw new Error('Session expired. Sign in again.'); }
  let data = {};
  try { data = await r.json(); } catch { /* non-json */ }
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
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

  const box = document.getElementById('quickProgressBox');
  const pText = document.getElementById('quickProgressText');
  const pSkills = document.getElementById('quickSkillsList');
  const pFindings = document.getElementById('quickFindings');
  box.classList.add('show');
  pText.textContent = 'Connecting…';
  pSkills.innerHTML = '';
  pFindings.innerHTML = '';

  const skills = {};
  let findingCount = 0;

  try {
    const resp = await fetch(api('/api/scan/stream'), {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ url, scope: State.scope }),
    });
    if (resp.status === 401) { Auth.logout(); return; }
    if (!resp.ok) throw new Error('API error ' + resp.status);

    pText.textContent = 'Scanning ' + shortUrl(url) + '…';

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
          if (e.event === 'skill_start') {
            skills[e.skill] = 'running';
            renderQuickSkills(skills);
            pText.textContent = 'Running ' + e.skill + '…';
          }
          if (e.event === 'skill_done') {
            skills[e.skill] = e.error ? 'error' : 'done';
            renderQuickSkills(skills);
            findingCount += (e.findings_count || 0);
            if (findingCount > 0) {
              pFindings.textContent = findingCount + ' finding' + (findingCount > 1 ? 's' : '') + ' so far';
            }
          }
          if (e.event === 'done') lastReport = e.report;
        } catch {}
      }
    }

    if (lastReport) {
      State.report = lastReport;
      State.scanId = lastReport.id;
      pText.textContent = 'Complete — ' + (lastReport.findings?.length || 0) + ' findings';
      toast('Scan complete', 'ok');
      setTimeout(() => {
        box.classList.remove('show');
        navigate('results', lastReport);
      }, 600);
    } else {
      pText.textContent = 'Finished';
      toast('Scan finished', 'ok');
      setTimeout(() => box.classList.remove('show'), 1500);
      loadHome();
    }
  } catch (e) {
    pText.textContent = 'Failed: ' + e.message;
    toast('Scan failed: ' + e.message, 'err');
    setTimeout(() => box.classList.remove('show'), 3000);
  } finally {
    btn.disabled = false;
  }
}

function renderQuickSkills(skills) {
  const el = document.getElementById('quickSkillsList');
  const colors = { running: 'var(--accent)', done: 'var(--green)', error: 'var(--red)' };
  el.innerHTML = Object.entries(skills).map(([name, status]) => `
    <div style="display:flex; align-items:center; gap:0.5rem; padding:0.2rem 0; font-size:0.75rem; color:var(--dim)">
      <span style="width:6px; height:6px; border-radius:50%; background:${colors[status] || 'var(--dim)'}; flex-shrink:0"></span>
      ${esc(name)}
      <span style="color:${colors[status] || 'var(--dim)'}; margin-left:auto; font-size:0.7rem">${status === 'running' ? '●' : status === 'done' ? '✓' : '✗'}</span>
    </div>
  `).join('');
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
function _invSetOut(wrapId, sumId, rawId, emptyClass, summaryHtml, rawObj) {
  const wrap = document.getElementById(wrapId);
  const sum = document.getElementById(sumId);
  const raw = document.getElementById(rawId);
  if (wrap) wrap.classList.remove(emptyClass);
  if (sum) sum.innerHTML = summaryHtml;
  if (raw) raw.textContent = rawObj !== undefined && rawObj !== null ? JSON.stringify(rawObj, null, 2) : '';
}

function _invFindingsHtml(findings) {
  const list = findings || [];
  if (!list.length) {
    return '<p class="inv-muted">No scanner-style findings for this pass. Open <strong>Full JSON</strong> for raw OSINT (WHOIS, DNS, subdomains, etc.), recon, and headers.</p>';
  }
  const rows = list.slice(0, 250).map(f => {
    const sev = (f.severity || 'Info').toLowerCase();
    const ev = f.evidence ? `<div class="inv-ev">${esc(String(f.evidence))}</div>` : '';
    return `<div class="inv-finding"><span class="sev sev-${sevClass(f.severity).toLowerCase()}">${esc(f.severity || 'Info')}</span><strong>${esc(f.title || '')}</strong>${ev}</div>`;
  });
  return `<div class="inv-findings">${rows.join('')}</div>`;
}

function _invChainSummaryHtml(data) {
  if (data.error && !data.raw) {
    return `<p class="inv-err">${esc(data.error)}</p>`;
  }
  const s = data.summary || {};
  const chain = data.chain || '—';
  let h = `<p><strong>${esc(chain.toUpperCase())}</strong> · <span class="mono">${esc(data.address || '')}</span></p>`;
  if (chain === 'solana') {
    if (s.lamports != null) h += `<div class="inv-kv"><span>Balance</span> ${esc(String(s.lamports))} lamports (~${esc(String(s.sol_approx))} SOL)</div>`;
    if (s.owner) h += `<div class="inv-kv"><span>Owner</span> ${esc(String(s.owner))}</div>`;
    if (s.parsed_type) h += `<div class="inv-kv"><span>Account type</span> ${esc(String(s.parsed_type))}</div>`;
    if (s.recent_signatures_count != null) h += `<div class="inv-kv"><span>Recent signatures</span> ${esc(String(s.recent_signatures_count))}</div>`;
    if (s.token_accounts_count != null) h += `<div class="inv-kv"><span>Token accounts</span> ${esc(String(s.token_accounts_count))}</div>`;
  } else if (chain === 'evm') {
    if (s.eth_approx != null) h += `<div class="inv-kv"><span>Balance</span> ~${esc(String(s.eth_approx))} ETH</div>`;
    if (s.transaction_count_hex) h += `<div class="inv-kv"><span>Nonce</span> ${esc(String(s.transaction_count_hex))}</div>`;
  }
  h += '<p class="inv-muted" style="margin-top:0.75rem">Expand <strong>Full JSON</strong> for complete RPC responses (signatures, account data, token accounts).</p>';
  return h;
}

async function runChainLookup() {
  const addr = document.getElementById('chainAddr').value.trim();
  if (!addr) { toast('Enter an address', 'err'); return; }
  _invSetOut('chainOut', 'chainSummary', 'chainRaw', 'inv-out-empty',
    '<p class="inv-muted">Looking up…</p>', null);
  try {
    const key = localStorage.getItem('diverg_helius_key') || '';
    const net = localStorage.getItem('diverg_helius_network') || 'mainnet';
    const r = await post('/api/investigation/blockchain', { address: addr, network: net, helius_api_key: key });
    _invSetOut('chainOut', 'chainSummary', 'chainRaw', 'inv-out-empty', _invChainSummaryHtml(r), r);
  } catch (e) {
    _invSetOut('chainOut', 'chainSummary', 'chainRaw', 'inv-out-empty',
      `<p class="inv-err">${esc(e.message)}</p>`, { error: e.message });
  }
}

function _invTokenBundleSummaryHtml(d) {
  if (!d.ok) {
    return `<p class="inv-err">${esc(d.error || 'Bundle analysis failed')}</p>`;
  }
  const rs = d.risk_score != null ? d.risk_score : (d.bundle_signals && d.bundle_signals.coordination_score);
  const rv = d.risk_verdict || '—';
  const cp = d.cluster_pct_supply != null ? d.cluster_pct_supply : d.focus_cluster_pct_supply;
  const cw = d.cluster_wallet_count != null ? d.cluster_wallet_count : (d.focus_cluster_wallets || []).length;
  const metrics = `<div class="inv-metric-grid">
    <div class="inv-metric inv-metric--hi"><div class="inv-metric-k">Risk score</div><div class="inv-metric-v">${esc(String(rs != null ? rs : '—'))}/100</div><div class="inv-muted" style="font-size:0.65rem;margin-top:0.25rem">${esc(rv)}</div></div>
    <div class="inv-metric inv-metric--hi"><div class="inv-metric-k">Cluster (same funder)</div><div class="inv-metric-v">${esc(String(cw))} wallets</div><div class="inv-muted" style="font-size:0.65rem;margin-top:0.25rem">${esc(String(cp != null ? cp : '—'))}% of supply</div></div>
    <div class="inv-metric"><div class="inv-metric-k">Cluster balance (tokens)</div><div class="inv-metric-v">${esc(String(d.focus_cluster_supply_ui != null ? d.focus_cluster_supply_ui : '—'))}</div></div>
    <div class="inv-metric"><div class="inv-metric-k">Total supply</div><div class="inv-metric-v">${esc(String(d.token_supply_ui != null ? d.token_supply_ui : '—'))}</div></div>
  </div>`;
  const bs = d.bundle_signals || {};
  let coordLine = '';
  if (bs.coordination_score != null || (bs.coordination_reasons && bs.coordination_reasons.length)) {
    const cr = Array.isArray(bs.coordination_reasons) ? bs.coordination_reasons.join(', ') : '';
    coordLine = `<p class="inv-muted">Coordination signals: <strong>${esc(String(bs.coordination_score != null ? bs.coordination_score : rs))}/100</strong>${cr ? ' · ' + esc(cr) : ''}</p>`;
  }
  if (d.risk_summary) {
    coordLine += `<p class="inv-muted" style="margin-top:0.35rem">${esc(d.risk_summary)}</p>`;
  }
  if (bs.error) {
    coordLine += `<p class="inv-err" style="margin-top:0.35rem">${esc(String(bs.error))}</p>`;
  }
  let seed = '';
  if (d.seed_wallet) {
    seed = `<p class="inv-kv"><span>Focus wallet</span> ${esc(d.seed_wallet)}</p>`;
    if (d.seed_balance_ui != null) seed += `<p class="inv-kv"><span>Balance</span> ${esc(String(d.seed_balance_ui))} tokens (${esc(String(d.seed_pct_supply != null ? d.seed_pct_supply : '—'))}% supply)</p>`;
  }
  let holders = '';
  if (d.top_holders && d.top_holders.length) {
    const rows = d.top_holders.slice(0, 20).map(h => {
      const w = h.wallet || '';
      const short = w.length > 10 ? w.slice(0, 8) + '…' : w;
      const fund = h.funder ? String(h.funder).slice(0, 14) + (String(h.funder).length > 14 ? '…' : '') : '—';
      const cl = h.in_focus_cluster ? '<span class="inv-cluster-dot" title="In cluster">●</span>' : '';
      return `<tr><td class="mono">${esc(short)}</td><td>${esc(String(h.pct_supply != null ? h.pct_supply : '—'))}%</td><td>${cl}</td><td class="mono" style="font-size:0.65rem">${esc(fund)}</td></tr>`;
    }).join('');
    holders = `<div class="inv-holders"><div class="inv-subhead" style="margin-top:0.75rem">Top holders</div><table><thead><tr><th>Wallet</th><th>% supply</th><th>Cluster</th><th>Funder</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }
  const p = d.params || {};
  let scanMeta = '';
  if (p.holder_fetch_source || p.unique_holders_sampled != null) {
    scanMeta = `<p class="inv-muted" style="font-size:0.7rem">Holder data: <strong>${esc(String(p.holder_fetch_source || '—'))}</strong> · ${esc(String(p.unique_holders_sampled ?? '—'))} unique owners in sample · funders fetched for up to ${esc(String(p.max_funded_by_lookups ?? '—'))} wallets</p>`;
  }
  if (d.excluded_liquidity_wallet) {
    const ew = d.excluded_liquidity_wallet;
    const short = ew.length > 14 ? ew.slice(0, 12) + '…' : ew;
    scanMeta += `<p class="inv-muted" style="font-size:0.7rem">Excluded from funder scan (liquidity-sized holder): <span class="mono">${esc(short)}</span></p>`;
  }
  const notes = [d.focus_cluster_note, d.disclaimer, d.pnl_note].filter(Boolean).map(x => `<p class="inv-muted">${esc(x)}</p>`).join('');
  return `<p class="mono" style="font-size:0.75rem;margin-bottom:0.35rem">${esc(d.mint || '')}</p>${scanMeta}${metrics}${coordLine}${seed}${holders}${notes}`;
}

async function runTokenBundle() {
  const mint = document.getElementById('tokenMint').value.trim();
  const wallet = document.getElementById('tokenSeedWallet').value.trim();
  if (!mint) { toast('Enter token mint', 'err'); return; }
  const key = (localStorage.getItem('diverg_helius_key') || '').trim();
  if (!key) { toast('Add Helius API key in Settings', 'err'); return; }
  _invSetOut('tokenBundleOut', 'tokenBundleSummary', 'tokenBundleRaw', 'inv-out-empty',
    '<p class="inv-muted">Analyzing token via Helius (holders, funders, coordination)… Can take up to a minute.</p>', null);
  try {
    const body = { mint, helius_api_key: key };
    if (wallet) body.wallet = wallet;
    const r = await post('/api/investigation/solana-bundle', body);
    const html = _invTokenBundleSummaryHtml(r);
    _invSetOut('tokenBundleOut', 'tokenBundleSummary', 'tokenBundleRaw', 'inv-out-empty', html, r);
    if (r.ok) toast('Token bundle analysis complete', 'ok');
    else toast(r.error || 'Bundle failed', 'err');
  } catch (e) {
    _invSetOut('tokenBundleOut', 'tokenBundleSummary', 'tokenBundleRaw', 'inv-out-empty',
      `<p class="inv-err">${esc(e.message)}</p>`, { error: e.message });
    toast(e.message, 'err');
  }
}

async function runOsint() {
  const d = document.getElementById('osintDomain').value.trim();
  if (!d) { toast('Enter a domain', 'err'); return; }
  _invSetOut('osintOut', 'osintSummary', 'osintRaw', 'inv-out-empty',
    '<p class="inv-muted">Running OSINT, recon, and headers (may take a minute)…</p>', null);
  try {
    const domain = d.replace(/^https?:\/\//, '').split('/')[0];
    const r = await post('/api/investigation/domain', { domain });
    const head = `<p><strong>${esc(r.domain || domain)}</strong> · ${r.findings_count ?? (r.findings || []).length} aggregated findings from headers/recon paths</p>`;
    const html = head + _invFindingsHtml(r.findings);
    _invSetOut('osintOut', 'osintSummary', 'osintRaw', 'inv-out-empty', html, r);
    toast('Domain investigation complete', 'ok');
  } catch (e) {
    _invSetOut('osintOut', 'osintSummary', 'osintRaw', 'inv-out-empty',
      `<p class="inv-err">${esc(e.message)}</p>`, { error: e.message });
    toast(e.message, 'err');
  }
}

async function runPoc() {
  const type = document.getElementById('pocType').value;
  const url = document.getElementById('pocUrl').value.trim();
  if (!url) { toast('Enter a URL', 'err'); return; }
  _invSetOut('pocOut', 'pocSummary', 'pocRaw', 'inv-out-empty', '<p class="inv-muted">Running PoC…</p>', null);
  try {
    const body = { type, url, verbose: true };
    if (type === 'idor') {
      body.param_to_change = document.getElementById('pocParam')?.value.trim() || 'id';
      body.new_value = document.getElementById('pocValue')?.value.trim() || '2';
    }
    const r = await post('/api/poc/simulate', body);
    const prev = r.body_preview ? `<pre class="inv-body-preview">${esc(r.body_preview)}</pre>` : '';
    const err = r.error ? `<p class="inv-err">${esc(r.error)}</p>` : '';
    const sum = `<p><strong>${esc(r.conclusion || '')}</strong></p><p class="inv-muted">HTTP ${esc(String(r.status_code ?? '—'))} · executed: ${r.success ? 'yes' : 'no'} · type: ${esc(r.poc_type || type)}</p>${err}${prev}`;
    _invSetOut('pocOut', 'pocSummary', 'pocRaw', 'inv-out-empty', sum, r);
  } catch (e) {
    _invSetOut('pocOut', 'pocSummary', 'pocRaw', 'inv-out-empty',
      `<p class="inv-err">${esc(e.message)}</p>`, { error: e.message });
  }
}

async function runReputation() {
  const t = document.getElementById('reputationTarget').value.trim();
  if (!t) { toast('Enter a domain', 'err'); return; }
  _invSetOut('reputationOut', 'reputationSummary', 'reputationRaw', 'inv-out-empty',
    '<p class="inv-muted">Running OSINT + entity reputation…</p>', null);
  try {
    const r = await post('/api/investigation/reputation', { target: t });
    const rep = r.entity_reputation || {};
    const hits = rep.findings || [];
    const head = `<p><strong>${esc(r.domain || t)}</strong></p><p class="inv-muted">${esc(rep.summary || '')}</p><p class="inv-muted">Entities searched: ${esc((rep.entities_searched || []).join(', ') || '—')}</p>`;
    const findingsHtml = hits.length
      ? _invFindingsHtml(hits.map(x => ({
          severity: x.severity || 'Medium',
          title: x.title || x.entity || 'Hit',
          evidence: [x.snippet, x.url].filter(Boolean).join(' — ')
        })))
      : '<p class="inv-muted">No reputation hits. Use recommended queries from JSON for manual search.</p>';
    const rec = (rep.recommended_queries || []).length
      ? `<div class="inv-ev" style="margin-top:0.75rem"><strong>Suggested queries</strong><br>${(rep.recommended_queries || []).slice(0, 12).map(q => esc(q)).join('<br>')}</div>`
      : '';
    _invSetOut('reputationOut', 'reputationSummary', 'reputationRaw', 'inv-out-empty',
      head + findingsHtml + rec, r);
    toast('Reputation check complete', 'ok');
  } catch (e) {
    _invSetOut('reputationOut', 'reputationSummary', 'reputationRaw', 'inv-out-empty',
      `<p class="inv-err">${esc(e.message)}</p>`, { error: e.message });
    toast(e.message, 'err');
  }
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
