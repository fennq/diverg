/* Diverg Console */

const CFG = { apiUrl: localStorage.getItem('diverg_api') || window.location.origin };
const api = p => CFG.apiUrl + p;

const State = { scope: 'full', scanId: null, report: null, historyData: [], findings: [], rewardsLbWindow: 'all' };

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
    investigation: 'Investigation', rewards: 'Rewards', settings: 'Settings',
  };
  document.getElementById('pageTitle').textContent = titles[page] || page;

  if (page === 'home') loadHome();
  if (page === 'analytics') loadAnalytics();
  if (page === 'history') loadHistory();
  if (page === 'findings') loadFindings();
  if (page === 'attack-paths') loadAttackPaths();
  if (page === 'rewards') loadRewards();
  if (page === 'settings') loadSettings();
  if (page === 'results') {
    const rep = data || State.report;
    if (rep) showResults(rep);
    else {
      document.getElementById('resultsTarget').textContent = 'Results';
      document.getElementById('resultsBadges').innerHTML = '';
      document.getElementById('resultsFindings').innerHTML = `<div class="empty" style="padding:2rem"><div class="empty-t">No results loaded</div><div class="empty-d">Open a scan from History or run a new scan.</div></div>`;
    }
  }

  window.scrollTo(0, 0);
}

document.querySelectorAll('.nav-item[data-page]').forEach(el =>
  el.addEventListener('click', () => navigate(el.dataset.page)));

// ── Scope handling ─────────────────────────────────────────────────────────
function applyScope(scope) {
  const next = (scope || '').toLowerCase();
  if (!next) return;
  State.scope = next;
  document.querySelectorAll('.scope-opt').forEach(o => {
    o.classList.toggle('active', (o.dataset.scope || '').toLowerCase() === next);
  });
  document.querySelectorAll('.pill[data-scope]').forEach(p => {
    p.classList.toggle('active', (p.dataset.scope || '').toLowerCase() === next);
  });
}

function setQuickScope(el) {
  applyScope(el?.dataset?.scope || '');
}

document.querySelectorAll('.scope-opt').forEach(opt =>
  opt.addEventListener('click', () => applyScope(opt.dataset.scope || '')));

document.querySelectorAll('.pill[data-scope]').forEach(p =>
  p.addEventListener('click', () => applyScope(p.dataset.scope || '')));

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

function copyInvText(text) {
  const t = (text || '').trim();
  if (!t) return;
  navigator.clipboard.writeText(t).then(() => toast('Copied', 'ok')).catch(() => toast('Copy failed', 'err'));
}

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

function fmtTs(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleString(); } catch { return String(iso); }
}

function provChip(meta) {
  const host = shortUrl(meta?.target_url || 'target');
  const when = ago(meta?.scanned_at);
  const sid = String(meta?.scan_id || '').slice(0, 8);
  return `<div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-top:0.35rem">
    <span class="badge unknown" style="font-size:0.65rem">${esc(host)}</span>
    <span class="badge unknown" style="font-size:0.65rem">${esc(when)}</span>
    ${sid ? `<span class="badge unknown" style="font-size:0.65rem" title="${esc(String(meta.scan_id))}">scan ${esc(sid)}</span>` : ''}
  </div>`;
}

function findingMatchesFilter(item) {
  const sevSel = (document.getElementById('findingsSeverityFilter')?.value || '').toLowerCase();
  const q = (document.getElementById('findingsSearchInput')?.value || '').trim().toLowerCase();
  const f = item?.finding || {};
  const sev = sevClass(f.severity).toLowerCase();
  if (sevSel && sev !== sevSel) return false;
  if (!q) return true;
  const blob = [
    f.title,
    f.category,
    f.description,
    f.impact,
    f.remediation,
    f.evidence,
    item?.target_url,
    item?.scan_id,
  ].filter(Boolean).join(' ').toLowerCase();
  return blob.includes(q);
}

function renderFindingsList() {
  const el = document.getElementById('findingsList');
  if (!el) return;
  const rows = (State.findings || []).filter(findingMatchesFilter);
  if (!rows.length) {
    el.innerHTML = `<div class="empty" style="padding:2rem"><div class="empty-t">No matching findings</div><div class="empty-d">Adjust severity or search query.</div></div>`;
    return;
  }
  el.innerHTML = rows.map(x => findingRow(x.finding || {}, x)).join('');
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
    const recent = document.getElementById('recentScans');
    if (recent) recent.innerHTML = `<div class="empty"><div class="empty-t">Loading recent scans…</div></div>`;
    const s = await get('/api/stats');
    document.getElementById('statScans').textContent = s.total_scans ?? '0';
    document.getElementById('statCritical').textContent = s.total_critical ?? '0';
    document.getElementById('statTargets').textContent = s.unique_targets ?? '0';
    document.getElementById('statAvgRisk').textContent = s.avg_risk_score > 0 ? s.avg_risk_score : '—';
    if (!s.recent_scans?.length) {
      recent.innerHTML = `<div class="empty"><div class="empty-t">No scans yet</div><div class="empty-d">Enter a URL above to start</div></div>`;
    } else {
      recent.innerHTML = `<div class="scan-list">${s.recent_scans.map(scanRow).join('')}</div>`;
    }
  } catch (e) {
    document.getElementById('statScans').textContent = '—';
    document.getElementById('recentScans').innerHTML = `<div class="empty"><div class="empty-t">Home stats unavailable</div><div class="empty-d">${esc(e?.message || 'Unknown error')}</div></div>`;
    toast('Failed to load home stats: ' + (e?.message || 'unknown error'), 'err');
  }
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
  let parseWarned = false;

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
          if (e.event === 'error') {
            pText.textContent = 'Scan error: ' + (e.error || 'unknown');
            toast('Scan error: ' + (e.error || 'unknown'), 'err');
          }
        } catch (err) {
          if (!parseWarned) {
            parseWarned = true;
            const msg = 'Malformed stream chunk from scanner';
            pText.textContent = msg;
            toast(msg, 'err');
            console.warn('quickLaunch stream parse error', err, line);
          }
        }
      }
    }

    if (lastReport) {
      State.report = lastReport;
      State.scanId = lastReport.id;
      pText.textContent = 'Complete — ' + (lastReport.findings?.length || 0) + ' findings';
      toast('Scan complete', 'ok');
      const shouldAutoNav = document.getElementById('toggleAutoNav')?.checked;
      setTimeout(() => {
        box.classList.remove('show');
        if (shouldAutoNav) navigate('results', lastReport);
        else loadHome();
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
  const launchBtn = document.querySelector('#page-scanner .btn.btn-primary[onclick="launchScan()"]');
  if (launchBtn) launchBtn.disabled = true;
  box.classList.add('show');

  document.getElementById('skillsList').innerHTML = '';
  document.getElementById('liveFindings').innerHTML = '';
  document.getElementById('progressText').textContent = 'Scanning…';

  const skills = {};
  let parseWarned = false;

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
          if (e.event === 'error') {
            document.getElementById('progressText').textContent = 'Scan error: ' + (e.error || 'unknown');
            toast('Scan error: ' + (e.error || 'unknown'), 'err');
          }
        } catch (err) {
          if (!parseWarned) {
            parseWarned = true;
            const msg = 'Malformed stream chunk from scanner';
            document.getElementById('progressText').textContent = msg;
            toast(msg, 'err');
            console.warn('launchScan stream parse error', err, line);
          }
        }
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
    } else {
      document.getElementById('progressText').textContent = 'Scan finished (no report returned)';
      toast('Scan finished without final report', 'err');
    }
  } catch (e) {
    document.getElementById('progressText').textContent = 'Failed: ' + (e?.message || 'unknown error');
    toast('Scan failed: ' + e.message, 'err');
  } finally {
    if (launchBtn) launchBtn.disabled = false;
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
    const topCats = document.getElementById('topCategories');
    if (topCats) topCats.innerHTML = `<div class="empty" style="padding:2rem"><div class="empty-t">Loading analytics…</div></div>`;
    const summary = await get('/api/analytics/summary?limit=120');
    const sev = summary.severity || {};
    const critical = sev.critical || 0;
    const high = sev.high || 0;
    const medium = sev.medium || 0;
    const low = sev.low || 0;
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
    const avgRisk = summary.avg_risk_score || 0;
    document.getElementById('donutValue').textContent = avgRisk > 0 ? avgRisk : '—';
    const donut = document.getElementById('riskDonut');
    const pct = Math.max(0, Math.min(avgRisk, 100));
    donut.style.background = `conic-gradient(var(--green) 0% ${pct}%, var(--red) ${pct}% 100%)`;

    // Trend chart (last 30 days) from scanned_at-backed API buckets
    const act = Array.isArray(summary.activity_30d) ? summary.activity_30d : [];
    const counts = act.map(x => Number(x.count || 0));
    const labels = act.map(x => {
      try { return new Date(x.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }); }
      catch { return String(x.date || ''); }
    });
    const maxCount = Math.max(...counts, 1);
    document.getElementById('trendBars').innerHTML = counts.map(c =>
      `<div class="trend-bar" style="height:${Math.max(c / maxCount * 100, 4)}%"></div>`
    ).join('');
    document.getElementById('trendLabels').innerHTML = `
      <span>${labels[0]}</span>
      <span>${labels[Math.floor(labels.length / 2)] || ''}</span>
      <span>${labels[labels.length - 1] || ''}</span>
    `;

    const sorted = (summary.top_categories || []).slice(0, 5).map(x => [x.category, x.count]);
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
    toast('Analytics load failed: ' + (e?.message || 'unknown error'), 'err');
    const catsEl = document.getElementById('topCategories');
    if (catsEl) {
      catsEl.innerHTML = `<div class="empty" style="padding:2rem"><div class="empty-t">Analytics unavailable</div><div class="empty-d">${esc(e?.message || 'Unknown error')}</div></div>`;
    }
  }
}

// ── HISTORY ────────────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const el = document.getElementById('historyList');
    if (el) el.innerHTML = `<div class="empty" style="padding:2rem"><div class="empty-t">Loading scans…</div></div>`;
    const data = await get('/api/history?limit=50');
    State.historyData = data.scans || [];
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
  } catch (e) {
    toast('Failed to load history', 'err');
    const el = document.getElementById('historyList');
    if (el) el.innerHTML = `<div class="empty" style="padding:2rem"><div class="empty-t">History unavailable</div><div class="empty-d">${esc(e?.message || 'Unknown error')}</div></div>`;
  }
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
    const el = document.getElementById('findingsList');
    if (el) el.innerHTML = `<div class="empty" style="padding:2rem"><div class="empty-t">Loading findings…</div></div>`;
    const data = await get('/api/findings?scan_limit=120&finding_limit=2000');
    const all = Array.isArray(data.findings) ? data.findings : [];
    State.findings = all;
    if (!all.length) {
      el.innerHTML = `<div class="empty" style="padding:2rem"><div class="empty-t">No findings</div><div class="empty-d">Run a scan to see vulnerability findings</div></div>`;
    } else {
      renderFindingsList();
    }
  } catch (e) {
    toast('Failed to load findings: ' + (e?.message || 'unknown error'), 'err');
    const el = document.getElementById('findingsList');
    if (el) el.innerHTML = `<div class="empty" style="padding:2rem"><div class="empty-t">Findings unavailable</div><div class="empty-d">${esc(e?.message || 'Unknown error')}</div></div>`;
  }
}

function findingRow(f, meta) {
  const s = sevClass(f.severity);
  return `
    <div class="finding">
      <div class="finding-h" onclick="this.parentElement.classList.toggle('open')">
        <span class="sev ${s}">${s}</span>
        <span class="finding-t">${esc(f.title || 'Finding')}</span>
        <span class="finding-cat">${esc(f.category || '')}</span>
      </div>
      ${meta ? `<div style="padding:0 1rem 0.35rem 1rem">${provChip(meta)}</div>` : ''}
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
  const parts = [`<span class="badge ${cls}">${esc(report.risk_verdict || 'Unknown')}${report.risk_score != null ? ' · safety ' + report.risk_score : ''}</span>`];
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
    const el = document.getElementById('attackPathsList');
    if (el) el.innerHTML = `<div class="empty"><div class="empty-t">Loading attack paths…</div></div>`;
    const data = await get('/api/attack-paths?scan_limit=120&path_limit=1200');
    const paths = Array.isArray(data.attack_paths) ? data.attack_paths : [];
    if (!paths.length) {
      el.innerHTML = `<div class="empty"><div class="empty-t">No attack paths discovered</div><div class="empty-d">Run a full scan to find chained vulnerabilities</div></div>`;
    } else {
      el.innerHTML = `<div class="scan-list">${paths.map(p => {
        const ap = p.attack_path || {};
        const steps = Array.isArray(ap.steps) ? ap.steps : (ap.chain || ap.path || []);
        return `<div style="padding:1rem 1.25rem; border-bottom:1px solid var(--border)">
          <div style="font-weight:500; margin-bottom:0.375rem">${esc(ap.title || ap.name || 'Attack Path')}</div>
          <div style="font-size:0.75rem; color:var(--dim); font-family:var(--mono)">${steps.map(s => esc(String(s))).join(' → ')}</div>
          ${ap.impact ? `<div style="font-size:0.75rem; color:var(--muted); margin-top:0.25rem">${esc(ap.impact)}</div>` : ''}
          ${provChip(p)}
        </div>`;
      }).join('')}</div>`;
    }
  } catch (e) {
    toast('Failed to load attack paths: ' + (e?.message || 'unknown error'), 'err');
    const el = document.getElementById('attackPathsList');
    if (el) el.innerHTML = `<div class="empty"><div class="empty-t">Attack paths unavailable</div><div class="empty-d">${esc(e?.message || 'Unknown error')}</div></div>`;
  }
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

function _invTokenBundleLoadingHtml(stepIdx, elapsedSec) {
  const steps = [
    'Loading token metadata and supply',
    'Mapping top holders and liquidity-sized wallets',
    'Tracing first funders and 2-hop roots',
    'Running coordination and split-pattern checks',
    'Merging bridge/mixer/cross-chain signals',
  ];
  const active = Math.max(0, Math.min(stepIdx, steps.length - 1));
  const items = steps.map((s, i) => {
    const cls = i < active ? 'done' : (i === active ? 'active' : '');
    const mark = i < active ? '✓' : (i === active ? '●' : '·');
    return `<li class="inv-scan-step ${cls}"><span class="inv-scan-step-mark">${mark}</span>${esc(s)}</li>`;
  }).join('');
  return `<div class="inv-scan-live">
    <div class="inv-scan-head">
      <span class="inv-scan-dot" aria-hidden="true"></span>
      <span>Bundle scan in progress (${elapsedSec}s)</span>
    </div>
    <div class="inv-scan-bar"><span class="inv-scan-bar-fill" style="width:${Math.min(96, 16 + active * 19)}%"></span></div>
    <ul class="inv-scan-steps">${items}</ul>
    <p class="inv-muted" style="margin-top:0.45rem">Live scan view: this updates while checks run.</p>
  </div>`;
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
    if (s.etherscan_recent_tx_count != null) {
      h += `<div class="inv-kv"><span>Recent txs (Etherscan)</span> ${esc(String(s.etherscan_recent_tx_count))}</div>`;
    }
    const samp = s.etherscan_recent_tx_sample;
    if (Array.isArray(samp) && samp.length) {
      h += '<ul class="inv-bundle-archetype" style="margin-top:0.5rem">';
      samp.slice(0, 6).forEach((t) => {
        const hash = t && t.hash;
        const link = hash ? `https://etherscan.io/tx/${encodeURIComponent(hash)}` : '';
        const row = [t.from, t.to, t.timeStamp].filter(Boolean).join(' · ');
        h += `<li class="inv-muted">${link ? `<a href="${esc(link)}" target="_blank" rel="noopener noreferrer" class="mono">${esc(String(hash).slice(0, 14))}…</a>` : ''} ${esc(row.slice(0, 120))}</li>`;
      });
      h += '</ul>';
    }
  }
  h += '<p class="inv-muted" style="margin-top:0.75rem">Expand <strong>Full JSON</strong> for complete RPC responses (signatures, account data, token accounts).</p>';
  return h;
}

function _flowGraphToMermaid(fg) {
  if (!fg || !Array.isArray(fg.edges) || !fg.edges.length) return '';
  const lines = ['flowchart LR'];
  const seen = new Map();
  let n = 0;
  function nodeId(addr) {
    const k = String(addr || '');
    if (!seen.has(k)) {
      seen.set(k, `n${n++}`);
    }
    return seen.get(k);
  }
  fg.edges.slice(0, 35).forEach((e) => {
    const a = nodeId(e.from);
    const b = nodeId(e.to);
    const al = String(e.from || '?').replace(/"/g, "'").slice(0, 16);
    const bl = String(e.to || '?').replace(/"/g, "'").slice(0, 16);
    lines.push(`  ${a}["${al}"] --> ${b}["${bl}"]`);
  });
  return lines.join('\n');
}

function _invChainFullSummaryHtml(data) {
  if (data.error && !data.crime_report && !(Array.isArray(data.findings) && data.findings.length)) {
    return `<p class="inv-err">${esc(data.error)}</p>`;
  }
  const cr = data.crime_report || {};
  let h = '';
  const ds = cr.data_sources;
  if (ds && typeof ds === 'object') {
    const ocr = ds.on_chain_reason != null ? String(ds.on_chain_reason) : '';
    if (ocr) {
      h += `<p class="inv-muted" style="margin-bottom:0.65rem"><strong>On-chain data:</strong> ${esc(ocr)}</p>`;
    }
  }
  if (data._truncated_findings != null) {
    h += `<p class="inv-muted">Response truncated (${esc(String(data._truncated_findings))} findings omitted). See <strong>Full JSON</strong>.</p>`;
  }
  const fgTrunc = data.flow_graph && data.flow_graph._truncated_edges;
  if (fgTrunc != null) {
    h += `<p class="inv-muted">${esc(String(fgTrunc))} flow edges omitted.</p>`;
  }
  if (cr.verdict) {
    h += `<div class="inv-metric inv-metric--hi" style="margin-bottom:0.55rem"><div class="inv-metric-k">Verdict</div><div class="inv-metric-v" style="font-size:0.9rem;line-height:1.35">${esc(String(cr.verdict))}</div></div>`;
  }
  if (cr.summary) {
    h += `<p class="inv-muted" style="margin-bottom:0.65rem">${esc(String(cr.summary))}</p>`;
  }
  if (cr.risk_score != null) {
    h += `<div class="inv-kv"><span>Risk score</span> ${esc(String(cr.risk_score))}/100</div>`;
  }
  const narr = cr.chronological_narrative;
  if (Array.isArray(narr) && narr.length) {
    h += '<div class="inv-subhead" style="margin-top:0.75rem">Chronology (sample)</div><ul class="inv-bundle-archetype">';
    narr.slice(0, 14).forEach((line) => { h += `<li class="inv-muted">${esc(String(line))}</li>`; });
    h += '</ul>';
  }
  const fh = cr.flow_highlights;
  if (Array.isArray(fh) && fh.length) {
    h += '<div class="inv-subhead" style="margin-top:0.75rem">Flow highlights</div><ul class="inv-bundle-archetype">';
    fh.slice(0, 12).forEach((line) => { h += `<li class="inv-muted">${esc(String(line))}</li>`; });
    h += '</ul>';
  }
  const rf = cr.red_flags;
  if (Array.isArray(rf) && rf.length) {
    h += '<div class="inv-subhead" style="margin-top:0.75rem">Red flags (signals)</div><ul class="inv-bundle-archetype">';
    rf.slice(0, 14).forEach((x) => { h += `<li class="inv-muted">${esc(String(x))}</li>`; });
    h += '</ul>';
  }
  const ex = cr.explorer_links;
  if (Array.isArray(ex) && ex.length) {
    h += '<div class="inv-subhead" style="margin-top:0.75rem">Explorer links</div><div style="display:flex;flex-wrap:wrap;gap:0.35rem">';
    ex.slice(0, 24).forEach((l) => {
      const url = l && l.url;
      const lab = (l && (l.label || l.address)) || 'open';
      if (url) {
        h += `<a class="btn btn-secondary" style="font-size:0.68rem;padding:0.28rem 0.55rem" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(String(lab).slice(0, 28))}</a>`;
      }
    });
    h += '</div>';
  }
  const fg = data.flow_graph;
  if (fg && Array.isArray(fg.edges) && fg.edges.length) {
    h += '<div class="inv-subhead" style="margin-top:0.75rem">Flow edges (sample)</div><ul class="inv-bundle-archetype">';
    fg.edges.slice(0, 18).forEach((e) => {
      const bits = [e.date_str, e.from, e.to, e.amount, e.unit].filter(Boolean).join(' · ');
      h += `<li class="inv-muted"><span class="mono">${esc(String(bits).slice(0, 220))}</span></li>`;
    });
    h += '</ul>';
    const mer = _flowGraphToMermaid(fg);
    if (mer) {
      window._divergLastFlowMermaid = mer;
      h += '<button type="button" class="btn btn-secondary" style="margin-top:0.45rem" onclick="copyInvText(window._divergLastFlowMermaid || \'\')">Copy flow as Mermaid</button>';
    }
  }
  h += '<div class="inv-subhead" style="margin-top:0.85rem">Findings</div>';
  h += _invFindingsHtml(data.findings);
  h += '<p class="inv-muted" style="margin-top:0.65rem">Heuristic / intelligence signals for <strong>authorized</strong> investigation — not proof of crime.</p>';
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

async function runFullChainInvestigation() {
  const addr = document.getElementById('chainAddr').value.trim();
  const tokensExtra = (document.getElementById('chainFullTokens') && document.getElementById('chainFullTokens').value.trim()) || '';
  if (!addr && !tokensExtra) {
    toast('Enter a wallet/contract in the field above, or add token addresses below', 'err');
    return;
  }
  const chain = (document.getElementById('chainFullChain') && document.getElementById('chainFullChain').value) || 'solana';
  const flowDepth = (document.getElementById('chainFullDepth') && document.getElementById('chainFullDepth').value) || 'full';
  const targetUrl = (document.getElementById('chainFullTargetUrl') && document.getElementById('chainFullTargetUrl').value.trim()) || '';
  let token_addresses = null;
  if (tokensExtra) {
    token_addresses = tokensExtra.split(',').map((s) => s.trim()).filter(Boolean);
  }
  _invSetOut('chainFullOut', 'chainFullSummary', 'chainFullRaw', 'inv-out-empty',
    '<p class="inv-muted">Full investigation running (may take up to ~2 minutes)…</p>', null);
  try {
    const body = {
      chain,
      flow_depth: flowDepth,
      deployer_address: addr || undefined,
      address: addr || undefined,
      token_addresses: token_addresses && token_addresses.length ? token_addresses : undefined,
      target_url: targetUrl || undefined,
    };
    const r = await post('/api/investigation/blockchain-full', body);
    _invSetOut('chainFullOut', 'chainFullSummary', 'chainFullRaw', 'inv-out-empty', _invChainFullSummaryHtml(r), r);
    toast('Full investigation complete', 'ok');
  } catch (e) {
    _invSetOut('chainFullOut', 'chainFullSummary', 'chainFullRaw', 'inv-out-empty',
      `<p class="inv-err">${esc(e.message)}</p>`, { error: e.message });
    toast(e.message || 'Investigation failed', 'err');
  }
}

/** Apply ?page=investigation&inv_address=…&inv_chain=… from extension or bookmark. */
function applyInvestigationDeepLink(params) {
  const invAddr = params.get('inv_address') || params.get('address');
  if (!invAddr) return false;
  const chainSel = document.getElementById('chainFullChain');
  const invChain = (params.get('inv_chain') || params.get('chain') || '').toLowerCase();
  if (chainSel && invChain) {
    const opt = Array.from(chainSel.options).find((o) => o.value === invChain);
    if (opt) chainSel.value = invChain;
  }
  const ca = document.getElementById('chainAddr');
  if (ca) ca.value = invAddr;
  const tu = document.getElementById('chainFullTargetUrl');
  const invUrl = params.get('inv_target_url');
  if (tu && invUrl) tu.value = invUrl;
  const depth = params.get('inv_flow_depth');
  const dEl = document.getElementById('chainFullDepth');
  if (dEl && (depth === 'deep' || depth === 'full')) dEl.value = depth;
  if (params.get('inv_full') === '1') {
    setTimeout(() => runFullChainInvestigation(), 400);
  }
  return true;
}

function _invTokenBundleSummaryHtml(d) {
  if (!d.ok) {
    return `<p class="inv-err">${esc(d.error || 'Bundle analysis failed')}</p>`;
  }
  const mintFull = d.mint || '';
  const meta = d.token_metadata || {};
  const metaLine = [meta.symbol, meta.name].filter(Boolean).join(' · ');
  let titleBlock = '';
  if (metaLine || meta.image) {
    titleBlock += '<div class="inv-bundle-title">';
    if (meta.image) {
      titleBlock += `<img class="inv-bundle-token-img" src="${esc(meta.image)}" alt="" width="36" height="36" loading="lazy" referrerpolicy="no-referrer" />`;
    }
    if (metaLine) {
      titleBlock += `<span class="inv-bundle-token-name">${esc(metaLine)}</span>`;
    }
    titleBlock += '</div>';
  }
  titleBlock += `<div class="inv-bundle-mint-row"><span class="mono inv-bundle-mint-full">${esc(mintFull)}</span>`;
  titleBlock += `<button type="button" class="btn btn-secondary inv-bundle-copy" onclick="copyInvText(this.getAttribute('data-mint'))" data-mint="${esc(mintFull)}">Copy mint</button>`;
  if (mintFull) {
    titleBlock += `<a class="inv-bundle-ext" href="https://solscan.io/token/${encodeURIComponent(mintFull)}" target="_blank" rel="noopener noreferrer">Solscan</a>`;
  }
  titleBlock += '</div>';

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
  coordLine += '<p class="inv-muted" style="margin-top:0.35rem"><strong>Heuristic signal</strong>: sampled-holder intelligence only; use as triage context, not standalone proof.</p>';
  const arch = Array.isArray(bs.bundle_archetype_hints) ? bs.bundle_archetype_hints : [];
  if (arch.length) {
    coordLine += `<ul class="inv-bundle-archetype">${arch.map((t) => `<li class="inv-muted">${esc(t)}</li>`).join('')}</ul>`;
  }
  const cm = bs.confidence_model || {};
  const cmTier = String(cm.tier || 'low');
  const observed = Array.isArray(cm.observed_signals) ? cm.observed_signals : [];
  const corroborated = Array.isArray(cm.corroborated_signals) ? cm.corroborated_signals : [];
  const hiConf = Array.isArray(cm.high_confidence_signals) ? cm.high_confidence_signals : [];
  const cand = Array.isArray(bs.candidate_evidence) ? bs.candidate_evidence : [];
  const candCount = cand.length;
  const candMixer = cand.filter((c) => c && (c.mixer_path_tier === 'weak' || c.mixer_path_tier === 'strong' || c.mixer_program_touch)).length;
  const candBridge = cand.filter((c) => c && c.bridge_program_touch).length;
  const candDeep = cand.filter((c) => c && Array.isArray(c.funder_chain) && c.funder_chain.length >= 3).length;
  const plainExplain = `<div class="inv-explain-grid" style="margin-top:0.6rem">
    <div class="inv-cc-stat"><div class="inv-cc-stat-k">What we saw</div><div class="inv-cc-stat-v">${esc(String(candCount))} wallet candidates</div><div class="inv-muted" style="font-size:0.67rem">${esc(String(candMixer))} mixer-linked · ${esc(String(candBridge))} bridge-touched · ${esc(String(candDeep))} deep-chain</div></div>
    <div class="inv-cc-stat"><div class="inv-cc-stat-k">Why it matters</div><div class="inv-cc-stat-v">${esc(String(observed.length))} observed signals</div><div class="inv-muted" style="font-size:0.67rem">${esc(String(corroborated.length))} corroborated</div></div>
    <div class="inv-cc-stat"><div class="inv-cc-stat-k">Confidence</div><div class="inv-cc-stat-v">${esc(cmTier)}</div><div class="inv-muted" style="font-size:0.67rem">${esc(String(hiConf.length))} high-confidence pattern(s)</div></div>
    <div class="inv-cc-stat"><div class="inv-cc-stat-k">What to verify next</div><div class="inv-cc-stat-v">Trace top 3 chains</div><div class="inv-muted" style="font-size:0.67rem">Check explorer hops + bridge endpoints + funding timing</div></div>
  </div>`;
  coordLine += plainExplain;

  const ccb = d.cross_chain_bundle;
  if (ccb && typeof ccb === 'object') {
    const notes = Array.isArray(ccb.investigator_notes) ? ccb.investigator_notes : [];
    const links = Array.isArray(ccb.foreign_explorer_links) ? ccb.foreign_explorer_links : [];
    const funderHits = Array.isArray(ccb.funder_bridge_hits) ? ccb.funder_bridge_hits : [];
    const mixerPathHits = Array.isArray(ccb.mixer_path_hits) ? ccb.mixer_path_hits : [];
    const sharedGroups = Array.isArray(ccb.shared_bridge_program_groups) ? ccb.shared_bridge_program_groups : [];
    const evmCounterparties = Array.isArray(ccb.counterparty_evm_addresses) ? ccb.counterparty_evm_addresses : [];

    // Divider to visually separate from bundle-signals block above
    const divider = '<hr class="inv-divider">';

    // Escalation banner — condensed
    let escalationBanner = '';
    if (ccb.combined_escalation) {
      escalationBanner = `<div class="inv-escalation-alert"><strong>Stacked signals:</strong> cross-chain token hints + bridge-adjacent wallets + mixer-tagged funders — manual correlation recommended.</div>`;
    }

    // Stat mini-grid — plain-English labels, matches risk-score grid style
    const tierVal = ccb.bridge_mixer_tier ? String(ccb.bridge_mixer_tier).charAt(0).toUpperCase() + String(ccb.bridge_mixer_tier).slice(1) : '—';
    const bridgeN = ccb.bridge_adjacent_holder_wallet_count != null ? ccb.bridge_adjacent_holder_wallet_count : '—';
    const funderBridgeN = ccb.wallets_with_bridge_touching_funder != null ? ccb.wallets_with_bridge_touching_funder : '—';
    const funderMixerN = ccb.wallets_with_mixer_touching_funder != null ? ccb.wallets_with_mixer_touching_funder : '—';
    const cexSplitTier = ccb.cex_split_pattern_confidence ? String(ccb.cex_split_pattern_confidence) : 'none';
    const cexSplitN = ccb.cex_split_wallet_count != null ? ccb.cex_split_wallet_count : '—';
    let statGrid = `<div class="inv-cc-stat-grid">
      <div class="inv-cc-stat"><div class="inv-cc-stat-k">Bridge activity</div><div class="inv-cc-stat-v">${esc(tierVal)}</div></div>
      <div class="inv-cc-stat"><div class="inv-cc-stat-k">Wallets with bridge contacts</div><div class="inv-cc-stat-v">${esc(String(bridgeN))}</div></div>
      <div class="inv-cc-stat"><div class="inv-cc-stat-k">Funded via bridge path</div><div class="inv-cc-stat-v">${esc(String(funderBridgeN))}</div></div>
      <div class="inv-cc-stat"><div class="inv-cc-stat-k">Funded via mixer path</div><div class="inv-cc-stat-v">${esc(String(funderMixerN))}</div></div>`;
    if (cexSplitTier !== 'none') {
      statGrid += `<div class="inv-cc-stat"><div class="inv-cc-stat-k">CEX split pattern</div><div class="inv-cc-stat-v">${esc(cexSplitTier)} (${esc(String(cexSplitN))})</div></div>`;
    }
    if (ccb.foreign_candidate_count) {
      statGrid += `<div class="inv-cc-stat"><div class="inv-cc-stat-k">Cross-chain token hints</div><div class="inv-cc-stat-v">${esc(String(ccb.foreign_candidate_count))}</div></div>`;
    }
    statGrid += '</div>';

    // Explorer links for other-chain token candidates
    let linksHtml = '';
    if (links.length) {
      linksHtml = `<p class="inv-muted" style="margin-top:0.35rem">Token found on other chains — verify on official bridge explorers:</p>
        <ul class="inv-cc-links">${links.slice(0, 10).map((l) => {
          const u = l && l.url;
          const ch = (l && l.chain) || 'link';
          return u ? `<li><a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(String(ch))}</a> <span class="inv-muted">(${esc(String(l.tier || 'tier ?'))})</span></li>` : '';
        }).filter(Boolean).join('')}</ul>`;
    }

    // Funder bridge hits — collapsible
    let funderHitsHtml = '';
    if (funderHits.length) {
      const funderItems = funderHits.slice(0, 8).map((h) => {
        const addr = String(h.funder_address || h.address || '');
        const progs = Array.isArray(h.programs) ? h.programs.join(', ') : String(h.program || h.programs || '');
        return `<li class="inv-muted"><code>${esc(addr.slice(0, 14))}…</code> → <span>${esc(progs)}</span></li>`;
      }).join('');
      funderHitsHtml = `<details class="inv-details-block" style="margin-top:0.5rem">
        <summary style="cursor:pointer">Funders with bridge-program activity (${funderHits.length})</summary>
        <ul style="margin:0.4rem 0 0 1rem;padding:0">${funderItems}</ul>
      </details>`;
    }

    // Funder mixer/privacy path hits — collapsible
    let mixerPathHitsHtml = '';
    if (mixerPathHits.length) {
      const mixerItems = mixerPathHits.slice(0, 10).map((h) => {
        const wallet = String(h.wallet || '');
        const addr = String(h.funder_address || '');
        const via = String(h.via || 'funder');
        const tier = String(h.tier || '');
        return `<li class="inv-muted"><code>${esc(wallet.slice(0, 12))}…</code> via ${esc(via)} → <code>${esc(addr.slice(0, 14))}…</code> <span class="inv-muted">(${esc(tier)})</span></li>`;
      }).join('');
      mixerPathHitsHtml = `<details class="inv-details-block" style="margin-top:0.5rem">
        <summary style="cursor:pointer">Funders with mixer/privacy path signals (${mixerPathHits.length})</summary>
        <ul style="margin:0.4rem 0 0 1rem;padding:0">${mixerItems}</ul>
      </details>`;
    }

    // Shared bridge program groups — collapsible when > 1
    let sharedGroupsHtml = '';
    if (sharedGroups.length) {
      const groupItems = sharedGroups.slice(0, 6).map((g) => {
        const prog = esc(String(g.program_label || g.program_id || g.program || ''));
        const cnt = esc(String(g.wallet_count || g.count || '?'));
        const sample = Array.isArray(g.sample_wallets) ? g.sample_wallets.slice(0, 2).map((w) => `<code>${esc(String(w).slice(0, 12))}…</code>`).join(', ') : '';
        return `<li class="inv-muted"><strong>${cnt}</strong> wallets share <em>${prog}</em>${sample ? ` — ${sample}` : ''}</li>`;
      }).join('');
      sharedGroupsHtml = `<details class="inv-details-block" style="margin-top:0.5rem">
        <summary style="cursor:pointer">Shared bridge programs (${sharedGroups.length})</summary>
        <ul style="margin:0.4rem 0 0 1rem;padding:0">${groupItems}</ul>
      </details>`;
    }

    // EVM counterparty addresses — collapsible
    let evmCounterpartiesHtml = '';
    if (evmCounterparties.length) {
      const evmItems = evmCounterparties.slice(0, 10).map((addr) => {
        const addrStr = String(addr);
        const ethUrl = `https://etherscan.io/address/${addrStr}`;
        return `<li class="inv-muted"><a href="${esc(ethUrl)}" target="_blank" rel="noopener noreferrer"><code>${esc(addrStr.slice(0, 14))}…</code></a></li>`;
      }).join('');
      evmCounterpartiesHtml = `<details class="inv-details-block" style="margin-top:0.5rem">
        <summary style="cursor:pointer">EVM bridge destinations — Wormhole history (${evmCounterparties.length})</summary>
        <ul style="margin:0.4rem 0 0 1rem;padding:0">${evmItems}</ul>
      </details>`;
    }

    // Investigator notes — first shown inline, rest collapsed
    let notesHtml = '';
    if (notes.length) {
      notesHtml += `<p class="inv-note-lead">${esc(notes[0])}</p>`;
      if (notes.length > 1) {
        const remaining = notes.slice(1).map((t) => `<li class="inv-muted">${esc(t)}</li>`).join('');
        notesHtml += `<details class="inv-details-block" style="margin-top:0.25rem">
          <summary style="cursor:pointer">More context (${notes.length - 1})</summary>
          <ul style="margin:0.4rem 0 0 1rem;padding:0">${remaining}</ul>
        </details>`;
      }
    }

    const disc = ccb.disclaimer ? `<p class="inv-muted" style="font-size:0.65rem;margin-top:0.5rem">${esc(ccb.disclaimer)}</p>` : '';

    // Mixer program on-chain hits (wallet + funder level)
    const fcbm = (bs.funding_cluster_bridge_mixer) || {};
    const mixerProgWalletHits = Array.isArray(fcbm.mixer_program_wallet_hits) ? fcbm.mixer_program_wallet_hits : [];
    const mixerProgFunderHits = Array.isArray(fcbm.funder_mixer_program_hits) ? fcbm.funder_mixer_program_hits : [];
    let mixerProgHtml = '';
    if (mixerProgWalletHits.length || mixerProgFunderHits.length) {
      let mpItems = '';
      mixerProgWalletHits.slice(0, 8).forEach((h) => {
        const w = String(h.wallet || '').slice(0, 12) + '…';
        const progs = Array.isArray(h.mixer_program_hits) ? h.mixer_program_hits.map((p) => esc(String(p.label || p.program_id || ''))).join(', ') : '';
        mpItems += `<li class="inv-muted">Wallet <code>${esc(w)}</code> → ${progs}</li>`;
      });
      mixerProgFunderHits.slice(0, 8).forEach((h) => {
        const f = String(h.funder || '').slice(0, 12) + '…';
        const progs = Array.isArray(h.mixer_program_hits) ? h.mixer_program_hits.map((p) => esc(String(p.label || p.program_id || ''))).join(', ') : '';
        mpItems += `<li class="inv-muted">Funder <code>${esc(f)}</code> → ${progs}</li>`;
      });
      mixerProgHtml = `<details class="inv-details-block" style="margin-top:0.5rem">
        <summary style="cursor:pointer">On-chain mixer program interactions (${mixerProgWalletHits.length + mixerProgFunderHits.length})</summary>
        <ul style="margin:0.4rem 0 0 1rem;padding:0">${mpItems}</ul>
      </details>`;
    }

    // Wash flow pattern alerts
    const washFlow = bs.wash_flow_patterns || {};
    let washHtml = '';
    const washConf = String(washFlow.confidence || 'none');
    if (washConf !== 'none' && washFlow.pattern_count > 0) {
      const washRisk = Array.isArray(washFlow.risk_lines) ? washFlow.risk_lines : [];
      let washItems = '';
      (washFlow.circular_flows || []).slice(0, 3).forEach((c) => {
        washItems += `<li class="inv-muted">Circular: ${(c.cycle || []).map((a) => esc(String(a).slice(0, 8))).join(' → ')}</li>`;
      });
      (washFlow.split_merge_flows || []).slice(0, 3).forEach((s) => {
        washItems += `<li class="inv-muted">Split-merge: ${esc(String(s.source || '').slice(0, 10))} → ${s.converge_count || '?'} intermediaries → ${esc(String(s.destination || '').slice(0, 10))}</li>`;
      });
      (washFlow.relay_flows || []).slice(0, 3).forEach((r) => {
        washItems += `<li class="inv-muted">Relay: ${esc(String(r.program_source || ''))} → <code>${esc(String(r.relay_address || '').slice(0, 12))}…</code> → ${(r.forwarded_to || []).length} chain addr(s)</li>`;
      });
      const washBanner = `<div class="inv-wash-alert" style="margin-top:0.5rem;padding:0.5rem 0.75rem;border-left:3px solid var(--err);background:rgba(255,60,60,0.06);border-radius:0.35rem"><strong>Wash flow patterns (${esc(washConf)})</strong>: ${washRisk.map((l) => esc(l)).join(' ')}</div>`;
      washHtml = washBanner + (washItems ? `<details class="inv-details-block" style="margin-top:0.35rem"><summary style="cursor:pointer">Pattern details (${washFlow.pattern_count})</summary><ul style="margin:0.4rem 0 0 1rem;padding:0">${washItems}</ul></details>` : '');
    }

    // Scan depth indicator
    const maxDepth = d.funder_chain_max_depth;
    let depthHtml = '';
    if (maxDepth != null && maxDepth > 0) {
      depthHtml = `<p class="inv-muted" style="font-size:0.7rem;margin-top:0.35rem">Funder chain depth: up to <strong>${esc(String(maxDepth))}</strong> hops traced${p.funder_max_hops ? ` (max ${esc(String(p.funder_max_hops))})` : ''}</p>`;
    }

    coordLine += `<div class="inv-cross-chain-bundle">${divider}<div class="inv-subhead">Cross-chain &amp; bridge signals</div>${escalationBanner}${statGrid}${depthHtml}${linksHtml}${funderHitsHtml}${mixerPathHitsHtml}${mixerProgHtml}${sharedGroupsHtml}${evmCounterpartiesHtml}${washHtml}${notesHtml}${disc}</div>`;
  }

  const topH = (d.top_holders || [])[0];
  let ownershipStrip = '';
  if (topH) {
    const id = topH.identity || {};
    let idPart = id.label
      ? `<span class="inv-id-chip" title="Helius wallet identity">${esc(id.label)}</span>`
      : '<span class="inv-muted">no Helius label</span>';
    const ifl = id.intel_flags || {};
    if (ifl.cex_tagged || ifl.privacy_mixer_tagged) {
      const bits = [];
      if (ifl.cex_tagged) bits.push('CEX-tagged');
      if (ifl.privacy_mixer_tagged) bits.push('privacy/mixer-tagged');
      idPart += ` <span class="inv-id-chip inv-id-chip--sub" title="Helius-derived flags">${esc(bits.join(' · '))}</span>`;
    }
    const clPart = topH.in_focus_cluster
      ? '<span class="inv-muted">Same-funder cluster: yes</span>'
      : '<span class="inv-muted">Same-funder cluster: no</span>';
    ownershipStrip = `<div class="inv-bundle-ownership"><div class="inv-bundle-ownership-h">Who holds the most (in this sample)</div><p class="inv-bundle-ownership-p">Top wallet ~<strong>${esc(String(topH.pct_supply != null ? topH.pct_supply : '—'))}%</strong> of supply · ${idPart} · ${clPart}</p></div>`;
  }
  const fk = d.focus_cluster_key || '';
  if (fk.indexOf('funder:') === 0) {
    const root = fk.slice('funder:'.length);
    const rootDisp = root.length > 12 ? root.slice(0, 10) + '…' : root;
    ownershipStrip += `<div class="inv-bundle-ownership inv-bundle-ownership--sub"><span class="inv-muted">Cluster aligns on shared ultimate funder</span> <span class="mono" title="${esc(root)}">${esc(rootDisp)}</span> · ${esc(String(cw))} wallets · ~${esc(String(cp != null ? cp : '—'))}% of sampled supply.</div>`;
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
      const id = h.identity || {};
      const iflags = id.intel_flags || {};
      let lab = id.label ? `<span class="inv-id-chip">${esc(id.label)}</span>` : '';
      if (iflags.cex_tagged || iflags.privacy_mixer_tagged) {
        const bits = [];
        if (iflags.cex_tagged) bits.push('CEX');
        if (iflags.privacy_mixer_tagged) bits.push('privacy/mixer');
        lab += (lab ? ' ' : '') + `<span class="inv-id-chip inv-id-chip--sub">${esc(bits.join(' · '))}</span>`;
      }
      if (!lab) lab = '—';
      const cat = id.category
        ? esc(id.category)
        : (id.type ? esc(id.type) : '—');
      let fund = '—';
      const fchain = Array.isArray(h.funder_chain) ? h.funder_chain : [];
      if (fchain.length >= 2) {
        fund = fchain.map((a, i) => {
          const s = String(a).slice(0, 10) + (String(a).length > 10 ? '…' : '');
          return i < fchain.length - 1 ? s + ' → ' : s;
        }).join('');
      } else if (h.funder) {
        const f1 = String(h.funder).slice(0, 12) + (String(h.funder).length > 12 ? '…' : '');
        fund = f1;
        if (h.funder_root) {
          const f2 = String(h.funder_root).slice(0, 10) + (String(h.funder_root).length > 10 ? '…' : '');
          fund = `${f1} → ${f2}`;
        }
      }
      const depthBadge = h.funder_chain_depth > 2 ? ` <span class="inv-depth-badge" title="${h.funder_chain_depth}-hop trace">${h.funder_chain_depth}h</span>` : '';
      const cl = h.in_focus_cluster ? '<span class="inv-cluster-dot" title="In same-funder cluster">●</span>' : '';
      const xi = h.x_intel;
      let xcell = '—';
      if (xi && xi.tweet_count) {
        const authors = Array.isArray(xi.posting_authors) ? xi.posting_authors.slice(0, 2) : [];
        const au = authors.map((a) => '@' + esc(String(a))).join(', ');
        const firstUrl = (xi.tweets && xi.tweets[0] && xi.tweets[0].url) ? xi.tweets[0].url : '';
        const inner = firstUrl
          ? `<a href="${esc(firstUrl)}" target="_blank" rel="noopener noreferrer">${esc(String(xi.tweet_count))} posts</a>`
          : esc(String(xi.tweet_count)) + ' posts';
        xcell = au ? `${au} · ${inner}` : inner;
      }
      return `<tr><td class="mono"><span title="${esc(w)}">${esc(short)}</span></td><td>${esc(String(h.pct_supply != null ? h.pct_supply : '—'))}%</td><td>${lab}</td><td>${cat}</td><td>${cl}</td><td class="mono inv-funder-cell" title="Funder chain (N-hop trace)">${esc(fund)}${depthBadge}</td><td class="inv-x-cell" title="X search: only shown when posts mention this address">${xcell}</td></tr>`;
    }).join('');
    holders = `<div class="inv-holders"><div class="inv-subhead" style="margin-top:0.75rem">Top holders</div><table class="inv-holders-table"><thead><tr><th>Wallet</th><th>%</th><th>Label</th><th>Category</th><th title="Same-funder cluster">Cl.</th><th>Funder / root</th><th>X (if mentioned)</th></tr></thead><tbody>${rows}</tbody></table><p class="inv-muted" style="font-size:0.65rem;margin-top:0.35rem">Hover wallet for full address. Helius labels; X column only when server search finds posts mentioning the address (set X_API_BEARER_TOKEN or NITTER_BASE_URL).</p></div>`;
  }
  const p = d.params || {};
  let scanMeta = '';
  if (p.holder_fetch_source || p.unique_holders_sampled != null) {
    scanMeta = `<p class="inv-muted" style="font-size:0.7rem">Holder data: <strong>${esc(String(p.holder_fetch_source || '—'))}</strong> · ${esc(String(p.unique_holders_sampled ?? '—'))} unique owners in sample · funders fetched for up to ${esc(String(p.max_funded_by_lookups ?? '—'))} wallets</p>`;
    if (p.holders_scanned_for_funders != null || p.holders_eligible_after_exclusions != null) {
      scanMeta += `<p class="inv-muted" style="font-size:0.7rem">Coverage: scanned ${esc(String(p.holders_scanned_for_funders ?? '—'))} / ${esc(String(p.holders_eligible_after_exclusions ?? '—'))} eligible holder wallets (${esc(String(p.holders_scan_coverage_pct ?? '—'))}%)${p.scan_all_holders ? ' · full-holder mode' : ''}</p>`;
    }
  }
  if (d.excluded_liquidity_wallet) {
    const ew = d.excluded_liquidity_wallet;
    const short = ew.length > 14 ? ew.slice(0, 12) + '…' : ew;
    scanMeta += `<p class="inv-muted" style="font-size:0.7rem">Excluded from funder scan (liquidity-sized holder): <span class="mono">${esc(short)}</span></p>`;
  }
  const notes = [d.focus_cluster_note, d.disclaimer, d.pnl_note].filter(Boolean).map(x => `<p class="inv-muted">${esc(x)}</p>`).join('');
  return `${titleBlock}${ownershipStrip}${scanMeta}${metrics}${coordLine}${seed}${holders}${notes}`;
}

async function runTokenBundle() {
  const mint = document.getElementById('tokenMint').value.trim();
  const wallet = document.getElementById('tokenSeedWallet').value.trim();
  if (!mint) { toast('Enter token mint', 'err'); return; }
  const key = (localStorage.getItem('diverg_helius_key') || '').trim();
  if (!key) { toast('Add Helius API key in Settings', 'err'); return; }
  const t0 = Date.now();
  let step = 0;
  _invSetOut(
    'tokenBundleOut',
    'tokenBundleSummary',
    'tokenBundleRaw',
    'inv-out-empty',
    _invTokenBundleLoadingHtml(step, 0),
    null
  );
  const ticker = setInterval(() => {
    step = (step + 1) % 5;
    const elapsed = Math.max(1, Math.floor((Date.now() - t0) / 1000));
    const sum = document.getElementById('tokenBundleSummary');
    if (sum) sum.innerHTML = _invTokenBundleLoadingHtml(step, elapsed);
  }, 1400);
  try {
    const body = { mint, helius_api_key: key };
    if (wallet) body.wallet = wallet;
    const skipX = document.getElementById('tokenBundleSkipX');
    if (skipX && skipX.checked) body.include_x_intel = false;
    const allHolders = document.getElementById('tokenBundleAllHolders');
    body.scan_all_holders = !!(allHolders && allHolders.checked);

    const r = await post('/api/investigation/solana-bundle', body);
    const html = _invTokenBundleSummaryHtml(r);
    _invSetOut('tokenBundleOut', 'tokenBundleSummary', 'tokenBundleRaw', 'inv-out-empty', html, r);
    if (r.ok) toast('Token bundle analysis complete', 'ok');
    else toast(r.error || 'Bundle failed', 'err');
  } catch (e) {
    _invSetOut('tokenBundleOut', 'tokenBundleSummary', 'tokenBundleRaw', 'inv-out-empty',
      `<p class="inv-err">${esc(e.message)}</p>`, { error: e.message });
    toast(e.message, 'err');
  } finally {
    clearInterval(ticker);
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

// ── REWARDS ────────────────────────────────────────────────────────────────
function setRewardsLeaderboardWindow(el) {
  document.querySelectorAll('#page-rewards .pill[data-lb]').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  State.rewardsLbWindow = el.dataset.lb || 'all';
  loadRewardsLeaderboardOnly();
}

async function loadRewardsLeaderboardOnly() {
  const tb = document.getElementById('rewardsLeaderboardBody');
  if (!tb) return;
  try {
    const w = State.rewardsLbWindow || 'all';
    const lb = await get('/api/rewards/leaderboard?window=' + encodeURIComponent(w));
    const rows = lb.leaderboard || [];
    if (!rows.length) {
      tb.innerHTML = '<tr><td colspan="3" style="padding:0.75rem; color:var(--dim)">No activity in this window yet.</td></tr>';
      return;
    }
    tb.innerHTML = rows.map(r => `
      <tr style="border-bottom:1px solid var(--border)">
        <td style="padding:0.5rem 0.25rem">${esc(String(r.rank))}</td>
        <td style="padding:0.5rem 0.25rem">${esc(r.display_name || 'User')}</td>
        <td style="padding:0.5rem 0.25rem; text-align:right; font-family:var(--mono)">${esc(String(r.points))}</td>
      </tr>`).join('');
  } catch (e) {
    tb.innerHTML = '<tr><td colspan="3" style="padding:0.75rem; color:var(--red)">' + esc(e.message) + '</td></tr>';
    toast(e.message, 'err');
  }
}

async function loadRewards() {
  document.querySelectorAll('#page-rewards .pill[data-lb]').forEach(p => {
    p.classList.toggle('active', p.dataset.lb === (State.rewardsLbWindow || 'all'));
  });
  try {
    const me = await get('/api/rewards/me');
    document.getElementById('rewardsBalance').textContent = me.balance != null ? String(me.balance) : '0';
    const code = me.referral_code || '';
    document.getElementById('rewardsReferralCode').textContent = code || '—';
    const link = code ? `${window.location.origin}/login?ref=${encodeURIComponent(code)}` : '';
    const hint = document.getElementById('rewardsReferralHint');
    if (hint) hint.textContent = link ? `Share: ${link}` : '';
    const refNote = document.getElementById('rewardsReferredNote');
    if (refNote) refNote.style.display = me.referred_by ? 'block' : 'none';

    const leg = document.getElementById('rewardsLedgerBody');
    const entries = me.recent_ledger || [];
    if (!entries.length) {
      leg.innerHTML = '<tr><td colspan="3" style="padding:0.75rem; color:var(--dim)">No point events yet.</td></tr>';
    } else {
      leg.innerHTML = entries.map(l => `
        <tr style="border-bottom:1px solid var(--border)">
          <td style="padding:0.5rem 0.25rem; white-space:nowrap; color:var(--dim)">${esc((l.created_at || '').replace('T', ' ').slice(0, 19))}</td>
          <td style="padding:0.5rem 0.25rem">${esc(l.reason || '')}</td>
          <td style="padding:0.5rem 0.25rem; text-align:right; font-family:var(--mono)">${l.delta > 0 ? '+' : ''}${esc(String(l.delta))}</td>
        </tr>`).join('');
    }
    await loadRewardsLeaderboardOnly();
  } catch (e) {
    toast(e.message, 'err');
  }
}

function copyRewardsLink() {
  const code = document.getElementById('rewardsReferralCode').textContent.trim();
  if (!code || code === '—') { toast('No referral code yet', 'err'); return; }
  const link = `${window.location.origin}/login?ref=${encodeURIComponent(code)}`;
  navigator.clipboard.writeText(link).then(() => toast('Link copied', 'ok')).catch(() => toast('Copy failed', 'err'));
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
    const d = await del('/api/history');
    toast(`Cleared ${d.deleted_count || 0} scans`, 'ok');
    loadHistory();
  } catch (e) { toast('Failed: ' + (e?.message || 'unknown error'), 'err'); }
}

/** Strip control chars for PDF standard fonts (Helvetica). */
function pdfSanitizeText(t) {
  if (t == null || t === '') return '';
  return String(t)
    .replace(/\r\n/g, '\n')
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '')
    .trim();
}

/** Plain-language labels so non-technical readers understand priority. */
function pdfFriendlySeverity(sevRaw) {
  const s = sevClass(sevRaw);
  const map = {
    Critical: 'Critical — treat as urgent; fix as soon as you can.',
    High: 'High — important; plan a fix soon.',
    Medium: 'Medium — worth fixing in your next regular update.',
    Low: 'Low — smaller risk; review when you have time.',
    Info: 'Informational — for awareness; usually no immediate action.',
  };
  return map[s] || 'Review the details below and decide with your team.';
}

function _jspdfConstructor() {
  const mod = window.jspdf;
  if (mod && typeof mod.jsPDF === 'function') return mod.jsPDF;
  if (typeof window.jsPDF === 'function') return window.jsPDF;
  return null;
}

function exportReportPdf() {
  if (!State.report) {
    toast('No report loaded', 'err');
    return;
  }
  const JsPDF = _jspdfConstructor();
  if (!JsPDF) {
    toast('PDF helper did not load. Refresh the page and try again.', 'err');
    return;
  }

  const doc = new JsPDF({ unit: 'pt', format: 'a4' });
  const margin = 48;
  const bottom = 56;
  const pageH = doc.internal.pageSize.getHeight();
  const pageW = doc.internal.pageSize.getWidth();
  const maxW = pageW - margin * 2;
  let y = 56;

  function newPage() {
    doc.addPage();
    y = 56;
  }

  function ensureSpace(lineHeight) {
    if (y + lineHeight > pageH - bottom) newPage();
  }

  function addTitle(text) {
    const raw = pdfSanitizeText(text);
    if (!raw) return;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(15);
    const lines = doc.splitTextToSize(raw, maxW);
    for (let i = 0; i < lines.length; i++) {
      ensureSpace(20);
      doc.text(lines[i], margin, y);
      y += 20;
    }
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    y += 8;
  }

  function addHeading(text) {
    const raw = pdfSanitizeText(text);
    if (!raw) return;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    const lines = doc.splitTextToSize(raw, maxW);
    for (let i = 0; i < lines.length; i++) {
      ensureSpace(15);
      doc.text(lines[i], margin, y);
      y += 15;
    }
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    y += 6;
  }

  function addBody(text) {
    const raw = pdfSanitizeText(text);
    if (!raw) return;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    const parts = raw.split(/\n\n+/);
    for (const part of parts) {
      const line = part.replace(/\n/g, ' ');
      const wrapped = doc.splitTextToSize(line, maxW);
      for (let i = 0; i < wrapped.length; i++) {
        ensureSpace(13);
        doc.text(wrapped[i], margin, y);
        y += 13;
      }
      y += 5;
    }
  }

  const rep = State.report;
  const findings = [...(rep.findings || [])].sort((a, b) => {
    const o = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    return (o[sevClass(a.severity)] ?? 5) - (o[sevClass(b.severity)] ?? 5);
  });

  addTitle('Security scan — plain-language summary');
  addBody(
    'This document explains your scan results in everyday words. It is meant for managers, product owners, and anyone who is not a security specialist. Use the technical view in Diverg and the JSON export for full detail. This summary is not legal or insurance advice.'
  );

  addHeading('What was scanned');
  addBody(`Target: ${pdfSanitizeText(rep.target_url) || 'Not recorded'}`);
  if (rep.scanned_at) addBody(`When: ${pdfSanitizeText(rep.scanned_at)}`);
  if (rep.id) addBody(`Report ID: ${pdfSanitizeText(rep.id)}`);

  addHeading('Overall picture');
  const verdict = pdfSanitizeText(rep.risk_verdict) || 'Not rated';
  const score =
    rep.risk_score != null && rep.risk_score !== ''
      ? ` Safety score: ${pdfSanitizeText(rep.risk_score)} (higher usually means safer in our model).`
      : '';
  addBody(`Result label: ${verdict}.${score}`);
  if (rep.risk_summary) addBody(String(rep.risk_summary));

  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const f of findings) {
    const k = sevClass(f.severity);
    if (counts[k] !== undefined) counts[k] += 1;
  }
  const breakdown = Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([k, n]) => `${n} ${k}`)
    .join(', ');

  addHeading('Findings at a glance');
  if (!findings.length) {
    addBody('No individual findings were listed for this scan. That may mean a clean result for the checks we ran, or that details are only in the raw data.');
  } else {
    addBody(
      `We reported ${findings.length} item(s). ${breakdown ? `Breakdown: ${breakdown}.` : ''} The next section walks through each one in simple language.`
    );
  }

  if (findings.length) {
    addHeading('Each finding — explained simply');
    findings.forEach((f, i) => {
      addHeading(`Finding ${i + 1}: ${pdfSanitizeText(f.title) || 'Untitled'}`);
      addBody(`Priority: ${pdfFriendlySeverity(f.severity)}`);
      if (f.category) addBody(`Topic area: ${pdfSanitizeText(f.category)}`);
      if (f.description) {
        addHeading('What it means');
        addBody(f.description);
      }
      if (f.impact) {
        addHeading('Why it matters');
        addBody(f.impact);
      }
      if (f.remediation) {
        addHeading('What to do next');
        addBody(f.remediation);
      }
      if (f.evidence) {
        const ev = String(f.evidence);
        const short = ev.length > 550 ? `${ev.slice(0, 550)}…` : ev;
        addHeading('Evidence (short excerpt)');
        addBody(short);
      }
      y += 12;
      ensureSpace(24);
    });
  }

  const aps = rep.attack_paths;
  if (Array.isArray(aps) && aps.length) {
    addHeading('Possible combined attack paths');
    addBody(
      'These describe ways several issues could be chained together. Share this section with whoever fixes security in your stack.'
    );
    aps.slice(0, 25).forEach((p, idx) => {
      const ap = p.attack_path || p;
      const title = pdfSanitizeText(ap.title || ap.name || `Chain ${idx + 1}`);
      addHeading(title);
      const steps = Array.isArray(ap.steps) ? ap.steps : ap.chain || ap.path || [];
      if (steps.length) {
        addBody(steps.map(s => pdfSanitizeText(s)).filter(Boolean).join(' → '));
      }
      if (ap.impact) addBody(ap.impact);
    });
  }

  if (rep.attack_paths_note) {
    addHeading('Note on attack paths');
    addBody(String(rep.attack_paths_note));
  }

  if (rep.remediation_plan) {
    addHeading('Remediation plan (from scan)');
    const plan =
      typeof rep.remediation_plan === 'string'
        ? rep.remediation_plan
        : JSON.stringify(rep.remediation_plan, null, 2);
    addBody(plan.length > 6000 ? `${plan.slice(0, 6000)}…` : plan);
  }

  if (rep.safe_to_run != null && rep.safe_to_run !== '') {
    addHeading('Automated testing');
    addBody(String(rep.safe_to_run));
  }

  const slug = (pdfSanitizeText(rep.target_url) || 'scan').replace(/[^\w.-]+/g, '_').slice(0, 60);
  doc.save(`diverg-summary-${slug}-${Date.now()}.pdf`);
  toast('PDF downloaded', 'ok');
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

(function initMobileNav() {
  const app = document.querySelector('.app');
  const toggle = document.getElementById('navToggle');
  const backdrop = document.getElementById('sidebarBackdrop');
  if (!app || !toggle || !backdrop) return;

  const mq = window.matchMedia('(max-width: 768px)');

  function closeSidebar() {
    app.classList.remove('sidebar-open');
    toggle.setAttribute('aria-expanded', 'false');
    toggle.setAttribute('aria-label', 'Open navigation menu');
    backdrop.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
  }

  function openSidebar() {
    app.classList.add('sidebar-open');
    toggle.setAttribute('aria-expanded', 'true');
    toggle.setAttribute('aria-label', 'Close navigation menu');
    backdrop.setAttribute('aria-hidden', 'false');
    if (mq.matches) document.body.style.overflow = 'hidden';
  }

  toggle.addEventListener('click', () => {
    if (app.classList.contains('sidebar-open')) closeSidebar();
    else openSidebar();
  });
  backdrop.addEventListener('click', closeSidebar);
  document.querySelectorAll('.nav-item[data-page]').forEach((el) => {
    el.addEventListener('click', () => {
      if (mq.matches) closeSidebar();
    });
  });
  window.addEventListener('resize', () => {
    if (!mq.matches) closeSidebar();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && app.classList.contains('sidebar-open')) closeSidebar();
  });
})();

(function initFindingsFilters() {
  const sev = document.getElementById('findingsSeverityFilter');
  const q = document.getElementById('findingsSearchInput');
  if (sev) sev.addEventListener('change', renderFindingsList);
  if (q) q.addEventListener('input', renderFindingsList);
})();

(function bootDashboard() {
  try {
    const params = new URLSearchParams(window.location.search);
    const page = (params.get('page') || params.get('p') || '').toLowerCase();
    if (page === 'investigation' && applyInvestigationDeepLink(params)) {
      navigate('investigation');
      return;
    }
  } catch (_) { /* ignore */ }
  loadHome();
})();
