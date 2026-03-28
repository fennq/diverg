/* ── Diverg Console — Main Application ─────────────────────────────────── */

// ── Config ────────────────────────────────────────────────────────────────
const CFG = {
  apiUrl: localStorage.getItem('diverg_api_url') || 'http://127.0.0.1:5000',
};

function api(path) { return CFG.apiUrl + path; }

// ── State ─────────────────────────────────────────────────────────────────
const State = {
  currentScanId: null,
  currentReport: null,
  allFindings: [],       // aggregated across all scans
  historyData: [],
  historyOffset: 0,
  historyTotal: 0,
  selectedScope: 'full',
};

// ── Router ────────────────────────────────────────────────────────────────
const PAGE_TITLES = {
  home:          'Home',
  scanner:       'Scanner',
  history:       'History',
  findings:      'All Findings',
  results:       'Scan Results',
  'attack-paths':'Attack Paths',
  investigation: 'Investigation',
  settings:      'Settings',
};

const PAGE_ACTIONS = {
  scanner: `<button class="btn-ghost" onclick="navigate('history')">View History</button>`,
  results: `
    <button class="btn-ghost" id="exportReportBtn" onclick="exportReport()">Export JSON</button>
    <button class="btn-sm"    id="deleteReportBtn" onclick="deleteCurrentScan()">Delete</button>
  `,
  history: `<button class="btn-fill" onclick="navigate('scanner')">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
    New Scan
  </button>`,
};

function navigate(page, data = null) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const pageEl = document.getElementById('page-' + page);
  if (pageEl) pageEl.classList.add('active');

  const navEl = document.querySelector(`[data-page="${page}"]`);
  if (navEl) navEl.classList.add('active');

  document.getElementById('pageTitle').textContent = PAGE_TITLES[page] || page;
  document.getElementById('pageActions').innerHTML = PAGE_ACTIONS[page] || '';

  if (page === 'home')          loadHome();
  if (page === 'history')       loadHistory();
  if (page === 'findings')      loadFindings();
  if (page === 'attack-paths')  loadAllAttackPaths();
  if (page === 'settings')      loadSettings();
  if (page === 'results' && data) showResults(data);

  window.scrollTo(0, 0);
}

// ── Sidebar nav clicks ────────────────────────────────────────────────────
document.querySelectorAll('.nav-item[data-page]').forEach(el => {
  el.addEventListener('click', () => navigate(el.dataset.page));
});

// ── Tabs (Results page) ───────────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    const panel = document.getElementById('tab-' + tab);
    if (panel) panel.classList.add('active');
  });
});

// ── Toast ─────────────────────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.getElementById('toastContainer').appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

// ── Fetch helpers ─────────────────────────────────────────────────────────
async function apiFetch(path, opts = {}) {
  const r = await fetch(api(path), {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// ── Risk utilities ────────────────────────────────────────────────────────
function riskClass(verdict) {
  if (!verdict) return 'unknown';
  const v = verdict.toLowerCase();
  if (v.includes('critical')) return 'critical';
  if (v.includes('high'))     return 'high';
  if (v.includes('medium'))   return 'medium';
  if (v.includes('low'))      return 'low';
  if (v.includes('clean') || v.includes('none') || v.includes('safe')) return 'clean';
  return 'unknown';
}

function riskBadgeHtml(verdict, score) {
  const cls = riskClass(verdict);
  const scoreStr = (score != null && score !== '') ? ` · ${score}` : '';
  return `<span class="risk-badge ${cls}">${verdict || 'Unknown'}${scoreStr}</span>`;
}

function sevClass(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'Critical';
  if (s === 'high')     return 'High';
  if (s === 'medium')   return 'Medium';
  if (s === 'low')      return 'Low';
  return 'Info';
}

function timeAgo(iso) {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)  return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString();
}

function shortUrl(url) {
  try {
    const u = new URL(url.startsWith('http') ? url : 'https://' + url);
    return u.hostname + (u.pathname !== '/' ? u.pathname : '');
  } catch { return url; }
}

// ── HOME PAGE ─────────────────────────────────────────────────────────────
async function loadHome() {
  try {
    const stats = await apiFetch('/api/stats');
    document.getElementById('statScans').textContent    = stats.total_scans ?? '0';
    document.getElementById('statCritical').textContent = stats.total_critical ?? '0';
    document.getElementById('statTargets').textContent  = stats.unique_targets ?? '0';
    document.getElementById('statAvgRisk').textContent  =
      stats.avg_risk_score > 0 ? stats.avg_risk_score : '—';

    const list = document.getElementById('recentScansList');
    if (!stats.recent_scans?.length) {
      list.innerHTML = `<div class="empty-state" style="padding:1.5rem 0">
        <div class="empty-state-title">No scans yet</div>
        <div class="empty-state-sub">Run your first scan to see results here</div>
      </div>`;
    } else {
      list.innerHTML = stats.recent_scans.map(s => miniScanRow(s)).join('');
    }
  } catch (e) {
    document.getElementById('statScans').textContent = 'API offline';
  }
}

function miniScanRow(s) {
  const cls = riskClass(s.risk_verdict);
  return `<div class="scan-row" onclick="openScan('${s.id}')">
    <div>
      <div class="scan-url">${shortUrl(s.target_url)}</div>
      <div class="scan-url-sub">${timeAgo(s.scanned_at)}</div>
    </div>
    ${riskBadgeHtml(s.risk_verdict, s.risk_score)}
    <span class="sev-pill Critical" style="font-size:0.6875rem">${s.critical || 0}C</span>
  </div>`;
}

// Quick scan from home
function quickLaunch() {
  const url = document.getElementById('quickUrl').value.trim();
  if (!url) { toast('Enter a target URL', 'error'); return; }
  const scope = document.getElementById('quickScope').value;
  navigate('scanner');
  setTimeout(() => {
    document.getElementById('scanUrl').value = url;
    setScope(scope);
    launchScan();
  }, 100);
}

// ── SCANNER PAGE ──────────────────────────────────────────────────────────
function setScope(scope) {
  State.selectedScope = scope;
  document.querySelectorAll('.scope-btn').forEach(b => {
    b.classList.toggle('selected', b.dataset.scope === scope);
  });
}

document.querySelectorAll('.scope-btn').forEach(btn => {
  btn.addEventListener('click', () => setScope(btn.dataset.scope));
});

async function launchScan() {
  let url = document.getElementById('scanUrl').value.trim();
  if (!url) { toast('Enter a target URL', 'error'); return; }
  if (!url.startsWith('http')) url = 'https://' + url;

  const goal  = document.getElementById('scanGoal').value.trim();
  const scope = State.selectedScope;

  const launchBtn = document.getElementById('launchBtn');
  launchBtn.disabled = true;
  launchBtn.innerHTML = `<span class="spinner"></span> Launching…`;

  const card = document.getElementById('progressCard');
  card.classList.add('visible');
  document.getElementById('progressTitle').textContent = 'Scanning…';
  document.getElementById('progressTarget').textContent = url;
  document.getElementById('progressDot').style.background = 'var(--accent)';
  document.getElementById('skillsTrack').innerHTML = '';
  document.getElementById('liveFindings').innerHTML = '';
  document.getElementById('progressDone').style.display = 'none';

  const skillState = {};
  let   lastReport = null;

  try {
    const resp = await fetch(api('/api/scan/stream'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, goal, scope }),
    });

    if (!resp.ok) throw new Error('API error: ' + resp.status);

    const reader = resp.body.getReader();
    const dec    = new TextDecoder();
    let   buf    = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const evt = JSON.parse(line);
          handleScanEvent(evt, skillState);
          if (evt.event === 'done') lastReport = evt.report;
        } catch {}
      }
    }
  } catch (e) {
    toast('Scan error: ' + e.message, 'error');
  }

  // Done
  launchBtn.disabled = false;
  launchBtn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"/></svg> Launch Scan`;
  document.getElementById('progressDot').style.background = 'var(--green)';
  document.getElementById('progressDot').style.animation = 'none';

  if (lastReport) {
    State.currentReport = lastReport;
    State.currentScanId = lastReport.id;
    document.getElementById('progressDone').style.display = 'block';
    document.getElementById('viewResultsBtn').onclick = () => navigate('results', lastReport);
    toast('Scan complete — ' + (lastReport.findings?.length || 0) + ' findings', 'success');

    const autoNav = document.getElementById('toggleAutoNav');
    if (!autoNav || autoNav.checked) {
      setTimeout(() => navigate('results', lastReport), 800);
    }
  }
}

function handleScanEvent(evt, skillState) {
  const track    = document.getElementById('skillsTrack');
  const liveFmts = document.getElementById('liveFindings');

  if (evt.event === 'scan_start') {
    document.getElementById('progressTitle').textContent = `Scanning (${evt.scope})`;
    return;
  }

  if (evt.event === 'skill_start') {
    skillState[evt.skill] = { status: 'running', count: 0 };
    renderSkillsTrack(track, skillState);
    return;
  }

  if (evt.event === 'skill_done') {
    if (skillState[evt.skill]) {
      skillState[evt.skill].status = 'done';
      skillState[evt.skill].count  = evt.findings_count || 0;
    }
    renderSkillsTrack(track, skillState);
    return;
  }

  if (evt.event === 'finding') {
    const f = evt.finding || {};
    const s = sevClass(f.severity);
    const alertCritical = document.getElementById('toggleCritical');
    if (s === 'Critical' && (!alertCritical || alertCritical.checked)) {
      toast('Critical: ' + (f.title || 'Finding'), 'error');
    }
    const row = document.createElement('div');
    row.className = 'live-finding-row';
    row.innerHTML = `<span class="sev-pill ${s}">${s}</span>
      <span class="live-finding-text">${escHtml(f.title || f.type || 'Finding')}</span>`;
    liveFmts.appendChild(row);
    return;
  }

  if (evt.event === 'error') {
    toast('Skill error: ' + evt.error, 'error');
  }
}

function renderSkillsTrack(track, skillState) {
  track.innerHTML = Object.entries(skillState).map(([name, info]) => `
    <div class="skill-row">
      <span class="skill-name">${name}</span>
      <span class="skill-status ${info.status}">${info.status}</span>
      <span class="skill-count">${info.status === 'done' ? info.count + ' findings' : ''}</span>
    </div>
  `).join('');
}

// ── HISTORY PAGE ──────────────────────────────────────────────────────────
async function loadHistory() {
  const scope   = document.getElementById('historyScope')?.value   || '';
  const verdict = document.getElementById('historyVerdict')?.value || '';

  let url = `/api/history?limit=50&offset=${State.historyOffset}`;
  if (scope)   url += `&scope=${encodeURIComponent(scope)}`;
  if (verdict) url += `&verdict=${encodeURIComponent(verdict)}`;

  try {
    const data = await apiFetch(url);
    State.historyData  = data.scans;
    State.historyTotal = data.total;

    document.getElementById('historyCount').textContent =
      `${data.total} scan${data.total !== 1 ? 's' : ''} total`;

    renderHistoryList(data.scans);
  } catch (e) {
    toast('Could not load history: ' + e.message, 'error');
  }
}

function filterHistory() {
  const q = (document.getElementById('historySearch')?.value || '').toLowerCase();
  const filtered = q
    ? State.historyData.filter(s =>
        (s.target_url || '').toLowerCase().includes(q) ||
        (s.label || '').toLowerCase().includes(q))
    : State.historyData;
  renderHistoryList(filtered);
}

function renderHistoryList(scans) {
  const list = document.getElementById('historyList');
  if (!scans?.length) {
    list.innerHTML = `<div class="empty-state">
      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="12 8 12 12 14 14"/><path d="M3.05 11a9 9 0 1 0 .5-4.5"/><polyline points="3 2 3 7 8 7"/></svg>
      <div class="empty-state-title">No scans found</div>
      <div class="empty-state-sub">Try adjusting your filters or run a new scan</div>
    </div>`;
    return;
  }
  list.innerHTML = scans.map(s => `
    <div class="scan-row" onclick="openScan('${s.id}')">
      <div style="min-width:0">
        <div class="scan-url">${escHtml(shortUrl(s.target_url))}</div>
        <div class="scan-url-sub">${escHtml(s.label || fmtDate(s.scanned_at))}</div>
      </div>
      <span class="scan-scope-pill">${s.scope || 'full'}</span>
      ${riskBadgeHtml(s.risk_verdict, s.risk_score)}
      <span style="font-size:0.75rem;color:var(--text-3);white-space:nowrap">
        ${s.total || 0} findings
        ${s.critical ? `<span style="color:var(--red);font-weight:600"> · ${s.critical}C</span>` : ''}
        ${s.high     ? `<span style="color:var(--orange)"> · ${s.high}H</span>` : ''}
      </span>
      <span class="scan-time">${timeAgo(s.scanned_at)}</span>
      <div class="scan-actions" onclick="event.stopPropagation()">
        <button class="btn-sm" onclick="deleteScan('${s.id}')">Delete</button>
      </div>
    </div>
  `).join('');
}

async function openScan(id) {
  try {
    const data = await apiFetch(`/api/history/${id}`);
    State.currentScanId = id;
    State.currentReport = data.report || data;
    navigate('results', State.currentReport);
  } catch (e) {
    toast('Could not load scan: ' + e.message, 'error');
  }
}

async function deleteScan(id) {
  if (!confirm('Delete this scan?')) return;
  try {
    await apiFetch(`/api/history/${id}`, { method: 'DELETE' });
    toast('Scan deleted', 'success');
    loadHistory();
  } catch (e) {
    toast('Delete failed: ' + e.message, 'error');
  }
}

async function deleteCurrentScan() {
  if (!State.currentScanId) return;
  await deleteScan(State.currentScanId);
  navigate('history');
}

// ── FINDINGS PAGE ─────────────────────────────────────────────────────────
async function loadFindings() {
  try {
    const data = await apiFetch('/api/history?limit=200');
    // Aggregate all findings from all scans
    const all = [];
    for (const scan of (data.scans || [])) {
      // We'd need full reports for findings — load them if they have findings
      if (scan.total > 0) {
        try {
          const full = await apiFetch(`/api/history/${scan.id}`);
          const findings = full.report?.findings || [];
          findings.forEach(f => all.push({ ...f, _scan: scan }));
        } catch {}
      }
    }
    State.allFindings = all;
    document.getElementById('findingsCount').textContent =
      `${all.length} findings across ${data.total} scan${data.total !== 1 ? 's' : ''}`;
    renderFindingsList(all, 'findingsList');
  } catch (e) {
    toast('Could not load findings: ' + e.message, 'error');
  }
}

function filterFindings() {
  const q   = (document.getElementById('findingsSearch')?.value || '').toLowerCase();
  const sev = document.getElementById('findingsSev')?.value || '';
  let filtered = State.allFindings;
  if (q)   filtered = filtered.filter(f => (f.title || '').toLowerCase().includes(q) || (f.category || '').toLowerCase().includes(q));
  if (sev) filtered = filtered.filter(f => sevClass(f.severity) === sev);
  renderFindingsList(filtered, 'findingsList');
  document.getElementById('findingsCount').textContent =
    `${filtered.length} of ${State.allFindings.length} findings`;
}

// ── RESULTS PAGE ──────────────────────────────────────────────────────────
function showResults(report) {
  if (!report) return;

  const findings = report.findings || [];
  const verdict  = report.risk_verdict || '';
  const score    = report.risk_score;
  const cls      = riskClass(verdict);

  // Hero
  document.getElementById('resultsUrl').textContent   = report.target_url || '—';
  document.getElementById('resultsMeta').textContent  =
    `Scope: ${report.scope || '—'} · Scanned: ${fmtDate(report.scanned_at)}`;
  document.getElementById('resultsRiskVerdict').innerHTML = riskBadgeHtml(verdict, score);

  // Score ring
  const ring = document.getElementById('scoreRing');
  ring.className = `score-ring ${cls}`;
  document.getElementById('scoreNum').textContent = score != null ? score : '—';

  // Severity counts
  document.getElementById('rc').textContent = findings.filter(f => sevClass(f.severity) === 'Critical').length;
  document.getElementById('rh').textContent = findings.filter(f => sevClass(f.severity) === 'High').length;
  document.getElementById('rm').textContent = findings.filter(f => sevClass(f.severity) === 'Medium').length;
  document.getElementById('rl').textContent = findings.filter(f => sevClass(f.severity) === 'Low').length;

  // Findings tab
  const sorted = [...findings].sort((a, b) => {
    const order = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    return (order[sevClass(a.severity)] ?? 5) - (order[sevClass(b.severity)] ?? 5);
  });
  renderFindingsList(sorted, 'resultsFindingsList');

  // Summary tab
  document.getElementById('resultsSummaryText').textContent  = report.summary || 'No summary available.';
  document.getElementById('resultsEvidenceText').textContent = report.evidence_summary || 'No evidence summary.';
  const skillsEl = document.getElementById('resultsSkillsRun');
  skillsEl.innerHTML = (report.skills_run || []).map(s =>
    `<span class="scan-scope-pill">${escHtml(s)}</span>`).join('');

  // Attack paths tab
  renderAttackPaths(report.attack_paths || [], 'resultsAttackPaths');

  // Remediation tab
  document.getElementById('resultsRemediation').textContent  = report.remediation_plan || 'No remediation plan available.';
  const sugg = report.suggested_next_tests;
  const suggEl = document.getElementById('resultsSuggested');
  if (Array.isArray(sugg)) {
    suggEl.innerHTML = sugg.map(t => `<div style="padding:0.25rem 0;color:var(--text-2);font-size:0.8125rem">• ${escHtml(String(t))}</div>`).join('');
  } else {
    suggEl.textContent = sugg || 'No suggestions.';
  }

  // Reset to findings tab
  document.querySelectorAll('.tab-btn').forEach((b, i) => b.classList.toggle('active', i === 0));
  document.querySelectorAll('.tab-panel').forEach((p, i) => p.classList.toggle('active', i === 0));
}

function renderFindingsList(findings, containerId) {
  const el = document.getElementById(containerId);
  if (!findings?.length) {
    el.innerHTML = `<div class="empty-state">
      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      <div class="empty-state-title">No findings</div>
      <div class="empty-state-sub">Nothing detected at this severity level</div>
    </div>`;
    return;
  }

  el.innerHTML = findings.map((f, i) => {
    const s   = sevClass(f.severity);
    const uid = `f-${containerId}-${i}`;
    const evidence = f.evidence || f.proof || f.url || '';
    const remediation = f.remediation || f.fix || '';
    return `
    <div class="finding-card" id="${uid}">
      <div class="finding-header" onclick="toggleFinding('${uid}')">
        <span class="sev-pill ${s}">${s}</span>
        <div style="flex:1;min-width:0">
          <div class="finding-title">${escHtml(f.title || f.type || 'Finding')}</div>
          <div class="finding-category">${escHtml(f.category || '')}</div>
        </div>
        <svg class="finding-chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
      </div>
      <div class="finding-body">
        ${f.description ? `<div class="finding-field">
          <div class="finding-field-label">Description</div>
          <div class="finding-field-value">${escHtml(f.description)}</div>
        </div>` : ''}
        ${f.impact ? `<div class="finding-field">
          <div class="finding-field-label">Impact</div>
          <div class="finding-field-value">${escHtml(f.impact)}</div>
        </div>` : ''}
        ${evidence ? `<div class="finding-field">
          <div class="finding-field-label">Evidence</div>
          <div class="finding-evidence">${escHtml(String(evidence).substring(0, 600))}</div>
        </div>` : ''}
        ${remediation ? `<div class="finding-field">
          <div class="finding-field-label">Remediation</div>
          <div class="finding-field-value">${escHtml(remediation)}</div>
        </div>` : ''}
        ${(f.category === 'Authorization' || f.category === 'Authentication') ? `
          <button class="poc-btn" onclick="simulatePoc(${JSON.stringify(JSON.stringify(f))}, '${uid}')">
            Run PoC Simulation
          </button>
          <div class="poc-result" id="poc-result-${uid}" style="display:none"></div>
        ` : ''}
      </div>
    </div>`;
  }).join('');
}

function toggleFinding(uid) {
  document.getElementById(uid)?.classList.toggle('open');
}

// ── ATTACK PATHS ──────────────────────────────────────────────────────────
function renderAttackPaths(paths, containerId) {
  const el = document.getElementById(containerId);
  if (!paths?.length) {
    el.innerHTML = `<div class="empty-state">
      <div class="empty-state-title">No attack paths found</div>
      <div class="empty-state-sub">A full-scope scan may surface chained attack paths</div>
    </div>`;
    return;
  }
  el.innerHTML = paths.map(p => {
    const steps = Array.isArray(p.steps) ? p.steps
      : (p.chain || p.path || []).map ? (p.chain || p.path || [])
      : [];
    const chainHtml = steps.length
      ? steps.map((s, i) => `${i > 0 ? `<span class="chain-arrow">→</span>` : ''}<span class="chain-step">${escHtml(String(s))}</span>`).join('')
      : escHtml(p.description || p.title || '');
    return `<div class="attack-path-card">
      <div class="attack-path-title">${escHtml(p.title || p.name || 'Attack Path')}</div>
      <div class="attack-path-chain">${chainHtml}</div>
      ${p.impact ? `<div style="margin-top:0.5rem;font-size:0.8125rem;color:var(--text-3)">${escHtml(p.impact)}</div>` : ''}
    </div>`;
  }).join('');
}

async function loadAllAttackPaths() {
  try {
    const data = await apiFetch('/api/history?limit=100');
    const allPaths = [];
    for (const scan of (data.scans || [])) {
      try {
        const full = await apiFetch(`/api/history/${scan.id}`);
        const paths = full.report?.attack_paths || [];
        paths.forEach(p => allPaths.push({ ...p, _target: scan.target_url }));
      } catch {}
    }
    if (!allPaths.length) {
      document.getElementById('allAttackPaths').innerHTML = `<div class="empty-state">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
        <div class="empty-state-title">No attack paths yet</div>
        <div class="empty-state-sub">Run a full-scope scan to discover chained attack paths</div>
      </div>`;
      return;
    }
    renderAttackPaths(allPaths, 'allAttackPaths');
  } catch (e) {
    toast('Could not load attack paths', 'error');
  }
}

// ── INVESTIGATION TOOLS ───────────────────────────────────────────────────
function runChainLookup() {
  const addr = document.getElementById('chainAddr').value.trim();
  if (!addr) { toast('Enter an address or tx hash', 'error'); return; }
  const el = document.getElementById('chainResult');
  el.textContent = 'Looking up…';
  apiFetch('/api/scan', {
    method: 'POST',
    body: JSON.stringify({ url: 'https://etherscan.io', goal: `Blockchain lookup for: ${addr}`, scope: 'passive' }),
  }).then(r => {
    el.textContent = `Target: ${addr}\n\nNote: Full on-chain tracing requires the full Diverg stack.\nThis ran a passive scan — expand with blockchain skills for deep analysis.\n\nRisk: ${r.risk_verdict || '—'}\nFindings: ${(r.findings || []).length}`;
  }).catch(e => {
    el.textContent = 'Error: ' + e.message + '\n\nMake sure the API server is running.';
  });
}

function runOsint() {
  const domain = document.getElementById('osintDomain').value.trim();
  if (!domain) { toast('Enter a domain', 'error'); return; }
  const el = document.getElementById('osintResult');
  el.textContent = 'Investigating…';
  const url = domain.startsWith('http') ? domain : 'https://' + domain;
  apiFetch('/api/scan', {
    method: 'POST',
    body: JSON.stringify({ url, scope: 'recon' }),
  }).then(r => {
    const lines = [`OSINT Report: ${domain}`, ''];
    (r.findings || []).forEach(f => {
      lines.push(`[${f.severity || '?'}] ${f.title}`);
      if (f.evidence) lines.push(`  → ${String(f.evidence).substring(0, 120)}`);
    });
    if (!r.findings?.length) lines.push('No significant findings.');
    el.textContent = lines.join('\n');
  }).catch(e => {
    el.textContent = 'Error: ' + e.message;
  });
}

async function runPoc() {
  const type  = document.getElementById('pocType').value;
  const url   = document.getElementById('pocUrl').value.trim();
  const param = document.getElementById('pocParam').value.trim();
  const value = document.getElementById('pocValue').value.trim();
  const el    = document.getElementById('pocResult');

  if (!url) { toast('Enter a target URL', 'error'); return; }
  el.textContent = 'Running…';

  const body = { type, url };
  if (type === 'idor') {
    body.param_to_change = param || 'id';
    body.new_value = value || '2';
  }

  try {
    const r = await apiFetch('/api/poc/simulate', { method: 'POST', body: JSON.stringify(body) });
    el.textContent = `Conclusion: ${r.conclusion}\nSuccess: ${r.success}\nStatus: ${r.status_code || '—'}\n\n${r.body_preview ? 'Response preview:\n' + r.body_preview.substring(0, 500) : ''}`;
    el.className = 'tool-result ' + (r.success ? 'success' : 'fail');
  } catch (e) {
    el.textContent = 'Error: ' + e.message;
  }
}

async function runReputation() {
  const target = document.getElementById('reputationTarget').value.trim();
  if (!target) { toast('Enter a target', 'error'); return; }
  const el = document.getElementById('reputationResult');
  el.textContent = 'Checking…';
  const url = target.startsWith('http') ? target : 'https://' + target;
  try {
    const r = await apiFetch('/api/scan', {
      method: 'POST',
      body: JSON.stringify({ url, scope: 'passive', goal: `Entity reputation check for: ${target}` }),
    });
    const lines = [`Reputation: ${target}`, `Verdict: ${r.risk_verdict || '—'}`, ''];
    (r.findings || []).slice(0, 10).forEach(f => lines.push(`[${f.severity}] ${f.title}`));
    el.textContent = lines.join('\n');
  } catch (e) {
    el.textContent = 'Error: ' + e.message;
  }
}

// PoC from finding card
async function simulatePoc(findingJson, uid) {
  const finding  = JSON.parse(findingJson);
  const resultEl = document.getElementById('poc-result-' + uid);
  resultEl.style.display = 'block';
  resultEl.textContent = 'Running PoC…';
  try {
    const r = await apiFetch('/api/poc/simulate', {
      method: 'POST',
      body: JSON.stringify({ finding }),
    });
    resultEl.textContent = `${r.conclusion}\nSuccess: ${r.success} · Status: ${r.status_code || '—'}`;
    resultEl.className = 'poc-result ' + (r.success ? 'success' : 'fail');
  } catch (e) {
    resultEl.textContent = 'Error: ' + e.message;
  }
}

// ── SETTINGS PAGE ─────────────────────────────────────────────────────────
function loadSettings() {
  document.getElementById('settingsApiUrl').value = CFG.apiUrl;
}

function saveSettings() {
  const url = document.getElementById('settingsApiUrl').value.trim();
  if (url) {
    CFG.apiUrl = url;
    localStorage.setItem('diverg_api_url', url);
    toast('Settings saved', 'success');
  }
}

async function testConnection() {
  const el = document.getElementById('connectionStatus');
  el.textContent = 'Testing…';
  try {
    const r = await apiFetch('/api/health');
    el.textContent = `Connected — ${r.service} v${r.version || '?'}`;
    el.style.color = 'var(--green)';
    toast('API is online', 'success');
  } catch (e) {
    el.textContent = 'Cannot reach API: ' + e.message;
    el.style.color = 'var(--red)';
    toast('API offline', 'error');
  }
}

async function exportHistory() {
  try {
    const data = await apiFetch('/api/history?limit=200');
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `diverg-history-${Date.now()}.json`;
    a.click();
    toast('Export downloaded', 'success');
  } catch (e) {
    toast('Export failed: ' + e.message, 'error');
  }
}

async function clearHistory() {
  if (!confirm('Delete ALL scan history? This cannot be undone.')) return;
  try {
    const data = await apiFetch('/api/history?limit=200');
    for (const s of (data.scans || [])) {
      await apiFetch(`/api/history/${s.id}`, { method: 'DELETE' });
    }
    toast('History cleared', 'success');
    loadHistory();
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  }
}

function exportReport() {
  if (!State.currentReport) return;
  const blob = new Blob([JSON.stringify(State.currentReport, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  const name = shortUrl(State.currentReport.target_url || 'scan').replace(/[^a-z0-9]/gi, '-');
  a.href = URL.createObjectURL(blob);
  a.download = `diverg-${name}-${Date.now()}.json`;
  a.click();
}

// ── Utilities ─────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// PoC type toggle
document.getElementById('pocType')?.addEventListener('change', function() {
  document.getElementById('pocIdorFields').style.display =
    this.value === 'idor' ? 'block' : 'none';
});

// ── Init ──────────────────────────────────────────────────────────────────
loadHome();
