/* Diverg Console — app.js */

const CFG = { apiUrl: localStorage.getItem('diverg_api') || 'http://127.0.0.1:5000' };
const api  = p => CFG.apiUrl + p;

const State = {
  scope: 'full',
  scanId: null,
  report: null,
  allFindings: [],
  historyData: [],
};

// ── Routing ───────────────────────────────────────────────────────────────
const TITLES = {
  home: 'Home', scanner: 'Scanner', history: 'History', findings: 'Findings',
  results: 'Results', 'attack-paths': 'Attack Paths', investigation: 'Investigation', settings: 'Settings',
};
const ACTIONS = {
  results: `<button class="btn btn-outline btn-sm" onclick="exportReport()">Export JSON</button>
             <button class="btn btn-danger btn-sm" onclick="deleteCurrentScan()">Delete</button>`,
};

function navigate(page, data) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.sb-item').forEach(n => n.classList.remove('active'));
  const pg = document.getElementById('page-' + page);
  if (pg) pg.classList.add('active');
  const ni = document.querySelector(`.sb-item[data-page="${page}"]`);
  if (ni) ni.classList.add('active');
  document.getElementById('pageTitle').textContent = TITLES[page] || page;
  document.getElementById('pageActions').innerHTML = ACTIONS[page] || '';
  if (page === 'home')         loadHome();
  if (page === 'history')      loadHistory();
  if (page === 'findings')     loadFindings();
  if (page === 'attack-paths') loadAllAttackPaths();
  if (page === 'settings')     loadSettings();
  if (page === 'results' && data) showResults(data);
  window.scrollTo(0, 0);
}

document.querySelectorAll('.sb-item[data-page]').forEach(el =>
  el.addEventListener('click', () => navigate(el.dataset.page)));

// Tabs
document.querySelectorAll('.tab[data-tab]').forEach(btn => btn.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('on'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('on'));
  btn.classList.add('on');
  const panel = document.getElementById('tab-' + btn.dataset.tab);
  if (panel) panel.classList.add('on');
}));

// Scope buttons
document.querySelectorAll('.scope-btn').forEach(btn =>
  btn.addEventListener('click', () => {
    State.scope = btn.dataset.scope;
    document.querySelectorAll('.scope-btn').forEach(b => b.classList.remove('on'));
    btn.classList.add('on');
  }));

// ── Toast ─────────────────────────────────────────────────────────────────
function toast(msg, type = 'inf') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.getElementById('toastContainer').appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

// ── API ───────────────────────────────────────────────────────────────────
async function get(path) {
  const r = await fetch(api(path));
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}
async function post(path, body) {
  const r = await fetch(api(path), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}
async function del(path) {
  const r = await fetch(api(path), { method: 'DELETE' });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}

// ── Helpers ───────────────────────────────────────────────────────────────
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function riskCls(v) {
  if (!v) return 'unknown';
  const l = v.toLowerCase();
  if (l.includes('critical')) return 'critical';
  if (l.includes('high'))     return 'high';
  if (l.includes('medium'))   return 'medium';
  if (l.includes('low'))      return 'low';
  if (l.includes('clean') || l.includes('safe') || l.includes('none')) return 'clean';
  return 'unknown';
}

function badgeHtml(verdict, score) {
  const c = riskCls(verdict);
  const s = (score != null && score !== '') ? ` · ${score}` : '';
  return `<span class="badge ${c}">${esc(verdict || 'Unknown')}${s}</span>`;
}

function sevCls(s) {
  const l = (s || '').toLowerCase();
  if (l === 'critical') return 'Critical';
  if (l === 'high')     return 'High';
  if (l === 'medium')   return 'Medium';
  if (l === 'low')      return 'Low';
  return 'Info';
}

function ago(iso) {
  if (!iso) return '—';
  const m = Math.floor((Date.now() - new Date(iso)) / 60000);
  if (m < 1)  return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function fmtDate(iso) {
  return iso ? new Date(iso).toLocaleString() : '—';
}

function shortUrl(u) {
  try { const x = new URL(u.startsWith('http') ? u : 'https://' + u); return x.hostname + (x.pathname !== '/' ? x.pathname : ''); }
  catch { return u; }
}

// ── HOME ──────────────────────────────────────────────────────────────────
async function loadHome() {
  try {
    const s = await get('/api/stats');
    document.getElementById('statScans').textContent    = s.total_scans ?? '0';
    document.getElementById('statCritical').textContent = s.total_critical ?? '0';
    document.getElementById('statTargets').textContent  = s.unique_targets ?? '0';
    document.getElementById('statAvgRisk').textContent  = s.avg_risk_score > 0 ? s.avg_risk_score : '—';
    const list = document.getElementById('recentScansList');
    if (!s.recent_scans?.length) {
      list.innerHTML = `<div class="empty" style="padding:1rem 0"><div class="empty-title">No scans yet</div><div class="empty-sub">Run your first scan</div></div>`;
    } else {
      list.innerHTML = `<div class="scan-list">${s.recent_scans.map(miniRow).join('')}</div>`;
    }
  } catch { document.getElementById('statScans').textContent = 'API offline'; }
}

function miniRow(s) {
  return `<div class="scan-row" onclick="openScan('${s.id}')">
    <div class="scan-row-main">
      <div class="scan-url">${esc(shortUrl(s.target_url))}</div>
      <div class="scan-sub">${ago(s.scanned_at)}</div>
    </div>
    ${badgeHtml(s.risk_verdict, s.risk_score)}
    ${s.critical ? `<span class="sev Critical">${s.critical}C</span>` : ''}
  </div>`;
}

function quickLaunch() {
  const url = document.getElementById('quickUrl').value.trim();
  if (!url) { toast('Enter a target URL', 'err'); return; }
  const scope = document.getElementById('quickScope').value;
  navigate('scanner');
  setTimeout(() => {
    document.getElementById('scanUrl').value = url;
    State.scope = scope;
    document.querySelectorAll('.scope-btn').forEach(b => b.classList.toggle('on', b.dataset.scope === scope));
    launchScan();
  }, 80);
}

// ── SCANNER ───────────────────────────────────────────────────────────────
async function launchScan() {
  let url = document.getElementById('scanUrl').value.trim();
  if (!url) { toast('Enter a target URL', 'err'); return; }
  if (!url.startsWith('http')) url = 'https://' + url;
  const goal  = document.getElementById('scanGoal').value.trim();
  const scope = State.scope;

  const btn = document.getElementById('launchBtn');
  btn.disabled = true;
  btn.innerHTML = `<span class="spin"></span> Launching…`;

  const card = document.getElementById('progressCard');
  card.classList.add('show');
  document.getElementById('progressTitle').textContent = 'Scanning…';
  document.getElementById('progressTarget').textContent = url;
  document.getElementById('progressDot').style.background = 'var(--accent)';
  document.getElementById('progressDot').style.animation = 'pulse 1.5s ease infinite';
  document.getElementById('skillsTrack').innerHTML = '';
  document.getElementById('liveFindings').innerHTML = '';
  document.getElementById('progressDone').style.display = 'none';

  const skills = {};
  let lastReport = null;

  try {
    const resp = await fetch(api('/api/scan/stream'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
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
        try { const e = JSON.parse(line); onEvent(e, skills); if (e.event === 'done') lastReport = e.report; }
        catch {}
      }
    }
  } catch (e) { toast('Scan error: ' + e.message, 'err'); }

  btn.disabled = false;
  btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"/></svg> Launch Scan`;
  document.getElementById('progressDot').style.background = 'var(--green)';
  document.getElementById('progressDot').style.animation = 'none';

  if (lastReport) {
    State.report = lastReport;
    State.scanId = lastReport.id;
    document.getElementById('progressDone').style.display = 'flex';
    document.getElementById('viewResultsBtn').onclick = () => navigate('results', lastReport);
    toast(`Scan complete — ${lastReport.findings?.length || 0} findings`, 'ok');
    const autoNav = document.getElementById('toggleAutoNav');
    if (!autoNav || autoNav.checked) setTimeout(() => navigate('results', lastReport), 700);
  }
}

function onEvent(e, skills) {
  const track = document.getElementById('skillsTrack');
  const live  = document.getElementById('liveFindings');
  if (e.event === 'scan_start') { document.getElementById('progressTitle').textContent = `Scanning (${e.scope})`; return; }
  if (e.event === 'skill_start') { skills[e.skill] = { st: 'run', ct: 0 }; renderSkills(track, skills); return; }
  if (e.event === 'skill_done')  { if (skills[e.skill]) { skills[e.skill].st = 'done'; skills[e.skill].ct = e.findings_count || 0; } renderSkills(track, skills); return; }
  if (e.event === 'finding') {
    const f = e.finding || {};
    const s = sevCls(f.severity);
    if (s === 'Critical' && document.getElementById('toggleCritical')?.checked)
      toast('Critical: ' + (f.title || 'Finding'), 'err');
    const row = document.createElement('div');
    row.className = 'live-item';
    row.innerHTML = `<span class="sev ${s}">${s}</span><span class="live-text">${esc(f.title || 'Finding')}</span>`;
    live.appendChild(row);
  }
  if (e.event === 'error') toast('Error: ' + e.error, 'err');
}

function renderSkills(track, skills) {
  track.innerHTML = Object.entries(skills).map(([name, info]) =>
    `<div class="skill-item">
      <span class="skill-name">${name}</span>
      <span class="skill-state ${info.st}">${info.st === 'run' ? 'running' : 'done'}</span>
      <span class="skill-ct">${info.st === 'done' ? info.ct + ' found' : ''}</span>
    </div>`).join('');
}

// ── HISTORY ───────────────────────────────────────────────────────────────
async function loadHistory() {
  const scope   = document.getElementById('historyScope')?.value || '';
  const verdict = document.getElementById('historyVerdict')?.value || '';
  let url = '/api/history?limit=50';
  if (scope)   url += '&scope=' + encodeURIComponent(scope);
  if (verdict) url += '&verdict=' + encodeURIComponent(verdict);
  try {
    const data = await get(url);
    State.historyData = data.scans;
    document.getElementById('historyCount').textContent = `${data.total} scan${data.total !== 1 ? 's' : ''}`;
    renderHistory(data.scans);
  } catch (e) { toast('Could not load history', 'err'); }
}

function filterHistory() {
  const q = (document.getElementById('historySearch')?.value || '').toLowerCase();
  const f = q ? State.historyData.filter(s => (s.target_url + s.label).toLowerCase().includes(q)) : State.historyData;
  renderHistory(f);
}

function renderHistory(scans) {
  const list = document.getElementById('historyList');
  if (!scans?.length) {
    list.innerHTML = `<div class="empty"><svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="12 8 12 12 14 14"/><path d="M3.05 11a9 9 0 1 0 .5-4.5"/><polyline points="3 2 3 7 8 7"/></svg><div class="empty-title">No scans found</div><div class="empty-sub">Try adjusting filters</div></div>`;
    return;
  }
  list.innerHTML = scans.map(s => `
    <div class="scan-row" onclick="openScan('${s.id}')">
      <div class="scan-row-main">
        <div class="scan-url">${esc(shortUrl(s.target_url))}</div>
        <div class="scan-sub">${s.label ? esc(s.label) + ' · ' : ''}${fmtDate(s.scanned_at)}</div>
      </div>
      <span class="scope-tag">${s.scope || 'full'}</span>
      ${badgeHtml(s.risk_verdict, s.risk_score)}
      <span style="font-size:0.75rem;color:var(--t3)">${s.total || 0} findings${s.critical ? ` <span style="color:var(--red)">· ${s.critical}C</span>` : ''}</span>
      <span class="scan-time">${ago(s.scanned_at)}</span>
      <div onclick="event.stopPropagation()">
        <button class="btn btn-ghost btn-sm" onclick="deleteScan('${s.id}')">Delete</button>
      </div>
    </div>`).join('');
}

async function openScan(id) {
  try {
    const data = await get(`/api/history/${id}`);
    State.scanId = id; State.report = data.report || data;
    navigate('results', State.report);
  } catch (e) { toast('Could not load scan', 'err'); }
}

async function deleteScan(id) {
  if (!confirm('Delete this scan?')) return;
  try { await del(`/api/history/${id}`); toast('Scan deleted', 'ok'); loadHistory(); }
  catch (e) { toast('Delete failed', 'err'); }
}
async function deleteCurrentScan() { if (State.scanId) { await deleteScan(State.scanId); navigate('history'); } }

// ── FINDINGS ──────────────────────────────────────────────────────────────
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
  } catch (e) { toast('Could not load findings', 'err'); }
}

function filterFindings() {
  const q   = (document.getElementById('findingsSearch')?.value || '').toLowerCase();
  const sev = document.getElementById('findingsSev')?.value || '';
  let f = State.allFindings;
  if (q)   f = f.filter(x => (x.title + (x.category || '')).toLowerCase().includes(q));
  if (sev) f = f.filter(x => sevCls(x.severity) === sev);
  renderFindings(f, 'findingsList');
  document.getElementById('findingsCount').textContent = `${f.length} of ${State.allFindings.length} findings`;
}

// ── RESULTS ───────────────────────────────────────────────────────────────
function showResults(report) {
  if (!report) return;
  const findings = report.findings || [];
  const cls = riskCls(report.risk_verdict);
  document.getElementById('resultsUrl').textContent  = report.target_url || '—';
  document.getElementById('resultsMeta').textContent = `Scope: ${report.scope || '—'} · ${fmtDate(report.scanned_at)}`;
  document.getElementById('resultsRiskVerdict').innerHTML = badgeHtml(report.risk_verdict, report.risk_score);
  const ring = document.getElementById('scoreRing');
  ring.className = `score-ring ${cls}`;
  document.getElementById('scoreNum').textContent = report.risk_score != null ? report.risk_score : '—';
  document.getElementById('rc').textContent = findings.filter(f => sevCls(f.severity) === 'Critical').length;
  document.getElementById('rh').textContent = findings.filter(f => sevCls(f.severity) === 'High').length;
  document.getElementById('rm').textContent = findings.filter(f => sevCls(f.severity) === 'Medium').length;
  document.getElementById('rl').textContent = findings.filter(f => sevCls(f.severity) === 'Low').length;
  const sorted = [...findings].sort((a, b) => {
    const o = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    return (o[sevCls(a.severity)] ?? 5) - (o[sevCls(b.severity)] ?? 5);
  });
  renderFindings(sorted, 'resultsFindingsList');
  document.getElementById('resultsSummaryText').textContent  = report.summary || 'No summary.';
  document.getElementById('resultsEvidenceText').textContent = report.evidence_summary || 'No evidence summary.';
  const tags = document.getElementById('resultsSkillsRun');
  tags.innerHTML = (report.skills_run || []).map(s => `<span class="skill-tag">${esc(s)}</span>`).join('');
  renderPaths(report.attack_paths || [], 'resultsAttackPaths');
  document.getElementById('resultsRemediation').textContent = report.remediation_plan || 'No remediation plan.';
  const sugg = report.suggested_next_tests;
  const el = document.getElementById('resultsSuggested');
  if (Array.isArray(sugg)) el.innerHTML = sugg.map(t => `<div style="padding:0.2rem 0;color:var(--t2)">• ${esc(String(t))}</div>`).join('');
  else el.textContent = sugg || 'No suggestions.';
  document.querySelectorAll('.tab').forEach((b, i) => b.classList.toggle('on', i === 0));
  document.querySelectorAll('.panel').forEach((p, i) => p.classList.toggle('on', i === 0));
}

function renderFindings(findings, containerId) {
  const el = document.getElementById(containerId);
  if (!findings?.length) {
    el.innerHTML = `<div class="empty"><svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><div class="empty-title">No findings</div><div class="empty-sub">Nothing detected</div></div>`;
    return;
  }
  el.className = 'findings';
  el.innerHTML = findings.map((f, i) => {
    const s   = sevCls(f.severity);
    const uid = `fd-${containerId}-${i}`;
    const ev  = f.evidence || f.proof || f.url || '';
    const rem = f.remediation || f.fix || '';
    const showPoc = f.category === 'Authorization' || f.category === 'Authentication';
    return `<div class="finding" id="${uid}">
      <div class="finding-head" onclick="toggleF('${uid}')">
        <span class="sev ${s}">${s}</span>
        <div style="flex:1;min-width:0">
          <div class="finding-title-text">${esc(f.title || f.type || 'Finding')}</div>
          <div class="finding-cat">${esc(f.category || '')}</div>
        </div>
        <svg class="chevron" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
      </div>
      <div class="finding-body">
        ${f.description ? `<div class="frow"><div class="flbl">Description</div><div class="fval">${esc(f.description)}</div></div>` : ''}
        ${f.impact ? `<div class="frow"><div class="flbl">Impact</div><div class="fval">${esc(f.impact)}</div></div>` : ''}
        ${ev ? `<div class="frow"><div class="flbl">Evidence</div><div class="fcode">${esc(String(ev).substring(0, 500))}</div></div>` : ''}
        ${rem ? `<div class="frow"><div class="flbl">Remediation</div><div class="fval">${esc(rem)}</div></div>` : ''}
        ${showPoc ? `<button class="poc-btn" onclick="simPoc(${JSON.stringify(JSON.stringify(f))}, '${uid}')">Run PoC Simulation</button><div class="poc-res" id="pr-${uid}" style="display:none"></div>` : ''}
      </div>
    </div>`;
  }).join('');
}

function toggleF(uid) { document.getElementById(uid)?.classList.toggle('open'); }

async function simPoc(fjson, uid) {
  const f   = JSON.parse(fjson);
  const res = document.getElementById('pr-' + uid);
  res.style.display = 'block'; res.textContent = 'Running…';
  try {
    const r = await post('/api/poc/simulate', { finding: f });
    res.textContent = `${r.conclusion}\nSuccess: ${r.success} · Status: ${r.status_code || '—'}`;
    res.className = 'poc-res ' + (r.success ? 'ok' : 'err');
  } catch (e) { res.textContent = 'Error: ' + e.message; }
}

// ── ATTACK PATHS ──────────────────────────────────────────────────────────
function renderPaths(paths, id) {
  const el = document.getElementById(id);
  if (!paths?.length) {
    el.innerHTML = `<div class="empty"><div class="empty-title">No attack paths</div><div class="empty-sub">A full-scope scan may surface chained attack paths</div></div>`;
    return;
  }
  el.className = 'paths';
  el.innerHTML = paths.map(p => {
    const steps = Array.isArray(p.steps) ? p.steps : (p.chain || p.path || []);
    const chain = steps.length
      ? steps.map((s, i) => `${i ? '<span class="chain-arr">→</span>' : ''}<span class="chain-step">${esc(String(s))}</span>`).join('')
      : esc(p.description || '');
    return `<div class="path-card">
      <div class="path-name">${esc(p.title || p.name || 'Attack Path')}</div>
      <div class="path-chain">${chain}</div>
      ${p.impact ? `<div style="font-size:0.8125rem;color:var(--t3);margin-top:0.375rem">${esc(p.impact)}</div>` : ''}
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
    renderPaths(all, 'allAttackPaths');
  } catch { toast('Could not load attack paths', 'err'); }
}

// ── INVESTIGATION ─────────────────────────────────────────────────────────
function runChainLookup() {
  const addr = document.getElementById('chainAddr').value.trim();
  if (!addr) { toast('Enter an address', 'err'); return; }
  const el = document.getElementById('chainResult');
  el.textContent = 'Looking up…';
  post('/api/scan', { url: 'https://etherscan.io', goal: `Blockchain lookup: ${addr}`, scope: 'passive' })
    .then(r => { el.textContent = `Address: ${addr}\n\nRisk: ${r.risk_verdict || '—'}\nFindings: ${(r.findings || []).length}\n\nNote: use diverg-auto with blockchain skills for deep analysis.`; })
    .catch(e => { el.textContent = 'Error: ' + e.message; });
}

function runOsint() {
  const domain = document.getElementById('osintDomain').value.trim();
  if (!domain) { toast('Enter a domain', 'err'); return; }
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
  const url  = document.getElementById('pocUrl').value.trim();
  const el   = document.getElementById('pocResult');
  if (!url) { toast('Enter a URL', 'err'); return; }
  el.textContent = 'Running…';
  const body = { type, url };
  if (type === 'idor') { body.param_to_change = document.getElementById('pocParam').value.trim() || 'id'; body.new_value = document.getElementById('pocValue').value.trim() || '2'; }
  try {
    const r = await post('/api/poc/simulate', body);
    el.textContent = `Conclusion: ${r.conclusion}\nSuccess: ${r.success} · Status: ${r.status_code || '—'}${r.body_preview ? '\n\n' + r.body_preview.substring(0, 400) : ''}`;
    el.className = 'inv-result ' + (r.success ? 'ok' : 'err');
  } catch (e) { el.textContent = 'Error: ' + e.message; }
}

async function runReputation() {
  const target = document.getElementById('reputationTarget').value.trim();
  if (!target) { toast('Enter a target', 'err'); return; }
  const el = document.getElementById('reputationResult'); el.textContent = 'Checking…';
  const url = target.startsWith('http') ? target : 'https://' + target;
  try {
    const r = await post('/api/scan', { url, scope: 'passive', goal: `Entity reputation: ${target}` });
    const lines = [`Reputation: ${target}`, `Verdict: ${r.risk_verdict || '—'}`, ''];
    (r.findings || []).slice(0, 8).forEach(f => lines.push(`[${f.severity}] ${f.title}`));
    el.textContent = lines.join('\n');
  } catch (e) { el.textContent = 'Error: ' + e.message; }
}

document.getElementById('pocType')?.addEventListener('change', function() {
  document.getElementById('pocIdorFields').style.display = this.value === 'idor' ? 'block' : 'none';
});

// ── SETTINGS ──────────────────────────────────────────────────────────────
function loadSettings() { document.getElementById('settingsApiUrl').value = CFG.apiUrl; }

function saveSettings() {
  const url = document.getElementById('settingsApiUrl').value.trim();
  if (url) { CFG.apiUrl = url; localStorage.setItem('diverg_api', url); toast('Saved', 'ok'); }
}

async function testConnection() {
  const el = document.getElementById('connStatus');
  el.textContent = 'Testing…'; el.style.color = 'var(--t3)';
  try {
    const r = await get('/api/health');
    el.textContent = `Connected — ${r.service} v${r.version || '?'}`; el.style.color = 'var(--green)';
    toast('API online', 'ok');
  } catch (e) { el.textContent = 'Cannot reach API: ' + e.message; el.style.color = 'var(--red)'; toast('API offline', 'err'); }
}

async function exportHistory() {
  try {
    const d = await get('/api/history?limit=200');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([JSON.stringify(d, null, 2)], { type: 'application/json' }));
    a.download = `diverg-history-${Date.now()}.json`; a.click();
    toast('Exported', 'ok');
  } catch (e) { toast('Export failed', 'err'); }
}

async function clearHistory() {
  if (!confirm('Delete ALL scan history? This cannot be undone.')) return;
  try {
    const d = await get('/api/history?limit=200');
    for (const s of (d.scans || [])) await del(`/api/history/${s.id}`);
    toast('Cleared', 'ok'); loadHistory();
  } catch (e) { toast('Error: ' + e.message, 'err'); }
}

function exportReport() {
  if (!State.report) return;
  const a = document.createElement('a');
  const name = shortUrl(State.report.target_url || 'scan').replace(/[^a-z0-9]/gi, '-');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(State.report, null, 2)], { type: 'application/json' }));
  a.download = `diverg-${name}-${Date.now()}.json`; a.click();
}

// ── Init ──────────────────────────────────────────────────────────────────
loadHome();
