/* ═══════════════════════════════════════════════════════════════════════
   Diverg Console — Dashboard JS
   ═══════════════════════════════════════════════════════════════════════ */

function navigate(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const target = document.getElementById('page-' + page);
  if (target) target.classList.add('active');

  document.querySelectorAll('.nav-item').forEach(item => {
    item.classList.remove('active');
    if (item.dataset.page === page) item.classList.add('active');
  });

  document.querySelectorAll('.tab-bar-item').forEach(tab => {
    tab.classList.remove('active');
    if (tab.dataset.page === page) tab.classList.add('active');
  });

  document.getElementById('sidebar').classList.remove('open');

  if (page === 'rewards') loadRewards();
  if (page === 'credits') loadCredits();
  if (page === 'history') renderHistory();
  if (page === 'analytics') updateAnalytics();
  if (page === 'investigation') void loadSolanaWatchlist({ silent: true });
}

function toggleSidebar() { document.getElementById('sidebar').classList.toggle('open'); }
function toggleUserMenu() { document.getElementById('userMenu').classList.toggle('show'); }
function logout() {
  localStorage.removeItem('dv_session');
  localStorage.removeItem('diverg_token');
  localStorage.removeItem('diverg_user');
  window.location.href = '/dashboard/login.html';
}

function getSessionToken() {
  return localStorage.getItem('dv_session') || localStorage.getItem('diverg_token') || '';
}

let serverScans = [];
let serverFindings = [];
let serverSummary = null;
let currentUser = null;
let lastScanReport = null;
let lastScanTarget = '';
let lastScanScope = 'full';
let currentScanFindings = [];
let currentHistoryWindow = 'all';
let currentFindingsFilter = 'all';
const SCOPE_HELP_TEXT = {
  full: 'Recommended: Full — complete assessment across recon, web, API, and high-value flaw checks.',
  quick: 'Quick — fastest baseline pass for rapid triage and smoke checks.',
  web: 'Web — focused web app and browser-surface testing.',
  api: 'API — API endpoint and abuse-path focused coverage.',
  crypto: 'Crypto — chain-aware checks for crypto-facing surfaces.',
  recon: 'Recon — discovery-focused map of exposed assets and surface area.',
  passive: 'Passive — non-invasive checks with low operational impact.',
  attack: 'Attack — deeper exploit-chain style checks that may take longer.',
};

// ── Init ─────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const token = getSessionToken();
  if (!token) {
    window.location.href = '/dashboard/login.html';
    return;
  }
  if (!localStorage.getItem('dv_session') && token) {
    localStorage.setItem('dv_session', token);
  }
  if (!localStorage.getItem('diverg_token') && token) {
    localStorage.setItem('diverg_token', token);
  }

  document.querySelectorAll('.nav-item').forEach(item =>
    item.addEventListener('click', () => navigate(item.dataset.page))
  );

  document.querySelectorAll('.tab-bar-item').forEach(tab =>
    tab.addEventListener('click', () => navigate(tab.dataset.page))
  );

  document.querySelectorAll('.toggle-pills').forEach(group => {
    group.querySelectorAll('.toggle-pill').forEach(pill => {
      pill.addEventListener('click', () => {
        group.querySelectorAll('.toggle-pill').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        if (group.id === 'leaderboardTabs') loadLeaderboard(pill.dataset.window);
      });
    });
  });

  document.querySelectorAll('.scope-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.scope-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      updateScopeHelp(pill.dataset.scope || 'full');
    });
  });

  document.querySelectorAll('#findingsTabs .toggle-pill').forEach((pill) => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('#findingsTabs .toggle-pill').forEach((p) => p.classList.remove('active'));
      pill.classList.add('active');
      currentFindingsFilter = pill.dataset.filter || 'all';
      renderFindingsPage();
    });
  });

  const findingsSearch = document.getElementById('findingsSearch');
  if (findingsSearch) findingsSearch.addEventListener('input', () => renderFindingsPage());
  const findingsSort = document.getElementById('findingsSort');
  if (findingsSort) findingsSort.addEventListener('change', () => renderFindingsPage());

  document.querySelectorAll('#historyTabs .toggle-pill').forEach((pill) => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('#historyTabs .toggle-pill').forEach((p) => p.classList.remove('active'));
      pill.classList.add('active');
      currentHistoryWindow = pill.dataset.time || 'all';
      renderHistory();
    });
  });

  const scanSearch = document.getElementById('scanFindingsSearch');
  const scanSeverity = document.getElementById('scanFindingsFilterSeverity');
  const scanVerified = document.getElementById('scanFindingsFilterVerified');
  const scanSort = document.getElementById('scanFindingsSort');
  if (scanSearch) scanSearch.addEventListener('input', () => applyScanFindingFilters());
  if (scanSeverity) scanSeverity.addEventListener('change', () => applyScanFindingFilters());
  if (scanVerified) scanVerified.addEventListener('change', () => applyScanFindingFilters());
  if (scanSort) scanSort.addEventListener('change', () => applyScanFindingFilters());

  document.addEventListener('click', (e) => {
    const userMenu = document.getElementById('userMenu');
    if (
      userMenu &&
      !e.target.closest('.user') &&
      !e.target.closest('.user-menu')
    ) {
      userMenu.classList.remove('show');
    }
  });
  const avatarFileInput = document.getElementById('avatarFileInput');
  if (avatarFileInput) {
    avatarFileInput.addEventListener('change', onAvatarFileSelected);
  }

  const quickUrl = document.getElementById('quickUrl');
  if (quickUrl) {
    quickUrl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const v = e.target.value.trim();
        const scanUrl = document.getElementById('scanUrl');
        if (v && scanUrl) {
          navigate('scanner');
          scanUrl.value = v;
          launchScan();
        }
      }
    });
  }

  loadSettings();
  loadUserProfile();
  ensureDefaultScope();
  updateScopeHelp('full');
  syncDashboardData();
  loadCredits();

  const tokenMintInput = document.getElementById('tokenMint');
  if (tokenMintInput) {
    tokenMintInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        runTokenBundle();
      }
    });
  }

  void refreshSolanaWatchlistCacheFromApi().then((ok) => {
    if (ok) renderSolanaWatchlistDom();
  });
});

function updateScopeHelp(scope) {
  const el = document.getElementById('scanScopeHelp');
  if (!el) return;
  el.textContent = SCOPE_HELP_TEXT[scope] || SCOPE_HELP_TEXT.full;
}

function ensureDefaultScope() {
  const pills = Array.from(document.querySelectorAll('.scope-pill'));
  if (!pills.length) return;
  const active = pills.find((p) => p.classList.contains('active'));
  if (active) return;
  const full = pills.find((p) => (p.dataset.scope || '') === 'full');
  (full || pills[0]).classList.add('active');
}

function getAvatarStorageKey(userId) {
  return 'dv_avatar_' + (userId || 'anon');
}

function nameToInitials(name) {
  const clean = String(name || '').trim();
  if (!clean) return 'DV';
  const parts = clean.split(/\s+/).filter(Boolean);
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}

function applyUserProfileUI(user) {
  const avatarEl = document.getElementById('userAvatar');
  const nameEl = document.getElementById('userName');
  if (!avatarEl || !nameEl) return;

  const displayName = (user && user.name) || (user && user.email ? user.email.split('@')[0] : 'Operator');
  nameEl.textContent = displayName;

  const avatarKey = getAvatarStorageKey(user && user.id);
  const customAvatar = localStorage.getItem(avatarKey) || '';
  const backendAvatar = (user && user.avatar_url) || '';
  const avatarUrl = customAvatar || backendAvatar;

  avatarEl.style.backgroundImage = '';
  avatarEl.style.backgroundSize = '';
  avatarEl.style.backgroundPosition = '';
  avatarEl.style.backgroundRepeat = '';
  avatarEl.textContent = nameToInitials(displayName);

  if (avatarUrl) {
    avatarEl.style.backgroundImage = 'url("' + avatarUrl + '")';
    avatarEl.style.backgroundSize = 'cover';
    avatarEl.style.backgroundPosition = 'center';
    avatarEl.style.backgroundRepeat = 'no-repeat';
    avatarEl.textContent = '';
  }
}

async function loadUserProfile() {
  const token = getSessionToken();
  if (!token) return;
  const apiUrl = getApiUrl();

  try {
    const localUser = JSON.parse(localStorage.getItem('diverg_user') || '{}');
    if (localUser && (localUser.name || localUser.email)) {
      currentUser = localUser;
      applyUserProfileUI(currentUser);
    }
  } catch (_) {
    // Ignore parse issues and continue with API source of truth.
  }

  try {
    const res = await fetch(apiUrl + '/api/auth/me', {
      headers: { Authorization: 'Bearer ' + token },
    });
    if (!res.ok) return;
    const data = await res.json();
    if (data && data.user) {
      currentUser = data.user;
      localStorage.setItem('diverg_user', JSON.stringify(currentUser));
      applyUserProfileUI(currentUser);
    }
  } catch (_) {
    // Keep whatever we have locally.
  }
}

function customizeAvatar() {
  const input = document.getElementById('avatarFileInput');
  if (!input) return;
  input.value = '';
  input.click();
}

function onAvatarFileSelected(event) {
  const file = event.target.files && event.target.files[0];
  if (!file || !currentUser || !currentUser.id) return;
  if (file.size > 2 * 1024 * 1024) {
    alert('Avatar file is too large (max 2MB).');
    return;
  }

  const reader = new FileReader();
  reader.onload = () => {
    const dataUrl = String(reader.result || '');
    if (!dataUrl) return;
    localStorage.setItem(getAvatarStorageKey(currentUser.id), dataUrl);
    applyUserProfileUI(currentUser);
    document.getElementById('userMenu').classList.remove('show');
  };
  reader.readAsDataURL(file);
}

function resetAvatar() {
  if (!currentUser || !currentUser.id) return;
  localStorage.removeItem(getAvatarStorageKey(currentUser.id));
  applyUserProfileUI(currentUser);
  document.getElementById('userMenu').classList.remove('show');
}

// ── Helpers ──────────────────────────────────────────────────────────────
function getApiUrl() {
  const stored = (localStorage.getItem('dv_api_url') || '').trim();
  const currentOrigin = window.location.origin.replace(/\/+$/, '');
  const isCurrentLocal = /localhost|127\.0\.0\.1/i.test(window.location.hostname);
  const isStoredLocal = /localhost|127\.0\.0\.1/i.test(stored);

  // Prevent production dashboards from accidentally pointing at local dev API.
  if (!isCurrentLocal && isStoredLocal) {
    localStorage.setItem('dv_api_url', currentOrigin);
    return currentOrigin;
  }

  return (stored || currentOrigin).replace(/\/+$/, '');
}

function ts() {
  const d = new Date();
  return '[' + d.toTimeString().slice(0, 8) + ']';
}

function termLine(el, text, cls) {
  const span = document.createElement('span');
  if (cls) span.className = 't-' + cls;
  span.textContent = text;
  el.appendChild(span);
  el.appendChild(document.createTextNode('\n'));
  el.scrollTop = el.scrollHeight;
}

async function apiJson(path, body) {
  const res = await fetch(getApiUrl() + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer ' + getSessionToken(),
    },
    body: JSON.stringify(body || {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (data && data.code === 'insufficient_credits') {
      const req = Number(data.required || 0);
      const avail = Number(data.available || 0);
      throw new Error(`Insufficient credits: need ${req}, available ${avail}.`);
    }
    if (data && data.code === 'rate_limited') {
      const retry = Number(data.retry_after || 0);
      throw new Error(`Rate limited. Please wait ${retry > 60 ? Math.ceil(retry / 60) + ' minutes' : retry + ' seconds'} before trying again.`);
    }
    throw new Error(data.error || ('HTTP ' + res.status));
  }
  return data;
}

async function apiAuth(method, path, body) {
  const opts = {
    method,
    headers: { Authorization: 'Bearer ' + getSessionToken() },
  };
  if (body != null && method !== 'GET' && method !== 'DELETE') {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(getApiUrl() + path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || ('HTTP ' + res.status));
  }
  return data;
}

let lastTokenBundleMint = '';
let solanaWatchlistCache = [];

function normalizeSolanaMint(raw) {
  return String(raw || '').replace(/\s+/g, '').trim();
}

function isValidSolanaMintString(m) {
  const s = normalizeSolanaMint(m);
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s);
}

function tvlUsdFromWatchlist(mint) {
  const m = normalizeSolanaMint(mint);
  for (let i = 0; i < solanaWatchlistCache.length; i += 1) {
    const row = solanaWatchlistCache[i];
    if (normalizeSolanaMint(row.mint) === m && row.tvl_usd != null && row.tvl_usd !== '') {
      const t = Number(row.tvl_usd);
      if (!Number.isNaN(t) && t >= 0) return t;
    }
  }
  return null;
}

function formatWatchlistCheckedAt(rawTs) {
  if (!rawTs) return '';
  const d = new Date(rawTs);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

async function refreshSolanaWatchlistCacheFromApi() {
  try {
    const data = await apiAuth('GET', '/api/solana/watchlist');
    solanaWatchlistCache = Array.isArray(data.items) ? data.items : [];
    return true;
  } catch (_) {
    return false;
  }
}

let _watchlistFlashTimer = null;
function flashWatchlistMessage(message, isError) {
  const el = document.getElementById('tokenWatchlistFlash');
  if (!el) {
    if (message && isError) alert(message);
    return;
  }
  el.textContent = message || '';
  el.classList.remove('token-watchlist-flash--ok', 'token-watchlist-flash--error');
  if (message) {
    el.classList.add(isError ? 'token-watchlist-flash--error' : 'token-watchlist-flash--ok');
  }
  if (_watchlistFlashTimer) clearTimeout(_watchlistFlashTimer);
  if (!message) return;
  _watchlistFlashTimer = setTimeout(() => {
    el.textContent = '';
    el.classList.remove('token-watchlist-flash--ok', 'token-watchlist-flash--error');
  }, 3200);
}

function bindSolanaWatchlistRowActions(container) {
  if (!container) return;
  container.querySelectorAll('[data-watch-load]').forEach((b) => {
    b.addEventListener('click', () => {
      const m = b.getAttribute('data-watch-load') || '';
      const mintIn = document.getElementById('tokenMint');
      if (mintIn) mintIn.value = m;
      const tvl = b.getAttribute('data-watch-tvl');
      const tvlIn = document.getElementById('watchlistTvlInput');
      if (tvlIn) tvlIn.value = (tvl && tvl.trim() !== '') ? tvl : '';
    });
  });
  container.querySelectorAll('[data-watch-scan]').forEach((b) => {
    b.addEventListener('click', () => {
      const m = b.getAttribute('data-watch-scan') || '';
      const mintIn = document.getElementById('tokenMint');
      if (mintIn) mintIn.value = m;
      const tvl = b.getAttribute('data-watch-tvl');
      const tvlIn = document.getElementById('watchlistTvlInput');
      if (tvlIn) tvlIn.value = (tvl && tvl.trim() !== '') ? tvl : '';
      runTokenBundle();
    });
  });
  container.querySelectorAll('[data-watch-del]').forEach((b) => {
    b.addEventListener('click', async () => {
      const id = parseInt(b.getAttribute('data-watch-del'), 10);
      if (!id) return;
      try {
        await apiAuth('DELETE', '/api/solana/watchlist/' + id);
        await loadSolanaWatchlist({ silent: true });
      } catch (err) {
        flashWatchlistMessage(String(err.message || err), true);
      }
    });
  });
}

function renderSolanaWatchlistDom() {
  const el = document.getElementById('solanaWatchlistBody');
  if (!el) return;
  const items = solanaWatchlistCache;
  if (!items.length) {
    el.innerHTML = '<div class="analytics-empty">No mints saved yet. Add the current mint or use “Add to watchlist” after a scan.</div>';
    return;
  }
  el.innerHTML = items.map((row) => {
    const mv = row.mint || '';
    const v = row.last_verdict ? escHtml(row.last_verdict) : '—';
    const s = row.last_risk_score != null && row.last_risk_score !== '' ? escHtml(String(row.last_risk_score)) : '—';
    const checked = formatWatchlistCheckedAt(row.last_checked_at);
    const checkedHtml = checked
      ? `<span title="From your last successful bundle scan for this mint">Last scan: ${escHtml(checked)}</span>`
      : '<span>Last scan: —</span>';
    const tvlN = row.tvl_usd != null && row.tvl_usd !== '' ? Number(row.tvl_usd) : NaN;
    const tvlForAttr = (!Number.isNaN(tvlN) && tvlN >= 0) ? String(tvlN) : '';
    const tvlLine = tvlForAttr
      ? `<div class="token-watchlist-tvl">Saved TVL (self-reported): $${escHtml(tvlN.toLocaleString(undefined, { maximumFractionDigits: 0 }))} — sent with bundle scans for tier context.</div>`
      : '';
    return `<div class="analytics-item analytics-item-stack token-watchlist-row">
      <div><strong class="token-mono-clip" title="${escAttr(mv)}">${escHtml(mv)}</strong></div>
      <div class="token-watchlist-meta"><span>Last verdict: ${v}</span><span>Score: ${s}</span>${checkedHtml}</div>
      <p class="token-watchlist-snapshot-note">Verdict and score reflect bundle heuristics (sampled holders, funding overlap)—not a full protocol audit.</p>
      ${tvlLine}
      <div class="token-watchlist-actions-inline">
        <button type="button" class="btn btn-ghost btn-sm" data-watch-load="${escAttr(mv)}" data-watch-tvl="${escAttr(tvlForAttr)}">Load</button>
        <button type="button" class="btn btn-ghost btn-sm" data-watch-scan="${escAttr(mv)}" data-watch-tvl="${escAttr(tvlForAttr)}">Run scan</button>
        <button type="button" class="btn btn-ghost btn-sm" data-watch-del="${row.id}">Remove</button>
      </div>
    </div>`;
  }).join('');
  bindSolanaWatchlistRowActions(el);
}

async function loadSolanaWatchlist(options) {
  const silent = options && options.silent;
  const el = document.getElementById('solanaWatchlistBody');
  if (!el) return;
  if (!silent) {
    el.innerHTML = '<div class="analytics-empty">Loading watchlist…</div>';
  }
  const ok = await refreshSolanaWatchlistCacheFromApi();
  if (!ok && !silent) {
    solanaWatchlistCache = [];
    el.innerHTML = '<div class="analytics-empty">Could not load watchlist. Check you are signed in.</div>';
    return;
  }
  renderSolanaWatchlistDom();
}

async function solanaWatchlistAddCurrentMint() {
  const mint = normalizeSolanaMint(document.getElementById('tokenMint')?.value || '');
  if (!mint) {
    alert('Enter a mint address first.');
    return;
  }
  if (!isValidSolanaMintString(mint)) {
    alert('Enter a valid Solana mint address (base58, typically 32–44 characters).');
    return;
  }
  await solanaWatchlistUpsertMint(mint);
}

async function solanaWatchlistAddFromResult() {
  const mint = normalizeSolanaMint(lastTokenBundleMint || document.getElementById('tokenMint')?.value || '');
  if (!mint) {
    alert('No mint to add.');
    return;
  }
  if (!isValidSolanaMintString(mint)) {
    alert('Mint on this result does not look like a valid Solana address.');
    return;
  }
  await solanaWatchlistUpsertMint(mint);
}

async function solanaWatchlistUpsertMint(mint) {
  const tvlEl = document.getElementById('watchlistTvlInput');
  const body = { mint: normalizeSolanaMint(mint) };
  if (tvlEl && tvlEl.value.trim()) {
    const x = parseFloat(String(tvlEl.value).replace(/,/g, ''));
    if (!Number.isNaN(x) && x >= 0) body.tvl_usd = x;
  }
  try {
    await apiAuth('POST', '/api/solana/watchlist', body);
    await refreshSolanaWatchlistCacheFromApi();
    renderSolanaWatchlistDom();
    flashWatchlistMessage('Saved to watchlist');
  } catch (err) {
    flashWatchlistMessage(String(err.message || err), true);
  }
}

function syncSolanaWatchlistSnapshot(mint, data) {
  if (!mint || !data || data.error) return;
  const m = normalizeSolanaMint(mint);
  if (!isValidSolanaMintString(m)) return;
  const verdict = String(data.risk_verdict || '').trim();
  const score = typeof data.risk_score === 'number' ? data.risk_score : null;
  apiAuth('PATCH', '/api/solana/watchlist', {
    mint: m,
    last_verdict: verdict,
    last_risk_score: score,
  })
    .then(() => loadSolanaWatchlist({ silent: true }))
    .catch(() => {});
}

function withProgress(out, label, promiseFactory) {
  const started = Date.now();
  let tick = 0;
  const timer = setInterval(() => {
    tick += 1;
    const sec = Math.round((Date.now() - started) / 1000);
    const dots = '.'.repeat((tick % 3) + 1);
    termLine(out, ts() + ' ' + label + ' still running' + dots + ' (' + sec + 's)', 'dim');
  }, 2200);

  return promiseFactory()
    .finally(() => clearInterval(timer));
}

// ── Skill labels for terminal output ─────────────────────────────────────
const SKILL_LABELS = {
  osint: 'External intelligence & DNS recon',
  recon: 'Subdomain & port enumeration',
  headers_ssl: 'Security headers & TLS analysis',
  crypto_security: 'Cryptographic controls (JWT, TLS, ciphers)',
  data_leak_risks: 'Data leak & exposure checks',
  company_exposure: 'Admin panels, staging, docs, storage',
  web_vulns: 'Injection & web vulnerability tests',
  auth_test: 'Authentication & session security',
  api_test: 'API endpoint discovery & abuse',
  high_value_flaws: 'IDOR, secret exposure, payment tampering',
  workflow_probe: 'Business logic & workflow abuse',
  race_condition: 'Concurrency & race condition tests',
  payment_financial: 'Payment manipulation & refund abuse',
  client_surface: 'Client-side JS analysis & script intel',
  dependency_audit: 'Dependency versions & CVE checks',
  logic_abuse: 'Numeric bounds & parameter abuse',
  entity_reputation: 'Entity reputation & fraud research',
  chain_validation_abuse: 'Batch validation & path abuse',
};

function skillLabel(name) {
  if (SKILL_LABELS[name]) return SKILL_LABELS[name];
  const base = name.split(':')[0];
  if (SKILL_LABELS[base]) return SKILL_LABELS[base] + ' (' + name.split(':').slice(1).join(':') + ')';
  return name.replace(/_/g, ' ');
}

function escHtml(v) {
  return String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function severityRank(sev) {
  const map = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return map[String(sev || '').toLowerCase()] ?? 5;
}

function confidenceRank(conf) {
  const map = { high: 0, medium: 1, low: 2 };
  return map[String(conf || '').toLowerCase()] ?? 3;
}

function findingEvidence(f) {
  return String((f && (f.evidence || f.proof)) || '').trim();
}

function normalizeFinding(f = {}) {
  return {
    id: String(f.id || f.fingerprint || f.title || '') || undefined,
    title: f.title || 'Untitled finding',
    severity: String(f.severity || 'low').toLowerCase(),
    category: f.category || 'Other',
    confidence: String(f.confidence || '').toLowerCase(),
    verified: !!f.verified,
    evidence: findingEvidence(f),
    impact: String(f.impact || f.business_impact || '').trim(),
    remediation: String(f.remediation || f.fix || f.recommendation || '').trim(),
    source: String(f.source || f._source_skill || '').trim(),
    url: String(f.url || f.endpoint || '').trim(),
  };
}

function normalizeFindings(list) {
  return (Array.isArray(list) ? list : []).map((f) => normalizeFinding(f));
}

function filteredOutTotal(report) {
  const evidence = report?.evidence_summary || {};
  return Number(report?.filtered_out_total ?? evidence.filtered_out_total ?? 0);
}

function filteredOutBreakdown(report) {
  const evidence = report?.evidence_summary || {};
  return report?.filtered_out_breakdown || evidence.filtered_out_breakdown || {};
}

function runtimeSeconds(metrics = {}) {
  return Number(metrics.elapsed_sec || metrics.duration_sec || metrics.runtime_sec || 0);
}

function verdictDisplay(report = {}) {
  const verdict = String(report.risk_verdict || '').trim();
  if (verdict) return verdict;
  const summary = String(report.risk_summary || '').trim();
  if (!summary) return 'Unknown';
  const firstSentence = summary.split('.').map((x) => x.trim()).filter(Boolean)[0];
  return firstSentence || summary.slice(0, 80);
}

function scoreOutOf100(v) {
  if (typeof v !== 'number' || Number.isNaN(v)) return 'n/a';
  return String(Math.max(0, Math.min(100, Math.round(v))));
}

function setInvestigationRaw(kind, data) {
  const wrap = document.getElementById(`${kind}RawWrap`);
  const pre = document.getElementById(`${kind}RawJson`);
  if (!wrap || !pre) return;
  wrap.style.display = 'block';
  pre.textContent = JSON.stringify(data || {}, null, 2);
}

function tokenVerdictBadge(verdict) {
  const v = String(verdict || '').trim().toLowerCase();
  if (v.includes('clean')) return { cls: 'badge-low', text: 'Clean' };
  if (v.includes('moderate')) return { cls: 'badge-medium', text: 'Moderate' };
  if (v.includes('high')) return { cls: 'badge-critical', text: 'High risk' };
  return { cls: 'badge-info', text: verdict || 'Unknown' };
}

function tokenSignalHumanize(sig) {
  const s = String(sig).toLowerCase();
  if (s.startsWith('bridge_mixer:')) return 'Funding path includes bridge or mixer contract interaction.';
  if (s.includes('same_first_fund')) return 'Multiple holders received initial funding in matching amounts.';
  if (s.includes('cex_strong_funder')) return 'A high share of holders were funded from exchange deposit wallets.';
  if (s.includes('parallel_cex_funder')) return 'Holders show parallel funding paths through exchange accounts.';
  if (s.includes('weak_custodial')) return 'Funder addresses show custodial or exchange-like labeling.';
  if (s.includes('mixer_keyword')) return 'Funder entity matched mixer-related labeling.';
  if (s.includes('shared_inbound')) return 'Multiple holders share the same inbound counterparty address.';
  if (s.includes('shared_outbound')) return 'Multiple holders sent tokens to the same receiving address.';
  if (s.startsWith('venue:')) return 'Funding routed through a known venue address.';
  return '';
}

function escAttr(v) {
  return String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function formatProgramTier(tier) {
  const v = String(tier || '').trim();
  if (!v) return 'baseline_program';
  return v.replaceAll('_', ' ');
}

function renderProgramList(rows, emptyText) {
  if (!Array.isArray(rows) || !rows.length) {
    return `<div class="analytics-empty">${escHtml(emptyText)}</div>`;
  }
  return rows.join('');
}

function formatTokenPct(n) {
  if (n === null || n === undefined || n === '') return '—';
  const x = Number(n);
  if (Number.isNaN(x)) return String(n);
  if (x < 0.01) return '<0.01%';
  return `${x.toFixed(2)}%`;
}

function renderTokenBundleLoading(deep) {
  const box = document.getElementById('tokenResult');
  if (!box) return;
  box.style.display = 'block';
  const note = deep ? 'Running deep analysis…' : 'Scanning on-chain holders…';
  box.innerHTML = `
    <div class="token-bundle-report token-bundle-report--loading">
      <div class="token-bundle-loading-title">${escHtml(note)}</div>
      <div class="token-bundle-skeleton" aria-hidden="true"></div>
    </div>`;
}

function renderTokenBundleError(mint, headline, detail) {
  const box = document.getElementById('tokenResult');
  if (!box) return;
  box.style.display = 'block';
  box.innerHTML = `
    <div class="token-bundle-report">
      <div class="token-bundle-header">
        <div>
          <h3 class="token-bundle-h3">${escHtml(headline)}</h3>
          <p class="token-bundle-lede">${escHtml(detail)}</p>
        </div>
        <span class="badge badge-critical">Unavailable</span>
      </div>
      <div class="token-mini-mono" title="${escHtml(mint)}">Mint: ${escHtml(mint)}</div>
    </div>`;
}

function truncAddr(addr) {
  const a = String(addr || '');
  return a.length > 12 ? `${a.slice(0, 6)}…${a.slice(-4)}` : a;
}

function renderTokenBundleSuccess(mint, data, opts) {
  const box = document.getElementById('tokenResult');
  if (!box) return;
  const o = opts && typeof opts === 'object' ? opts : {};
  lastTokenBundleMint = normalizeSolanaMint(mint);
  box.style.display = 'block';
  const verdict = data.risk_verdict || 'Unknown';
  const badge = tokenVerdictBadge(verdict);
  const coord = typeof data.risk_score === 'number' ? Math.max(0, Math.min(100, data.risk_score)) : 0;
  const cp = typeof data.cluster_pct_supply === 'number' ? data.cluster_pct_supply : 0;
  const cw = data.cluster_wallet_count ?? 0;
  const holderCount = data.params?.unique_holders_sampled
    ?? data.top_holders?.length
    ?? data.holder_count
    ?? data.holders_count
    ?? '—';
  const signals = Array.isArray(data.risk_signals) ? data.risk_signals : [];
  const summary = String(data.risk_summary || '').trim();
  const signalBlocks = signals.slice(0, 14).map((sig) => {
    const raw = String(sig);
    const human = tokenSignalHumanize(raw);
    const label = raw.length > 96 ? `${raw.slice(0, 93)}…` : raw;
    if (!human) return `<div class="token-signal-card"><div class="token-signal-name">${escHtml(label)}</div></div>`;
    return `<div class="token-signal-card"><div class="token-signal-name">${escHtml(label)}</div><div class="token-signal-expl">${escHtml(human)}</div></div>`;
  }).join('');
  const cross = data.cross_chain_bundle && typeof data.cross_chain_bundle === 'object' && data.cross_chain_bundle.combined_escalation;
  const crossNote = cross
    ? '<p class="token-bundle-note">Cross-chain bridge and mixer funding signals detected across linked tokens.</p>'
    : '';
  const tpa = (data.token_program_analysis && typeof data.token_program_analysis === 'object')
    ? data.token_program_analysis
    : {};
  const am = (data.bundle_signals && data.bundle_signals.authority_misuse && typeof data.bundle_signals.authority_misuse === 'object')
    ? data.bundle_signals.authority_misuse
    : {};
  const tStd = String(tpa.token_standard || 'unknown');
  const tRisk = String(tpa.risk_level || 'low');
  const tExt = Array.isArray(tpa.extensions) ? tpa.extensions : [];
  const amScore = Number(am.score || 0);
  const amSig = Array.isArray(am.matched_signals) ? am.matched_signals : [];
  const solanaDepthBlock = `
    <details class="token-wallet-section">
      <summary class="token-bundle-h4">Solana protocol-depth signals</summary>
      <div class="token-bundle-summary" style="margin-top:8px;">
        <span class="token-bundle-summary-label">Token standard</span>
        <p>${escHtml(tStd)} · program-risk ${escHtml(tRisk)}</p>
      </div>
      <div class="token-bundle-summary" style="margin-top:8px;">
        <span class="token-bundle-summary-label">Authority misuse</span>
        <p>score ${Number.isFinite(amScore) ? amScore.toFixed(2) : '0.00'} / 10 · signals ${escHtml(String(amSig.length))}</p>
      </div>
      ${tExt.length ? `<div class="token-bundle-summary" style="margin-top:8px;"><span class="token-bundle-summary-label">Token-2022 extensions</span><p>${escHtml(tExt.slice(0, 8).join(', '))}</p></div>` : ''}
    </details>
  `;

  const wlTvl = o.watchlistTvlUsd;
  const watchlistTvlNote = (wlTvl != null && !Number.isNaN(Number(wlTvl)))
    ? `<div class="token-bundle-verdict-hint">Using <strong>saved watchlist TVL</strong> (self-reported): $${escHtml(Number(wlTvl).toLocaleString(undefined, { maximumFractionDigits: 0 }))} — included in this request for security-profile tier context.</div>`
    : '';

  const holders = Array.isArray(data.top_holders) ? data.top_holders : [];
  const holdersRows = holders.slice(0, 20).map((h, i) => {
    const addr = h.wallet || '';
    const bal = h.amount_ui != null ? Number(h.amount_ui).toLocaleString(undefined, { maximumFractionDigits: 2 }) : '—';
    const pct = h.pct_supply != null ? `${Number(h.pct_supply).toFixed(2)}%` : '—';
    const funder = h.funder || '—';
    const cluster = h.in_focus_cluster ? '<span class="token-cluster-tag">cluster</span>' : '';
    return `<tr><td class="col-num">${i + 1}</td><td class="col-mono" title="${escHtml(addr)}">${escHtml(truncAddr(addr))}</td><td>${escHtml(bal)}</td><td>${escHtml(pct)}</td><td class="col-mono" title="${escHtml(funder)}">${escHtml(truncAddr(funder))}</td><td>${cluster}</td></tr>`;
  }).join('');

  const clusterWallets = Array.isArray(data.focus_cluster_wallets) ? data.focus_cluster_wallets : [];
  const holderMap = {};
  holders.forEach((h) => { if (h.wallet) holderMap[h.wallet] = h; });
  const clusterRows = clusterWallets.slice(0, 40).map((addr) => {
    const h = holderMap[addr] || {};
    const bal = h.amount_ui != null ? Number(h.amount_ui).toLocaleString(undefined, { maximumFractionDigits: 2 }) : '—';
    const pct = h.pct_supply != null ? `${Number(h.pct_supply).toFixed(2)}%` : '—';
    const funder = h.funder || '—';
    return `<tr><td class="col-mono" title="${escHtml(addr)}">${escHtml(truncAddr(addr))}</td><td>${escHtml(bal)}</td><td>${escHtml(pct)}</td><td class="col-mono" title="${escHtml(funder)}">${escHtml(truncAddr(funder))}</td></tr>`;
  }).join('');

  box.innerHTML = `
    <div class="token-bundle-report">
      <div class="token-bundle-header">
        <div>
          <h3 class="token-bundle-h3">Scan results</h3>
        </div>
        <div class="token-bundle-header-actions">
          <span class="badge ${badge.cls}">${escHtml(badge.text)}</span>
          <button type="button" class="btn btn-ghost btn-sm" id="tokenBundleWatchlistBtn">Add to watchlist</button>
        </div>
      </div>
      ${watchlistTvlNote}
      <div class="token-bundle-scores">
        <div class="token-score-block">
          <div class="token-score-head">
            <span>Funding overlap</span>
            <span class="token-score-num">${coord.toFixed(1)} / 100</span>
          </div>
          <p class="token-score-desc">Higher values indicate stronger overlap in how holders were funded.</p>
          <div class="token-meter" role="img" aria-label="Funding overlap ${coord} out of 100"><div class="token-meter-fill token-meter-fill--coord" style="width:${coord}%"></div></div>
        </div>
        <div class="token-score-block">
          <div class="token-score-head">
            <span>Largest cluster</span>
            <span class="token-score-num">${formatTokenPct(cp)} · ${cw} wallets</span>
          </div>
          <p class="token-score-desc">Percentage of sampled supply held by the largest linked wallet group.</p>
          <div class="token-meter" role="img" aria-label="Cluster ${formatTokenPct(cp)}"><div class="token-meter-fill token-meter-fill--cluster" style="width:${Math.min(100, Math.max(0, cp))}%"></div></div>
        </div>
      </div>
      <div class="token-bundle-metrics">
        <div class="token-metric"><span class="token-metric-label">Mint</span><span class="token-metric-val token-mono-clip" title="${escHtml(mint)}">${escHtml(mint)}</span></div>
        <div class="token-metric"><span class="token-metric-label">Verdict</span><span class="token-metric-val">${escHtml(verdict)}</span></div>
        <div class="token-metric"><span class="token-metric-label">Holders scanned</span><span class="token-metric-val">${escHtml(String(holderCount))}</span></div>
        <div class="token-metric"><span class="token-metric-label">Cluster wallets</span><span class="token-metric-val">${cw}</span></div>
      </div>
      ${summary ? `<div class="token-bundle-summary"><span class="token-bundle-summary-label">Summary</span><p>${escHtml(summary)}</p></div>` : ''}
      ${signals.length ? `<div class="token-signals-section"><h4 class="token-bundle-h4">What drove the score</h4><div class="token-signal-grid">${signalBlocks}</div></div>` : ''}
      ${solanaDepthBlock}
      ${holdersRows ? `<details class="token-wallet-section"><summary class="token-bundle-h4">Top holders (${holders.length})</summary><div class="token-wallet-table"><table><thead><tr><th class="col-num">#</th><th>Address</th><th>Balance</th><th>% Supply</th><th>Funder</th><th></th></tr></thead><tbody>${holdersRows}</tbody></table></div></details>` : ''}
      ${clusterRows ? `<details class="token-wallet-section"><summary class="token-bundle-h4">Cluster wallets (${clusterWallets.length})</summary><div class="token-wallet-table"><table><thead><tr><th>Address</th><th>Balance</th><th>% Supply</th><th>Funder</th></tr></thead><tbody>${clusterRows}</tbody></table></div></details>` : ''}
      ${crossNote}
    </div>`;
  const wlBtn = document.getElementById('tokenBundleWatchlistBtn');
  if (wlBtn) wlBtn.addEventListener('click', () => { solanaWatchlistAddFromResult(); });
}

function getFindingsPageList() {
  return serverFindings.length
    ? serverFindings
    : JSON.parse(localStorage.getItem('dv_findings') || '[]');
}

function renderSimpleList(items, emptyText = 'No data') {
  if (!Array.isArray(items) || !items.length) {
    return `<div class="analytics-empty">${emptyText}</div>`;
  }
  return items.join('');
}

function renderKpiAdjustmentsList(notes) {
  return renderSimpleList(notes, 'No KPI notes yet.');
}

function formatDiffBaselineTime(rawTs) {
  if (!rawTs) return '';
  const d = new Date(rawTs);
  if (Number.isNaN(d.getTime())) return String(rawTs);
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

function sanitizeDiffRows(rows) {
  if (!Array.isArray(rows)) return [];
  return rows.filter((x) => x && typeof x === 'object');
}

function renderScanDiff(report) {
  const diff = (report && report.scan_diff && typeof report.scan_diff === 'object') ? report.scan_diff : null;
  const hasBaseline = !!(diff && diff.has_baseline);
  const setText = (id, v) => {
    const el = document.getElementById(id);
    if (el) el.textContent = String(v);
  };
  setText('scanDiffNew', diff ? Number(diff.new_count || 0) : 0);
  setText('scanDiffFixed', diff ? Number(diff.fixed_count || 0) : 0);
  setText('scanDiffRegressed', diff ? Number(diff.regressed_count || 0) : 0);
  setText('scanDiffImproved', diff ? Number(diff.improved_count || 0) : 0);

  const note = document.getElementById('scanDiffNote');
  const cta = document.getElementById('scanDiffCta');
  const vStrip = document.getElementById('scanDiffVerificationStrip');
  const vs = diff && diff.verification_summary && typeof diff.verification_summary === 'object'
    ? diff.verification_summary
    : null;
  if (vStrip) {
    if (vs && vs.one_line) {
      vStrip.hidden = false;
      vStrip.textContent = String(vs.one_line);
      const nReg = diff ? Number(diff.regressed_count || 0) : 0;
      const nFixed = diff ? Number(diff.fixed_count || 0) : 0;
      if (nReg > 0) {
        vStrip.setAttribute('data-tone', 'warn');
      } else if (nFixed > 0 && hasBaseline) {
        vStrip.setAttribute('data-tone', 'positive');
      } else if (vs.baseline_scope_match === false && hasBaseline) {
        vStrip.setAttribute('data-tone', 'warn');
      } else {
        vStrip.setAttribute('data-tone', hasBaseline ? 'neutral' : 'neutral');
      }
    } else {
      vStrip.hidden = true;
      vStrip.textContent = '';
      vStrip.removeAttribute('data-tone');
    }
  }
  if (note) {
    if (!diff) {
      note.textContent = 'Run a first scan to create a baseline, then recheck the same target and profile to track deltas.';
    } else if (!hasBaseline) {
      note.textContent = 'No baseline scan for this URL and profile yet. This run establishes the baseline — recheck after remediation to see what cleared.';
    } else {
      const baselineLabel = formatDiffBaselineTime(diff.baseline_scanned_at);
      const baselineAt = baselineLabel ? ` (baseline: ${baselineLabel})` : '';
      let scopeHint = '';
      if (vs && vs.baseline_scope_match === false && vs.baseline_scope && vs.current_scope) {
        scopeHint =
          ` Profile mismatch: compared to latest “${String(vs.baseline_scope)}” run; this scan is “${String(vs.current_scope)}”.`;
      }
      note.textContent = `Compared against your most recent scan on this URL and profile${baselineAt}.${scopeHint}`;
    }
  }
  if (cta) {
    const recheckBtn = '<button class="btn btn-primary btn-sm" onclick="recheckLastTarget()">Recheck same target</button>';
    if (!diff || !hasBaseline) {
      cta.innerHTML = recheckBtn;
    } else {
      cta.innerHTML = `${recheckBtn}<span class="scan-diff-cta-hint"> Run again after fixes to refresh this comparison.</span>`;
    }
  }

  const toFindingRow = (f) =>
    `<div class="analytics-item analytics-item-stack"><strong>${escHtml(f.title || 'Untitled finding')}</strong><span>${escHtml((f.severity || 'info').toUpperCase())} · ${escHtml(f.category || 'Other')}</span></div>`;
  const toSeverityChangeRow = (pair) => {
    const before = pair.before || {};
    const after = pair.after || {};
    return `<div class="analytics-item analytics-item-stack"><strong>${escHtml(after.title || before.title || 'Untitled finding')}</strong><span>${escHtml((before.severity || 'info').toUpperCase())} → ${escHtml((after.severity || 'info').toUpperCase())}</span></div>`;
  };

  const newRowsRaw = sanitizeDiffRows(diff?.new_findings);
  const fixedRowsRaw = sanitizeDiffRows(diff?.fixed_findings);
  const regressedRowsRaw = sanitizeDiffRows(diff?.regressed_findings).filter((x) => x.before || x.after);
  const improvedRowsRaw = sanitizeDiffRows(diff?.improved_findings).filter((x) => x.before || x.after);

  const newList = document.getElementById('scanDiffNewList');
  if (newList) {
    const rows = newRowsRaw.slice(0, 5).map(toFindingRow);
    newList.innerHTML = renderSimpleList(rows, hasBaseline ? 'No new findings in this run.' : 'Baseline run (no prior diff).');
  }
  const fixedList = document.getElementById('scanDiffFixedList');
  if (fixedList) {
    const rows = fixedRowsRaw.slice(0, 5).map(toFindingRow);
    fixedList.innerHTML = renderSimpleList(rows, hasBaseline ? 'No fixed findings in this run.' : 'Baseline run (no prior diff).');
  }
  const regressedList = document.getElementById('scanDiffRegressedList');
  if (regressedList) {
    const rows = regressedRowsRaw.slice(0, 5).map(toSeverityChangeRow);
    regressedList.innerHTML = renderSimpleList(rows, 'No severity regressions.');
  }
  const improvedList = document.getElementById('scanDiffImprovedList');
  if (improvedList) {
    const rows = improvedRowsRaw.slice(0, 5).map(toSeverityChangeRow);
    improvedList.innerHTML = renderSimpleList(rows, 'No severity improvements.');
  }
}

function recheckLastTarget() {
  const url = String(lastScanTarget || '').trim();
  if (!url) {
    alert('Run a first scan so we can establish a baseline for diff tracking.');
    return;
  }
  const scanUrl = document.getElementById('scanUrl');
  if (scanUrl) scanUrl.value = url;
  launchScan();
}

function buildAssessmentModel(report, findings, diagnostics) {
  const verdict = report.risk_verdict || 'Unknown';
  const score = typeof report.risk_score === 'number' ? report.risk_score : 0;
  const critical = findings.filter((f) => f.severity === 'critical');
  const high = findings.filter((f) => f.severity === 'high');
  const verified = findings.filter((f) => f.verified);
  const attackPaths = Array.isArray(report.attack_paths) ? report.attack_paths : [];
  const guidance = Array.isArray(report.suggested_next_tests) ? report.suggested_next_tests : [];

  const model = {
    badgeClass: 'badge-info',
    badgeText: 'Unknown',
    headline: 'Mixed signal',
    subtitle: 'The scan completed, but the overall posture needs manual review.',
    scoreHelp: `Security score ${score}/100. Higher is better.`,
    reasons: [],
    actions: [],
  };

  if (verdict === 'Safe') {
    model.badgeClass = 'badge-low';
    model.badgeText = 'Looks Good';
    model.headline = 'This site currently looks relatively healthy.';
    model.subtitle = 'No major high-confidence exploit path is standing out from this scan.';
  } else if (verdict === 'Caution') {
    model.badgeClass = 'badge-medium';
    model.badgeText = 'Needs Attention';
    model.headline = 'This site is not obviously broken, but it needs attention.';
    model.subtitle = 'The scan found issues that could matter depending on the site’s purpose, data sensitivity, or auth flows.';
  } else if (verdict === 'Risky') {
    model.badgeClass = 'badge-critical';
    model.badgeText = 'Risky';
    model.headline = 'This site currently looks high risk.';
    model.subtitle = 'The scan found stronger indicators of exploitable or business-impacting security issues.';
  }

  if (critical.length) {
    model.reasons.push(`<div class="analytics-item analytics-item-stack"><strong>${critical.length} critical finding${critical.length > 1 ? 's' : ''}</strong><span>Critical issues strongly push the site into a risky state.</span></div>`);
  }
  if (high.length) {
    model.reasons.push(`<div class="analytics-item analytics-item-stack"><strong>${high.length} high-severity finding${high.length > 1 ? 's' : ''}</strong><span>High-severity findings mean the site needs attention even if the score is still decent.</span></div>`);
  }
  if (attackPaths.length) {
    const topScore = attackPaths.reduce((max, p) => Math.max(max, Number(p.exploitability_score || 0)), 0);
    model.reasons.push(`<div class="analytics-item analytics-item-stack"><strong>${attackPaths.length} attack path${attackPaths.length > 1 ? 's' : ''}</strong><span>The scanner found correlated issue chains with a top exploitability score of ${topScore}.</span></div>`);
  }
  if (verified.length) {
    model.reasons.push(`<div class="analytics-item analytics-item-stack"><strong>${verified.length} verified finding${verified.length > 1 ? 's' : ''}</strong><span>Verified findings have direct evidence rather than just weak heuristics.</span></div>`);
  }
  if (diagnostics.length) {
    model.reasons.push(`<div class="analytics-item analytics-item-stack"><strong>${diagnostics.length} scanner diagnostic${diagnostics.length > 1 ? 's' : ''}</strong><span>Some checks were blocked, errored, or incomplete, so absence of findings is not perfect proof of safety.</span></div>`);
  }
  if (!model.reasons.length) {
    model.reasons.push('<div class="analytics-item analytics-item-stack"><strong>No major signal</strong><span>This scan did not surface strong evidence of exploitable issues.</span></div>');
  }

  const topFindings = [...critical, ...high].slice(0, 3);
  topFindings.forEach((f) => {
    model.actions.push(`<div class="analytics-item analytics-item-stack"><strong>Review: ${escHtml(f.title)}</strong><span>${escHtml(f.category || 'Security issue')}</span></div>`);
  });
  guidance.slice(0, 3).forEach((g) => {
    model.actions.push(`<div class="analytics-item analytics-item-stack"><strong>${escHtml(g.action || 'Next step')}</strong><span>${escHtml(g.reason || '')}</span></div>`);
  });
  if (!model.actions.length) {
    model.actions.push('<div class="analytics-item analytics-item-stack"><strong>No urgent action</strong><span>Monitor the site and re-scan after major changes.</span></div>');
  }

  return model;
}

function setupScanTabs() {
  const pills = document.querySelectorAll('#scanResultsTabs .toggle-pill');
  if (!pills.length) return;
  pills.forEach((pill) => {
    pill.onclick = () => {
      pills.forEach((p) => p.classList.remove('active'));
      pill.classList.add('active');
      const tab = pill.dataset.scanTab;
      document.querySelectorAll('.scan-tab-panel').forEach((panel) => {
        panel.classList.toggle('active', panel.id === `scanTab-${tab}`);
      });
    };
  });
}

function setActiveScanTab(tab) {
  const pills = document.querySelectorAll('#scanResultsTabs .toggle-pill');
  pills.forEach((p) => p.classList.toggle('active', p.dataset.scanTab === tab));
  document.querySelectorAll('.scan-tab-panel').forEach((panel) => {
    panel.classList.toggle('active', panel.id === `scanTab-${tab}`);
  });
}

function getScanFilteredFindings() {
  const q = String(document.getElementById('scanFindingsSearch')?.value || '').trim().toLowerCase();
  const sev = String(document.getElementById('scanFindingsFilterSeverity')?.value || 'all');
  const verifiedMode = String(document.getElementById('scanFindingsFilterVerified')?.value || 'all');
  const sortMode = String(document.getElementById('scanFindingsSort')?.value || 'severity');

  let out = [...currentScanFindings];
  if (sev !== 'all') out = out.filter((f) => f.severity === sev);
  if (verifiedMode === 'verified') out = out.filter((f) => f.verified);
  if (verifiedMode === 'unverified') out = out.filter((f) => !f.verified);
  if (q) {
    out = out.filter((f) =>
      String(f.title || '').toLowerCase().includes(q) ||
      String(f.category || '').toLowerCase().includes(q) ||
      String(f.evidence || '').toLowerCase().includes(q)
    );
  }
  out.sort((a, b) => {
    if (sortMode === 'confidence') return confidenceRank(a.confidence) - confidenceRank(b.confidence) || severityRank(a.severity) - severityRank(b.severity);
    if (sortMode === 'title') return String(a.title || '').localeCompare(String(b.title || ''));
    return severityRank(a.severity) - severityRank(b.severity) || confidenceRank(a.confidence) - confidenceRank(b.confidence);
  });
  return out;
}

function renderScanFindingsTable() {
  const body = document.getElementById('scanResultsBody');
  const countEl = document.getElementById('scanFindingsCount');
  if (!body || !countEl) return;
  const findings = getScanFilteredFindings();
  countEl.textContent = `${findings.length} issue${findings.length === 1 ? '' : 's'}`;
  if (!findings.length) {
    body.innerHTML = `<tr><td colspan="6"><div class="empty"><div class="empty-title">No matching findings</div><div class="empty-desc">Adjust filters or search terms.</div></div></td></tr>`;
    return;
  }
  body.innerHTML = findings.map((f, idx) => {
    const verifiedBadge = f.verified ? '<span style="color:#22c55e;font-size:0.7rem;margin-left:4px;" title="Verified">&#x2713;</span>' : '';
    const confLabel = f.confidence
      ? `<span class="conf-${f.confidence}" style="font-size:0.6875rem;">${escHtml(f.confidence)}</span>`
      : '<span style="font-size:0.6875rem;color:var(--text-dim);">n/a</span>';
    const proofButton = f.evidence
      ? `<button class="btn btn-ghost trust-action-btn" onclick="toggleEvidenceRow('scan-ev-${idx}')">View proof</button>`
      : '<span class="evidence-tag">No direct proof</span>';
    const fpButton = `<button class="btn btn-ghost trust-action-btn" onclick="markFindingFalsePositive(${idx})">Mark FP</button>`;
    const why = f.impact
      ? escHtml(f.impact)
      : `Severity ${escHtml(f.severity)} in ${escHtml(f.category)} with ${escHtml(f.confidence || 'unknown')} confidence.`;
    const fix = f.remediation
      ? escHtml(f.remediation)
      : 'Review remediation guidance for this category and re-run scan after patching.';
    const proof = f.evidence ? escHtml(f.evidence) : 'No direct evidence captured in this run.';
    const sourceLine = f.source ? `<p class="trust-source">Source: ${escHtml(f.source)}</p>` : '';
    const targetLine = f.url ? `<p class="trust-source">Target: ${escHtml(f.url)}</p>` : '';
    const evidenceRow = `
      <tr class="evidence-row" id="scan-ev-${idx}" style="display:none;">
        <td></td>
        <td colspan="5">
          <div class="trust-details-grid">
            <div class="trust-detail">
              <span class="trust-label">What was found</span>
              <p>${escHtml(f.title)}</p>
              ${sourceLine}
              ${targetLine}
            </div>
            <div class="trust-detail">
              <span class="trust-label">Why it matters</span>
              <p>${why}</p>
            </div>
            <div class="trust-detail">
              <span class="trust-label">Proof</span>
              <pre>${proof}</pre>
            </div>
            <div class="trust-detail">
              <span class="trust-label">Fix first</span>
              <p>${fix}</p>
            </div>
          </div>
        </td>
      </tr>`;
    return `<tr><td class="col-num">${idx + 1}</td><td class="col-primary">${escHtml(f.title)}${verifiedBadge}</td><td><span class="badge badge-${escHtml(f.severity)}">${escHtml(f.severity)}</span></td><td>${escHtml(f.category)}</td><td>${confLabel}</td><td><div class="trust-actions">${proofButton}${fpButton}</div></td></tr>${evidenceRow}`;
  }).join('');
}

function toggleEvidenceRow(rowId) {
  const row = document.getElementById(rowId);
  if (!row) return;
  row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
}

async function markFindingFalsePositive(index) {
  const finding = currentScanFindings[index];
  if (!finding) return;
  const reason = window.prompt(
    'Reason for false positive?\nExample: expected behavior, protected by WAF, unreachable endpoint, duplicate finding',
    'expected behavior'
  );
  if (reason === null) return;
  const notes = window.prompt('Optional notes for future triage (can be empty):', '') ?? '';
  try {
    const out = await apiJson('/api/findings/false-positive', { finding, reason, notes });
    alert(out.added ? 'Marked as false positive and learning rule added.' : 'Already known false positive pattern.');
  } catch (err) {
    alert('Failed to mark false positive: ' + err.message);
  }
}

function renderScanPriorities(findings) {
  const box = document.getElementById('scanPriorityList');
  if (!box) return;
  const ranked = [...(findings || [])]
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || confidenceRank(a.confidence) - confidenceRank(b.confidence))
    .slice(0, 3);
  if (!ranked.length) {
    box.innerHTML = '<div class="analytics-empty">No strict findings detected in this run.</div>';
    return;
  }
  box.innerHTML = ranked.map((f, i) => {
    const why = f.impact || `${f.category} issue with ${f.confidence || 'unknown'} confidence.`;
    return `<div class="priority-item">
      <div class="priority-rank">#${i + 1}</div>
      <div class="priority-copy">
        <div class="priority-title">${escHtml(f.title)}</div>
        <div class="priority-meta"><span class="badge badge-${escHtml(f.severity)}">${escHtml(f.severity)}</span>${f.verified ? '<span class="priority-verified">verified</span>' : ''}</div>
        <p>${escHtml(why)}</p>
      </div>
    </div>`;
  }).join('');
}

function applyScanFindingFilters() {
  renderScanFindingsTable();
}

function renderScanAnalytics(report, findings) {
  lastScanReport = report || {};
  const summary = report.summary || {};
  const evidence = report.evidence_summary || {};
  const metrics = report.scan_metrics || {};
  const diagnostics = Array.isArray(report.scan_diagnostics) ? report.scan_diagnostics : [];
  const skillsRun = Array.isArray(report.skills_run) ? report.skills_run : [];
  const attackPaths = Array.isArray(report.attack_paths) ? report.attack_paths : [];
  const roleCounts = report.attack_path_role_counts || {};
  const gapAnalysis = Array.isArray(report.gap_analysis) ? report.gap_analysis : [];
  const suggestions = Array.isArray(report.suggested_next_tests) ? report.suggested_next_tests : [];
  const remediation = report.remediation_plan || {};
  const siteClass = report.site_classification || {};
  const confidenceCounts = evidence.confidence_counts || {};
  const verifiedCount = evidence.verified_count || findings.filter((f) => f.verified).length;
  const filteredTotal = filteredOutTotal(report);
  const filteredBreakdown = filteredOutBreakdown(report);
  const proofBundle = (report.proof_bundle && typeof report.proof_bundle === 'object') ? report.proof_bundle : {};
  const proofCount = Number(proofBundle.total_bundles || 0);
  const replayCandidates = Number(proofBundle.replay_candidates || 0);
  const provenance = (report.report_provenance && typeof report.report_provenance === 'object') ? report.report_provenance : {};
  const score = typeof report.risk_score === 'number' ? report.risk_score : 0;
  const verdict = verdictDisplay(report);
  const runtime = runtimeSeconds(metrics);
  const pages = Number(metrics.pages_crawled || 0);
  const endpoints = Number(metrics.endpoints_found || 0);
  const assessment = buildAssessmentModel(report, findings, diagnostics);
  const badge = document.getElementById('scanAssessmentBadge');
  badge.className = `badge ${assessment.badgeClass}`;
  badge.textContent = assessment.badgeText;
  document.getElementById('scanAssessmentHeadline').textContent = assessment.headline;
  document.getElementById('scanAssessmentSubtitle').textContent = assessment.subtitle;
  document.getElementById('scanAssessmentScoreHelp').textContent = assessment.scoreHelp;
  document.getElementById('scanAssessmentReasons').innerHTML = renderSimpleList(assessment.reasons, 'No clear reasons');
  document.getElementById('scanAssessmentActions').innerHTML = renderSimpleList(assessment.actions, 'No immediate actions');

  document.getElementById('scanSummaryScore').textContent = String(score);
  document.getElementById('scanSummaryVerdict').textContent = `Security score: higher is better · ${verdict}`;
  document.getElementById('scanSummaryStrict').textContent = String(findings.length);
  document.getElementById('scanSummarySeverities').textContent = `${summary.critical || 0} critical / ${summary.high || 0} high`;
  document.getElementById('scanSummaryVerified').textContent = String(verifiedCount);
  document.getElementById('scanSummaryConfidence').textContent = `${confidenceCounts.high || 0} high confidence`;
  document.getElementById('scanSummaryPaths').textContent = String(attackPaths.length);
  document.getElementById('scanSummaryRoles').textContent = `${Object.values(roleCounts).reduce((a, b) => a + Number(b || 0), 0)} role signals`;
  document.getElementById('scanSummarySkills').textContent = String(skillsRun.length);
  document.getElementById('scanSummaryDuration').textContent = `${runtime.toFixed(1)}s runtime`;
  document.getElementById('scanSummaryFiltered').textContent = String(filteredTotal);
  document.getElementById('scanSummaryFilteredNote').textContent = `Diagnostics: ${diagnostics.length} · Safe: ${report.safe_to_run ? 'yes' : 'no'}`;
  document.getElementById('scanSummaryDiagnostics').textContent = String(diagnostics.length);
  const complianceSummary = report.compliance_summary || {};
  const complianceFrameworks = Object.keys(complianceSummary);
  const complianceControls = complianceFrameworks.reduce((acc, fw) => {
    const controls = complianceSummary[fw] || {};
    return acc + Object.keys(controls).length;
  }, 0);
  document.getElementById('scanSummaryComplianceImpacted').textContent = String(complianceControls);
  document.getElementById('scanSummaryComplianceNote').textContent = `${complianceFrameworks.length} frameworks impacted`;
  const tiHits = findings.filter((f) => {
    const cat = String(f.category || '');
    const sev = String(f.severity || '').toLowerCase();
    return cat.includes('Threat Intelligence') && sev !== 'info';
  }).length;
  document.getElementById('scanSummaryThreatHits').textContent = String(tiHits);
  document.getElementById('scanSummaryThreatNote').textContent = tiHits ? 'Known-bad indicators detected' : 'No known-bad indicators';

  document.getElementById('scanEvidenceStrict').textContent = String(findings.length);
  document.getElementById('scanEvidenceFiltered').textContent = String(filteredTotal);
  document.getElementById('scanEvidenceVerified').textContent = String(verifiedCount);
  document.getElementById('scanEvidenceHigh').textContent = String(confidenceCounts.high || 0);
  document.getElementById('scanEvidenceMedium').textContent = String(confidenceCounts.medium || 0);
  document.getElementById('scanEvidenceLow').textContent = String(confidenceCounts.low || 0);

  const sourceRows = Object.entries(evidence.source_breakdown || {})
    .slice(0, 8)
    .map(([k, v]) => `<div class="analytics-item"><span>${escHtml(k)}</span><span class="analytics-pill">${v}</span></div>`);
  document.getElementById('scanEvidenceSources').innerHTML = renderSimpleList(sourceRows, 'No evidence source data');

  const filteredRows = Object.entries(filteredBreakdown)
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .map(([k, v]) => `<div class="analytics-item"><span>${escHtml(k.replaceAll('_', ' '))}</span><span class="analytics-pill">${v}</span></div>`);
  document.getElementById('scanFilteredBreakdown').innerHTML = renderSimpleList(
    filteredRows,
    filteredTotal ? 'Filtered without detailed reason map' : 'No filtered signals'
  );

  const byCategory = {};
  findings.forEach((f) => {
    const key = f.category || 'Other';
    byCategory[key] = (byCategory[key] || 0) + 1;
  });
  const categoryRows = Object.entries(byCategory)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([k, v]) => `<div class="analytics-item"><span>${escHtml(k)}</span><span class="analytics-pill">${v}</span></div>`);
  document.getElementById('scanCategoryBreakdown').innerHTML = renderSimpleList(categoryRows, 'No category analytics');

  document.getElementById('scanMetricDuration').textContent = `${runtime.toFixed(1)}s`;
  document.getElementById('scanMetricPages').textContent = String(pages);
  document.getElementById('scanMetricEndpoints').textContent = String(endpoints);
  document.getElementById('scanMetricSkills').textContent = String(skillsRun.length);
  document.getElementById('scanSkillsRun').innerHTML = renderSimpleList(
    skillsRun.map((s) => `<div class="analytics-item"><span>${escHtml(skillLabel(s))}</span><span class="analytics-pill">${escHtml(s)}</span></div>`),
    'No skill execution data'
  );

  document.getElementById('scanClassification').innerHTML = renderSimpleList([
    `<div class="analytics-item"><span>Crypto classified</span><span class="analytics-pill">${siteClass.is_crypto ? 'yes' : 'no'}</span></div>`,
    `<div class="analytics-item"><span>Crypto confidence</span><span class="analytics-pill">${siteClass.confidence ?? 0}</span></div>`,
    `<div class="analytics-item"><span>Auth supplied</span><span class="analytics-pill">${report.auth_supplied ? 'yes' : 'no'}</span></div>`,
    `<div class="analytics-item"><span>Proof bundles</span><span class="analytics-pill">${proofCount}</span></div>`,
    `<div class="analytics-item"><span>Replay candidates</span><span class="analytics-pill">${replayCandidates}</span></div>`,
    `<div class="analytics-item"><span>Program strategy</span><span class="analytics-pill">${escHtml((provenance.program_strategy && provenance.program_strategy.option) || 'C')}</span></div>`,
  ], 'No classification data');
  document.getElementById('scanGuidance').innerHTML = renderSimpleList(
    suggestions.map((g) => `<div class="analytics-item analytics-item-stack"><strong>${escHtml(g.action || 'Next step')}</strong><span>${escHtml(g.reason || '')}</span></div>`),
    'No follow-up guidance'
  );

  const renderRemediation = (id, items) => {
    document.getElementById(id).innerHTML = renderSimpleList(
      (items || []).slice(0, 8).map((item) => `<div class="analytics-item analytics-item-stack"><strong>${escHtml(item.title || 'Finding')}</strong><span>${escHtml(item.remediation || '')}</span></div>`),
      'No items'
    );
  };
  renderRemediation('scanRemediationNow', remediation.fix_now);
  renderRemediation('scanRemediationSoon', remediation.fix_soon);
  renderRemediation('scanRemediationHarden', remediation.harden);

  document.getElementById('scanPathCount').textContent = String(attackPaths.length);
  document.getElementById('scanPathTopScore').textContent = String(
    attackPaths.reduce((max, p) => Math.max(max, Number(p.exploitability_score || 0)), 0)
  );
  document.getElementById('scanPathEntry').textContent = String(roleCounts.entry || 0);
  document.getElementById('scanPathPrivilege').textContent = String(roleCounts.privilege || 0);
  document.getElementById('scanPathPivot').textContent = String(roleCounts.pivot || 0);
  document.getElementById('scanPathImpact').textContent = String((roleCounts.data || 0) + (roleCounts.financial || 0));
  document.getElementById('scanGapAnalysis').innerHTML = renderSimpleList(
    gapAnalysis.map((g) => `<div class="analytics-item analytics-item-stack"><strong>${escHtml(g.chain_template || 'Coverage gap')}</strong><span>${escHtml(g.reason || '')}</span></div>`),
    'No attack-path gaps'
  );

  document.getElementById('scanDiagnosticsList').innerHTML = renderSimpleList(
    diagnostics.map((d) => `<div class="analytics-item analytics-item-stack"><strong>${escHtml((d.skill || 'scanner') + ' · ' + (d.level || 'info'))}</strong><span>${escHtml(d.message || '')}</span></div>`),
    'No diagnostics'
  );
  renderScanDiff(report || {});
  renderComplianceSummary(report.compliance_summary || {});
  renderThreatIntelSummary(findings);
}

function exportComplianceCsv() {
  const report = (lastScanReport && typeof lastScanReport === 'object') ? lastScanReport : {};
  const summary = report.compliance_summary || {};
  const rows = [['framework', 'control', 'findings_count']];
  Object.entries(summary).forEach(([framework, controls]) => {
    Object.entries(controls || {}).forEach(([control, count]) => {
      rows.push([framework, control, String(count)]);
    });
  });
  if (rows.length === 1) {
    alert('No compliance data to export.');
    return;
  }
  const csv = rows
    .map((r) => r.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(','))
    .join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const href = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  a.href = href;
  a.download = `diverg_compliance_${stamp}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(href);
}

function exportThreatIntelJson() {
  const findings = Array.isArray(currentScanFindings) ? currentScanFindings : [];
  const tiFindings = findings.filter((f) => String(f.category || '').includes('Threat Intelligence'));
  if (!tiFindings.length) {
    alert('No threat intel findings to export.');
    return;
  }
  const payload = {
    exported_at: new Date().toISOString(),
    target: lastScanTarget || '',
    scope: lastScanScope || 'full',
    count: tiFindings.length,
    findings: tiFindings,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const href = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  a.href = href;
  a.download = `diverg_threat_intel_${stamp}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(href);
}

function renderComplianceSummary(compSummary) {
  const el = document.getElementById('scanComplianceSummary');
  if (!el) return;
  const frameworks = Object.entries(compSummary);
  if (!frameworks.length) {
    el.innerHTML = '<div class="analytics-empty">No compliance data for this scan</div>';
    return;
  }
  const labels = {
    owasp_top10: 'OWASP Top 10',
    pci_dss: 'PCI-DSS',
    soc2: 'SOC 2',
    nist_csf: 'NIST CSF',
    iso_27001: 'ISO 27001',
  };
  let html = '';
  for (const [fw, controls] of frameworks) {
    const name = labels[fw] || fw;
    const items = Object.entries(controls)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([ctrl, count]) =>
        `<div class="analytics-item"><span>${escHtml(ctrl)}</span><span class="analytics-pill">${count}</span></div>`
      ).join('');
    html += `<div style="margin-bottom:12px"><div style="font-weight:600;font-size:0.75rem;margin-bottom:4px;color:var(--text-primary)">${escHtml(name)}</div>${items}</div>`;
  }
  el.innerHTML = html;
}

function renderThreatIntelSummary(findings) {
  const el = document.getElementById('scanThreatIntelSummary');
  if (!el) return;
  const tiFindings = findings.filter(f => (f.category || '').includes('Threat Intelligence'));
  if (!tiFindings.length) {
    el.innerHTML = '<div class="analytics-empty">No threat intelligence findings</div>';
    return;
  }
  const infoOnly = tiFindings.every(f => (f.severity || '').toLowerCase() === 'info');
  if (infoOnly) {
    el.innerHTML = '<div class="analytics-empty">No threat intelligence hits — infrastructure appears clean</div>';
    return;
  }
  el.innerHTML = tiFindings
    .filter(f => (f.severity || '').toLowerCase() !== 'info')
    .slice(0, 10)
    .map(f => {
      const sev = (f.severity || 'medium').toLowerCase();
      return `<div class="analytics-item analytics-item-stack"><div><span class="badge badge-${sev}">${sev}</span> <strong>${escHtml(f.title || '')}</strong></div><span>${escHtml((f.evidence || '').slice(0, 200))}</span></div>`;
    }).join('');
}

// ── Scanner (streaming) ─────────────────────────────────────────────────
async function launchScan() {
  const url = document.getElementById('scanUrl').value.trim();
  if (!url) {
    alert('Enter a target URL before starting a scan.');
    return;
  }

  const scope = document.querySelector('.scope-pill.active')?.dataset.scope || 'full';
  const progressBox = document.getElementById('scanProgress');
  const terminal = document.getElementById('scanTerminal');

  terminal.innerHTML = '';
  progressBox.classList.add('show');
  document.getElementById('scanResults').style.display = 'none';

  termLine(terminal, ts() + ' ─── Diverg Scan Engine ───', 'accent');
  termLine(terminal, ts() + ' Target: ' + url, null);
  termLine(terminal, ts() + ' Scope:  ' + scope.toUpperCase(), null);
  termLine(terminal, ts() + ' Connecting to scan engine...', 'dim');

  const apiUrl = getApiUrl() + '/api/scan/stream';
  const token = getSessionToken();
  let report = null;

  try {
    const res = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + token,
      },
      body: JSON.stringify({ url, scope }),
    });

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody.error || 'HTTP ' + res.status);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    const activeSkills = new Set();
    let totalFindings = 0;
    const t0 = Date.now();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });

      const lines = buf.split('\n');
      buf = lines.pop();

      for (const line of lines) {
        if (!line.trim()) continue;
        let ev;
        try { ev = JSON.parse(line); } catch { continue; }

        if (ev.event === 'scan_start') {
          termLine(terminal, ts() + ' Scan accepted — engine running...', 'green');
        } else if (ev.event === 'skill_start') {
          activeSkills.add(ev.skill);
          termLine(terminal, ts() + ' ▸ ' + skillLabel(ev.skill), 'yellow');
        } else if (ev.event === 'skill_done') {
          activeSkills.delete(ev.skill);
          const cnt = ev.findings_count || 0;
          totalFindings += cnt;
          const cls = ev.error ? 'red' : (cnt > 0 ? 'accent' : 'green');
          const suffix = ev.error
            ? ' — error'
            : (cnt > 0 ? ' — ' + cnt + ' finding' + (cnt > 1 ? 's' : '') : ' — clean');
          termLine(terminal, ts() + ' ✓ ' + skillLabel(ev.skill) + suffix, cls);
        } else if (ev.event === 'done') {
          report = ev.report || ev;
        } else if (ev.event === 'error') {
          termLine(terminal, ts() + ' Error: ' + (ev.error || 'unknown'), 'red');
        }
      }
    }

    if (!report) throw new Error('Stream ended without results');

    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    const findings = Array.isArray(report.findings) ? report.findings : [];
    const attackPaths = Array.isArray(report.attack_paths) ? report.attack_paths : [];

    termLine(terminal, '', null);
    termLine(terminal, ts() + ' ─── Scan Complete (' + elapsed + 's) ───', 'green');
    termLine(terminal, ts() + ' Findings: ' + findings.length, findings.length ? 'yellow' : 'dim');
    if (typeof report.risk_score === 'number') {
      termLine(terminal, ts() + ' Risk score: ' + report.risk_score + (report.risk_verdict ? ' (' + report.risk_verdict + ')' : ''), 'accent');
    }
    if (Array.isArray(report.skills_run) && report.skills_run.length) {
      termLine(terminal, ts() + ' Skills: ' + report.skills_run.length + ' modules executed', 'dim');
    }

    progressBox.classList.remove('show');
    showScanResults(url, scope, findings, attackPaths, report);
    loadCredits();
    const autoNav = document.getElementById('prefAutoNav');
    if (!autoNav || autoNav.checked) {
      setActiveScanTab('findings');
    }
    syncDashboardData();
  } catch (err) {
    termLine(terminal, ts() + ' Scan failed: ' + err.message, 'red');
    progressBox.classList.remove('show');
  }
}

function showScanResults(url, scope, findingsInput, pathsInput, report) {
  const container = document.getElementById('scanResults');
  const findings = normalizeFindings(findingsInput);
  findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  currentScanFindings = findings;
  lastScanTarget = String(url || '').trim();
  lastScanScope = String(scope || 'full').trim().toLowerCase() || 'full';
  applyScanFindingFilters();
  renderScanPriorities(findings);

  container.style.display = 'block';

  const paths = Array.isArray(pathsInput) ? pathsInput : [];
  const pathsCard = document.getElementById('attackPathsCard');
  const pathsBody = document.getElementById('attackPathsBody');
  const pathsCount = document.getElementById('attackPathsCount');

  if (paths.length > 0) {
    pathsCount.textContent = paths.length + ' chains';
    pathsBody.innerHTML = paths.map(p => {
      const steps = Array.isArray(p.steps)
        ? p.steps
        : Array.isArray(p.path)
          ? p.path
          : [p.title || p.description || 'Attack path'];
      const chain = steps.map((s) => {
        if (s && typeof s === 'object') {
          const role = s.role ? `[${String(s.role)}] ` : '';
          const label = s.finding_title || s.title || s.name || 'attack step';
          return `<span class="step">${role}${label}</span>`;
        }
        return `<span class="step">${String(s)}</span>`;
      }).join('<span class="arrow">→</span>');
      const sev = String(
        p.severity
        || (Array.isArray(p.steps) && p.steps.some((s) => ['critical', 'high'].includes(String(s.severity || '').toLowerCase())) ? 'high' : 'medium')
      ).toLowerCase();
      const impact = p.impact || p.summary || p.description || '';
      return `<div class="attack-path"><div><div class="attack-path-chain">${chain}</div><div class="attack-path-impact">${impact}</div></div><div class="attack-path-severity"><span class="badge badge-${sev}">${sev}</span></div></div>`;
    }).join('');
    pathsCard.style.display = 'block';
  } else {
    pathsCard.style.display = 'none';
  }

  const totalFindings = findings.length;
  const critCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const score = typeof report?.risk_score === 'number'
    ? report.risk_score
    : Math.max(0, 100 - critCount * 25 - highCount * 15 - (totalFindings - critCount - highCount) * 5);

  addToHistory(url, scope, totalFindings, score, critCount, highCount);
  updateStats();
  renderFindings(findings, url);
  renderScanAnalytics(report || {}, findings);
  setupScanTabs();
}

function renderFindings(newFindings, url) {
  const stored = JSON.parse(localStorage.getItem('dv_findings') || '[]');
  const enriched = newFindings.map(f => ({ ...f, target: url, date: new Date().toLocaleString() }));
  const merged = [...enriched, ...stored].slice(0, 200);
  localStorage.setItem('dv_findings', JSON.stringify(merged));
  renderFindingsPage();
}

function renderFindingsPage() {
  const findings = getFindingsPageList();
  const body = document.getElementById('findingsBody');
  if (!body) return;
  const search = String(document.getElementById('findingsSearch')?.value || '').trim().toLowerCase();
  const sort = String(document.getElementById('findingsSort')?.value || 'newest');
  let out = [...findings];

  if (currentFindingsFilter === 'verified') {
    out = out.filter((f) => !!f.verified);
  } else if (currentFindingsFilter !== 'all') {
    out = out.filter((f) => String(f.severity || '').toLowerCase() === currentFindingsFilter);
  }
  if (search) {
    out = out.filter((f) =>
      String(f.title || '').toLowerCase().includes(search) ||
      String(f.category || '').toLowerCase().includes(search) ||
      String(f.target || '').toLowerCase().includes(search)
    );
  }
  out.sort((a, b) => {
    if (sort === 'severity') return severityRank(a.severity) - severityRank(b.severity);
    if (sort === 'confidence') return confidenceRank(a.confidence) - confidenceRank(b.confidence);
    if (sort === 'title') return String(a.title || '').localeCompare(String(b.title || ''));
    const ad = parseDateSafe(a.date)?.getTime() || 0;
    const bd = parseDateSafe(b.date)?.getTime() || 0;
    return bd - ad;
  });

  if (!out.length) {
    body.innerHTML = `<tr><td colspan="7"><div class="empty"><div class="empty-title">No findings</div><div class="empty-desc">Try a different filter or run a new scan.</div></div></td></tr>`;
    return;
  }
  body.innerHTML = out.slice(0, 50).map((f, i) => {
    const sev = (f.severity || 'low').toLowerCase();
    const verifiedBadge = f.verified ? '<span style="color:#22c55e;font-size:0.7rem;margin-left:4px;" title="Verified">&#x2713;</span>' : '';
    const confLabel = f.confidence ? `<span style="font-size:0.6875rem;color:var(--text-dim);">${f.confidence}</span>` : '';
    return `<tr><td class="col-num">${i + 1}</td><td class="col-primary">${escHtml(f.title)}${verifiedBadge}</td><td><span class="badge badge-${sev}">${sev}</span></td><td>${escHtml(f.category)}</td><td>${confLabel}</td><td class="col-mono" style="max-width:160px;overflow:hidden;text-overflow:ellipsis;">${escHtml(f.target || '')}</td><td class="col-mono">${escHtml(f.date || '')}</td></tr>`;
  }).join('');
}

function clearScan() {
  document.getElementById('scanResults').style.display = 'none';
  document.getElementById('scanUrl').value = '';
}

// ── Investigation (SPL token scanner only) ───────────────────────────────
let lastBundleWatchlistTvlUsd = null;

async function runTokenBundle() {
  const mint = normalizeSolanaMint(document.getElementById('tokenMint').value);
  if (!mint) return;
  if (!isValidSolanaMintString(mint)) {
    alert('Enter a valid Solana mint address (base58, typically 32–44 characters).');
    return;
  }
  const mintInput = document.getElementById('tokenMint');
  if (mintInput && mintInput.value !== mint) mintInput.value = mint;
  await refreshSolanaWatchlistCacheFromApi();
  const deep = !!(document.getElementById('tokenDeepScan') && document.getElementById('tokenDeepScan').checked);
  const btn = document.getElementById('tokenScanBtn');
  if (btn) btn.disabled = true;
  renderTokenBundleLoading(deep);
  const heliusApiKey = (document.getElementById('heliusKey') || {}).value || localStorage.getItem('dv_helius_key') || '';
  const payload = {
    mint,
    scan_all_holders: deep,
    max_funded_by_lookups: deep ? 1200 : 350,
    include_x_intel: deep,
  };
  const tvlWl = tvlUsdFromWatchlist(mint);
  lastBundleWatchlistTvlUsd = tvlWl;
  if (tvlWl !== null) payload.tvl_usd = tvlWl;
  if (heliusApiKey) payload.helius_api_key = heliusApiKey;
  apiJson('/api/investigation/solana-bundle', payload)
    .then((data) => {
      if (data.error) {
        lastBundleWatchlistTvlUsd = null;
        renderTokenBundleError(mint, 'Scan did not complete', String(data.error));
        setInvestigationRaw('token', data);
        return;
      }
      renderTokenBundleSuccess(mint, data, { watchlistTvlUsd: lastBundleWatchlistTvlUsd });
      syncSolanaWatchlistSnapshot(mint, data);
      setInvestigationRaw('token', data);
      loadCredits();
    })
    .catch((err) => {
      lastBundleWatchlistTvlUsd = null;
      let detail = String(err.message || 'Unknown error');
      if (/authentication required/i.test(detail)) {
        detail = 'Not signed in, or this tab’s token does not match the API (wrong API URL in Settings, or stale session). Log out, confirm Settings → API URL matches this server, then sign in again.';
      } else if (/\b524\b|gateway time-?out|timeout/i.test(detail)) {
        detail = 'Gateway timeout (524): this scan took longer than the CDN/proxy waited—common with Deep scan. Try again with Deep scan off, or raise the proxy read timeout for /api/investigation/solana-bundle on your host.';
      }
      renderTokenBundleError(mint, 'Request failed', detail);
      setInvestigationRaw('token', { error: detail });
    })
    .finally(() => {
      if (btn) btn.disabled = false;
    });
}

// ── History & Stats ──────────────────────────────────────────────────────
function addToHistory(url, scope, findingsCount, score, critCount, highCount) {
  const scans = JSON.parse(localStorage.getItem('dv_scans') || '[]');
  scans.unshift({
    url, scope,
    findings: findingsCount,
    score: score !== undefined ? score : Math.max(0, 100 - findingsCount * 15),
    critical: critCount || 0,
    high: highCount || 0,
    date: new Date().toLocaleString()
  });
  localStorage.setItem('dv_scans', JSON.stringify(scans.slice(0, 100)));
  renderHistory();
}

function parseDateSafe(value) {
  if (!value) return null;
  try {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
  } catch (_) {
    return null;
  }
}

function percentDelta(current, previous) {
  if (!previous) {
    return current ? 100 : 0;
  }
  return Math.round(((current - previous) / previous) * 100);
}

function formatDeltaLabel(current, previous, mode = 'percent') {
  if (mode === 'count') {
    const diff = current - previous;
    return { text: `${diff >= 0 ? '+' : ''}${diff}`, up: diff >= 0 };
  }
  const diff = percentDelta(current, previous);
  return { text: `${diff >= 0 ? '+' : ''}${diff}%`, up: diff >= 0 };
}

function setDelta(elId, current, previous, mode = 'percent') {
  const el = document.getElementById(elId);
  if (!el) return;
  const out = formatDeltaLabel(current, previous, mode);
  el.textContent = out.text;
  if (el.classList.contains('stat-delta')) {
    el.classList.remove('up', 'down');
    el.classList.add(out.up ? 'up' : 'down');
  } else {
    el.classList.toggle('down', !out.up);
    el.classList.toggle('up', out.up);
  }
}

function renderActivityChart(activity) {
  const line = document.getElementById('activityChartLine');
  const fill = document.getElementById('activityChartFill');
  if (!line || !fill || !Array.isArray(activity) || !activity.length) return;
  const width = 500;
  const height = 160;
  const baseY = 140;
  const max = Math.max(...activity.map((x) => Number(x.count || 0)), 1);
  const step = activity.length > 1 ? width / (activity.length - 1) : width;
  const points = activity.map((item, idx) => {
    const x = Math.round(idx * step);
    const y = Math.round(baseY - ((Number(item.count || 0) / max) * 90));
    return [x, y];
  });
  const linePath = points.map(([x, y], idx) => `${idx === 0 ? 'M' : 'L'}${x} ${y}`).join(' ');
  const fillPath = `${linePath} L${width} ${height} L0 ${height} Z`;
  line.setAttribute('d', linePath);
  fill.setAttribute('d', fillPath);
}

function renderHistory() {
  const scans = serverScans.length
    ? serverScans
    : JSON.parse(localStorage.getItem('dv_scans') || '[]');
  const now = Date.now();
  const maxAgeMs = currentHistoryWindow === '24h' ? 24 * 60 * 60 * 1000
    : currentHistoryWindow === '7d' ? 7 * 24 * 60 * 60 * 1000
      : currentHistoryWindow === '30d' ? 30 * 24 * 60 * 60 * 1000
        : null;
  const filteredScans = maxAgeMs == null
    ? scans
    : scans.filter((s) => {
      const t = parseDateSafe(s.date)?.getTime();
      return t && (now - t) <= maxAgeMs;
    });

  const makeRows = (list) => list.map((s, i) =>
    `<tr><td class="col-num">${i + 1}</td><td class="col-primary col-mono">${s.url}</td><td><span class="badge badge-info">${s.scope}</span></td><td>${s.findings}</td><td>${s.score}/100</td><td class="col-mono">${s.date}</td><td><button class="btn btn-ghost" onclick="exportScanById('${String(s.id || '').replace(/'/g, '&#39;')}')">Export</button></td></tr>`
  ).join('');

  const hb = document.getElementById('historyBody');
  const hsb = document.getElementById('homeScansBody');
  if (hb) {
    hb.innerHTML = filteredScans.length
      ? makeRows(filteredScans)
      : `<tr><td colspan="7"><div class="empty"><div class="empty-title">No history in selected window</div><div class="empty-desc">Change the time filter or run a new scan.</div></div></td></tr>`;
  }
  if (hsb) {
    hsb.innerHTML = scans.length
      ? makeRows(scans.slice(0, 8))
      : `<tr><td colspan="6"><div class="empty"><div class="empty-title">No scans yet</div><div class="empty-desc">Launch a scan to get started.</div></div></td></tr>`;
  }

  const rf = document.getElementById('homeRecentFindings');
  const findings = (serverFindings.length ? serverFindings : JSON.parse(localStorage.getItem('dv_findings') || '[]')).slice(0, 5);
  if (rf) {
    rf.innerHTML = findings.length ? findings.map(f =>
      `<tr><td class="col-primary" style="font-size:0.75rem;">${f.title}</td><td><span class="badge badge-${(f.severity || 'low').toLowerCase()}">${f.severity}</span></td><td class="col-mono" style="font-size:0.625rem;color:var(--text-dim);">${f.date || ''}</td></tr>`
    ).join('') : `<tr><td colspan="3"><div class="empty" style="padding:20px;"><div class="empty-desc">No findings yet</div></div></td></tr>`;
  }
}

async function exportScanById(scanId) {
  const id = String(scanId || '').trim();
  if (!id) {
    alert('Scan export failed: missing scan id');
    return;
  }
  const apiUrl = getApiUrl();
  const token = getSessionToken();
  try {
    const res = await fetch(`${apiUrl}/api/history/${encodeURIComponent(id)}`, {
      headers: { Authorization: 'Bearer ' + token },
    });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new Error(e.error || ('HTTP ' + res.status));
    }
    const payload = await res.json();
    const targetRaw = String(payload.target_url || 'scan');
    const targetSafe = targetRaw.replace(/^https?:\/\//i, '').replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 80) || 'scan';
    const whenRaw = String(payload.scanned_at || payload.created_at || '').replace(/[:.]/g, '-');
    const whenSafe = whenRaw.slice(0, 32) || new Date().toISOString().replace(/[:.]/g, '-');
    const fileName = `diverg_scan_${targetSafe}_${whenSafe}_${id}.json`;
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const href = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = href;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(href);
  } catch (err) {
    alert('Scan export failed: ' + err.message);
  }
}

function updateStats() {
  const scans = serverScans.length
    ? serverScans
    : JSON.parse(localStorage.getItem('dv_scans') || '[]');
  const findings = serverFindings.length
    ? serverFindings
    : JSON.parse(localStorage.getItem('dv_findings') || '[]');
  const n = scans.length;
  const targets = new Set(scans.map(s => s.url)).size;
  const avg = serverSummary && typeof serverSummary.avg_risk_score === 'number'
    ? Math.round(serverSummary.avg_risk_score)
    : (n ? Math.round(scans.reduce((a, s) => a + (s.score || 0), 0) / n) : 0);

  const now = new Date();
  const dayMs = 24 * 60 * 60 * 1000;
  const scanDates = scans.map((s) => ({ ...s, parsedDate: parseDateSafe(s.date) })).filter((s) => s.parsedDate);
  const countInRange = (startMs, endMs, reducer = null) => scanDates.reduce((acc, s) => {
    const t = s.parsedDate.getTime();
    if (t >= startMs && t < endMs) {
      return acc + (reducer ? reducer(s) : 1);
    }
    return acc;
  }, 0);
  const uniqueTargetsInRange = (startMs, endMs) => new Set(
    scanDates.filter((s) => {
      const t = s.parsedDate.getTime();
      return t >= startMs && t < endMs;
    }).map((s) => s.url)
  ).size;

  const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const yesterdayStart = todayStart - dayMs;
  const weekStart = now.getTime() - (7 * dayMs);
  const prevWeekStart = now.getTime() - (14 * dayMs);
  const monthStart = now.getTime() - (30 * dayMs);
  const prevMonthStart = now.getTime() - (60 * dayMs);

  const scansToday = countInRange(todayStart, now.getTime());
  const scansYesterday = countInRange(yesterdayStart, todayStart);
  const findingsToday = countInRange(todayStart, now.getTime(), (s) => Number(s.findings || 0));
  const findingsYesterday = countInRange(yesterdayStart, todayStart, (s) => Number(s.findings || 0));
  const criticalThisWeek = countInRange(weekStart, now.getTime(), (s) => Number(s.critical || 0));
  const criticalPrevWeek = countInRange(prevWeekStart, weekStart, (s) => Number(s.critical || 0));
  const targetsToday = uniqueTargetsInRange(todayStart, now.getTime());
  const targetsYesterday = uniqueTargetsInRange(yesterdayStart, todayStart);
  const weekCount = countInRange(weekStart, now.getTime());
  const prevWeekCount = countInRange(prevWeekStart, weekStart);
  const monthCount = countInRange(monthStart, now.getTime());
  const prevMonthCount = countInRange(prevMonthStart, monthStart);
  const currentScoreAvg = scanDates.length
    ? Math.round(scanDates.reduce((acc, s) => acc + Number(s.score || 0), 0) / scanDates.length)
    : 0;
  const prevScoreAvgRaw = scanDates.filter((s) => s.parsedDate.getTime() >= prevWeekStart && s.parsedDate.getTime() < weekStart);
  const prevScoreAvg = prevScoreAvgRaw.length
    ? Math.round(prevScoreAvgRaw.reduce((acc, s) => acc + Number(s.score || 0), 0) / prevScoreAvgRaw.length)
    : currentScoreAvg;

  const totalCrit = serverSummary?.severity?.critical ?? scans.reduce((a, s) => a + (s.critical || 0), 0);
  const totalHigh = serverSummary?.severity?.high ?? scans.reduce((a, s) => a + (s.high || 0), 0);
  const totalMed = serverSummary?.severity?.medium ?? findings.filter(f => (f.severity || '').toLowerCase() === 'medium').length;
  const totalLow = serverSummary?.severity?.low ?? findings.filter(f => (f.severity || '').toLowerCase() === 'low').length;
  const totalFindings = findings.length;

  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  set('statScans', n);
  set('statCritical', totalCrit);
  set('statTargets', targets);
  set('statScore', n ? avg + '/100' : '—');
  set('bannerScans', scansToday);
  set('bannerFindings', totalFindings);
  set('bannerTargets', targets);
  set('analyticsScans', n);
  set('analyticsCritical', totalCrit);
  set('analyticsHigh', totalHigh);
  set('analyticsScore', avg);
  set('analyticsStrictFindings', Number(serverSummary?.strict_findings_total || findings.length || 0));
  set('analyticsFilteredSignals', Number(serverSummary?.filtered_signals_total || 0));
  set('analyticsProofBundles', Number(serverSummary?.proof_bundle_total || 0));
  set('analyticsProofReplayCandidates', Number(serverSummary?.proof_replay_candidates || 0));
  set('metricWeekly', weekCount);
  set('metricMonthly', monthCount);

  setDelta('bannerScansDelta', scansToday, scansYesterday, 'percent');
  setDelta('bannerFindingsDelta', findingsToday, findingsYesterday, 'count');
  setDelta('bannerTargetsDelta', targetsToday, targetsYesterday, 'count');
  setDelta('statScansDelta', weekCount, prevWeekCount, 'percent');
  setDelta('statCritDelta', criticalThisWeek, criticalPrevWeek, 'count');
  setDelta('statTargDelta', targetsToday, targetsYesterday, 'count');
  setDelta('statScoreDelta', avg, prevScoreAvg, 'percent');
  setDelta('metricWeeklyDelta', weekCount, prevWeekCount, 'percent');
  setDelta('metricMonthlyDelta', monthCount, prevMonthCount, 'percent');

  set('bannerPointsDelta', 'Live');

  const maxBar = Math.max(totalCrit, totalHigh, totalMed, totalLow, 1);
  const pct = v => Math.round((v / maxBar) * 100) + '%';
  const setBar = (fillId, valId, v) => {
    const fill = document.getElementById(fillId);
    const val = document.getElementById(valId);
    if (fill) fill.style.width = pct(v);
    if (val) val.textContent = v;
  };
  setBar('barCritical', 'valCritical', totalCrit);
  setBar('barHigh', 'valHigh', totalHigh);
  setBar('barMedium', 'valMedium', totalMed);
  setBar('barLow', 'valLow', totalLow);
  setBar('barCritical2', 'valCritical2', totalCrit);
  setBar('barHigh2', 'valHigh2', totalHigh);
  setBar('barMedium2', 'valMedium2', totalMed);
  setBar('barLow2', 'valLow2', totalLow);

  const activity = Array.isArray(serverSummary?.activity_30d) && serverSummary.activity_30d.length
    ? serverSummary.activity_30d
    : (() => {
        const buckets = {};
        for (let i = 29; i >= 0; i--) {
          const d = new Date(now.getTime() - (i * dayMs));
          const key = d.toISOString().slice(0, 10);
          buckets[key] = 0;
        }
        scanDates.forEach((s) => {
          const key = s.parsedDate.toISOString().slice(0, 10);
          if (key in buckets) buckets[key] += 1;
        });
        return Object.entries(buckets).map(([date, count]) => ({ date, count }));
      })();
  renderActivityChart(activity);
}

function updateAnalytics() { updateStats(); renderFindingsPage(); }

async function syncDashboardData() {
  const apiUrl = getApiUrl();
  const token = getSessionToken();
  if (!token) return;
  try {
    const [historyRes, findingsRes, summaryRes] = await Promise.all([
      fetch(apiUrl + '/api/history?limit=120', { headers: { Authorization: 'Bearer ' + token } }),
      fetch(apiUrl + '/api/findings?scan_limit=120&finding_limit=2000', { headers: { Authorization: 'Bearer ' + token } }),
      fetch(apiUrl + '/api/analytics/summary?limit=120', { headers: { Authorization: 'Bearer ' + token } }),
    ]);

    if (historyRes.ok) {
      const historyData = await historyRes.json();
      serverScans = (historyData.scans || []).map(s => ({
        id: s.id,
        url: s.target_url,
        scope: (s.scope || 'full').toLowerCase(),
        findings: Number(s.total || 0),
        score: Number(s.risk_score || 0),
        critical: Number(s.critical || 0),
        high: Number(s.high || 0),
        date: s.scanned_at || s.created_at || '',
      }));
      localStorage.setItem('dv_scans', JSON.stringify(serverScans.slice(0, 120)));
    }

    if (findingsRes.ok) {
      const findingsData = await findingsRes.json();
      serverFindings = (findingsData.findings || []).map(row => {
        const f = normalizeFinding(row.finding || {});
        return {
          title: f.title,
          severity: f.severity,
          category: f.category,
          target: row.target_url || '',
          date: row.scanned_at || '',
          confidence: f.confidence || '',
          verified: f.verified,
          evidence: f.evidence,
          impact: f.impact || '',
          remediation: f.remediation || '',
          source: f.source || '',
          url: f.url || '',
        };
      });
      localStorage.setItem('dv_findings', JSON.stringify(serverFindings.slice(0, 2000)));
    }

    if (summaryRes.ok) {
      serverSummary = await summaryRes.json();
    }
  } catch (_) {
    // Fallback to local cache already handled by render functions.
  }

  renderHistory();
  renderFindingsPage();
  updateStats();
}

// ── Rewards ──────────────────────────────────────────────────────────────
function loadRewards() {
  const apiUrl = getApiUrl();
  fetch(apiUrl + '/api/rewards/me', {
    headers: { 'Authorization': 'Bearer ' + getSessionToken() }
  })
    .then(r => r.ok ? r.json() : Promise.reject(r))
    .then(data => {
      const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
      set('rewardsBalance', (data.balance || 0).toLocaleString());
      set('bannerPoints', (data.balance || 0).toLocaleString());
      if (data.referral_code) set('referralCode', data.referral_code);

      const lb = document.getElementById('ledgerBody');
      if (data.recent_ledger && data.recent_ledger.length) {
        lb.innerHTML = data.recent_ledger.map(row =>
          `<tr><td class="col-primary">${formatReason(row.reason)}</td><td style="font-family:var(--mono);font-weight:700;color:${row.delta > 0 ? 'var(--green)' : 'var(--red)'};">${row.delta > 0 ? '+' : ''}${row.delta}</td><td class="col-mono">${row.created_at || ''}</td></tr>`
        ).join('');
      }
      loadLeaderboard('all');
    })
    .catch(() => {});
}

function loadLeaderboard(win) {
  const apiUrl = getApiUrl();
  fetch(apiUrl + '/api/rewards/leaderboard?window=' + (win || 'all'), {
    headers: { 'Authorization': 'Bearer ' + getSessionToken() }
  })
    .then(r => r.ok ? r.json() : Promise.reject(r))
    .then(data => {
      const body = document.getElementById('leaderboardBody');
      if (data.leaderboard && data.leaderboard.length) {
        body.innerHTML = data.leaderboard.map(e =>
          `<tr><td class="col-num" style="font-weight:700;${e.rank <= 3 ? 'color:var(--accent);' : ''}">${e.rank}</td><td class="col-primary">${e.display_name || e.user_id}</td><td style="font-family:var(--mono);font-weight:700;color:var(--accent);">${(e.points || 0).toLocaleString()}</td></tr>`
        ).join('');
      }
    })
    .catch(() => {});
}

function formatReason(reason) {
  const map = {
    scan_complete: 'Scan Completed', investigation_blockchain: 'Blockchain Investigation',
    investigation_blockchain_full: 'Full Chain Investigation', investigation_domain: 'Domain Investigation',
    investigation_reputation: 'Reputation Check', investigation_solana_bundle: 'Solana Bundle Analysis',
    poc_simulate: 'PoC Simulation', referral_signup_referrer: 'Referral (You)',
    referral_signup_referee: 'Referral Bonus', referral_first_scan: 'Referral First Scan',
  };
  return map[reason] || reason.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function copyReferral() {
  const code = document.getElementById('referralCode').textContent;
  if (!code || code === '—') return;
  navigator.clipboard.writeText(code).then(() => {
    const btn = document.querySelector('.referral-code-row .btn');
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
  });
}

// ── Credits ──────────────────────────────────────────────────────────────
let creditsState = null;
let _creditsResetTarget = null;
let _creditsCountdownTimer = null;

function _startCreditCountdown(resetIso) {
  if (_creditsCountdownTimer) clearInterval(_creditsCountdownTimer);
  _creditsCountdownTimer = null;
  if (!resetIso) return;
  const target = new Date(resetIso).getTime();
  if (isNaN(target)) return;
  _creditsResetTarget = target;

  function tick() {
    const diff = Math.max(0, _creditsResetTarget - Date.now());
    const h = Math.floor(diff / 3600000);
    const m = Math.floor((diff % 3600000) / 60000);
    const s = Math.floor((diff % 60000) / 1000);
    const pad = (n) => String(n).padStart(2, '0');
    const display = pad(h) + ':' + pad(m) + ':' + pad(s);
    setElText('creditsResetCountdown', display);
    setElText('creditsResetAt', display);
    if (diff <= 0) {
      clearInterval(_creditsCountdownTimer);
      _creditsCountdownTimer = null;
      setElText('creditsResetCountdown', '00:00:00');
      setTimeout(() => loadCredits(), 2000);
    }
  }

  tick();
  _creditsCountdownTimer = setInterval(tick, 1000);
}

function formatCreditsNumber(v) {
  const n = Number(v || 0);
  if (!Number.isFinite(n)) return '0';
  return (Math.round(n * 100) / 100).toLocaleString(undefined, { maximumFractionDigits: 2 });
}

function setElText(id, value) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = String(value);
}

function base58Encode(bytes) {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  if (!bytes || !bytes.length) return '';
  let digits = [0];
  for (let i = 0; i < bytes.length; i += 1) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j += 1) {
      const x = digits[j] * 256 + carry;
      digits[j] = x % 58;
      carry = Math.floor(x / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let out = '';
  for (let i = 0; i < bytes.length && bytes[i] === 0; i += 1) out += alphabet[0];
  for (let i = digits.length - 1; i >= 0; i -= 1) out += alphabet[digits[i]];
  return out;
}

function applyCreditsUI(data) {
  const state = (data && data.state) || {};
  creditsState = state;
  setElText('creditsRemaining', formatCreditsNumber(state.credits_available));
  setElText('creditsDailyGrant', formatCreditsNumber(state.daily_grant_total));
  setElText('creditsTokenBalance', formatCreditsNumber(state.token_balance_ui));
  _startCreditCountdown(data.next_reset_at);
  setElText('creditsBaseDaily', formatCreditsNumber(data.base_daily_credits));
  setElText('creditsTokensPerStep', formatCreditsNumber(data.tokens_per_step));
  setElText('creditsPerStep', formatCreditsNumber(data.credits_per_step));
  setElText('creditsMint', data.mint || '');
  const costs = data.costs || {};
  setElText('costWebScan', formatCreditsNumber(costs.web_scan != null ? costs.web_scan : 2));
  setElText('costTokenScan', formatCreditsNumber(costs.token_scan != null ? costs.token_scan : 2));
  setElText('costTokenDeep', formatCreditsNumber(costs.token_deep_scan != null ? costs.token_deep_scan : 3.5));

  const walletAddr = (state.wallet_address || '').trim();
  const isLinked = walletAddr.length > 0;
  const connectedEl = document.getElementById('creditsWalletConnected');
  const disconnectedEl = document.getElementById('creditsWalletDisconnected');
  const connectBtn = document.getElementById('creditsConnectBtn');
  const refreshBtn = document.getElementById('creditsRefreshBtn');
  if (connectedEl) connectedEl.style.display = isLinked ? 'block' : 'none';
  if (disconnectedEl) disconnectedEl.style.display = isLinked ? 'none' : 'block';
  if (connectBtn) {
    connectBtn.textContent = isLinked ? 'Change Wallet' : 'Connect Phantom';
  }
  if (refreshBtn) refreshBtn.style.display = isLinked ? '' : 'none';
  if (isLinked) {
    setElText('creditsWalletAddress', walletAddr);
    setElText('creditsWalletTokens', formatCreditsNumber(state.token_balance_ui));
  }
}

async function loadCredits() {
  try {
    const data = await apiAuth('GET', '/api/credits/me');
    applyCreditsUI(data || {});
  } catch (_) {
    // Keep existing UI values.
  }
}

async function connectPhantomAndLinkWallet() {
  const provider = window.solana;
  if (!provider || !provider.isPhantom) {
    alert('Phantom wallet not detected. Install Phantom and refresh.');
    return;
  }
  const btn = document.getElementById('creditsConnectBtn');
  if (btn) btn.disabled = true;
  try {
    const resp = await provider.connect();
    const pk = (resp && resp.publicKey) || provider.publicKey || null;
    const walletAddress = pk && typeof pk.toBase58 === 'function'
      ? pk.toBase58()
      : String(pk || '');
    if (!walletAddress) {
      throw new Error('Could not read Phantom wallet address');
    }
    const challenge = await apiJson('/api/credits/wallet/challenge', { wallet_address: walletAddress });
    const msg = String(challenge.message || '');
    if (!msg) throw new Error('Missing wallet challenge message');
    const encoded = new TextEncoder().encode(msg);
    const signed = await provider.signMessage(encoded, 'utf8');
    const sigRaw = signed && signed.signature ? signed.signature : signed;
    const sigBytes = sigRaw instanceof Uint8Array
      ? sigRaw
      : Array.isArray(sigRaw)
        ? Uint8Array.from(sigRaw)
        : [];
    const signature = base58Encode(sigBytes);
    const signatureBase64 = sigBytes.length ? btoa(String.fromCharCode(...sigBytes)) : '';
    if (!signature) throw new Error('Wallet signature failed');
    const heliusApiKey = (document.getElementById('heliusKey') || {}).value || localStorage.getItem('dv_helius_key') || '';
    const out = await apiJson('/api/credits/wallet/link', {
      wallet_address: walletAddress,
      nonce: challenge.nonce,
      signature,
      signature_base64: signatureBase64,
      signature_bytes: Array.from(sigBytes),
      helius_api_key: heliusApiKey,
    });
    applyCreditsUI({
      mint: out.mint,
      state: out.state,
      next_daily_grant_total: out.next_daily_grant_total,
      next_reset_at: out.next_reset_at,
      base_daily_credits: 5,
      tokens_per_step: 100000,
      credits_per_step: 20,
      costs: {
        web_scan: 2,
        token_scan: 2,
        token_deep_scan: 3.5,
      },
    });
    await loadCredits();
    alert('Wallet linked and credits refreshed.');
  } catch (err) {
    alert(String((err && err.message) || err || 'Wallet link failed'));
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function refreshCreditsWallet() {
  try {
    const heliusApiKey = (document.getElementById('heliusKey') || {}).value || localStorage.getItem('dv_helius_key') || '';
    await apiJson('/api/credits/wallet/refresh', { helius_api_key: heliusApiKey });
    await loadCredits();
  } catch (err) {
    alert(String((err && err.message) || err || 'Refresh failed'));
  }
}

// ── Settings ─────────────────────────────────────────────────────────────
function saveSettings() { localStorage.setItem('dv_api_url', document.getElementById('apiUrl').value.trim()); alert('Saved'); }

function testConnection() {
  const u = document.getElementById('apiUrl').value.trim() || getApiUrl();
  fetch(u + '/api/health').then(r => r.ok ? alert('Connected') : alert('Error')).catch(() => alert('Failed'));
}

function saveHelius() {
  localStorage.setItem('dv_helius_key', document.getElementById('heliusKey').value.trim());
  localStorage.setItem('dv_helius_network', document.getElementById('heliusNetwork').value);
  alert('Saved');
}

function testHelius() {
  if (!document.getElementById('heliusKey').value.trim()) { alert('Enter a key'); return; }
  alert('Testing...');
}

function loadSettings() {
  document.getElementById('apiUrl').value = getApiUrl();
  document.getElementById('heliusKey').value = localStorage.getItem('dv_helius_key') || '';
  document.getElementById('heliusNetwork').value = localStorage.getItem('dv_helius_network') || 'mainnet';
  const prefAutoNav = document.getElementById('prefAutoNav');
  if (prefAutoNav) {
    const stored = localStorage.getItem('dv_pref_auto_nav');
    prefAutoNav.checked = stored == null ? true : stored === '1';
    prefAutoNav.addEventListener('change', () => {
      localStorage.setItem('dv_pref_auto_nav', prefAutoNav.checked ? '1' : '0');
    });
  }
}

function exportData() {
  const data = {
    scans: JSON.parse(localStorage.getItem('dv_scans') || '[]'),
    findings: JSON.parse(localStorage.getItem('dv_findings') || '[]'),
    ts: new Date().toISOString()
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = 'diverg-' + Date.now() + '.json'; a.click();
}

function clearData() {
  if (confirm('Clear all local data?')) {
    localStorage.removeItem('dv_scans');
    localStorage.removeItem('dv_findings');
    location.reload();
  }
}
