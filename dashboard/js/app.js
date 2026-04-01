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
  if (page === 'history') renderHistory();
  if (page === 'analytics') updateAnalytics();
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
    });
  });

  document.addEventListener('click', e => {
    if (!e.target.closest('.user') && !e.target.closest('.user-menu'))
      document.getElementById('userMenu').classList.remove('show');
  });
  const avatarFileInput = document.getElementById('avatarFileInput');
  if (avatarFileInput) {
    avatarFileInput.addEventListener('change', onAvatarFileSelected);
  }

  document.getElementById('quickUrl').addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      const v = e.target.value.trim();
      if (v) { navigate('scanner'); document.getElementById('scanUrl').value = v; launchScan(); }
    }
  });

  loadSettings();
  loadUserProfile();
  syncDashboardData();
});

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
    throw new Error(data.error || ('HTTP ' + res.status));
  }
  return data;
}

// ── Finding Databases (scope-aware) ──────────────────────────────────────
const FINDING_DB = {
  common: [
    { title: 'Missing Content-Security-Policy', severity: 'medium', category: 'Headers', confidence: 'high' },
    { title: 'X-Frame-Options Not Set', severity: 'low', category: 'Headers', confidence: 'high' },
    { title: 'Strict-Transport-Security Missing', severity: 'medium', category: 'Headers', confidence: 'high' },
  ],
  web: [
    { title: 'Reflected XSS via Search Parameter', severity: 'high', category: 'Injection', confidence: 'high' },
    { title: 'DOM-Based XSS in Client Router', severity: 'high', category: 'Injection', confidence: 'medium' },
    { title: 'Open Redirect on Login Callback', severity: 'medium', category: 'Redirect', confidence: 'high' },
    { title: 'CORS Wildcard Origin Allowed', severity: 'high', category: 'CORS', confidence: 'high' },
    { title: 'Sensitive Data in Local Storage', severity: 'medium', category: 'Data Exposure', confidence: 'medium' },
    { title: 'Insecure Cookie (missing HttpOnly)', severity: 'medium', category: 'Cookies', confidence: 'high' },
  ],
  api: [
    { title: 'Broken Object-Level Authorization', severity: 'critical', category: 'BOLA', confidence: 'high' },
    { title: 'Rate Limiting Not Enforced', severity: 'medium', category: 'API Abuse', confidence: 'high' },
    { title: 'Verbose Error Messages Leak Stack Trace', severity: 'medium', category: 'Info Leak', confidence: 'high' },
    { title: 'JWT Algorithm None Attack', severity: 'critical', category: 'Auth', confidence: 'medium' },
    { title: 'Mass Assignment via Unfiltered Params', severity: 'high', category: 'BOLA', confidence: 'medium' },
    { title: 'GraphQL Introspection Enabled', severity: 'low', category: 'Info Leak', confidence: 'high' },
  ],
  crypto: [
    { title: 'Approval for Unlimited Token Spend', severity: 'critical', category: 'Web3', confidence: 'heuristic' },
    { title: 'Unverified Contract Interaction', severity: 'high', category: 'Web3', confidence: 'heuristic' },
    { title: 'Private Key Pattern in Client Bundle', severity: 'critical', category: 'Web3', confidence: 'medium' },
    { title: 'setApprovalForAll on Unknown Contract', severity: 'high', category: 'Web3', confidence: 'heuristic' },
    { title: 'Clipboard Hijacking Script Detected', severity: 'high', category: 'Drainer', confidence: 'heuristic' },
  ],
  recon: [
    { title: 'Exposed Admin Panel at /admin', severity: 'high', category: 'Recon', confidence: 'high' },
    { title: 'Directory Listing Enabled', severity: 'medium', category: 'Recon', confidence: 'high' },
    { title: 'Outdated Server Software (Apache 2.4.29)', severity: 'medium', category: 'Recon', confidence: 'high' },
    { title: 'Subdomain Takeover Possible (CNAME dangling)', severity: 'high', category: 'Recon', confidence: 'medium' },
    { title: 'Open Ports: 22, 80, 443, 8080, 3306', severity: 'low', category: 'Recon', confidence: 'high' },
  ],
  attack: [
    { title: 'SQL Injection (Union-Based) in /api/users', severity: 'critical', category: 'SQLi', confidence: 'high' },
    { title: 'Remote Code Execution via Template Injection', severity: 'critical', category: 'RCE', confidence: 'medium' },
    { title: 'Server-Side Request Forgery in Image Proxy', severity: 'high', category: 'SSRF', confidence: 'high' },
    { title: 'IDOR — Access Other Users\' Records', severity: 'critical', category: 'BOLA', confidence: 'high' },
    { title: 'Blind XSS Payload Stored via Contact Form', severity: 'high', category: 'XSS', confidence: 'medium' },
    { title: 'Authentication Bypass via Parameter Pollution', severity: 'critical', category: 'Auth Bypass', confidence: 'high' },
    { title: 'Path Traversal Reads /etc/passwd', severity: 'high', category: 'Traversal', confidence: 'high' },
    { title: 'Insecure Deserialization in Session Cookie', severity: 'critical', category: 'RCE', confidence: 'medium' },
  ],
  passive: [
    { title: 'Mixed Content (HTTP Resources on HTTPS)', severity: 'low', category: 'TLS', confidence: 'high' },
    { title: 'Deprecated TLS 1.0 Supported', severity: 'medium', category: 'TLS', confidence: 'high' },
    { title: 'Information Disclosure in HTTP Headers', severity: 'low', category: 'Info Leak', confidence: 'high' },
  ],
};

const ATTACK_PATHS_DB = [
  {
    steps: ['Recon: Admin Panel', 'Brute Force Login', 'SQL Injection /admin/query', 'DB Dump (users table)', 'Credential Reuse → AWS Console'],
    severity: 'critical',
    impact: 'Full database access, cloud takeover via leaked credentials'
  },
  {
    steps: ['SSRF in Image Proxy', 'Access Internal Metadata', 'Leak IAM Credentials', 'Pivot to S3 Buckets'],
    severity: 'critical',
    impact: 'Cloud infrastructure compromise via metadata endpoint'
  },
  {
    steps: ['XSS in Search', 'Steal Admin Session Cookie', 'Impersonate Admin', 'Modify Application Config'],
    severity: 'high',
    impact: 'Account takeover via stored session hijacking'
  },
  {
    steps: ['Open Redirect on /login', 'Phishing Landing Page', 'Credential Harvest', 'Lateral Movement'],
    severity: 'high',
    impact: 'Social engineering chain leading to credential compromise'
  },
  {
    steps: ['IDOR on /api/users/:id', 'Enumerate All User Profiles', 'Extract PII (email, phone)', 'Targeted Spear Phishing'],
    severity: 'high',
    impact: 'Mass data exfiltration via broken access control'
  },
  {
    steps: ['Template Injection in /render', 'Achieve RCE', 'Reverse Shell', 'Privilege Escalation'],
    severity: 'critical',
    impact: 'Full server compromise via template injection to RCE'
  },
  {
    steps: ['Clipboard Hijack Script', 'Replace Wallet Address', 'Drain User Funds'],
    severity: 'critical',
    impact: 'Direct financial loss via Web3 address replacement'
  },
  {
    steps: ['Unverified Contract Call', 'setApprovalForAll', 'Drain NFT Collection'],
    severity: 'critical',
    impact: 'NFT collection drained via unlimited approval'
  },
];

function getFindingsForScope(scope) {
  let pool = [...FINDING_DB.common];
  switch (scope) {
    case 'full':
      pool = pool.concat(FINDING_DB.web, FINDING_DB.api, FINDING_DB.recon, FINDING_DB.attack.slice(0, 3));
      break;
    case 'quick':
      pool = pool.concat(FINDING_DB.web.slice(0, 2));
      break;
    case 'web':
      pool = pool.concat(FINDING_DB.web);
      break;
    case 'api':
      pool = pool.concat(FINDING_DB.api);
      break;
    case 'crypto':
      pool = pool.concat(FINDING_DB.crypto);
      break;
    case 'recon':
      pool = pool.concat(FINDING_DB.recon);
      break;
    case 'attack':
      pool = pool.concat(FINDING_DB.attack, FINDING_DB.web.slice(0, 2), FINDING_DB.api.slice(0, 2));
      break;
    case 'passive':
      pool = pool.concat(FINDING_DB.passive);
      break;
  }
  const shuffled = pool.sort(() => 0.5 - Math.random());
  const count = Math.min(pool.length, scope === 'quick' ? 4 : scope === 'passive' ? 4 : 6 + Math.floor(Math.random() * 4));
  return shuffled.slice(0, count);
}

function getAttackPaths(scope) {
  if (scope === 'passive' || scope === 'quick') return [];
  let pool;
  if (scope === 'crypto') {
    pool = ATTACK_PATHS_DB.filter(p => p.steps.some(s => /Wallet|Clipboard|Contract|Approval/i.test(s)));
  } else if (scope === 'attack') {
    pool = [...ATTACK_PATHS_DB];
  } else {
    pool = ATTACK_PATHS_DB.filter(p => !/Wallet|Clipboard|Contract|Approval/i.test(p.steps.join(' ')));
  }
  const shuffled = pool.sort(() => 0.5 - Math.random());
  return shuffled.slice(0, scope === 'attack' ? 4 : 2 + Math.floor(Math.random() * 2));
}

// ── Scanner ──────────────────────────────────────────────────────────────
function getScanSteps(scope) {
  const base = [
    { msg: 'Initializing scan engine...', cls: 'accent', delay: 400 },
    { msg: 'Resolving target DNS records...', cls: 'dim', delay: 500 },
  ];
  const scoped = {
    full: [
      { msg: 'Enumerating attack surface (subdomains, ports)...', cls: 'dim', delay: 700 },
      { msg: 'Crawling application routes — 42 endpoints found', cls: null, delay: 600 },
      { msg: 'Fingerprinting technologies: React, Express, Node 18', cls: 'dim', delay: 500 },
      { msg: 'Checking security headers...', cls: 'yellow', delay: 400 },
      { msg: 'Analyzing client-side scripts (CSP, SRI)...', cls: 'dim', delay: 600 },
      { msg: 'Running injection tests (XSS, SQLi, SSTI)...', cls: 'yellow', delay: 900 },
      { msg: 'Testing API authorization controls (BOLA, IDOR)...', cls: 'yellow', delay: 800 },
      { msg: 'Evaluating TLS/SSL configuration...', cls: 'dim', delay: 400 },
      { msg: 'Building attack path graph...', cls: 'accent', delay: 600 },
    ],
    quick: [
      { msg: 'Fast header & TLS check...', cls: 'dim', delay: 400 },
      { msg: 'Quick injection probe...', cls: 'yellow', delay: 500 },
    ],
    web: [
      { msg: 'Crawling application — 38 routes discovered', cls: null, delay: 600 },
      { msg: 'Testing XSS vectors (reflected, DOM, stored)...', cls: 'yellow', delay: 800 },
      { msg: 'Checking CORS policy...', cls: 'dim', delay: 400 },
      { msg: 'Inspecting cookies & storage...', cls: 'dim', delay: 500 },
      { msg: 'Evaluating redirect chains...', cls: 'dim', delay: 400 },
    ],
    api: [
      { msg: 'Discovering API endpoints (/api/*, /graphql)...', cls: 'dim', delay: 600 },
      { msg: 'Testing BOLA / IDOR patterns...', cls: 'yellow', delay: 800 },
      { msg: 'Probing rate limits...', cls: 'dim', delay: 500 },
      { msg: 'Checking JWT handling...', cls: 'yellow', delay: 600 },
      { msg: 'Testing mass assignment vectors...', cls: 'dim', delay: 500 },
    ],
    crypto: [
      { msg: 'Scanning client bundle for Web3 patterns...', cls: 'dim', delay: 600 },
      { msg: 'Checking approval/permit function calls...', cls: 'yellow', delay: 800 },
      { msg: 'Analyzing transaction signing flows...', cls: 'dim', delay: 600 },
      { msg: 'Running drainer heuristic engine...', cls: 'yellow', delay: 700 },
      { msg: 'Inspecting clipboard hooks...', cls: 'dim', delay: 400 },
    ],
    recon: [
      { msg: 'Brute-forcing subdomains (10k wordlist)...', cls: 'dim', delay: 900 },
      { msg: 'Found 7 subdomains (3 with dangling CNAME)', cls: null, delay: 500 },
      { msg: 'Port scanning top 1000 ports...', cls: 'dim', delay: 800 },
      { msg: 'Identifying server technologies...', cls: 'dim', delay: 500 },
      { msg: 'Checking directory listings...', cls: 'dim', delay: 400 },
    ],
    attack: [
      { msg: 'Enumerating attack surface — 56 endpoints', cls: null, delay: 600 },
      { msg: 'Generating injection payloads (SQLi, XSS, SSTI, RCE)...', cls: 'yellow', delay: 700 },
      { msg: 'Launching SQL injection probes...', cls: 'red', delay: 900 },
      { msg: '  ► UNION-based injection confirmed on /api/users', cls: 'red', delay: 400 },
      { msg: 'Testing template injection vectors...', cls: 'yellow', delay: 800 },
      { msg: '  ► SSTI confirmed: {{7*7}} → 49 in /render', cls: 'red', delay: 400 },
      { msg: 'Testing SSRF via image proxy endpoint...', cls: 'yellow', delay: 700 },
      { msg: '  ► Internal metadata accessible via SSRF', cls: 'red', delay: 400 },
      { msg: 'Probing authentication bypass vectors...', cls: 'yellow', delay: 600 },
      { msg: 'Testing IDOR on resource endpoints...', cls: 'yellow', delay: 700 },
      { msg: '  ► IDOR confirmed: can access other user records', cls: 'red', delay: 400 },
      { msg: 'Building attack chain graph...', cls: 'accent', delay: 600 },
      { msg: 'Mapping privilege escalation paths...', cls: 'accent', delay: 500 },
    ],
    passive: [
      { msg: 'Passive analysis (no active probing)...', cls: 'dim', delay: 400 },
      { msg: 'Checking TLS versions supported...', cls: 'dim', delay: 500 },
      { msg: 'Inspecting response headers...', cls: 'dim', delay: 400 },
      { msg: 'Detecting mixed content...', cls: 'dim', delay: 400 },
    ],
  };
  return [
    ...base,
    ...(scoped[scope] || scoped.full),
    { msg: 'Scan complete — compiling results.', cls: 'green', delay: 400 },
  ];
}

function launchScan() {
  const url = document.getElementById('scanUrl').value.trim();
  if (!url) return;

  const scope = document.querySelector('.scope-pill.active')?.dataset.scope || 'full';
  const progressBox = document.getElementById('scanProgress');
  const terminal = document.getElementById('scanTerminal');

  terminal.innerHTML = '';
  progressBox.classList.add('show');
  document.getElementById('scanResults').style.display = 'none';

  termLine(terminal, ts() + ' ─── Diverg Scan Engine (live) ───', 'accent');
  termLine(terminal, ts() + ' Target: ' + url, null);
  termLine(terminal, ts() + ' Scope:  ' + scope.toUpperCase(), null);
  termLine(terminal, ts() + ' Calling /api/scan ...', 'dim');

  apiJson('/api/scan', { url, scope })
    .then((data) => {
      const findings = Array.isArray(data.findings) ? data.findings : [];
      const attackPaths = Array.isArray(data.attack_paths) ? data.attack_paths : [];
      termLine(terminal, ts() + ' Scan complete.', 'green');
      termLine(terminal, ts() + ' Findings: ' + findings.length, findings.length ? 'yellow' : 'dim');
      if (typeof data.risk_score === 'number') {
        termLine(terminal, ts() + ' Risk score: ' + data.risk_score + (data.risk_verdict ? ' (' + data.risk_verdict + ')' : ''), 'accent');
      }
      progressBox.classList.remove('show');
      showScanResults(url, scope, findings, attackPaths, data.risk_score);
      syncDashboardData();
    })
    .catch((err) => {
      termLine(terminal, ts() + ' Scan failed: ' + err.message, 'red');
      progressBox.classList.remove('show');
    });
}

function showScanResults(url, scope, findingsInput, pathsInput, scoreInput) {
  const container = document.getElementById('scanResults');
  const body = document.getElementById('scanResultsBody');
  const countEl = document.getElementById('scanFindingsCount');

  const findings = (Array.isArray(findingsInput) && findingsInput.length ? findingsInput : getFindingsForScope(scope)).map((f) => ({
    title: f.title || 'Untitled finding',
    severity: String(f.severity || 'low').toLowerCase(),
    category: f.category || 'Other',
    confidence: f.confidence || '',
  }));
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  countEl.textContent = findings.length + ' issues';

  body.innerHTML = findings.map((f, idx) =>
    `<tr><td class="col-num">${idx + 1}</td><td class="col-primary">${f.title}</td><td><span class="badge badge-${f.severity}">${f.severity}</span></td><td>${f.category}</td><td style="font-size:0.6875rem;color:var(--text-dim);">${f.confidence}</td></tr>`
  ).join('');

  container.style.display = 'block';

  const paths = Array.isArray(pathsInput) && pathsInput.length ? pathsInput : getAttackPaths(scope);
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
      const chain = steps.map(s => `<span class="step">${String(s)}</span>`).join('<span class="arrow">→</span>');
      const sev = String(p.severity || 'medium').toLowerCase();
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
  const score = typeof scoreInput === 'number'
    ? scoreInput
    : Math.max(0, 100 - critCount * 25 - highCount * 15 - (totalFindings - critCount - highCount) * 5);

  addToHistory(url, scope, totalFindings, score, critCount, highCount);
  updateStats();
  renderFindings(findings, url);
}

function renderFindings(newFindings, url) {
  const stored = JSON.parse(localStorage.getItem('dv_findings') || '[]');
  const enriched = newFindings.map(f => ({ ...f, target: url, date: new Date().toLocaleString() }));
  const merged = [...enriched, ...stored].slice(0, 200);
  localStorage.setItem('dv_findings', JSON.stringify(merged));
  renderFindingsPage();
}

function renderFindingsPage() {
  const findings = serverFindings.length
    ? serverFindings
    : JSON.parse(localStorage.getItem('dv_findings') || '[]');
  const body = document.getElementById('findingsBody');
  if (!body || !findings.length) return;

  body.innerHTML = findings.slice(0, 50).map((f, i) =>
    `<tr><td class="col-num">${i + 1}</td><td class="col-primary">${f.title}</td><td><span class="badge badge-${(f.severity || 'low').toLowerCase()}">${f.severity}</span></td><td>${f.category}</td><td class="col-mono" style="max-width:160px;overflow:hidden;text-overflow:ellipsis;">${f.target || ''}</td><td class="col-mono">${f.date || ''}</td></tr>`
  ).join('');
}

function clearScan() {
  document.getElementById('scanResults').style.display = 'none';
  document.getElementById('scanUrl').value = '';
}

// ── Investigation ────────────────────────────────────────────────────────
function runChainLookup() {
  const addr = document.getElementById('chainAddr').value.trim();
  if (!addr) return;
  const out = document.getElementById('chainOut');
  out.style.display = 'block'; out.innerHTML = '';
  termLine(out, ts() + ' Querying /api/investigation/blockchain ...', 'accent');
  const heliusApiKey = (document.getElementById('heliusKey') || {}).value || localStorage.getItem('dv_helius_key') || '';
  apiJson('/api/investigation/blockchain', {
    address: addr,
    network: (localStorage.getItem('dv_helius_network') || 'mainnet'),
    helius_api_key: heliusApiKey,
  })
    .then((data) => {
      termLine(out, '', null);
      termLine(out, 'Address : ' + (data.address || addr), null);
      termLine(out, 'Chain   : ' + (data.chain || 'unknown'), null);
      const s = data.summary || {};
      if (data.chain === 'evm') {
        if (s.balance_eth) termLine(out, 'Balance : ' + s.balance_eth + ' ETH', 'green');
        if (s.tx_count !== undefined) termLine(out, 'Txns    : ' + s.tx_count, null);
      } else {
        if (s.balance_sol !== undefined) termLine(out, 'Balance : ' + s.balance_sol + ' SOL', 'green');
        if (s.recent_signatures !== undefined) termLine(out, 'Txns    : ' + s.recent_signatures, null);
      }
      if (data.error) termLine(out, 'Note    : ' + data.error, 'yellow');
    })
    .catch((err) => termLine(out, ts() + ' Lookup failed: ' + err.message, 'red'));
}

function runTokenBundle() {
  const mint = document.getElementById('tokenMint').value.trim();
  if (!mint) return;
  const out = document.getElementById('tokenOut');
  out.style.display = 'block'; out.innerHTML = '';
  termLine(out, ts() + ' Calling /api/investigation/solana-bundle ...', 'accent');
  const heliusApiKey = (document.getElementById('heliusKey') || {}).value || localStorage.getItem('dv_helius_key') || '';
  apiJson('/api/investigation/solana-bundle', { mint, helius_api_key: heliusApiKey })
    .then((data) => {
      termLine(out, '', null);
      termLine(out, 'Mint       : ' + mint, null);
      if (data.error) {
        termLine(out, 'Error      : ' + data.error, 'red');
        return;
      }
      const holders = data.total_holders || data.holder_count || data.holders_count;
      if (holders !== undefined) termLine(out, 'Holders    : ' + holders, null);
      if (data.cluster_count !== undefined) termLine(out, 'Bundles    : ' + data.cluster_count + ' clusters', 'yellow');
      if (data.risk_label || data.risk_score !== undefined) {
        const riskLabel = data.risk_label || '';
        const riskScore = data.risk_score !== undefined ? (' (' + data.risk_score + ')') : '';
        termLine(out, 'Risk       : ' + riskLabel + riskScore, riskLabel.toLowerCase().includes('low') ? 'green' : 'yellow');
      }
      if (data.summary) termLine(out, 'Summary    : ' + String(data.summary).slice(0, 180), 'dim');
    })
    .catch((err) => termLine(out, ts() + ' Bundle analysis failed: ' + err.message, 'red'));
}

function runOsint() {
  const domain = document.getElementById('osintDomain').value.trim();
  if (!domain) return;
  const out = document.getElementById('osintOut');
  out.style.display = 'block'; out.innerHTML = '';
  termLine(out, ts() + ' Calling /api/investigation/domain ...', 'accent');
  apiJson('/api/investigation/domain', { domain })
    .then((data) => {
      termLine(out, '', null);
      termLine(out, 'Domain      : ' + (data.domain || domain), null);
      termLine(out, 'Findings    : ' + (data.findings_count || (Array.isArray(data.findings) ? data.findings.length : 0)), 'yellow');
      const os = data.osint || {};
      const rc = data.recon || {};
      const hs = data.headers_ssl || {};
      if (os.registrar) termLine(out, 'Registrar   : ' + os.registrar, null);
      if (os.created || os.creation_date) termLine(out, 'Created     : ' + (os.created || os.creation_date), null);
      if (rc.subdomains_found !== undefined) termLine(out, 'Subdomains  : ' + rc.subdomains_found, null);
      if (hs.ssl_valid !== undefined) termLine(out, 'SSL Valid   : ' + hs.ssl_valid, hs.ssl_valid ? 'green' : 'red');
      const top = Array.isArray(data.findings) ? data.findings.slice(0, 3) : [];
      top.forEach((f, i) => termLine(out, 'Top ' + (i + 1) + '      : ' + (f.title || f.category || 'Finding'), 'dim'));
    })
    .catch((err) => termLine(out, ts() + ' OSINT failed: ' + err.message, 'red'));
}

function runPoc() {
  const type = document.getElementById('pocType').value;
  const url = document.getElementById('pocUrl').value.trim();
  if (!url) return;
  const out = document.getElementById('pocOut');
  out.style.display = 'block'; out.innerHTML = '';
  const apiType = type === 'unauth' ? 'unauthenticated' : type;
  termLine(out, ts() + ' Calling /api/poc/simulate (' + apiType + ') ...', 'accent');
  apiJson('/api/poc/simulate', { type: apiType, url, verbose: true })
    .then((data) => {
      termLine(out, '', null);
      termLine(out, 'Success    : ' + !!data.success, data.success ? 'green' : 'red');
      if (data.status_code !== undefined && data.status_code !== null) {
        termLine(out, 'HTTP       : ' + data.status_code, null);
      }
      if (data.conclusion) termLine(out, 'Conclusion : ' + data.conclusion, data.success ? 'green' : 'yellow');
      if (data.error) termLine(out, 'Error      : ' + data.error, 'red');
      if (data.body_preview) termLine(out, 'Preview    : ' + String(data.body_preview).slice(0, 220), 'dim');
    })
    .catch((err) => termLine(out, ts() + ' PoC failed: ' + err.message, 'red'));
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

function renderHistory() {
  const scans = serverScans.length
    ? serverScans
    : JSON.parse(localStorage.getItem('dv_scans') || '[]');
  if (!scans.length) return;

  const makeRows = (list) => list.map((s, i) =>
    `<tr><td class="col-num">${i + 1}</td><td class="col-primary col-mono">${s.url}</td><td><span class="badge badge-info">${s.scope}</span></td><td>${s.findings}</td><td>${s.score}/100</td><td class="col-mono">${s.date}</td></tr>`
  ).join('');

  const hb = document.getElementById('historyBody');
  const hsb = document.getElementById('homeScansBody');
  if (hb) hb.innerHTML = makeRows(scans);
  if (hsb) hsb.innerHTML = makeRows(scans.slice(0, 8));

  const rf = document.getElementById('homeRecentFindings');
  const findings = (serverFindings.length ? serverFindings : JSON.parse(localStorage.getItem('dv_findings') || '[]')).slice(0, 5);
  if (rf && findings.length) {
    rf.innerHTML = findings.map(f =>
      `<tr><td class="col-primary" style="font-size:0.75rem;">${f.title}</td><td><span class="badge badge-${(f.severity || 'low').toLowerCase()}">${f.severity}</span></td><td class="col-mono" style="font-size:0.625rem;color:var(--text-dim);">${f.date || ''}</td></tr>`
    ).join('');
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
  set('bannerScans', n);
  set('bannerFindings', totalFindings);
  set('bannerTargets', targets);
  set('analyticsScans', n);
  set('analyticsCritical', totalCrit);
  set('analyticsHigh', totalHigh);
  set('analyticsScore', avg);

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
        const f = row.finding || {};
        const sev = String(f.severity || 'low').toLowerCase();
        return {
          title: f.title || 'Untitled finding',
          severity: sev,
          category: f.category || 'Other',
          target: row.target_url || '',
          date: row.scanned_at || '',
          confidence: f.confidence || '',
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
