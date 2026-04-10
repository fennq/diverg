/**
 * Diverg Extension — Popup logic.
 * Full web scan via API when configured; otherwise Diverg Open (in-browser scan).
 */

(function () {
  const BUILD_ID = 'sectester-extension@2a7157e';
  const buildEl = document.getElementById('popup-build-id');
  if (buildEl) buildEl.textContent = `build: ${BUILD_ID}`;
  const scanUrlEl = document.getElementById('scan-url');
  const useCurrentTabBtn = document.getElementById('use-current-tab');
  const runScanBtn = document.getElementById('run-scan');
  const statusSection = document.getElementById('status-section');
  const statusEl = document.getElementById('status');
  const resultsSummary = document.getElementById('results-summary');
  const summaryCountEl = document.getElementById('summary-count');
  const severityBarEl = document.getElementById('severity-bar');
  const viewResultsLink = document.getElementById('view-results');
  const optionsBtnEl = document.getElementById('options-btn');
  const optionsDropdownEl = document.getElementById('options-dropdown');
  const modeQuickEl = document.getElementById('mode-quick');
  const modeFullEl = document.getElementById('mode-full');
  const modeOptionEl = document.getElementById('mode-option');
  const optionScanForWrapEl = document.getElementById('option-scan-for-wrap');
  const scanForSelectEl = document.getElementById('scan-for-select');
  const autoScanCheckboxEl = document.getElementById('auto-scan-on-visit');

  const STORAGE_KEY = 'diverg_last_scan';
  const SCAN_MODE_KEY = 'diverg_scan_mode';
  const SCAN_GOAL_KEY = 'diverg_scan_goal';
  const API_BASE_KEY = 'diverg_api_base_url';
  const AUTO_SCAN_KEY = 'autoScanEnabled';
  /** Default API when not set in Options — auto-detect 127.0.0.1:5000 or localhost:5000. */
  const DEFAULT_OPTION_SCAN_API = 'http://127.0.0.1:5000';

  function setStatus(text, isError = false) {
    statusSection.hidden = false;
    statusEl.textContent = text;
    statusEl.classList.toggle('error', isError);
  }

  function hideStatus() {
    statusSection.hidden = true;
  }

  function showSummary(result) {
    const findings = result.findings || [];
    const count = findings.length;
    const evidence = result.evidence_summary || {};
    const filteredTotal = Number(result.filtered_out_total ?? evidence.filtered_out_total ?? 0);
    const proofBundle = result.proof_bundle || {};
    const proofCount = Number(proofBundle.total_bundles || 0);
    const replayCandidates = Number(proofBundle.replay_candidates || 0);
    summaryCountEl.textContent = count === 0
      ? 'No issues found'
      : `${count} finding${count === 1 ? '' : 's'}${evidence.quality ? ` · evidence ${evidence.quality}` : ''}`;

    const bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    findings.forEach((f) => {
      const s = (f.severity || 'Info').trim();
      if (bySeverity[s] !== undefined) bySeverity[s]++;
    });

    severityBarEl.innerHTML = '';
    ['Critical', 'High', 'Medium', 'Low', 'Info'].forEach((sev) => {
      if (bySeverity[sev] === 0) return;
      const chip = document.createElement('span');
      chip.className = `severity-chip ${sev.toLowerCase()}`;
      chip.textContent = `${sev}: ${bySeverity[sev]}`;
      severityBarEl.appendChild(chip);
    });

    if (evidence.verified_count) {
      const chip = document.createElement('span');
      chip.className = 'severity-chip info';
      chip.textContent = `Verified: ${evidence.verified_count}`;
      severityBarEl.appendChild(chip);
    }

    if (typeof result.risk_score === 'number' && result.risk_verdict) {
      const chip = document.createElement('span');
      const rv = result.risk_verdict;
      chip.className = `severity-chip ${rv === 'Risky' ? 'critical' : rv === 'Caution' ? 'medium' : 'low'}`;
      chip.textContent = `Score ${result.risk_score}/100 · ${rv}`;
      severityBarEl.appendChild(chip);
    }

    const strictChip = document.createElement('span');
    strictChip.className = 'severity-chip info';
    strictChip.textContent = `Strict: ${count}`;
    severityBarEl.appendChild(strictChip);

    if (filteredTotal > 0) {
      const chip = document.createElement('span');
      chip.className = 'severity-chip info';
      chip.textContent = `Filtered: ${filteredTotal}`;
      severityBarEl.appendChild(chip);
    }
    if (proofCount > 0) {
      const chip = document.createElement('span');
      chip.className = 'severity-chip info';
      chip.textContent = `Proof: ${proofCount}${replayCandidates ? ` (${replayCandidates} replay)` : ''}`;
      severityBarEl.appendChild(chip);
    }

    resultsSummary.hidden = false;
  }

  function setLoading(loading) {
    runScanBtn.disabled = loading;
    runScanBtn.classList.toggle('is-loading', loading);
  }

  async function getCurrentTabUrl() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.url && (tab.url.startsWith('http:') || tab.url.startsWith('https:'))) {
        return tab.url;
      }
    } catch (_) {}
    return '';
  }

  async function loadStoredResults() {
    try {
      const raw = await chrome.storage.local.get(STORAGE_KEY);
      const data = raw[STORAGE_KEY];
      if (data && data.target_url && Array.isArray(data.findings)) {
        showSummary(data);
      }
    } catch (_) {}
  }

  function getScanMode() {
    if (modeOptionEl?.checked) return 'option';
    if (modeFullEl?.checked) return 'full';
    return 'quick';
  }

  function getSelectedGoal() {
    const val = scanForSelectEl?.value;
    return (val && String(val).trim()) || (scanForSelectEl?.options?.[0]?.value) || 'payment bypass';
  }

  function getSelectedGoalLabel() {
    const opt = scanForSelectEl?.selectedOptions?.[0];
    return opt ? opt.textContent.trim() : 'Payment / checkout';
  }

  function updateOptionScanForVisibility() {
    if (optionScanForWrapEl) optionScanForWrapEl.hidden = getScanMode() !== 'option';
  }

  async function saveScanGoal(goal) {
    await chrome.storage.local.set({ [SCAN_GOAL_KEY]: goal || 'full audit' });
  }

  /** Resolve API base: from Options first, else auto-detect (127.0.0.1:5000 / localhost:5000). */
  async function getApiBase() {
    const raw = await chrome.storage.local.get(API_BASE_KEY);
    let base = (raw[API_BASE_KEY] || '').trim().replace(/\/+$/, '');
    if (base) return base;
    if (typeof window !== 'undefined' && window.DivergAPI && typeof window.DivergAPI.detectApiBase === 'function') {
      return await window.DivergAPI.detectApiBase();
    }
    return DEFAULT_OPTION_SCAN_API;
  }

  /**
   * Full scan only. Uses API base from Options or auto-detect.
   * Returns result or null (no fallback here — caller runs extended scan).
   */
  async function runFullScanViaApi(url) {
    const base = await getApiBase();
    if (!base) return null;
    const streamUrl = `${base}/api/scan/stream`;
    const body = JSON.stringify({ url, goal: undefined });
    try {
      const res = await fetch(streamUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      if (!res.ok) return null;
      const reader = res.body?.getReader();
      if (!reader) return null;
      const decoder = new TextDecoder();
      let buffer = '';
      let lastResult = null;
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';
        for (const line of lines) {
          const t = line.trim();
          if (!t) continue;
          try {
            const data = JSON.parse(t);
            if (data.event === 'skill_start' && data.skill) setStatus(`Running ${data.skill}…`);
            if (data.event === 'skill_done' && data.skill) setStatus(`${data.skill}: ${data.findings_count ?? 0} findings`);
            if (data.event === 'done' && data.report) lastResult = data.report;
          } catch (_) {}
        }
      }
      if (lastResult) return lastResult;
      const fallbackUrl = `${base}/api/scan`;
      const fallback = await fetch(fallbackUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      if (!fallback.ok) return null;
      const data = await fallback.json();
      return data.findings ? data : null;
    } catch (_) {
      return null;
    }
  }

  /**
   * Option scan only. Uses API base from Options or auto-detect. Sends goal for focused scan.
   * Returns result or null (caller runs in-browser runOptionScan).
   */
  async function runOptionScanViaApi(url, goal) {
    const base = await getApiBase();
    const streamUrl = `${base}/api/scan/stream`;
    const body = JSON.stringify({ url, goal: goal || undefined });
    try {
      const res = await fetch(streamUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      if (!res.ok) return null;
      const reader = res.body?.getReader();
      if (!reader) return null;
      const decoder = new TextDecoder();
      let buffer = '';
      let lastResult = null;
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';
        for (const line of lines) {
          const t = line.trim();
          if (!t) continue;
          try {
            const data = JSON.parse(t);
            if (data.event === 'skill_start' && data.skill) setStatus(`Running ${data.skill}…`);
            if (data.event === 'skill_done' && data.skill) setStatus(`${data.skill}: ${data.findings_count ?? 0} findings`);
            if (data.event === 'done' && data.report) lastResult = data.report;
          } catch (_) {}
        }
      }
      if (lastResult) return lastResult;
      const fallbackUrl = `${base}/api/scan`;
      const fallback = await fetch(fallbackUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      if (!fallback.ok) return null;
      const data = await fallback.json();
      return data.findings ? data : null;
    } catch (_) {
      return null;
    }
  }

  async function saveScanMode() {
    const mode = getScanMode();
    await chrome.storage.local.set({ [SCAN_MODE_KEY]: mode });
    updateOptionScanForVisibility();
  }

  function loadScanScript() {
    return new Promise((resolve) => {
      if (typeof window !== 'undefined' && window.DivergScan && typeof window.DivergScan.runStandardScan === 'function') {
        resolve();
        return;
      }
      const script = document.createElement('script');
      script.src = 'scan.js';
      script.onload = () => resolve();
      script.onerror = () => resolve();
      (document.head || document.documentElement).appendChild(script);
    });
  }

  async function runScan() {
    const url = (scanUrlEl.value || '').trim();
    if (!url) {
      setStatus('Enter or select a URL to scan.', true);
      return;
    }

    await loadScanScript();
    const DivergScan = typeof window !== 'undefined' ? window.DivergScan : undefined;
    if (!DivergScan || typeof DivergScan.runStandardScan !== 'function') {
      setStatus('Scan engine failed to load. Check that scan.js exists next to popup.html.', true);
      return;
    }

    setLoading(true);
    hideStatus();
    resultsSummary.hidden = true;

    const mode = getScanMode();
    const goal = getSelectedGoal();
    const goalLabel = getSelectedGoalLabel();

    try {
      await saveScanMode();

      if (mode === 'quick') {
        setStatus('Fetching page and analyzing headers…');
        const result = await DivergScan.runStandardScan(url);
        await chrome.storage.local.set({ [STORAGE_KEY]: result });
        hideStatus();
        showSummary(result);
        return;
      }

      if (mode === 'option') {
        setStatus(`Scanning for: ${goalLabel}…`);
        let result = await runOptionScanViaApi(url, goal);
        if (!result) {
          setStatus(`Scanning for: ${goalLabel} (in-browser)…`);
          result = await DivergScan.runOptionScan(url, goal);
        }
        await chrome.storage.local.set({ [STORAGE_KEY]: result });
        hideStatus();
        showSummary(result);
        return;
      }

      if (mode === 'full') {
        setStatus('Running full scan…');
        let result = await runFullScanViaApi(url);
        if (!result) {
          setStatus('Full scan (fallback): headers, page, path probe…');
          try {
            result = await DivergScan.runExtendedScan(url);
          } catch (err) {
            setStatus('Full scan failed: ' + (err && err.message ? err.message : 'Could not complete scan. Try Diverg Open or set API URL in Options.'), true);
            return;
          }
        }
        await chrome.storage.local.set({ [STORAGE_KEY]: result });
        hideStatus();
        showSummary(result);
      }
    } catch (e) {
      setStatus('Scan failed: ' + (e.message || 'Unknown error'), true);
    } finally {
      setLoading(false);
    }
  }

  useCurrentTabBtn.addEventListener('click', async () => {
    const url = await getCurrentTabUrl();
    if (url) scanUrlEl.value = url;
    else setStatus('Could not get current tab URL.', true);
  });

  runScanBtn.addEventListener('click', runScan);

  function toggleOptionsDropdown() {
    const isOpen = optionsDropdownEl && !optionsDropdownEl.hidden;
    if (optionsDropdownEl) optionsDropdownEl.hidden = isOpen;
    if (optionsBtnEl) optionsBtnEl.setAttribute('aria-expanded', !isOpen ? 'true' : 'false');
  }

  function closeOptionsDropdown() {
    if (optionsDropdownEl) optionsDropdownEl.hidden = true;
    if (optionsBtnEl) optionsBtnEl.setAttribute('aria-expanded', 'false');
  }

  if (optionsBtnEl) {
    optionsBtnEl.addEventListener('click', (e) => {
      e.stopPropagation();
      toggleOptionsDropdown();
    });
  }

  document.addEventListener('click', (e) => {
    if (optionsDropdownEl && !optionsDropdownEl.hidden &&
        optionsBtnEl && !optionsBtnEl.contains(e.target) &&
        optionsDropdownEl && !optionsDropdownEl.contains(e.target)) {
      closeOptionsDropdown();
    }
  });

  if (modeQuickEl) modeQuickEl.addEventListener('change', saveScanMode);
  if (modeFullEl) modeFullEl.addEventListener('change', saveScanMode);
  if (modeOptionEl) modeOptionEl.addEventListener('change', saveScanMode);

  if (scanForSelectEl) {
    scanForSelectEl.addEventListener('change', () => saveScanGoal(scanForSelectEl.value));
  }

  if (autoScanCheckboxEl) {
    autoScanCheckboxEl.addEventListener('change', () => {
      chrome.storage.local.set({ [AUTO_SCAN_KEY]: autoScanCheckboxEl.checked });
    });
  }

  // On load: set URL, restore scan mode (quick/full/option), goal, auto-scan, show/hide Scan for, load last results
  (async () => {
    const url = await getCurrentTabUrl();
    if (url) scanUrlEl.value = url;
    const raw = await chrome.storage.local.get([SCAN_MODE_KEY, SCAN_GOAL_KEY, AUTO_SCAN_KEY]);
    const mode = raw[SCAN_MODE_KEY] || 'quick';
    if (modeQuickEl) modeQuickEl.checked = mode === 'quick';
    if (modeFullEl) modeFullEl.checked = mode === 'full';
    if (modeOptionEl) modeOptionEl.checked = mode === 'option';
    if (autoScanCheckboxEl) autoScanCheckboxEl.checked = !!raw[AUTO_SCAN_KEY];
    const savedGoal = (raw[SCAN_GOAL_KEY] || 'payment bypass').trim();
    if (scanForSelectEl && savedGoal) {
      const hasOption = Array.from(scanForSelectEl.options).some((o) => o.value === savedGoal);
      if (hasOption) scanForSelectEl.value = savedGoal;
    }
    updateOptionScanForVisibility();
    await loadStoredResults();
  })();
})();

/** Popup tabs: Security scan vs Solana bundle (Helius in Options). */
(function () {
  const POPUP_TAB_KEY = 'divergPopupTab';
  const SOL_MINT_KEY = 'solanaBundleMint';
  const SOL_WALLET_KEY = 'solanaBundleWallet';
  const SOL_MODE_KEY = 'solanaScanMode';

  const tabBtns = document.querySelectorAll('.popup-tab');
  const panelWeb = document.getElementById('popup-panel-web');
  const panelSol = document.getElementById('popup-panel-sol');
  const solMint = document.getElementById('popup-sol-mint');
  const solWallet = document.getElementById('popup-sol-wallet');
  const solWalletOnly = document.getElementById('popup-sol-wallet-only');
  const solAnalyze = document.getElementById('popup-sol-analyze');
  const solState = document.getElementById('popup-sol-state');
  const solOut = document.getElementById('popup-sol-out');
  const solModeToken = document.getElementById('sol-mode-token');
  const solModeAddress = document.getElementById('sol-mode-address');
  const solTokenFields = document.getElementById('sol-token-fields');
  const solAddressFields = document.getElementById('sol-address-fields');

  if (!panelSol || !solAnalyze) return;

  function getSolScanMode() {
    return solModeAddress?.checked ? 'address' : 'token';
  }

  function updateSolFieldVisibility() {
    const mode = getSolScanMode();
    if (solTokenFields) solTokenFields.hidden = mode !== 'token';
    if (solAddressFields) solAddressFields.hidden = mode !== 'address';
  }

  function saveSolMode() {
    const mode = getSolScanMode();
    chrome.storage.local.set({ [SOL_MODE_KEY]: mode });
    updateSolFieldVisibility();
  }

  function escapeHtml(s) {
    const div = document.createElement('div');
    div.textContent = s == null ? '' : s;
    return div.innerHTML;
  }

  function setTab(which) {
    const isWeb = which === 'web';
    if (panelWeb) panelWeb.classList.toggle('hidden', !isWeb);
    if (panelSol) panelSol.classList.toggle('hidden', isWeb);
    tabBtns.forEach((b) => {
      const on = b.getAttribute('data-popup-tab') === which;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    chrome.storage.local.set({ [POPUP_TAB_KEY]: which });
  }

  async function tryFillMintFromActiveTab() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const u = (tab && tab.url) || '';
      let m = u.match(/solscan\.io\/token\/([1-9A-HJ-NP-Za-km-z]{32,44})/i);
      if (!m) m = u.match(/dexscreener\.com\/solana\/([1-9A-HJ-NP-Za-km-z]{32,44})/i);
      if (m && solMint && !solMint.value.trim()) solMint.value = m[1];
    } catch (_) {}
  }

  chrome.storage.local.get([POPUP_TAB_KEY, SOL_MINT_KEY, SOL_WALLET_KEY, SOL_MODE_KEY], (o) => {
    if (o[SOL_MINT_KEY] && solMint) solMint.value = o[SOL_MINT_KEY];
    if (o[SOL_WALLET_KEY] && solWallet) solWallet.value = o[SOL_WALLET_KEY];
    if (o[SOL_WALLET_KEY] && solWalletOnly) solWalletOnly.value = o[SOL_WALLET_KEY];

    const mode = o[SOL_MODE_KEY] || 'token';
    if (solModeToken) solModeToken.checked = mode === 'token';
    if (solModeAddress) solModeAddress.checked = mode === 'address';
    updateSolFieldVisibility();

    const tab = o[POPUP_TAB_KEY] === 'sol' ? 'sol' : 'web';
    setTab(tab);
    if (tab === 'sol') tryFillMintFromActiveTab();
  });

  tabBtns.forEach((b) => {
    b.addEventListener('click', () => {
      const w = b.getAttribute('data-popup-tab') || 'web';
      setTab(w);
      if (w === 'sol') tryFillMintFromActiveTab();
    });
  });

  if (solModeToken) solModeToken.addEventListener('change', saveSolMode);
  if (solModeAddress) solModeAddress.addEventListener('change', saveSolMode);

  function renderSolError(msg) {
    solState.textContent = msg;
    solState.className = 'popup-sol-status error';
    solOut.innerHTML = '';
  }

  async function resolveApiBaseWithFallback(rawBase) {
    const explicit = (rawBase || '').trim().replace(/\/+$/, '');
    if (explicit) return explicit;
    if (typeof window !== 'undefined' && window.DivergAPI && typeof window.DivergAPI.detectApiBase === 'function') {
      return await window.DivergAPI.detectApiBase();
    }
    return 'http://127.0.0.1:5000';
  }

  async function runServerSolanaBundleScan(mint, wallet) {
    const raw = await chrome.storage.local.get(['diverg_api_base_url', 'diverg_auth_token', 'heliusApiKey']);
    const token = (raw.diverg_auth_token || '').trim();
    if (!token) return { ok: false, skipped: true, error: 'No JWT configured.' };
    const base = await resolveApiBaseWithFallback(raw.diverg_api_base_url || '');
    const body = { mint };
    if (wallet) body.wallet = wallet;
    const heliusKey = (raw.heliusApiKey || '').trim();
    if (heliusKey) body.helius_api_key = heliusKey;
    const res = await fetch(`${base}/api/investigation/solana-bundle`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + token,
      },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      return { ok: false, error: data.error || `HTTP ${res.status}` };
    }
    return Object.assign({ ok: true, _source: 'server_api' }, data);
  }

  async function runServerBlockchainFull(address) {
    const raw = await chrome.storage.local.get(['diverg_api_base_url', 'diverg_auth_token']);
    const token = (raw.diverg_auth_token || '').trim();
    if (!token) return { ok: false, skipped: true, error: 'No JWT configured.' };
    const base = await resolveApiBaseWithFallback(raw.diverg_api_base_url || '');
    const res = await fetch(`${base}/api/investigation/blockchain-full`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + token,
      },
      body: JSON.stringify({
        address,
        deployer_address: address,
        chain: 'solana',
        flow_depth: 'full',
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      return { ok: false, error: data.error || `HTTP ${res.status}` };
    }
    return Object.assign({ ok: true, _source: 'server_api' }, data);
  }

  function renderBlockchainFullResult(data, address) {
    const parts = [];
    const score = data.risk_score != null ? Number(data.risk_score) : null;
    const verdict = data.risk_verdict ? String(data.risk_verdict) : (data.crime_report && data.crime_report.verdict ? String(data.crime_report.verdict) : '');
    parts.push(
      `<div class="sol-card-mini highlight">` +
        `<div class="sol-k-mini">Assessment</div>` +
        `<div class="sol-v-mini">${escapeHtml(score != null ? `${score}/100` : '—')} · ${escapeHtml(verdict || 'Unknown')}</div>` +
        (data.risk_summary ? `<div class="sol-v-mini" style="font-size:11px;margin-top:6px">${escapeHtml(String(data.risk_summary).slice(0, 280))}</div>` : '') +
      `</div>`
    );
    if (address) {
      parts.push(`<div class="sol-card-mini"><div class="sol-k-mini">Address</div><div class="sol-v-mini mono">${escapeHtml(address)}</div></div>`);
    }

    const cr = data.crime_report || {};
    const eq = cr.evidence_quality || {};
    const cc = eq.confidence_counts || {};
    const findings = Array.isArray(cr.findings_with_evidence) ? cr.findings_with_evidence : [];
    parts.push(
      `<div class="sol-card-mini">` +
        `<div class="sol-k-mini">Evidence</div>` +
        `<div class="sol-v-mini">Strict: ${escapeHtml(String(findings.length))} · Verified: ${escapeHtml(String(Number(eq.verified_count || 0)))} · High confidence: ${escapeHtml(String(Number(cc.high || 0)))}${eq.quality ? ` · Quality: ${escapeHtml(String(eq.quality))}` : ''}</div>` +
      `</div>`
    );

    if (findings.length) {
      parts.push('<div class="sol-h3-mini">Top verified signals</div><ul class="sol-list-mini">');
      findings.slice(0, 6).forEach((f) => {
        const sev = f && f.severity ? String(f.severity) : 'Info';
        const title = f && f.title ? String(f.title) : 'Finding';
        const conf = f && f.confidence ? String(f.confidence) : '';
        const proof = f && f.proof ? String(f.proof).replace(/\s+/g, ' ').slice(0, 96) : '';
        parts.push(
          `<li><strong>[${escapeHtml(sev)}]</strong> ${escapeHtml(title)}` +
            (conf ? ` · ${escapeHtml(conf)} confidence` : '') +
            (f && f.verified ? ' · verified' : ' · unverified') +
            (proof ? `<br><span style="opacity:.8">proof: ${escapeHtml(proof)}</span>` : '') +
          `</li>`
        );
      });
      parts.push('</ul>');
    }
    parts.push('<p class="sol-disclaimer-mini">Source: Diverg backend investigation (Arkham-enabled when server key is configured).</p>');
    solOut.innerHTML = parts.join('');
  }

  function renderSolResult(data) {
    solState.textContent = '';
    solState.className = 'popup-sol-status';
    const parts = [];
    const score = data.risk_score != null ? Number(data.risk_score) : null;
    const verdict = data.risk_verdict ? String(data.risk_verdict) : '';
    if (score != null || verdict) {
      const scoreText = score != null ? `${String(score)}/100` : '—';
      const verdictText = verdict || 'Unknown';
      parts.push(
        `<div class="sol-card-mini highlight">` +
          `<div class="sol-k-mini">Assessment</div>` +
          `<div class="sol-v-mini">${escapeHtml(scoreText)} · ${escapeHtml(verdictText)}</div>` +
          (data.risk_summary ? `<div class="sol-v-mini" style="font-size:11px;margin-top:6px">${escapeHtml(String(data.risk_summary).slice(0, 260))}</div>` : '') +
        `</div>`
      );
    }
    if (data.mint) {
      parts.push(`<div class="sol-card-mini"><div class="sol-k-mini">Mint</div><div class="sol-v-mini mono">${escapeHtml(data.mint)}</div></div>`);
    }
    const tm = data.token_metadata;
    if (tm && (tm.symbol || tm.name)) {
      const line = [tm.symbol, tm.name].filter(Boolean).join(' · ');
      parts.push(
        `<div class="sol-card-mini highlight"><div class="sol-k-mini">Token</div><div class="sol-v-mini">${escapeHtml(line)}</div></div>`
      );
    }
    if (data.token_supply_ui != null) {
      parts.push(`<div class="sol-card-mini"><div class="sol-k-mini">Token supply</div><div class="sol-v-mini">${escapeHtml(String(data.token_supply_ui))}</div></div>`);
    }
    if (data.seed_wallet) {
      parts.push(`<div class="sol-card-mini"><div class="sol-k-mini">Wallet</div><div class="sol-v-mini mono">${escapeHtml(data.seed_wallet)}</div></div>`);
      if (data.seed_balance_ui != null) {
        parts.push(`<div class="sol-card-mini"><div class="sol-k-mini">Balance (tokens)</div><div class="sol-v-mini">${escapeHtml(String(data.seed_balance_ui))}</div></div>`);
      }
      if (data.seed_pct_supply != null) {
        parts.push(`<div class="sol-card-mini"><div class="sol-k-mini">% supply</div><div class="sol-v-mini">${escapeHtml(String(data.seed_pct_supply))}%</div></div>`);
      }
    }
    parts.push(
      `<div class="sol-card-mini highlight"><div class="sol-k-mini">Cluster (same funder)</div><div class="sol-v-mini">${escapeHtml(String((data.focus_cluster_wallets || []).length))} wallets · ${escapeHtml(String(data.focus_cluster_pct_supply != null ? data.focus_cluster_pct_supply : '—'))}%</div><div class="sol-k-mini" style="margin-top:6px">Cluster balance</div><div class="sol-v-mini">${escapeHtml(String(data.focus_cluster_supply_ui != null ? data.focus_cluster_supply_ui : '—'))}</div></div>`
    );
    if (data.bundle_signals && data.bundle_signals.coordination_score != null) {
      const bs = data.bundle_signals;
      const rs = Array.isArray(bs.coordination_reasons) ? bs.coordination_reasons.join(', ') : '';
      parts.push(
        `<div class="sol-card-mini"><div class="sol-k-mini">Coordination score</div><div class="sol-v-mini">${escapeHtml(String(bs.coordination_score))}/100</div>${rs ? `<div class="sol-k-mini" style="margin-top:6px">Signals</div><div class="sol-v-mini" style="font-size:11px">${escapeHtml(rs)}</div>` : ''}</div>`
      );
      if (bs.error) {
        parts.push(`<p class="sol-disclaimer-mini">${escapeHtml(String(bs.error))}</p>`);
      }
      if (Array.isArray(bs.bundle_archetype_hints) && bs.bundle_archetype_hints.length) {
        bs.bundle_archetype_hints.forEach((hint) => {
          parts.push(`<p class="sol-disclaimer-mini">${escapeHtml(hint)}</p>`);
        });
      }
      const am = bs.authority_misuse && typeof bs.authority_misuse === 'object' ? bs.authority_misuse : null;
      if (am) {
        const amScore = Number(am.score || 0);
        const amSev = String(am.severity || 'low');
        const amSig = Array.isArray(am.matched_signals) ? am.matched_signals : [];
        parts.push(
          `<div class="sol-card-mini"><div class="sol-k-mini">Authority misuse</div><div class="sol-v-mini">${escapeHtml(amScore.toFixed(2))}/10 · ${escapeHtml(amSev)} · ${escapeHtml(String(amSig.length))} signals</div></div>`
        );
      }
    }
    if (data.token_program_analysis && typeof data.token_program_analysis === 'object') {
      const tpa = data.token_program_analysis;
      const tStd = String(tpa.token_standard || 'unknown');
      const tRisk = String(tpa.risk_level || 'low');
      const exts = Array.isArray(tpa.extensions) ? tpa.extensions : [];
      parts.push(
        `<div class="sol-card-mini"><div class="sol-k-mini">Token program</div><div class="sol-v-mini">${escapeHtml(tStd)} · ${escapeHtml(tRisk)}</div>${exts.length ? `<div class="sol-v-mini" style="font-size:11px">${escapeHtml(exts.slice(0, 6).join(', '))}</div>` : ''}</div>`
      );
    }
    const cr = data.crime_report;
    if (cr && typeof cr === 'object') {
      const eq = cr.evidence_quality || {};
      const cc = eq.confidence_counts || {};
      const strictN = Array.isArray(cr.findings_with_evidence) ? cr.findings_with_evidence.length : 0;
      const verifiedN = Number(eq.verified_count || 0);
      const highN = Number(cc.high || 0);
      const quality = eq.quality ? String(eq.quality) : '';
      if (strictN || verifiedN || highN || quality) {
        parts.push(
          `<div class="sol-card-mini">` +
            `<div class="sol-k-mini">Evidence</div>` +
            `<div class="sol-v-mini">Strict: ${escapeHtml(String(strictN))} · Verified: ${escapeHtml(String(verifiedN))} · High confidence: ${escapeHtml(String(highN))}${quality ? ` · Quality: ${escapeHtml(quality)}` : ''}</div>` +
          `</div>`
        );
      }
      if (Array.isArray(cr.findings_with_evidence) && cr.findings_with_evidence.length) {
        parts.push('<div class="sol-h3-mini">Top verified signals</div><ul class="sol-list-mini">');
        cr.findings_with_evidence.slice(0, 5).forEach((f) => {
          const sev = f && f.severity ? String(f.severity) : 'Info';
          const conf = f && f.confidence ? String(f.confidence) : '';
          const v = f && f.verified ? 'verified' : 'unverified';
          const title = f && f.title ? String(f.title) : 'Finding';
          const proof = f && f.proof ? String(f.proof).replace(/\s+/g, ' ').slice(0, 80) : '';
          parts.push(
            `<li><strong>[${escapeHtml(sev)}]</strong> ${escapeHtml(title)}` +
              (conf ? ` · ${escapeHtml(conf)} confidence` : '') +
              ` · ${escapeHtml(v)}` +
              (proof ? `<br><span style="opacity:.8">proof: ${escapeHtml(proof)}</span>` : '') +
            `</li>`
          );
        });
        parts.push('</ul>');
      }
    }
    const p = data.params || {};
    if (p.holder_fetch_source || p.unique_holders_sampled != null) {
      parts.push(
        `<p class="sol-disclaimer-mini">Holders: <strong>${escapeHtml(String(p.holder_fetch_source || '—'))}</strong> · ${escapeHtml(String(p.unique_holders_sampled ?? '—'))} owners sampled · ${escapeHtml(String(p.max_funded_by_lookups ?? '—'))} wallets scanned</p>`
      );
    }
    if (data.excluded_liquidity_wallet) {
      const ew = data.excluded_liquidity_wallet;
      parts.push(
        `<p class="sol-disclaimer-mini">Skipped LP-sized holder from funder scan: <span class="mono">${escapeHtml(ew.slice(0, 10))}…</span></p>`
      );
    }
    if (data.top_holders && data.top_holders.length) {
      parts.push('<div class="sol-h3-mini">Top holders</div><ul class="sol-list-mini">');
      data.top_holders.slice(0, 6).forEach((h) => {
        const tag = h.in_focus_cluster ? ' <span style="color:var(--primary)">●</span>' : '';
        let idLab = h.identity && h.identity.label ? ` · ${escapeHtml(h.identity.label)}` : '';
        const ifl = (h.identity && h.identity.intel_flags) || {};
        if (ifl.cex_tagged || ifl.privacy_mixer_tagged) {
          const bits = [];
          if (ifl.cex_tagged) bits.push('CEX');
          if (ifl.privacy_mixer_tagged) bits.push('mix/priv');
          idLab += ` · ${escapeHtml(bits.join('/'))}`;
        }
        let fund = '';
        if (h.funder) {
          fund = ` · ${escapeHtml(h.funder.slice(0, 6))}…`;
          if (h.funder_root) fund += `→${escapeHtml(h.funder_root.slice(0, 5))}…`;
        }
        parts.push(
          `<li title="${escapeHtml(h.wallet)}">${escapeHtml(h.wallet.slice(0, 6))}… ${escapeHtml(String(h.pct_supply))}%${idLab}${fund}${tag}</li>`
        );
      });
      parts.push('</ul>');
    }
    const fk = data.focus_cluster_key || '';
    if (fk.indexOf('funder:') === 0 && data.top_holders && data.top_holders[0]) {
      const th = data.top_holders[0];
      const idPart = th.identity && th.identity.label ? escapeHtml(th.identity.label) : 'no label';
      parts.push(
        `<p class="sol-disclaimer-mini">Top holder ~${escapeHtml(String(th.pct_supply))}% · Helius: ${idPart}${th.in_focus_cluster ? ' · in cluster' : ''}</p>`
      );
    }
    const ccb = data.cross_chain_bundle;
    if (ccb && typeof ccb === 'object') {
      const bridgeN = ccb.bridge_adjacent_holder_wallet_count || 0;
      const sharedN = (ccb.shared_bridge_program_groups || []).length;
      const tier = ccb.bridge_mixer_tier ? String(ccb.bridge_mixer_tier).charAt(0).toUpperCase() + String(ccb.bridge_mixer_tier).slice(1) : 'Low';
      const notes = Array.isArray(ccb.investigator_notes) ? ccb.investigator_notes : [];
      const evmN = Array.isArray(ccb.counterparty_evm_addresses) ? ccb.counterparty_evm_addresses.length : 0;
      const hasMixer = ccb.strict_mixer_cluster_max_wallets >= 2 || ccb.any_mixer_tagged_funder;
      const hasBridge = bridgeN > 0 || sharedN > 0;
      const hasEvm = evmN > 0;
      const cexSplitTier = String(ccb.cex_split_pattern_confidence || 'none');
      const cexSplitN = Number(ccb.cex_split_wallet_count || 0);
      const hasCexSplit = cexSplitTier !== 'none' && cexSplitN > 0;

      if (hasBridge || hasMixer || hasEvm || hasCexSplit || ccb.combined_escalation) {
        parts.push(`<div class="sol-card-mini"><div class="sol-k-mini">Cross-chain / bridge signals</div>`);

        // Escalation warning — one compact line
        if (ccb.combined_escalation) {
          parts.push(`<div class="sol-v-mini" style="font-size:11px;color:#fca5a5;border-left:2px solid #ef4444;padding-left:6px;margin-bottom:4px">⚠ Stacked signals — manual review required</div>`);
        }

        // Single compact summary line
        const summaryParts = [`Activity: <strong>${escapeHtml(tier)}</strong>`];
        if (bridgeN > 0) summaryParts.push(`${escapeHtml(String(bridgeN))} bridge-adjacent wallets`);
        if (sharedN > 0) summaryParts.push(`${escapeHtml(String(sharedN))} shared bridge programs`);
        if (hasMixer) {
          if (ccb.strict_mixer_cluster_max_wallets >= 2) summaryParts.push(`mixer cluster (${escapeHtml(String(ccb.strict_mixer_cluster_max_wallets))} wallets)`);
          else if (ccb.any_mixer_tagged_funder) summaryParts.push('mixer-tagged funder');
        }
        if (hasCexSplit) {
          summaryParts.push(`CEX split ${escapeHtml(cexSplitTier)} (${escapeHtml(String(cexSplitN))} wallets)`);
        }
        parts.push(`<div class="sol-v-mini" style="font-size:11px">${summaryParts.join(' · ')}</div>`);

        // EVM destinations — count only, no raw hex
        if (hasEvm) {
          parts.push(`<div class="sol-v-mini" style="font-size:11px">Wormhole bridge history: ${escapeHtml(String(evmN))} EVM destination${evmN > 1 ? 's' : ''} — see full report</div>`);
        }

        // First investigator note only
        if (notes.length) {
          parts.push(`<p class="sol-disclaimer-mini">${escapeHtml(notes[0])}</p>`);
        }

        if (ccb.disclaimer) parts.push(`<p class="sol-disclaimer-mini" style="opacity:0.6">${escapeHtml(ccb.disclaimer)}</p>`);
        parts.push('</div>');
      }
    }
    if (data.disclaimer) parts.push(`<p class="sol-disclaimer-mini">${escapeHtml(data.disclaimer)}</p>`);
    if (data.pnl_note) parts.push(`<p class="sol-disclaimer-mini">${escapeHtml(data.pnl_note)}</p>`);
    if (data.focus_cluster_note) parts.push(`<p class="sol-disclaimer-mini">${escapeHtml(data.focus_cluster_note)}</p>`);
    solOut.innerHTML = parts.join('');
  }

  solAnalyze.addEventListener('click', () => {
    const mode = getSolScanMode();
    const mint = solMint && solMint.value ? solMint.value.trim() : '';
    const wallet = solWallet && solWallet.value ? solWallet.value.trim() : '';
    const walletOnly = solWalletOnly && solWalletOnly.value ? solWalletOnly.value.trim() : '';

    if (mode === 'token') {
      if (!mint) {
        renderSolError('Enter a token mint.');
        return;
      }
    } else {
      if (!walletOnly) {
        renderSolError('Enter a wallet address.');
        return;
      }
    }

    if (solAnalyze.disabled) return;

    chrome.storage.local.set({
      [SOL_MINT_KEY]: mint,
      [SOL_WALLET_KEY]: mode === 'token' ? (wallet || '') : walletOnly
    });
    solState.textContent =
      mode === 'token'
        ? 'Checking Diverg API (Arkham-enabled) first…'
        : 'Checking Diverg API full investigation…';
    solState.className = 'popup-sol-status scanning';
    solOut.innerHTML = '';

    const bundle = typeof globalThis !== 'undefined' && globalThis.divergSolanaBundle ? globalThis.divergSolanaBundle : null;
    solAnalyze.disabled = true;
    const btnText = solAnalyze.querySelector('span');
    if (btnText) btnText.textContent = 'Analyzing…';

    (async () => {
      try {
        if (mode === 'token') {
          const serverData = await runServerSolanaBundleScan(mint, wallet || null);
          if (serverData && serverData.ok) {
            solState.textContent = 'Done (Diverg API + Arkham intelligence).';
            solState.className = 'popup-sol-status';
            renderSolResult(serverData);
            return;
          }
        } else {
          const serverData = await runServerBlockchainFull(walletOnly);
          if (serverData && serverData.ok) {
            solState.textContent = 'Done (Diverg full blockchain investigation).';
            solState.className = 'popup-sol-status';
            renderBlockchainFullResult(serverData, walletOnly);
            return;
          }
        }

        // Fallback: local Helius scan when server JWT/API path is unavailable.
        if (!bundle || typeof bundle.runBundleSnapshot !== 'function') {
          renderSolError('Server API unavailable and local Solana module missing — reload extension.');
          return;
        }
        const raw = await chrome.storage.local.get(['heliusApiKey']);
        const key = (raw.heliusApiKey || '').trim();
        if (!key) {
          renderSolError('Server API unavailable. Add JWT for Arkham-backed results or add Helius key for local fallback.');
          return;
        }

        if (mode === 'token') {
          solState.textContent = 'Falling back to local Helius scan…';
          const data = await bundle.runBundleSnapshot(key, mint, { wallet: wallet || null });
          if (!data || !data.ok) {
            renderSolError((data && data.error) || 'Local fallback failed');
            return;
          }
          solState.textContent = 'Done (local Helius fallback).';
          solState.className = 'popup-sol-status';
          renderSolResult(data);
          return;
        }

        if (typeof bundle.analyzeWalletBundle !== 'function') {
          renderSolError('Server API unavailable and wallet fallback is not available in this extension version.');
          return;
        }
        solState.textContent = 'Falling back to local wallet analysis…';
        const data = await bundle.analyzeWalletBundle(key, walletOnly, {
          onProgress: (msg) => {
            solState.textContent = msg;
          },
        });
        if (!data || !data.ok) {
          renderSolError((data && data.error) || 'Local fallback failed');
          return;
        }
        solState.textContent = 'Done (local Helius fallback).';
        solState.className = 'popup-sol-status';
        renderSolResult({ ...data, mode: 'wallet_deep_graph' });
      } catch (e) {
        renderSolError((e && e.message) || 'Network error');
      } finally {
        solAnalyze.disabled = false;
        if (btnText) btnText.textContent = 'Analyze Solana';
      }
    })();
  });
})();
