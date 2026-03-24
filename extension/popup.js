/**
 * Diverg Extension — Popup logic.
 * Full web scan via API when configured; otherwise built-in quick scan.
 */

(function () {
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
    summaryCountEl.textContent = count === 0 ? 'No issues found' : `${count} finding${count === 1 ? '' : 's'}`;

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
            setStatus('Full scan failed: ' + (err && err.message ? err.message : 'Could not complete scan. Try Quick scan or set API URL in Options.'), true);
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

  const tabBtns = document.querySelectorAll('.popup-tab');
  const panelWeb = document.getElementById('popup-panel-web');
  const panelSol = document.getElementById('popup-panel-sol');
  const solMint = document.getElementById('popup-sol-mint');
  const solWallet = document.getElementById('popup-sol-wallet');
  const solAnalyze = document.getElementById('popup-sol-analyze');
  const solState = document.getElementById('popup-sol-state');
  const solOut = document.getElementById('popup-sol-out');

  if (!panelSol || !solAnalyze) return;

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

  chrome.storage.local.get([POPUP_TAB_KEY, SOL_MINT_KEY, SOL_WALLET_KEY], (o) => {
    if (o[SOL_MINT_KEY] && solMint) solMint.value = o[SOL_MINT_KEY];
    if (o[SOL_WALLET_KEY] && solWallet) solWallet.value = o[SOL_WALLET_KEY];
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

  function renderSolError(msg) {
    solState.textContent = msg;
    solState.className = 'popup-sol-status error';
    solOut.innerHTML = '';
  }

  function renderSolResult(data) {
    solState.textContent = '';
    solState.className = 'popup-sol-status';
    const parts = [];
    parts.push(`<div class="sol-card-mini"><div class="sol-k-mini">Mint</div><div class="sol-v-mini mono">${escapeHtml(data.mint)}</div></div>`);
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
    if (data.top_holders && data.top_holders.length) {
      parts.push('<div class="sol-h3-mini">Top holders</div><ul class="sol-list-mini">');
      data.top_holders.slice(0, 6).forEach((h) => {
        const tag = h.in_focus_cluster ? ' <span style="color:var(--primary)">●</span>' : '';
        parts.push(`<li>${escapeHtml(h.wallet.slice(0, 6))}… ${escapeHtml(String(h.pct_supply))}%${tag}</li>`);
      });
      parts.push('</ul>');
    }
    if (data.disclaimer) parts.push(`<p class="sol-disclaimer-mini">${escapeHtml(data.disclaimer)}</p>`);
    if (data.pnl_note) parts.push(`<p class="sol-disclaimer-mini">${escapeHtml(data.pnl_note)}</p>`);
    if (data.focus_cluster_note) parts.push(`<p class="sol-disclaimer-mini">${escapeHtml(data.focus_cluster_note)}</p>`);
    solOut.innerHTML = parts.join('');
  }

  solAnalyze.addEventListener('click', () => {
    const mint = solMint && solMint.value ? solMint.value.trim() : '';
    const wallet = solWallet && solWallet.value ? solWallet.value.trim() : '';
    if (!mint) {
      renderSolError('Enter a token mint.');
      return;
    }
    if (solAnalyze.disabled) return;

    chrome.storage.local.set({ [SOL_MINT_KEY]: mint, [SOL_WALLET_KEY]: wallet || '' });
    solState.textContent = 'Calling Helius…';
    solState.className = 'popup-sol-status scanning';
    solOut.innerHTML = '';

    const bundle = typeof globalThis !== 'undefined' && globalThis.divergSolanaBundle ? globalThis.divergSolanaBundle : null;
    if (!bundle || typeof bundle.runBundleSnapshot !== 'function') {
      renderSolError('Solana module missing — reload the extension.');
      return;
    }

    chrome.storage.local.get(['heliusApiKey'], (o) => {
      const key = (o.heliusApiKey || '').trim();
      if (!key) {
        renderSolError('Add your Helius API key in Options.');
        return;
      }
      solAnalyze.disabled = true;
      solAnalyze.textContent = 'Analyzing…';
      bundle
        .runBundleSnapshot(key, mint, { wallet: wallet || null })
        .then((data) => {
          if (!data || !data.ok) {
            renderSolError((data && data.error) || 'Request failed');
            return;
          }
          renderSolResult(data);
        })
        .catch((e) => {
          renderSolError(e.message || 'Network error');
        })
        .finally(() => {
          solAnalyze.disabled = false;
          solAnalyze.textContent = 'Analyze bundle';
        });
    });
  });
})();
