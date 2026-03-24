(function () {
  const STORAGE_KEYS = { results: 'autoScanResults', status: 'autoScanStatus' };
  const stateEl = document.getElementById('state');
  const risksEl = document.getElementById('risks');
  const footerEl = document.getElementById('footer');

  function onlyTrueRisks(findings) {
    if (!Array.isArray(findings)) return [];
    return findings.filter(function (f) {
      var s = (f.severity || '').toLowerCase();
      return s === 'critical' || s === 'high';
    });
  }

  function escapeHtml(s) {
    var div = document.createElement('div');
    div.textContent = s == null ? '' : s;
    return div.innerHTML;
  }

  function render(state, data) {
    stateEl.textContent = '';
    stateEl.className = 'state';
    risksEl.innerHTML = '';
    footerEl.innerHTML = '';

    if (state === 'no-tab') {
      stateEl.className = 'state noTab';
      stateEl.textContent = 'No tab selected. Switch to a tab or navigate to a site.';
      return;
    }

    if (state === 'scanning') {
      stateEl.className = 'state scanning';
      stateEl.textContent = 'Scanning…';
      return;
    }

    if (state === 'error') {
      stateEl.className = 'state error';
      stateEl.textContent = data && data.error ? data.error : 'Scan failed.';
      footerEl.innerHTML = 'Run <code>python api_server.py</code> in your Diverg folder. · <a href="options.html" target="_blank">Options</a>';
      return;
    }

    if (state === 'done' && data) {
      var origin = data.origin || data.url || '';
      stateEl.textContent = 'Site: ' + origin;
      var risks = onlyTrueRisks(data.findings || []);

      if (risks.length === 0) {
        risksEl.innerHTML = '<p class="noRisks">No Critical or High risks found for this site.</p>';
      } else {
        risks.forEach(function (f) {
          var li = document.createElement('div');
          li.className = 'risk ' + (f.severity || 'high').toLowerCase();
          li.innerHTML =
            '<div class="riskTitle">' + escapeHtml(f.title || 'Finding') + '</div>' +
            (f.url ? '<p class="riskUrl">' + escapeHtml(f.url) + '</p>' : '') +
            '<span class="riskSeverity ' + (f.severity || 'high').toLowerCase() + '">' + escapeHtml(f.severity || 'High') + '</span>';
          risksEl.appendChild(li);
        });
      }

      footerEl.innerHTML = '<a href="results.html" target="_blank">View full report</a> · <a href="options.html" target="_blank">Options</a>';
      return;
    }

    stateEl.className = 'state noTab';
    stateEl.textContent = 'Navigate to a site to see risks.';
  }

  function updateForTab(tabId) {
    if (!tabId) {
      render('no-tab');
      return;
    }

    chrome.storage.local.get([STORAGE_KEYS.results, STORAGE_KEYS.status], function (o) {
      var results = o[STORAGE_KEYS.results] || {};
      var status = o[STORAGE_KEYS.status] || {};
      var data = results[tabId];
      var st = status[tabId];

      if (st === 'scanning') {
        render('scanning');
        return;
      }
      if (st === 'error' && data) {
        render('error', data);
        return;
      }
      if (data) {
        render('done', data);
        return;
      }
      render('no-tab');
    });
  }

  function getActiveTabId(cb) {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      cb(tabs[0] ? tabs[0].id : null);
    });
  }

  getActiveTabId(function (tabId) {
    updateForTab(tabId);
  });

  chrome.tabs.onActivated.addListener(function (activeInfo) {
    getActiveTabId(function (tabId) {
      if (tabId === activeInfo.tabId) updateForTab(tabId);
    });
  });

  chrome.storage.onChanged.addListener(function (changes, areaName) {
    if (areaName !== 'local') return;
    if (changes[STORAGE_KEYS.results] || changes[STORAGE_KEYS.status]) {
      getActiveTabId(updateForTab);
    }
  });
})();

(function () {
  var TAB_KEY = 'divergSidePanelTab';
  var SOL_MINT_KEY = 'solanaBundleMint';
  var SOL_WALLET_KEY = 'solanaBundleWallet';

  var tabBtns = document.querySelectorAll('.tabBtn');
  var panelWeb = document.getElementById('panelWeb');
  var panelSol = document.getElementById('panelSol');
  var solMint = document.getElementById('solMint');
  var solWallet = document.getElementById('solWallet');
  var solAnalyze = document.getElementById('solAnalyze');
  var solState = document.getElementById('solState');
  var solOut = document.getElementById('solOut');

  if (!panelSol || !solAnalyze) return;

  function escapeHtml(s) {
    var div = document.createElement('div');
    div.textContent = s == null ? '' : s;
    return div.innerHTML;
  }

  function setTab(which) {
    var isWeb = which === 'web';
    if (panelWeb) panelWeb.classList.toggle('hidden', !isWeb);
    if (panelSol) panelSol.classList.toggle('hidden', isWeb);
    tabBtns.forEach(function (b) {
      var on = b.getAttribute('data-tab') === which;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    chrome.storage.local.set({ [TAB_KEY]: which });
  }

  function tryFillMintFromActiveTab() {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      var u = (tabs[0] && tabs[0].url) || '';
      var m = u.match(/solscan\.io\/token\/([1-9A-HJ-NP-Za-km-z]{32,44})/i);
      if (m && solMint && !solMint.value.trim()) solMint.value = m[1];
      var m2 = u.match(/dexscreener\.com\/solana\/([1-9A-HJ-NP-Za-km-z]{32,44})/i);
      if (m2 && solMint && !solMint.value.trim()) solMint.value = m2[1];
    });
  }

  chrome.storage.local.get([TAB_KEY, SOL_MINT_KEY, SOL_WALLET_KEY], function (o) {
    if (o[SOL_MINT_KEY] && solMint) solMint.value = o[SOL_MINT_KEY];
    if (o[SOL_WALLET_KEY] && solWallet) solWallet.value = o[SOL_WALLET_KEY];
    var tab = o[TAB_KEY] === 'sol' ? 'sol' : 'web';
    setTab(tab);
    if (tab === 'sol') tryFillMintFromActiveTab();
  });

  tabBtns.forEach(function (b) {
    b.addEventListener('click', function () {
      var w = b.getAttribute('data-tab') || 'web';
      setTab(w);
      if (w === 'sol') tryFillMintFromActiveTab();
    });
  });

  function renderSolError(msg) {
    solState.textContent = msg;
    solState.className = 'state solState error';
    solOut.innerHTML = '';
  }

  function renderSolResult(data) {
    solState.textContent = '';
    solState.className = 'state solState';
    var parts = [];
    parts.push('<div class="solCard"><div class="solK">Mint</div><div class="solV mono">' + escapeHtml(data.mint) + '</div></div>');
    if (data.token_supply_ui != null) {
      parts.push('<div class="solCard"><div class="solK">Token supply (ui)</div><div class="solV">' + escapeHtml(String(data.token_supply_ui)) + '</div></div>');
    }
    if (data.seed_wallet) {
      parts.push('<div class="solCard"><div class="solK">Wallet</div><div class="solV mono">' + escapeHtml(data.seed_wallet) + '</div></div>');
      if (data.seed_balance_ui != null) {
        parts.push('<div class="solCard"><div class="solK">Wallet balance (tokens)</div><div class="solV">' + escapeHtml(String(data.seed_balance_ui)) + '</div></div>');
      }
      if (data.seed_pct_supply != null) {
        parts.push('<div class="solCard"><div class="solK">Wallet % supply</div><div class="solV">' + escapeHtml(String(data.seed_pct_supply)) + '%</div></div>');
      }
    }
    parts.push(
      '<div class="solCard highlight"><div class="solK">Cluster (same direct funder)</div><div class="solV">' +
        escapeHtml(String((data.focus_cluster_wallets || []).length)) +
        ' wallets · ' +
        escapeHtml(String(data.focus_cluster_pct_supply != null ? data.focus_cluster_pct_supply : '—')) +
        '% of supply</div>' +
        '<div class="solK">Cluster balance (ui)</div><div class="solV">' +
        escapeHtml(String(data.focus_cluster_supply_ui != null ? data.focus_cluster_supply_ui : '—')) +
        '</div></div>'
    );
    if (data.top_holders && data.top_holders.length) {
      parts.push('<div class="solH3">Top holders (sample)</div><ul class="solList">');
      data.top_holders.slice(0, 8).forEach(function (h) {
        var tag = h.in_focus_cluster ? ' <span class="tag">cluster</span>' : '';
        parts.push('<li class="mono">' + escapeHtml(h.wallet.slice(0, 8)) + '… ' + escapeHtml(String(h.pct_supply)) + '%' + tag + '</li>');
      });
      parts.push('</ul>');
    }
    if (data.disclaimer) {
      parts.push('<p class="solDisclaimer">' + escapeHtml(data.disclaimer) + '</p>');
    }
    if (data.pnl_note) {
      parts.push('<p class="solDisclaimer">' + escapeHtml(data.pnl_note) + '</p>');
    }
    if (data.focus_cluster_note) {
      parts.push('<p class="solDisclaimer">' + escapeHtml(data.focus_cluster_note) + '</p>');
    }
    solOut.innerHTML = parts.join('');
  }

  solAnalyze.addEventListener('click', function () {
    var mint = (solMint && solMint.value) ? solMint.value.trim() : '';
    var wallet = (solWallet && solWallet.value) ? solWallet.value.trim() : '';
    if (!mint) {
      renderSolError('Enter a token mint.');
      return;
    }
    chrome.storage.local.set({ [SOL_MINT_KEY]: mint, [SOL_WALLET_KEY]: wallet || '' });
    solState.textContent = 'Calling Helius…';
    solState.className = 'state solState scanning';
    solOut.innerHTML = '';

    var bundle = typeof globalThis !== 'undefined' && globalThis.divergSolanaBundle ? globalThis.divergSolanaBundle : null;
    if (!bundle || typeof bundle.runBundleSnapshot !== 'function') {
      renderSolError('Solana module missing — reload the extension.');
      return;
    }

    chrome.storage.local.get(['heliusApiKey'], function (o) {
      var key = (o.heliusApiKey || '').trim();
      if (!key) {
        renderSolError('Add your Helius API key in Options (linked below).');
        return;
      }
      var opts = { wallet: wallet || null };
      bundle.runBundleSnapshot(key, mint, opts).then(function (data) {
        if (!data || !data.ok) {
          renderSolError((data && data.error) || 'Request failed');
          return;
        }
        renderSolResult(data);
      }).catch(function (e) {
        renderSolError(e.message || 'Network error');
      });
    });
  });
})();
