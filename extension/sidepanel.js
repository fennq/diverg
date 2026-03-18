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
