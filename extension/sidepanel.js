(function () {
  const STORAGE_KEYS = { results: 'autoScanResults', status: 'autoScanStatus' };
  const stateEl = document.getElementById('state');
  const risksEl = document.getElementById('risks');
  const footerEl = document.getElementById('footer');

  function allRisks(findings) {
    if (!Array.isArray(findings)) return [];
    var order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return findings.slice().sort(function (a, b) {
      var sa = (a.severity || 'info').toLowerCase();
      var sb = (b.severity || 'info').toLowerCase();
      return (order[sa] !== undefined ? order[sa] : 5) - (order[sb] !== undefined ? order[sb] : 5);
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
      stateEl.textContent = data && data.error ? data.error : 'Could not complete scan for this tab.';
      footerEl.innerHTML = '<a href="options.html" target="_blank">Options</a>';
      return;
    }

    if (state === 'done' && data) {
      var origin = data.origin || data.url || '';
      var risks = allRisks(data.findings || []);
      var durationStr = data.scanDurationMs != null ? ' · ' + (data.scanDurationMs < 1000 ? data.scanDurationMs + 'ms' : (data.scanDurationMs / 1000).toFixed(1) + 's') : '';
      if (data.score != null && data.verdict != null) {
        var score = data.score;
        var verdict = data.verdict;
        var evidence = data.evidence_summary || {};
        var summaryText =
          data.summaryText != null && data.summaryText !== ''
            ? data.summaryText
            : data.safeToRun
              ? 'Safe to run'
              : 'Proceed with caution';
        var scoreColor = verdict === 'Risky' ? '#b91c1c' : (verdict === 'Caution' ? '#a16207' : '#15803d');
        stateEl.innerHTML = '<div class="scoreVerdict">' +
          '<div class="scoreVerdict-label">Scan score</div>' +
          '<div class="scoreVerdict-value" style="color:' + scoreColor + '">' + score + '<span class="scoreVerdict-total">/100</span></div>' +
          '<div class="scoreVerdict-summary">' + escapeHtml(summaryText) + '</div>' +
          '<div class="scoreVerdict-verdict">Verdict: ' + escapeHtml(verdict) + '</div>' +
          (evidence.quality ? '<div class="scoreVerdict-evidence">Evidence: ' + escapeHtml(evidence.quality) + ' · verified ' + escapeHtml(String(evidence.verified_count || 0)) + '/' + escapeHtml(String(evidence.total_findings || 0)) + '</div>' : '') +
          '</div>' +
          '<div class="state-meta">' + escapeHtml(origin) + ' · ' + risks.length + ' findings' + durationStr + '</div>';
      } else {
        stateEl.innerHTML = '<div class="state-meta">' + escapeHtml(origin) + ' · ' + risks.length + ' findings' + durationStr + '</div>';
      }

      if (risks.length === 0) {
        risksEl.innerHTML = '<p class="noRisks">No security issues found for this site.</p>';
      } else {
        risks.forEach(function (f) {
          var li = document.createElement('div');
          var sev = (f.severity || 'info').toLowerCase();
          li.className = 'risk ' + sev;
          var conf = f.confidence ? String(f.confidence) : '';
          var src = f.source ? String(f.source) : '';
          var metaBits = [];
          if (conf) metaBits.push('confidence: ' + conf);
          if (f.verified) metaBits.push('verified');
          if (src) metaBits.push('source: ' + src);
          li.innerHTML =
            '<div class="riskTitle">' + escapeHtml(f.title || 'Finding') + '</div>' +
            (f.url ? '<p class="riskUrl">' + escapeHtml(f.url) + '</p>' : '') +
            '<span class="riskSeverity ' + sev + '">' + escapeHtml(f.severity || 'Info') + '</span>' +
            (metaBits.length ? '<p class="riskUrl">' + escapeHtml(metaBits.join(' · ')) + '</p>' : '');
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
