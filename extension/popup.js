(function () {
  const urlEl = document.getElementById('url');
  const scanBtn = document.getElementById('scan');
  const scanCurrentBtn = document.getElementById('scanCurrent');
  const autoScanEl = document.getElementById('autoScan');
  const scanSummary = document.getElementById('scanSummary');
  const summaryCount = document.getElementById('summaryCount');
  const summaryPills = document.getElementById('summaryPills');
  const viewResultsLink = document.getElementById('viewResults');

  function setStatus(msg, isError) {
    var el = document.getElementById('status');
    if (el) { el.textContent = msg; el.className = 'status' + (isError ? ' error' : ' ok'); }
  }

  // Auto-scan: load from storage and save on change
  chrome.storage.local.get({ autoScanEnabled: false }, function (o) {
    if (autoScanEl) autoScanEl.checked = !!o.autoScanEnabled;
  });
  if (autoScanEl) {
    autoScanEl.addEventListener('change', function () {
      chrome.storage.local.set({ autoScanEnabled: autoScanEl.checked });
    });
  }

  // Scan summary from last report
  function renderSummary(report) {
    if (!report || !report.findings || !report.findings.length) {
      scanSummary.setAttribute('hidden', '');
      return;
    }
    var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    report.findings.forEach(function (f) {
      var s = (f.severity || 'info').toLowerCase();
      if (counts[s] !== undefined) counts[s]++; else counts.info++;
    });
    summaryCount.textContent = report.findings.length + ' findings';
    summaryPills.innerHTML = '';
    [['critical', 'Critical'], ['high', 'High'], ['medium', 'MEDIUM'], ['low', 'LOW'], ['info', 'INFO']].forEach(function (pair) {
      if (counts[pair[0]] > 0) {
        var span = document.createElement('span');
        span.className = 'pill ' + pair[0];
        span.textContent = pair[1].toUpperCase() + ': ' + counts[pair[0]];
        summaryPills.appendChild(span);
      }
    });
    scanSummary.removeAttribute('hidden');
  }

  chrome.storage.local.get(['lastReport'], function (o) {
    renderSummary(o.lastReport);
  });

  scanCurrentBtn.addEventListener('click', function () {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (tabs[0] && tabs[0].url && (tabs[0].url.startsWith('http://') || tabs[0].url.startsWith('https://'))) {
        urlEl.value = tabs[0].url;
      } else {
        setStatus('Current tab is not a valid URL', true);
      }
    });
  });

  function getApiBase() {
    return window.DivergAPI ? window.DivergAPI.detectApiBase() : Promise.resolve('http://127.0.0.1:5000');
  }

  scanBtn.addEventListener('click', async function () {
    var url = urlEl.value.trim();
    if (!url) {
      setStatus('Enter a URL', true);
      return;
    }
    var fullUrl = url.startsWith('http') ? url : 'https://' + url;
    scanBtn.disabled = true;
    setStatus('Scanning…');

    try {
      var apiBase = await getApiBase();
      var res = await fetch(apiBase + '/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: fullUrl, scope: 'api' }),
      });
      var data = await res.json();
      if (data.error) {
        setStatus('Error: ' + data.error, true);
        return;
      }
      await new Promise(function (resolve) {
        chrome.storage.local.set({ lastReport: data, lastReportUrl: fullUrl }, resolve);
      });
      renderSummary(data);
      setStatus('Done.');
      viewResultsLink.click();
    } catch (e) {
      setStatus('API not reachable. Run: python api_server.py', true);
    } finally {
      scanBtn.disabled = false;
    }
  });
})();
