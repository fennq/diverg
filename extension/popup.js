(function () {
  const urlEl = document.getElementById('url');
  const scanBtn = document.getElementById('scan');
  const scanCurrentBtn = document.getElementById('scanCurrent');
  const statusEl = document.getElementById('status');
  const viewResultsLink = document.getElementById('viewResults');

  function getApiBase() {
    return new Promise(function (resolve) {
      chrome.storage.local.get({ apiBase: 'http://127.0.0.1:5000' }, function (o) {
        resolve(o.apiBase.replace(/\/$/, ''));
      });
    });
  }

  function setStatus(msg, isError) {
    statusEl.textContent = msg;
    statusEl.className = 'status' + (isError ? ' error' : ' ok');
  }

  scanCurrentBtn.addEventListener('click', function () {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (tabs[0] && tabs[0].url && (tabs[0].url.startsWith('http://') || tabs[0].url.startsWith('https://'))) {
        urlEl.value = tabs[0].url;
      } else {
        setStatus('Current tab is not a valid URL', true);
      }
    });
  });

  scanBtn.addEventListener('click', async function () {
    const url = urlEl.value.trim();
    if (!url) {
      setStatus('Enter a URL', true);
      return;
    }
    const fullUrl = url.startsWith('http') ? url : 'https://' + url;
    scanBtn.disabled = true;
    setStatus('Scanning…');

    try {
      const apiBase = await getApiBase();
      const res = await fetch(apiBase + '/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: fullUrl, scope: 'api' }),
      });
      const data = await res.json();
      if (data.error) {
        setStatus('Error: ' + data.error, true);
        return;
      }
      await new Promise(function (resolve) {
        chrome.storage.local.set({ lastReport: data, lastReportUrl: fullUrl }, resolve);
      });
      setStatus('Done. ' + (data.findings && data.findings.length) + ' findings.');
      viewResultsLink.click();
    } catch (e) {
      setStatus('Request failed: ' + e.message, true);
    } finally {
      scanBtn.disabled = false;
    }
  });
})();
