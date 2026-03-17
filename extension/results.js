(function () {
  const findingsList = document.getElementById('findingsList');
  const noFindingsEl = document.getElementById('noFindings');
  const targetUrlEl = document.getElementById('targetUrl');
  const summaryEl = document.getElementById('summary');
  const pocModal = document.getElementById('pocModal');
  const pocConclusion = document.getElementById('pocConclusion');
  const pocMeta = document.getElementById('pocMeta');
  const pocBody = document.getElementById('pocBody');
  const pocClose = document.getElementById('pocClose');

  function getApiBase() {
    return new Promise(function (resolve) {
      chrome.storage.local.get({ apiBase: 'http://127.0.0.1:5000' }, function (o) {
        resolve(o.apiBase.replace(/\/$/, ''));
      });
    });
  }

  function canSimulate(finding) {
    if (!finding.url || !finding.url.startsWith('http')) return false;
    var t = (finding.title || '').toLowerCase();
    var c = (finding.category || '').toLowerCase();
    if (finding.poc_type === 'idor' || finding.poc_type === 'unauthenticated') return true;
    if (/idor|insecure direct object|object reference/.test(t) || /idor/.test(c)) return true;
    if (/unauthenticated|no auth|without auth|dangerous http/.test(t)) return true;
    if (/access control/.test(c) && (/id|user|account/.test(t))) return true;
    return true;
  }

  function renderFinding(finding, index) {
    var li = document.createElement('li');
    li.className = 'finding ' + (finding.severity || 'info').toLowerCase();
    var severity = (finding.severity || 'Info').toLowerCase();
    var showSimulate = canSimulate(finding);
    li.innerHTML =
      '<div class="findingHeader">' +
        '<span class="findingTitle">' + escapeHtml(finding.title || 'Untitled') + '</span>' +
        '<span class="findingSeverity ' + severity + '">' + escapeHtml(finding.severity || 'Info') + '</span>' +
      '</div>' +
      (finding.url ? '<p class="findingUrl">' + escapeHtml(finding.url) + '</p>' : '') +
      (showSimulate
        ? '<div class="findingActions"><button type="button" class="btnSimulate" data-index="' + index + '">Simulate</button></div>'
        : '');
    li.dataset.index = String(index);
    findingsList.appendChild(li);
    if (showSimulate) {
      li.querySelector('.btnSimulate').addEventListener('click', function () {
        runSimulate(finding);
      });
    }
  }

  function escapeHtml(s) {
    var div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  function runSimulate(finding) {
    getApiBase().then(function (apiBase) {
      var btn = document.querySelector('.btnSimulate[data-index="' + (findingsList.querySelectorAll('.finding').length) + '"]');
      var buttons = document.querySelectorAll('.btnSimulate');
      buttons.forEach(function (b) { b.disabled = true; });
      fetch(apiBase + '/api/poc/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          finding: {
            url: finding.url,
            title: finding.title,
            category: finding.category,
            evidence: finding.evidence,
            poc_type: finding.poc_type || (canSimulate(finding) ? (/unauthenticated|no auth/i.test(finding.title || '') ? 'unauthenticated' : 'idor') : null),
          },
        }),
      })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          pocConclusion.textContent = data.conclusion || data.error || 'No result.';
          pocMeta.textContent = (data.status_code != null ? 'Status: ' + data.status_code + ' — ' : '') + (data.poc_type || '');
          pocBody.textContent = data.body_preview || '(none)';
          pocModal.style.display = 'flex';
        })
        .catch(function (e) {
          pocConclusion.textContent = 'Request failed: ' + e.message;
          pocMeta.textContent = '';
          pocBody.textContent = '';
          pocModal.style.display = 'flex';
        })
        .finally(function () {
          buttons.forEach(function (b) { b.disabled = false; });
        });
    });
  }

  pocClose.addEventListener('click', function () {
    pocModal.style.display = 'none';
  });
  pocModal.addEventListener('click', function (e) {
    if (e.target === pocModal) pocModal.style.display = 'none';
  });

  chrome.storage.local.get(['lastReport', 'lastReportUrl'], function (o) {
    var report = o.lastReport;
    var url = o.lastReportUrl || '';
    targetUrlEl.textContent = url || '—';
    if (!report || !report.findings || !report.findings.length) {
      noFindingsEl.style.display = 'block';
      return;
    }
    var s = report.summary;
    if (s) {
      summaryEl.textContent =
        'Total: ' + (s.total_findings || report.findings.length) +
        ' (Critical: ' + (s.critical || 0) + ', High: ' + (s.high || 0) + ', Medium: ' + (s.medium || 0) + ', Low: ' + (s.low || 0) + ', Info: ' + (s.info || 0) + ')';
    } else {
      summaryEl.textContent = 'Findings: ' + report.findings.length;
    }
    report.findings.forEach(function (f, i) { renderFinding(f, i); });
  });
})();
