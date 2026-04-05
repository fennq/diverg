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
    return (window.DivergAPI && window.DivergAPI.detectApiBase) ? window.DivergAPI.detectApiBase() : Promise.resolve('http://127.0.0.1:5000');
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
    var ev = finding.evidence && String(finding.evidence).trim();
    var im = finding.impact && String(finding.impact).trim();
    var rem = finding.remediation && String(finding.remediation).trim();
    var ctx = finding.context && String(finding.context).trim();
    var ftype = finding.finding_type && String(finding.finding_type).trim();
    var hasDetails = !!(ev || im || rem || ctx);
    var detailsBlock = '';
    if (hasDetails) {
      detailsBlock =
        '<details class="findingDetails">' +
          '<summary>Evidence &amp; remediation</summary>' +
          (ev ? '<div class="findingBlock"><strong>Evidence</strong><pre class="findingPre">' + escapeHtml(ev) + '</pre></div>' : '') +
          (im ? '<div class="findingBlock"><strong>Impact</strong><p class="findingPara">' + escapeHtml(im) + '</p></div>' : '') +
          (rem ? '<div class="findingBlock"><strong>Remediation</strong><p class="findingPara">' + escapeHtml(rem) + '</p></div>' : '') +
          (ctx ? '<div class="findingBlock findingContext"><strong>Why this matters</strong><p class="findingPara">' + escapeHtml(ctx) + '</p></div>' : '') +
        '</details>';
    }
    var ftypeBadge = '';
    if (ftype) {
      var ftypeLabel = ftype === 'vulnerability' ? 'Real risk'
        : ftype === 'hardening' ? 'Hardening'
        : ftype === 'informational' ? 'Informational'
        : ftype === 'positive' ? 'Looks good'
        : ftype;
      ftypeBadge = '<span class="findingType findingType--' + escapeHtml(ftype) + '">' + escapeHtml(ftypeLabel) + '</span>';
    }
    li.innerHTML =
      '<div class="findingHeader">' +
        '<span class="findingTitle">' + escapeHtml(finding.title || 'Untitled') + '</span>' +
        '<span class="findingSeverity ' + severity + '">' + escapeHtml(finding.severity || 'Info') + '</span>' +
        ftypeBadge +
      '</div>' +
      (finding.url ? '<p class="findingUrl">' + escapeHtml(finding.url) + '</p>' : '') +
      ((finding.confidence || finding.source || finding.verified)
        ? '<p class="findingUrl">' +
            escapeHtml(
              [
                finding.confidence ? 'confidence: ' + finding.confidence : '',
                finding.verified ? 'verified' : '',
                finding.source ? 'source: ' + finding.source : ''
              ].filter(Boolean).join(' · ')
            ) +
          '</p>'
        : '') +
      (finding.proof ? '<p class="findingUrl">proof: ' + escapeHtml(String(finding.proof).substring(0, 220)) + '</p>' : '') +
      detailsBlock +
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
          pocConclusion.textContent = 'API not reachable. Run: python api_server.py';
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

  function renderPhase4(report) {
    var sec = document.getElementById('phase4Section');
    var riskEl = document.getElementById('riskBlock');
    var remEl = document.getElementById('remediationBlock');
    var pathsEl = document.getElementById('attackPathsBlock');
    var gapEl = document.getElementById('gapBlock');
    if (!sec || !riskEl) return;
    var plan = report.remediation_plan || {};
    var paths = report.attack_paths || [];
    var gaps = report.gap_analysis || [];
    var sug = report.suggested_next_tests || [];
    var hasRisk = typeof report.risk_score === 'number';
    var hasRem = (plan.fix_now && plan.fix_now.length) || (plan.fix_soon && plan.fix_soon.length) || (plan.harden_when_possible && plan.harden_when_possible.length);
    var hasPaths = paths.length > 0;
    var hasGap = gaps.length > 0 || sug.length > 0;
    if (!hasRisk && !hasRem && !hasPaths && !hasGap) {
      sec.hidden = true;
      return;
    }
    sec.hidden = false;

    if (hasRisk) {
      var v = String(report.risk_verdict || 'Unknown');
      var vl = v.toLowerCase();
      var color = v === 'Risky' ? '#f85149' : (v === 'Caution' ? '#d29922' : '#3fb950');
      riskEl.innerHTML =
        '<h2 class="phase4Title">Phase 4 — Intelligence synthesis</h2>' +
        '<div class="riskScoreRow">' +
        '<span class="riskScoreValue" style="color:' + color + '">' + report.risk_score + '</span>' +
        '<span class="riskScoreSlash">/100</span>' +
        '<span class="riskVerdictBadge riskVerdict--' + escapeHtml(vl) + '">' + escapeHtml(v) + '</span>' +
        '</div>' +
        (report.risk_summary ? '<p class="riskSummary">' + escapeHtml(report.risk_summary) + '</p>' : '') +
        (typeof report.safe_to_run === 'boolean'
          ? '<p class="riskMeta">' + escapeHtml(report.safe_to_run ? 'Lower priority for blocking routine use.' : 'Review critical items before sensitive actions on this origin.') + '</p>'
          : '');
    } else {
      riskEl.innerHTML = '<h2 class="phase4Title">Phase 4 — Intelligence synthesis</h2><p class="riskMeta">Risk score not available for this report.</p>';
    }

    function tierHtml(title, items) {
      if (!items || !items.length) return '';
      var h = '<details class="remTier" open><summary>' + escapeHtml(title) + ' (' + items.length + ')</summary><ul class="remList">';
      items.forEach(function (it) {
        h += '<li><strong>' + escapeHtml(it.title || '') + '</strong>';
        if (it.severity) h += ' <span class="remSev">' + escapeHtml(it.severity) + '</span>';
        if (it.url) {
          h += '<br><a class="remLink" href="' + escapeHtml(it.url) + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(it.url.length > 96 ? it.url.substring(0, 96) + '…' : it.url) + '</a>';
        }
        h += '<p class="remText">' + escapeHtml(it.remediation || '') + '</p></li>';
      });
      h += '</ul></details>';
      return h;
    }
    if (hasRem) {
      remEl.innerHTML =
        '<h3 class="phase4Sub">Remediation plan</h3>' +
        tierHtml('Fix now', plan.fix_now) +
        tierHtml('Fix soon', plan.fix_soon) +
        tierHtml('Harden when possible', plan.harden_when_possible);
    } else {
      remEl.innerHTML = '';
    }

    if (hasPaths) {
      var ph = '<h3 class="phase4Sub">Correlated attack paths</h3><p class="phase4Hint">Chains built from findings across skills — use as hypotheses, then verify with evidence.</p>';
      paths.slice(0, 20).forEach(function (p) {
        ph += '<details class="pathCard"><summary><span class="pathChain">' + escapeHtml(p.chain_type || 'Chain') + '</span> · exploitability ' + escapeHtml(String(p.exploitability_score != null ? p.exploitability_score : '—')) + '</summary>';
        ph += '<p class="pathImpact">' + escapeHtml(p.impact_summary || '') + '</p>';
        ph += '<pre class="pathStory">' + escapeHtml(p.attack_story || '') + '</pre></details>';
      });
      pathsEl.innerHTML = ph;
    } else {
      pathsEl.innerHTML = '';
    }

    if (hasGap) {
      var gh = '<h3 class="phase4Sub">Gaps and suggested next tests</h3>';
      if (gaps.length) {
        gh += '<ul class="gapList">';
        gaps.forEach(function (g) {
          gh += '<li><strong>' + escapeHtml(g.missing_role || '') + '</strong>: ' + escapeHtml(g.reason || '') +
            (g.suggested_skills ? ' <span class="gapSkills">Skills: ' + escapeHtml(g.suggested_skills.join(', ')) + '</span>' : '') + '</li>';
        });
        gh += '</ul>';
      }
      if (sug.length) {
        gh += '<ul class="sugList">';
        sug.forEach(function (s) {
          gh += '<li><strong>' + escapeHtml(s.action || '') + '</strong> — ' + escapeHtml(s.reason || '') + '</li>';
        });
        gh += '</ul>';
      }
      if (report.attack_paths_note) {
        gh += '<p class="phase4Note">' + escapeHtml(report.attack_paths_note) + '</p>';
      }
      gapEl.innerHTML = gh;
    } else {
      gapEl.innerHTML = report.attack_paths_note ? '<p class="phase4Note">' + escapeHtml(report.attack_paths_note) + '</p>' : '';
    }
  }

  chrome.storage.local.get(['lastReport', 'lastReportUrl', 'diverg_last_scan'], function (o) {
    var report = o.lastReport;
    var url = o.lastReportUrl || '';
    if ((!report || !report.findings) && o.diverg_last_scan && Array.isArray(o.diverg_last_scan.findings)) {
      report = o.diverg_last_scan;
      url = report.target_url || url;
    }
    targetUrlEl.textContent = url || '—';
    if (!report || !report.findings || !report.findings.length) {
      noFindingsEl.style.display = 'block';
      return;
    }
    var s = report.summary;
    if (s) {
      var evidence = report.evidence_summary || {};
      var filteredTotal = Number(report.filtered_out_total != null ? report.filtered_out_total : (evidence.filtered_out_total || 0));
      var proofBundle = report.proof_bundle || {};
      var proofTotal = Number(proofBundle.total_bundles || 0);
      var replayCandidates = Number(proofBundle.replay_candidates || 0);
      summaryEl.textContent =
        'Total: ' + (s.total_findings || report.findings.length) +
        ' (Critical: ' + (s.critical || 0) + ', High: ' + (s.high || 0) + ', Medium: ' + (s.medium || 0) + ', Low: ' + (s.low || 0) + ', Info: ' + (s.info || 0) + ')' +
        (evidence.quality ? ' · Evidence: ' + evidence.quality + ' · Verified: ' + (evidence.verified_count || 0) + '/' + (evidence.total_findings || report.findings.length) : '') +
        ' · Strict: ' + (report.findings.length || 0) +
        ' · Filtered: ' + filteredTotal +
        (proofTotal ? (' · Proof: ' + proofTotal + (replayCandidates ? ' (' + replayCandidates + ' replay)' : '')) : '');
    } else {
      summaryEl.textContent = 'Findings: ' + report.findings.length;
    }
    renderPhase4(report);
    report.findings.forEach(function (f, i) { renderFinding(f, i); });
  });
})();
