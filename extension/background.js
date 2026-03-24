/**
 * Diverg Extension — Auto-scan on visit. 100% in-browser: no API, no Python.
 * Fetches page headers and runs a quick check in the tab to find security issues; opens side panel with results.
 * Tech lives in both Sectester and diverg-extension.
 */
(function () {
  const DEBOUNCE_MS = 1500;
  const STORAGE_KEYS = {
    autoScanEnabled: 'autoScanEnabled',
    results: 'autoScanResults',
    status: 'autoScanStatus',
  };

  let debounceTimers = {};

  function getOrigin(url) {
    try {
      const u = new URL(url);
      return u.origin;
    } catch (_) {
      return '';
    }
  }

  function isHttpOrHttps(url) {
    return url && (url.startsWith('http://') || url.startsWith('https://'));
  }

  function clearDebounce(tabId) {
    if (debounceTimers[tabId]) {
      clearTimeout(debounceTimers[tabId]);
      debounceTimers[tabId] = null;
    }
  }

  function bgFinding(title, severity, url, category, evidence, meta) {
    var m = meta || {};
    return {
      title: title,
      severity: severity,
      url: url,
      category: category,
      evidence: evidence,
      confidence: m.confidence || '',
      source: m.source || '',
      proof: m.proof || '',
      verified: m.verified !== undefined ? !!m.verified : false,
    };
  }

  function normalizeConfidence(value) {
    var conf = String(value || '').trim().toLowerCase();
    return (conf === 'high' || conf === 'medium' || conf === 'low') ? conf : '';
  }

  function defaultFindingSource(f) {
    var category = String(f.category || '').toLowerCase();
    var title = String(f.title || '').toLowerCase();
    if (category === 'headers') return 'header_analysis';
    if (category === 'client-side') return 'dom_scan';
    if (category === 'sensitive data') return 'regex_match';
    if (category === 'link credibility') return 'link_analysis';
    if (category === 'scan') return title.indexOf('fetch') !== -1 ? 'scan_error' : 'scan_summary';
    return 'analysis';
  }

  function defaultFindingConfidence(f, source) {
    var sev = String(f.severity || '').trim().toLowerCase();
    if (source === 'header_analysis') return 'high';
    if (source === 'regex_match') return sev === 'high' ? 'medium' : 'low';
    if (source === 'dom_scan' || source === 'link_analysis') return sev === 'high' ? 'medium' : 'low';
    if (source === 'scan_error') return 'medium';
    return sev === 'info' ? 'low' : 'medium';
  }

  function finalizeFindings(findings) {
    return (Array.isArray(findings) ? findings : []).map(function (f) {
      var source = String(f.source || '').trim() || defaultFindingSource(f);
      var confidence = normalizeConfidence(f.confidence) || defaultFindingConfidence(f, source);
      var proof = String(f.proof || '').trim() || String(f.evidence || '').substring(0, 280);
      var verified = f.verified !== undefined ? !!f.verified : source === 'header_analysis';
      return Object.assign({}, f, {
        source: source,
        confidence: confidence,
        proof: proof,
        verified: verified,
      });
    });
  }

  function buildEvidenceSummary(findings) {
    var summary = {
      total_findings: 0,
      confidence_counts: { high: 0, medium: 0, low: 0 },
      verified_count: 0,
      unverified_count: 0,
      source_breakdown: {},
      quality: 'limited',
    };
    (findings || []).forEach(function (f) {
      var conf = normalizeConfidence(f.confidence) || 'medium';
      summary.total_findings++;
      summary.confidence_counts[conf]++;
      if (f.verified) summary.verified_count++;
      var src = String(f.source || 'unknown');
      summary.source_breakdown[src] = (summary.source_breakdown[src] || 0) + 1;
    });
    summary.unverified_count = Math.max(0, summary.total_findings - summary.verified_count);
    summary.verified_ratio = summary.total_findings ? Number((summary.verified_count / summary.total_findings).toFixed(2)) : 0;
    if (summary.confidence_counts.high >= 3 || summary.verified_ratio >= 0.5) summary.quality = 'strong';
    else if (summary.confidence_counts.high >= 1 || summary.confidence_counts.medium >= 3) summary.quality = 'moderate';
    return summary;
  }

  function computeScoreAndVerdict(findings) {
    var list = findings || [];
    var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    var basePenalty = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
    var confidenceWeight = { high: 1.0, medium: 0.65, low: 0.35 };
    var deductions = 0;
    var hasSensitiveData = false;

    list.forEach(function (f) {
      var sev = String(f.severity || 'info').toLowerCase();
      var conf = normalizeConfidence(f.confidence) || 'medium';
      if (counts[sev] !== undefined) counts[sev]++;
      deductions += (basePenalty[sev] || 0) * (confidenceWeight[conf] || confidenceWeight.medium);
      if (String(f.category || '').toLowerCase() === 'sensitive data' && conf !== 'low') hasSensitiveData = true;
    });

    var score = Math.max(0, Math.min(100, Math.round(100 - deductions)));
    var verdict = 'Safe';
    var summaryText = 'Safe to run';
    var safeToRun = true;
    if (counts.critical > 0 || score < 40) {
      verdict = 'Risky';
      summaryText = 'Not recommended — significant security risks';
      safeToRun = false;
    } else if (counts.high > 0 || score < 70 || hasSensitiveData) {
      verdict = 'Caution';
      summaryText = hasSensitiveData ? 'Sensitive data patterns detected — proceed with caution' : 'Proceed with caution';
      safeToRun = false;
    }
    return { score: score, verdict: verdict, summaryText: summaryText, safeToRun: safeToRun, counts: counts };
  }

  function findingsFromHeaders(url, headers) {
    const findings = [];
    const h = headers || {};
    const get = function (name) {
      const lower = name.toLowerCase();
      for (const k in h) if (k.toLowerCase() === lower) return h[k];
      return null;
    };

    if (!get('strict-transport-security'))
      findings.push(bgFinding('Missing Strict-Transport-Security (HSTS)', 'High', url, 'Headers', 'Header not set. Enables HTTPS enforcement.', { confidence: 'high', source: 'header_analysis', proof: 'strict-transport-security absent', verified: true }));
    if (!get('x-frame-options'))
      findings.push(bgFinding('Missing X-Frame-Options', 'Medium', url, 'Headers', 'Site can be embedded in iframes; clickjacking possible.', { confidence: 'high', source: 'header_analysis', proof: 'x-frame-options absent', verified: true }));
    if (!get('x-content-type-options'))
      findings.push(bgFinding('Missing X-Content-Type-Options: nosniff', 'Medium', url, 'Headers', 'Browser may MIME-sniff content.', { confidence: 'high', source: 'header_analysis', proof: 'x-content-type-options absent', verified: true }));
    if (!get('content-security-policy'))
      findings.push(bgFinding('Missing Content-Security-Policy', 'Medium', url, 'Headers', 'No CSP; XSS and injection harder to mitigate.', { confidence: 'high', source: 'header_analysis', proof: 'content-security-policy absent', verified: true }));
    if (!get('referrer-policy'))
      findings.push(bgFinding('Missing Referrer-Policy', 'Low', url, 'Headers', 'Referrer may leak to third parties.', { confidence: 'high', source: 'header_analysis', proof: 'referrer-policy absent', verified: true }));
    if (!get('permissions-policy') && !get('feature-policy'))
      findings.push(bgFinding('Missing Permissions-Policy', 'Low', url, 'Headers', 'Browser features not restricted.', { confidence: 'high', source: 'header_analysis', proof: 'permissions-policy/feature-policy absent', verified: true }));

    return findings;
  }

  const SHORTENER_HOSTS = new Set([
    'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'buff.ly', 'is.gd', 'cutt.ly', 'rb.gy', 'rebrand.ly',
  ]);
  const SUSPICIOUS_TLDS = new Set(['top', 'xyz', 'click', 'gq', 'tk', 'ml', 'cf', 'work', 'zip', 'country']);

  function isIpHost(host) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  }

  function scoreLinkCredibility(pageUrl, href) {
    let u;
    try {
      u = new URL(href, pageUrl);
    } catch (_) {
      return null;
    }
    if (!/^https?:$/i.test(u.protocol)) return null;
    const origin = new URL(pageUrl).origin;
    const host = (u.hostname || '').toLowerCase();
    const tld = host.includes('.') ? host.split('.').pop() : '';
    const hay = host + ' ' + (u.pathname || '').toLowerCase();
    let score = 0;
    const reasons = [];

    if (host.startsWith('xn--')) { score += 45; reasons.push('punycode-domain'); }
    if (isIpHost(host)) { score += 40; reasons.push('ip-host'); }
    if (SHORTENER_HOSTS.has(host)) { score += 30; reasons.push('url-shortener'); }
    if (SUSPICIOUS_TLDS.has(tld)) { score += 22; reasons.push('suspicious-tld'); }
    if (/\b(airdrop|claim|bonus|giveaway|walletconnect|seed|private[-_ ]?key|drainer|free)\b/i.test(hay)) {
      score += 18; reasons.push('phishing-keywords');
    }
    if (u.protocol === 'http:') { score += 15; reasons.push('insecure-http'); }
    if (u.origin !== origin) { score += 8; reasons.push('external-origin'); }

    return { url: u.toString(), score: score, reasons: reasons };
  }

  function getPageSecurityData() {
    const scripts = Array.from(document.querySelectorAll('script')).map(function (s) {
      return { src: s.src || null, integrity: s.getAttribute('integrity'), inline: !s.src };
    });
    const forms = Array.from(document.querySelectorAll('form')).map(function (f) {
      return { action: f.action || '', method: (f.method || 'get').toLowerCase() };
    });
    const links = Array.from(document.querySelectorAll('a[href]')).map(function (a) {
      return a.href || a.getAttribute('href') || '';
    });
    const cookies = document.cookie ? document.cookie.length : 0;
    let bodyText = '';
    try {
      bodyText = (document.body && document.body.innerText) ? document.body.innerText.substring(0, 10000) : '';
    } catch (_) {}
    const suspicious = [];
    if (/api[_-]?key\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{20,}/i.test(bodyText)) suspicious.push('Possible API key in page');
    if (/password\s*[:=]\s*['"]?[^'"]{8,}/i.test(bodyText)) suspicious.push('Possible password in page');
    if (/bearer\s+[a-zA-Z0-9_\-.]{20,}/i.test(bodyText)) suspicious.push('Possible Bearer token in page');
    return { scripts: scripts, forms: forms, links: links, cookies: cookies, suspicious: suspicious };
  }

  function findingsFromPageData(url, pageData) {
    const findings = [];
    if (!pageData) return findings;

    const scripts = pageData.scripts || [];
    const withoutSri = scripts.filter(function (s) { return s.src && !s.integrity; });
    if (withoutSri.length > 0)
      findings.push(bgFinding('External scripts without SRI (' + withoutSri.length + ')', 'Medium', url, 'Client-side', 'Subresource Integrity missing; scripts can be tampered.', { confidence: 'high', source: 'dom_scan', proof: withoutSri.slice(0, 5).map(function (s) { return s.src; }).join(', '), verified: true }));

    const forms = pageData.forms || [];
    const httpForms = forms.filter(function (f) { return f.action && f.action.toLowerCase().startsWith('http:'); });
    if (httpForms.length > 0)
      findings.push(bgFinding('Form submits over HTTP', 'High', url, 'Client-side', 'Form action uses http://; credentials may be sent in cleartext.', { confidence: 'high', source: 'dom_scan', proof: httpForms.slice(0, 5).map(function (f) { return f.action; }).join(', '), verified: true }));

    const suspicious = pageData.suspicious || [];
    suspicious.forEach(function (s) {
      findings.push(bgFinding(s, 'High', url, 'Sensitive data', 'Possible secret in page content.', { confidence: 'medium', source: 'regex_match', proof: s, verified: false }));
    });

    const links = Array.isArray(pageData.links) ? pageData.links : [];
    if (links.length > 0) {
      const uniq = Array.from(new Set(links)).slice(0, 400);
      const scored = uniq.map(function (h) { return scoreLinkCredibility(url, h); }).filter(Boolean).sort(function (a, b) { return b.score - a.score; });
      const risky = scored.filter(function (x) { return x.score >= 40; });
      const caution = scored.filter(function (x) { return x.score >= 20; });
      if (risky.length > 0) {
        findings.push(bgFinding(
          'Link credibility risk (' + risky.length + ')',
          'High',
          url,
          'Link credibility',
          'Risky outbound links detected from live DOM links. Top: ' + risky.slice(0, 10).map(function (x) { return x.url + ' [' + x.reasons.join(',') + ']'; }).join(' | '),
          { confidence: 'medium', source: 'link_analysis', proof: risky.slice(0, 5).map(function (x) { return x.url + ' [' + x.reasons.join(',') + ']'; }).join(' | '), verified: false }
        ));
      } else if (caution.length > 0) {
        findings.push(bgFinding(
          'Link credibility caution (' + caution.length + ')',
          'Medium',
          url,
          'Link credibility',
          'Suspicious outbound links detected from live DOM links. Top: ' + caution.slice(0, 10).map(function (x) { return x.url + ' [' + x.reasons.join(',') + ']'; }).join(' | '),
          { confidence: 'low', source: 'link_analysis', proof: caution.slice(0, 5).map(function (x) { return x.url + ' [' + x.reasons.join(',') + ']'; }).join(' | '), verified: false }
        ));
      } else {
        findings.push(bgFinding('Link credibility: no risky patterns', 'Info', url, 'Link credibility', 'Analyzed ' + scored.length + ' link(s) from live DOM; no risky patterns found.', { confidence: 'medium', source: 'link_analysis', proof: 'analyzed ' + scored.length + ' links', verified: false }));
      }
    }

    return findings;
  }

  function runScanForTab(tabId, url) {
    clearDebounce(tabId);

    chrome.storage.local.get([STORAGE_KEYS.autoScanEnabled, STORAGE_KEYS.status], function (o) {
      if (!o[STORAGE_KEYS.autoScanEnabled]) return;

      const status = Object.assign({}, o[STORAGE_KEYS.status] || {});
      status[tabId] = 'scanning';
      chrome.storage.local.set({ [STORAGE_KEYS.status]: status });

      const origin = getOrigin(url);
      let allFindings = [];

      function finish() {
        chrome.storage.local.get([STORAGE_KEYS.results, STORAGE_KEYS.status], function (prev) {
          const results = Object.assign({}, prev[STORAGE_KEYS.results] || {});
          const statusObj = Object.assign({}, prev[STORAGE_KEYS.status] || {});
          const finalizedFindings = finalizeFindings(allFindings);
          const verdict = computeScoreAndVerdict(finalizedFindings);
          results[tabId] = {
            url: url,
            origin: origin,
            findings: finalizedFindings,
            summary: Object.assign({ total: finalizedFindings.length, total_findings: finalizedFindings.length }, verdict.counts),
            evidence_summary: buildEvidenceSummary(finalizedFindings),
            score: verdict.score,
            verdict: verdict.verdict,
            summaryText: verdict.summaryText,
            safeToRun: verdict.safeToRun,
            scannedAt: new Date().toISOString(),
            error: null,
          };
          statusObj[tabId] = 'done';
          chrome.storage.local.set({ [STORAGE_KEYS.results]: results, [STORAGE_KEYS.status]: statusObj }, function () {
            chrome.sidePanel.open({ tabId: tabId }).catch(function () {});
          });
        });
      }

      fetch(url, { method: 'GET', credentials: 'omit', redirect: 'follow' })
        .then(function (res) {
          const headers = {};
          res.headers.forEach(function (v, k) { headers[k] = v; });
          allFindings = findingsFromHeaders(url, headers);

          return chrome.scripting.executeScript({ target: { tabId: tabId }, func: getPageSecurityData });
        })
        .then(function (results) {
          const pageData = results && results[0] && results[0].result;
          allFindings = allFindings.concat(findingsFromPageData(url, pageData));
          finish();
        })
        .catch(function (err) {
          allFindings = [bgFinding('Could not fetch headers', 'Info', url, 'Scan', err.message || 'Request failed (e.g. CORS or invalid URL).', { confidence: 'medium', source: 'scan_error', proof: err.message || 'request failed', verified: false })];
          chrome.scripting.executeScript({ target: { tabId: tabId }, func: getPageSecurityData })
            .then(function (results) {
              const pageData = results && results[0] && results[0].result;
              allFindings = allFindings.concat(findingsFromPageData(url, pageData));
              finish();
            })
            .catch(function () { finish(); });
        });
    });
  }

  function scheduleScan(tabId, url) {
    clearDebounce(tabId);
    debounceTimers[tabId] = setTimeout(function () {
      debounceTimers[tabId] = null;
      runScanForTab(tabId, url);
    }, DEBOUNCE_MS);
  }

  chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
    if (changeInfo.status !== 'complete' || !tab.url) return;
    if (!isHttpOrHttps(tab.url)) return;

    const origin = getOrigin(tab.url);
    chrome.storage.local.get([STORAGE_KEYS.autoScanEnabled, STORAGE_KEYS.results], function (o) {
      if (!o[STORAGE_KEYS.autoScanEnabled]) return;

      const existing = (o[STORAGE_KEYS.results] || {})[tabId];
      const lastOrigin = existing ? existing.origin : null;

      if (origin !== lastOrigin) {
        scheduleScan(tabId, tab.url);
      }
    });
  });

  chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (msg.type === 'GET_AUTO_SCAN_ENABLED') {
      chrome.storage.local.get({ [STORAGE_KEYS.autoScanEnabled]: false }, function (o) {
        sendResponse({ enabled: o[STORAGE_KEYS.autoScanEnabled] });
      });
      return true;
    }
  });
})();
