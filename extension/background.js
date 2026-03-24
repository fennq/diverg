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

  function findingsFromHeaders(url, headers) {
    const findings = [];
    const h = headers || {};
    const get = function (name) {
      const lower = name.toLowerCase();
      for (const k in h) if (k.toLowerCase() === lower) return h[k];
      return null;
    };

    if (!get('strict-transport-security'))
      findings.push({ severity: 'High', title: 'Missing Strict-Transport-Security (HSTS)', url: url, category: 'Headers', evidence: 'Header not set. Enables HTTPS enforcement.' });
    if (!get('x-frame-options'))
      findings.push({ severity: 'Medium', title: 'Missing X-Frame-Options', url: url, category: 'Headers', evidence: 'Site can be embedded in iframes; clickjacking possible.' });
    if (!get('x-content-type-options'))
      findings.push({ severity: 'Medium', title: 'Missing X-Content-Type-Options: nosniff', url: url, category: 'Headers', evidence: 'Browser may MIME-sniff content.' });
    if (!get('content-security-policy'))
      findings.push({ severity: 'Medium', title: 'Missing Content-Security-Policy', url: url, category: 'Headers', evidence: 'No CSP; XSS and injection harder to mitigate.' });
    if (!get('referrer-policy'))
      findings.push({ severity: 'Low', title: 'Missing Referrer-Policy', url: url, category: 'Headers', evidence: 'Referrer may leak to third parties.' });
    if (!get('permissions-policy') && !get('feature-policy'))
      findings.push({ severity: 'Low', title: 'Missing Permissions-Policy', url: url, category: 'Headers', evidence: 'Browser features not restricted.' });

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
      findings.push({ severity: 'Medium', title: 'External scripts without SRI (' + withoutSri.length + ')', url: url, category: 'Client-side', evidence: 'Subresource Integrity missing; scripts can be tampered.' });

    const forms = pageData.forms || [];
    const httpForms = forms.filter(function (f) { return f.action && f.action.toLowerCase().startsWith('http:'); });
    if (httpForms.length > 0)
      findings.push({ severity: 'High', title: 'Form submits over HTTP', url: url, category: 'Client-side', evidence: 'Form action uses http://; credentials may be sent in cleartext.' });

    const suspicious = pageData.suspicious || [];
    suspicious.forEach(function (s) {
      findings.push({ severity: 'High', title: s, url: url, category: 'Sensitive data', evidence: 'Possible secret in page content.' });
    });

    const links = Array.isArray(pageData.links) ? pageData.links : [];
    if (links.length > 0) {
      const uniq = Array.from(new Set(links)).slice(0, 400);
      const scored = uniq.map(function (h) { return scoreLinkCredibility(url, h); }).filter(Boolean).sort(function (a, b) { return b.score - a.score; });
      const risky = scored.filter(function (x) { return x.score >= 40; });
      const caution = scored.filter(function (x) { return x.score >= 20; });
      if (risky.length > 0) {
        findings.push({
          severity: 'High',
          title: 'Link credibility risk (' + risky.length + ')',
          url: url,
          category: 'Link credibility',
          evidence: 'Risky outbound links detected from live DOM links. Top: ' + risky.slice(0, 10).map(function (x) { return x.url + ' [' + x.reasons.join(',') + ']'; }).join(' | '),
        });
      } else if (caution.length > 0) {
        findings.push({
          severity: 'Medium',
          title: 'Link credibility caution (' + caution.length + ')',
          url: url,
          category: 'Link credibility',
          evidence: 'Suspicious outbound links detected from live DOM links. Top: ' + caution.slice(0, 10).map(function (x) { return x.url + ' [' + x.reasons.join(',') + ']'; }).join(' | '),
        });
      } else {
        findings.push({
          severity: 'Info',
          title: 'Link credibility: no risky patterns',
          url: url,
          category: 'Link credibility',
          evidence: 'Analyzed ' + scored.length + ' link(s) from live DOM; no risky patterns found.',
        });
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
          results[tabId] = {
            url: url,
            origin: origin,
            findings: allFindings,
            summary: { total: allFindings.length },
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
          allFindings = [{ severity: 'Info', title: 'Could not fetch headers', url: url, category: 'Scan', evidence: err.message || 'Request failed (e.g. CORS or invalid URL).' }];
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
