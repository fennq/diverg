/**
 * Diverg Extension — Deep security scan (headers, HTML, path probe).
 * Thorough checks with detailed evidence. No external API required for extended scan.
 */

(function (global) {
  try {
  const SECURITY_HEADERS = [
    { name: 'Strict-Transport-Security', severity: 'High', missing: 'HSTS not set.', impact: 'Browser may allow HTTP; traffic not enforced as HTTPS.', remediation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload', finding_type: 'hardening', context: 'If the site already redirects HTTP→HTTPS (common behind Cloudflare/CDN), real risk is lower. HSTS prevents SSL-strip downgrade attacks and is expected on production sites.' },
    { name: 'Content-Security-Policy', severity: 'Medium', missing: 'CSP not set.', impact: 'No browser-level XSS mitigation.', remediation: "Implement Content-Security-Policy (e.g. default-src 'self')", finding_type: 'hardening', context: 'CSP matters most on sites with user input, forms, or third-party scripts. Static sites benefit less but CSP still limits damage from supply-chain compromises.' },
    { name: 'X-Frame-Options', severity: 'Medium', missing: 'X-Frame-Options not set.', impact: 'Clickjacking possible.', remediation: "Add X-Frame-Options: DENY or SAMEORIGIN", finding_type: 'hardening', context: 'Real clickjacking risk requires the page to have authenticated actions or sensitive forms. For static/marketing pages, this is a best-practice gap, not an active threat.' },
    { name: 'X-Content-Type-Options', severity: 'Low', missing: 'X-Content-Type-Options not set.', impact: 'MIME sniffing possible.', remediation: 'Add X-Content-Type-Options: nosniff', finding_type: 'hardening', context: 'Prevents browsers from guessing content types. Trivial to add and universally recommended. Low real-world risk on most sites.' },
    { name: 'Referrer-Policy', severity: 'Low', missing: 'Referrer-Policy not set.', impact: 'Full URL may leak in Referer.', remediation: 'Add Referrer-Policy: strict-origin-when-cross-origin', finding_type: 'hardening', context: 'Mainly matters if URLs contain tokens, session IDs, or sensitive paths. Low-risk for public pages with clean URLs.' },
    { name: 'Permissions-Policy', severity: 'Low', missing: 'Permissions-Policy not set.', impact: 'Browser features not restricted.', remediation: 'Add Permissions-Policy to restrict camera, mic, etc.', finding_type: 'hardening', context: 'Restricts browser APIs (camera, mic, geolocation). Low-priority unless the site embeds third-party iframes or scripts.' },
    { name: 'Cross-Origin-Opener-Policy', severity: 'Low', missing: 'COOP not set.', impact: 'Cross-origin context sharing possible.', remediation: 'Add Cross-Origin-Opener-Policy: same-origin where appropriate', finding_type: 'hardening', context: 'Isolates browsing context from cross-origin windows. Mainly relevant for sites handling sensitive data. Often unnecessary for public/static sites.' },
  ];

  const DANGEROUS_HEADERS = [
    { name: 'Server', msg: 'Exposes server software/version.', severity: 'Low', context: 'Common CDN values like "cloudflare" or "nginx" are expected and not a real disclosure. Only concerning if it reveals specific versions of custom/backend software.' },
    { name: 'X-Powered-By', msg: 'Exposes backend framework.', severity: 'Low', context: 'Reveals the backend stack (e.g. Express, PHP). Useful to attackers for targeted exploits but low-risk alone. Easy to remove.' },
    { name: 'X-AspNet-Version', msg: 'Exposes ASP.NET version.', severity: 'Low', context: 'Specific version disclosure helps attackers pick known CVEs. Should be removed in production.' },
    { name: 'X-AspNetMvc-Version', msg: 'Exposes ASP.NET MVC version.', severity: 'Low', context: 'Same as X-AspNet-Version — specific version info aids targeted attacks. Remove in production.' },
  ];

  function getHeader(headers, name) {
    const lower = name.toLowerCase();
    for (const [k, v] of headers.entries()) if (k.toLowerCase() === lower) return v;
    return null;
  }

  function allHeadersList(response) {
    const out = [];
    response.headers.forEach((v, k) => { out.push(`${k}: ${v}`); });
    return out;
  }

  function finding(title, severity, url, category, evidence, impact, remediation, detail, meta) {
    const m = meta || {};
    const o = {
      title,
      severity,
      url,
      category,
      evidence,
      impact,
      remediation,
      confidence: m.confidence || '',
      source: m.source || '',
      proof: m.proof || '',
      verified: !!m.verified,
    };
    if (detail) o.detail = detail;
    if (m.context) o.context = m.context;
    if (m.finding_type) o.finding_type = m.finding_type;
    return o;
  }

  function normalizeConfidence(value) {
    const conf = String(value || '').trim().toLowerCase();
    return conf === 'high' || conf === 'medium' || conf === 'low' ? conf : '';
  }

  function defaultFindingSource(finding) {
    const category = String(finding.category || '').toLowerCase();
    const title = String(finding.title || '').toLowerCase();
    if (category === 'headers' || category === 'cookies' || category === 'transport' || category === 'information disclosure') return 'header_analysis';
    if (category === 'page structure' || category === 'client-side') return 'dom_scan';
    if (category === 'path probe') return 'path_probe';
    if (category === 'link credibility') return 'link_analysis';
    if (category === 'scan') return title.indexOf('failed') !== -1 ? 'scan_error' : 'scan_summary';
    return 'analysis';
  }

  function defaultFindingConfidence(finding, source) {
    const sev = String(finding.severity || '').trim().toLowerCase();
    if (source === 'header_analysis' || source === 'path_probe') return 'high';
    if (source === 'scan_error') return 'medium';
    if (source === 'link_analysis' || source === 'dom_scan') {
      return sev === 'high' || sev === 'medium' ? 'medium' : 'low';
    }
    return sev === 'info' ? 'low' : 'medium';
  }

  function finalizeFinding(f) {
    const source = String(f.source || '').trim() || defaultFindingSource(f);
    const confidence = normalizeConfidence(f.confidence) || defaultFindingConfidence(f, source);
    const proof = String(f.proof || '').trim() || String(f.detail || f.evidence || '').substring(0, 280);
    const verified = f.verified !== undefined ? !!f.verified : source === 'header_analysis';
    return Object.assign({}, f, {
      confidence: confidence,
      source: source,
      proof: proof,
      verified: verified,
    });
  }

  function finalizeFindings(findings) {
    return (Array.isArray(findings) ? findings : []).map(finalizeFinding);
  }

  function buildEvidenceSummary(findings) {
    const summary = {
      total_findings: 0,
      confidence_counts: { high: 0, medium: 0, low: 0 },
      finding_type_counts: { vulnerability: 0, hardening: 0, informational: 0, positive: 0 },
      verified_count: 0,
      unverified_count: 0,
      source_breakdown: {},
      quality: 'limited',
    };
    (findings || []).forEach((f) => {
      const conf = normalizeConfidence(f.confidence) || 'medium';
      summary.total_findings++;
      summary.confidence_counts[conf]++;
      if (f.verified) summary.verified_count++;
      const src = String(f.source || 'unknown');
      summary.source_breakdown[src] = (summary.source_breakdown[src] || 0) + 1;
      const ft = String(f.finding_type || '').toLowerCase();
      if (summary.finding_type_counts[ft] !== undefined) summary.finding_type_counts[ft]++;
    });
    summary.unverified_count = Math.max(0, summary.total_findings - summary.verified_count);
    summary.verified_ratio = summary.total_findings ? Number((summary.verified_count / summary.total_findings).toFixed(2)) : 0;
    if (summary.confidence_counts.high >= 3 || summary.verified_ratio >= 0.5) summary.quality = 'strong';
    else if (summary.confidence_counts.high >= 1 || summary.confidence_counts.medium >= 3) summary.quality = 'moderate';
    return summary;
  }

  function buildScanSummary(findings) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const typeCounts = { vulnerability: 0, hardening: 0, informational: 0, positive: 0 };
    (findings || []).forEach((f) => {
      const sev = String(f.severity || 'info').toLowerCase();
      if (counts[sev] !== undefined) counts[sev]++;
      const ft = String(f.finding_type || '').toLowerCase();
      if (typeCounts[ft] !== undefined) typeCounts[ft]++;
    });
    return Object.assign({ total_findings: (findings || []).length, finding_types: typeCounts }, counts);
  }

  function finalizeScanOutput(targetUrl, scanType, findings, scanMeta) {
    const finalized = finalizeFindings(findings);
    return {
      target_url: targetUrl,
      scan_type: scanType,
      findings: finalized,
      summary: buildScanSummary(finalized),
      evidence_summary: buildEvidenceSummary(finalized),
      scanned_at: new Date().toISOString(),
      scan_meta: scanMeta || {},
    };
  }

  function analyzeHeaders(url, response) {
    const findings = [];
    const headers = response.headers;

    const allHeaderLines = allHeadersList(response);
    const headerSummary = allHeaderLines.length ? allHeaderLines.join('\n') : 'No headers captured.';
    findings.push(finding(
      'Response headers (full list)',
      'Info',
      url,
      'Headers',
      `Total: ${allHeaderLines.length} header(s). Use this to verify every header the server sends.`,
      'Review for any unexpected or sensitive headers.',
      'Remove or restrict headers that leak stack or version info.',
      headerSummary
    ));

    for (const def of SECURITY_HEADERS) {
      const value = getHeader(headers, def.name);
      if (!value || !value.trim()) {
        findings.push(finding(
          def.missing,
          def.severity,
          url,
          'Headers',
          `'${def.name}' was not present in the response. Check the full header list above.`,
          def.impact,
          def.remediation,
          undefined,
          { finding_type: def.finding_type || 'hardening', context: def.context || '' }
        ));
        continue;
      }
      if (def.name === 'Strict-Transport-Security') {
        if (!/includeSubDomains/i.test(value)) {
          findings.push(finding(
            'HSTS missing includeSubDomains',
            'Medium',
            url,
            'Headers',
            `Current value: ${value}. Subdomains are not covered.`,
            'Subdomains can be loaded over HTTP.',
            'Add includeSubDomains to the HSTS header.',
            value
          ));
        }
        const maxAgeMatch = value.match(/max-age\s*=\s*(\d+)/i);
        if (maxAgeMatch) {
          const maxAge = parseInt(maxAgeMatch[1], 10);
          if (maxAge < 31536000) {
            findings.push(finding(
              `HSTS max-age too low (${maxAge}s)`,
              'Low',
              url,
              'Headers',
              `max-age=${maxAge}. Recommended ≥ 31536000 (1 year). Full header: ${value}`,
              'Short max-age reduces long-term HSTS protection.',
              'Set max-age to at least 31536000.',
              value
            ));
          }
        }
      }
      if (def.name === 'Content-Security-Policy' && value) {
        const hasUnsafeInline = /'unsafe-inline'|unsafe-inline/i.test(value);
        const hasUnsafeEval = /'unsafe-eval'|unsafe-eval/i.test(value);
        if (hasUnsafeInline || hasUnsafeEval) {
          const parts = [];
          if (hasUnsafeInline) parts.push('unsafe-inline');
          if (hasUnsafeEval) parts.push('unsafe-eval');
          findings.push(finding(
            `CSP allows ${parts.join(' and ')}`,
            'Medium',
            url,
            'Headers',
            `Content-Security-Policy weakens XSS protection. Directives include: ${parts.join(', ')}. Full CSP: ${value.substring(0, 300)}${value.length > 300 ? '…' : ''}`,
            'Script injection or inline execution may be possible; CSP is less effective.',
            "Tighten script-src; avoid 'unsafe-inline' and 'unsafe-eval' where possible.",
            value
          ));
        }
      }
    }

    for (const dh of DANGEROUS_HEADERS) {
      const value = getHeader(headers, dh.name);
      if (value && value.trim()) {
        findings.push(finding(
          `Information disclosure: ${dh.name}`,
          dh.severity,
          url,
          'Information Disclosure',
          `Header value: ${value}. This can be used to fingerprint the stack.`,
          dh.msg,
          `Remove or genericize the ${dh.name} header.`,
          value,
          { finding_type: 'hardening', context: dh.context || '' }
        ));
      }
    }

    const setCookies = headers.get('set-cookie') || headers.get('Set-Cookie');
    if (setCookies) {
      const cookieStr = Array.isArray(setCookies) ? setCookies.join('\n---\n') : setCookies;
      const hasSecure = /;\s*Secure\b/i.test(cookieStr);
      const hasHttpOnly = /;\s*HttpOnly\b/i.test(cookieStr);
      const hasSameSite = /;\s*SameSite\s*=/i.test(cookieStr);
      if (!hasSecure) {
        findings.push(finding(
          'Set-Cookie: Secure flag not seen',
          'Medium',
          url,
          'Cookies',
          'At least one cookie in the response does not include the Secure attribute. Raw Set-Cookie value(s) below for verification.',
          'Cookies can be sent over HTTP; risk of interception.',
          'Add the Secure attribute to all cookies on HTTPS.',
          cookieStr.substring(0, 800),
          { finding_type: 'vulnerability', context: 'Without the Secure flag, cookies can be sent over plain HTTP, making them interceptable. This is a real issue if the site handles authentication or sensitive data.' }
        ));
      }
      if (!hasHttpOnly) {
        findings.push(finding(
          'Set-Cookie: HttpOnly flag not seen',
          'Medium',
          url,
          'Cookies',
          'Session or sensitive cookies should use HttpOnly so JavaScript cannot read them. Raw Set-Cookie value(s) below.',
          'XSS could steal session if cookies are readable by script.',
          'Add HttpOnly to session and sensitive cookies.',
          cookieStr.substring(0, 800),
          { finding_type: 'hardening', context: 'HttpOnly prevents JavaScript from reading the cookie. Critical for session cookies, less important for non-sensitive cookies like analytics or UI preferences.' }
        ));
      }
      findings.push(finding(
        'Cookie attributes summary',
        'Info',
        url,
        'Cookies',
        `Secure: ${hasSecure ? 'yes' : 'no'}. HttpOnly: ${hasHttpOnly ? 'yes' : 'no'}. SameSite present: ${hasSameSite ? 'yes' : 'no'}.`,
        'Review the full Set-Cookie value(s) in the detail section.',
        'Set Secure, HttpOnly, and SameSite=Strict/Lax where appropriate.',
        cookieStr.substring(0, 1000)
      ));
    }

    if (url.startsWith('http://')) {
      findings.push(finding('Page served over HTTP', 'High', url, 'Transport', 'Final request URL uses http:// — connection is not encrypted.', 'Traffic is visible to eavesdroppers.', 'Serve over HTTPS and redirect HTTP to HTTPS.', undefined, { finding_type: 'vulnerability', context: 'Serving over plain HTTP is a real security problem. All traffic is visible to anyone on the network. This should be fixed.' }));
    } else if (url.startsWith('https://')) {
      findings.push(finding('Page served over HTTPS', 'Info', url, 'Transport', 'Final request URL uses https:// — connection is encrypted.', 'Traffic is encrypted in transit.', 'None.', undefined, { finding_type: 'positive', context: 'HTTPS is correctly configured. Traffic is encrypted.' }));
    }

    const acao = getHeader(headers, 'Access-Control-Allow-Origin');
    if (acao === '*') {
      findings.push(finding(
        'CORS allows any origin (*)',
        'Low',
        url,
        'Headers',
        `Access-Control-Allow-Origin: ${acao}. Any website can make cross-origin requests.`,
        'With credentials, data could be exposed to any origin.',
        'Restrict to specific origins or avoid credentials with *.',
        `Access-Control-Allow-Origin: ${acao}`,
        { finding_type: 'hardening', context: 'CORS * is only dangerous if combined with credentials (Access-Control-Allow-Credentials: true). For public APIs or static assets, wildcard CORS is standard and expected. Check whether credentials are also allowed before treating this as a real risk.' }
      ));
    }

    const allow = getHeader(headers, 'Allow');
    if (allow) {
      findings.push(finding(
        'HTTP Allow header (methods)',
        'Info',
        url,
        'Headers',
        `Server reports allowed methods: ${allow}.`,
        'Useful for knowing what methods the server accepts (GET, POST, PUT, DELETE, etc.).',
        'Restrict methods to what is actually needed.',
        allow
      ));
    }

    return findings;
  }

  function extractForms(html) {
    const forms = [];
    const formRe = /<form[^>]*>[\s\S]*?<\/form>/gi;
    let m;
    while ((m = formRe.exec(html)) !== null) {
      const block = m[0];
      const action = (block.match(/action\s*=\s*["']([^"']*)["']/i) || [null, ''])[1];
      const method = (block.match(/method\s*=\s*["']?(\w+)["']?/i) || [null, 'GET'])[1].toUpperCase();
      const inputs = (block.match(/<input[^>]*name\s*=\s*["']([^"']*)["']/gi) || []).map(s => (s.match(/name\s*=\s*["']([^"']*)["']/i) || [null, '?'])[1]);
      forms.push({ action: action || '(same page)', method, inputs });
    }
    return forms;
  }

  function extractScriptSrcs(html) {
    return (html.match(/<script[^>]*src\s*=\s*["']([^"']+)["']/gi) || []).map(s => (s.match(/src\s*=\s*["']([^"']+)["']/i) || [null, ''])[1]);
  }

  function extractLinks(html) {
    const hrefs = (html.match(/<a[^>]*href\s*=\s*["']([^"']+)["']/gi) || []).map(s => (s.match(/href\s*=\s*["']([^"']+)["']/i) || [null, ''])[1]);
    return hrefs;
  }

  const SHORTENER_HOSTS = new Set([
    'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'buff.ly', 'is.gd', 'cutt.ly', 'rb.gy', 'rebrand.ly',
  ]);
  const SUSPICIOUS_TLDS = new Set(['top', 'xyz', 'click', 'gq', 'tk', 'ml', 'cf', 'work', 'zip', 'country']);

  function isIpHost(host) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  }

  function analyzeLinkCredibility(pageUrl, links) {
    const origin = new URL(pageUrl).origin;
    const seen = new Set();
    const scored = [];

    for (const raw of (links || [])) {
      if (!raw || typeof raw !== 'string') continue;
      let abs;
      try {
        abs = new URL(raw, pageUrl);
      } catch (_) {
        continue;
      }
      if (!/^https?:$/i.test(abs.protocol)) continue;
      const href = abs.toString();
      if (seen.has(href)) continue;
      seen.add(href);

      let score = 0;
      const reasons = [];
      const host = abs.hostname.toLowerCase();
      const tld = host.includes('.') ? host.split('.').pop() : '';
      const hay = (host + ' ' + abs.pathname.toLowerCase());

      if (host.startsWith('xn--')) {
        score += 45;
        reasons.push('punycode-domain');
      }
      if (isIpHost(host)) {
        score += 40;
        reasons.push('ip-host');
      }
      if (SHORTENER_HOSTS.has(host)) {
        score += 30;
        reasons.push('url-shortener');
      }
      if (SUSPICIOUS_TLDS.has(tld)) {
        score += 22;
        reasons.push('suspicious-tld');
      }
      if (/\b(airdrop|claim|bonus|giveaway|walletconnect|seed|private[-_ ]?key|drainer|free)\b/i.test(hay)) {
        score += 18;
        reasons.push('phishing-keywords');
      }
      if (abs.protocol === 'http:') {
        score += 15;
        reasons.push('insecure-http');
      }
      if (abs.origin !== origin) {
        score += 8;
        reasons.push('external-origin');
      }

      const severity = score >= 70 ? 'High' : score >= 40 ? 'Medium' : score >= 20 ? 'Low' : 'Info';
      scored.push({ url: href, host, score, severity, reasons });
    }

    scored.sort((a, b) => b.score - a.score);
    const risky = scored.filter((x) => x.score >= 40);
    const caution = scored.filter((x) => x.score >= 20);

    return { total: scored.length, riskyCount: risky.length, cautionCount: caution.length, top: scored.slice(0, 25) };
  }

  function analyzeHtml(url, html) {
    const findings = [];
    if (!html || typeof html !== 'string') return findings;

    const forms = extractForms(html);
    const scriptSrcs = extractScriptSrcs(html);
    const links = extractLinks(html);
    const inlineScriptCount = (html.match(/<script[^>]*>[\s\S]*?<\/script>/gi) || []).length;
    const iframeCount = (html.match(/<iframe/gi) || []).length;
    const metaTags = (html.match(/<meta[^>]+>/gi) || []).length;

    const formDetail = forms.map((f, i) => `Form ${i + 1}: action="${f.action}", method=${f.method}, inputs=[${f.inputs.join(', ')}]`).join('\n');
    if (forms.length > 0) {
      const hasToken = /csrf|_token|authenticity_token|__requestverificationtoken/i.test(html);
      findings.push(finding(
        `Page has ${forms.length} form(s)`,
        hasToken ? 'Info' : 'Medium',
        url,
        'Page Structure',
        `Forms: ${forms.length}. ${hasToken ? 'Common CSRF token name found in page.' : 'No common CSRF token name (csrf, _token, authenticity_token) found — verify manually.'} Each form's action, method, and input names are listed in the detail section.`,
        hasToken ? 'Forms present; token name detected.' : 'If state-changing forms lack CSRF protection, they may be vulnerable to CSRF.',
        'Implement CSRF tokens for state-changing forms; verify in browser.',
        formDetail,
        { finding_type: hasToken ? 'positive' : 'hardening', context: hasToken ? 'CSRF token detected — forms appear protected.' : 'CSRF tokens are needed for forms that change state (login, payment, settings). Read-only search forms or contact forms sending to third-party APIs (Web3Forms, Formspree) may not need CSRF protection.' }
      ));
    }

    if (inlineScriptCount > 0 || scriptSrcs.length > 0) {
      const externalList = scriptSrcs.slice(0, 20).join('\n');
      findings.push(finding(
        `Scripts: ${inlineScriptCount} inline, ${scriptSrcs.length} external`,
        'Info',
        url,
        'Page Structure',
        `Inline <script> blocks: ${inlineScriptCount}. External script srcs: ${scriptSrcs.length}. Inline scripts are harder to lock down with CSP. First 20 external URLs in detail.`,
        'Inline scripts increase XSS surface; external scripts should be from trusted origins.',
        'Move scripts to external files; use CSP script-src to restrict.',
        externalList || '(none)'
      ));
    }

    if (links.length > 0) {
      const externalLinks = links.filter(h => h.startsWith('http') && !h.startsWith(new URL(url).origin));
      findings.push(finding(
        `Page has ${links.length} link(s), ${externalLinks.length} to external origins`,
        'Info',
        url,
        'Page Structure',
        `Total <a href>: ${links.length}. External: ${externalLinks.length}. Review for open redirect or untrusted targets.`,
        'External links can be phished or lead to untrusted sites.',
        'Validate redirect targets; use rel="noopener" for target="_blank".',
        externalLinks.slice(0, 30).join('\n') || '(none)'
      ));

      const cred = analyzeLinkCredibility(url, links);
      if (cred.riskyCount > 0) {
        findings.push(finding(
          `Link credibility risk: ${cred.riskyCount} risky link(s)`,
          'High',
          url,
          'Link credibility',
          `Detected ${cred.riskyCount} high-confidence risky link(s) out of ${cred.total} scanned.`,
          'Users can be redirected to phishing/malicious destinations.',
          'Remove suspicious links, validate partner domains, and add allowlists.',
          cred.top
            .filter((x) => x.score >= 40)
            .slice(0, 20)
            .map((x) => `${x.url} | score=${x.score} | ${x.reasons.join(',')}`)
            .join('\n')
        ));
      } else if (cred.cautionCount > 0) {
        findings.push(finding(
          `Link credibility caution: ${cred.cautionCount} suspicious link(s)`,
          'Medium',
          url,
          'Link credibility',
          `Detected ${cred.cautionCount} suspicious link(s) out of ${cred.total} scanned.`,
          'Potential trust and phishing risk from outbound links.',
          'Review and keep only trusted outbound domains.',
          cred.top
            .filter((x) => x.score >= 20)
            .slice(0, 20)
            .map((x) => `${x.url} | score=${x.score} | ${x.reasons.join(',')}`)
            .join('\n')
        ));
      }
    }

    if (url.startsWith('https://') && /(?:src|href)\s*=\s*["']http:\/\//i.test(html)) {
      const count = (html.match(/(?:src|href)\s*=\s*["']http:\/\//gi) || []).length;
      const examples = (html.match(/(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi) || []).slice(0, 10).join(', ');
      findings.push(finding(
        'Mixed content: HTTP resources on HTTPS page',
        'Medium',
        url,
        'Page Structure',
        `Found ${count} resource(s) loaded over http://. Browsers may block or warn. Example attributes: ${examples}`,
        'Insecure resources can be tampered with; some browsers block them.',
        'Load all resources over HTTPS.',
        `Count: ${count}. Search the page for src="http:// or href="http://`
      ));
    }

    const passwordInputs = (html.match(/<input[^>]*type\s*=\s*["']?password["']?[^>]*>/gi) || []);
    const withoutOff = passwordInputs.filter(block => !/autocomplete\s*=\s*["']?off["']?/i.test(block));
    if (withoutOff.length > 0) {
      findings.push(finding(
        `${withoutOff.length} password input(s) without autocomplete=off`,
        'Low',
        url,
        'Page Structure',
        'Password fields may allow browser autocomplete. Some sites allow this by design.',
        'On shared devices, consider disabling autocomplete for sensitive inputs.',
        'Add autocomplete="off" only if consistent with product requirements.',
        `Count: ${withoutOff.length}. Inspect <input type="password"> in DevTools.`
      ));
    }

    if (iframeCount > 0 || metaTags > 0) {
      findings.push(finding(
        `Page structure: ${iframeCount} iframe(s), ${metaTags} meta tag(s)`,
        'Info',
        url,
        'Page Structure',
        `iframes can load third-party content; meta tags may include viewport, description, or refresh. Review for sensitive meta (e.g. refresh redirects).`,
        'iframes can be used for clickjacking or loading untrusted content.',
        'Use X-Frame-Options/CSP frame-ancestors; validate meta refresh targets.',
        `iframes: ${iframeCount}, meta tags: ${metaTags}`
      ));
    }

    return findings;
  }

  const PROBE_PATHS = [
    { path: '/.env', label: 'Env file' },
    { path: '/.git/config', label: 'Git config' },
    { path: '/config.json', label: 'Config JSON' },
    { path: '/.env.local', label: 'Env local' },
    { path: '/api', label: 'API root' },
    { path: '/api/v1', label: 'API v1' },
    { path: '/api/v2', label: 'API v2' },
    { path: '/graphql', label: 'GraphQL' },
    { path: '/admin', label: 'Admin' },
    { path: '/administrator', label: 'Administrator' },
    { path: '/wp-admin', label: 'WordPress admin' },
    { path: '/phpmyadmin', label: 'phpMyAdmin' },
    { path: '/server-status', label: 'Server status' },
    { path: '/debug', label: 'Debug' },
    { path: '/actuator', label: 'Spring actuator' },
    { path: '/actuator/health', label: 'Actuator health' },
    { path: '/.well-known/security.txt', label: 'Security.txt' },
    { path: '/backup', label: 'Backup' },
    { path: '/backups', label: 'Backups' },
    { path: '/storage', label: 'Storage' },
    { path: '/uploads', label: 'Uploads' },
    { path: '/swagger', label: 'Swagger' },
    { path: '/openapi.json', label: 'OpenAPI JSON' },
    { path: '/.htaccess', label: 'htaccess' },
    { path: '/web.config', label: 'Web config' },
    { path: '/robots.txt', label: 'Robots' },
    { path: '/sitemap.xml', label: 'Sitemap' },
    { path: '/crossdomain.xml', label: 'Crossdomain' },
    { path: '/client-access-policy.xml', label: 'Client access policy' },
    { path: '/.DS_Store', label: 'DS_Store' },
    { path: '/wp-json', label: 'WordPress REST' },
    { path: '/api/docs', label: 'API docs' },
    { path: '/api-docs', label: 'API docs alt' },
    { path: '/health', label: 'Health' },
    { path: '/status', label: 'Status' },
    { path: '/metrics', label: 'Metrics' },
    { path: '/info', label: 'Info' },
    { path: '/env', label: 'Env' },
    { path: '/config', label: 'Config' },
    { path: '/console', label: 'Console' },
    { path: '/manager/html', label: 'Tomcat manager' },
    { path: '/.well-known/change-password', label: 'Change password' },
    { path: '/checkout', label: 'Checkout' },
    { path: '/order', label: 'Order' },
    { path: '/cart', label: 'Cart' },
    { path: '/payment', label: 'Payment' },
    { path: '/billing', label: 'Billing' },
    { path: '/login', label: 'Login' },
    { path: '/signin', label: 'Sign in' },
  ];

  /** Path subsets for option scan when API is unavailable. Goal → path labels to include. */
  const GOAL_PATH_FILTER = {
    'admin panel': ['Admin', 'Administrator', 'wp-admin', 'phpMyAdmin', 'Debug', 'Actuator', 'manager', 'Console'],
    'payment bypass': ['Checkout', 'Order', 'Cart', 'Payment', 'Billing', 'Backup'],
    'auth': ['Admin', 'Login', 'Actuator', 'Sign in'],
    'recon': ['Robots', 'Sitemap', 'API', 'GraphQL', 'Swagger', 'OpenAPI', 'security.txt', 'Backup', 'config', 'Env'],
    'headers': [],
    'client-side': [],
    'sql injection': ['api', 'API', 'GraphQL', 'Admin', 'Swagger', 'OpenAPI'],
    'full audit': null,
  };

  function getPathsForGoal(goal) {
    const key = (goal || '').toLowerCase().trim();
    const filter = GOAL_PATH_FILTER[key];
    if (filter === null || key === 'full audit') return PROBE_PATHS;
    if (!filter || filter.length === 0) return [];
    return PROBE_PATHS.filter((p) => filter.some((f) => p.label.toLowerCase().includes(f.toLowerCase()) || p.path.toLowerCase().includes(f.toLowerCase())));
  }

  const PROBE_CONCURRENCY = 12;

  async function probeOnePath(origin, path, label) {
    const url = origin + (path.startsWith('/') ? path : '/' + path);
    try {
      const res = await fetch(url, { method: 'GET', redirect: 'follow', credentials: 'omit', mode: 'cors' });
      const status = res.status;
      let bodyPreview = '';
      try {
        const text = await res.text();
        bodyPreview = text.length > 200 ? text.substring(0, 200) + '…' : text;
      } catch (_) {}
      return { path, label, status, len: bodyPreview.length, preview: bodyPreview.substring(0, 120), resUrl: res.url || url };
    } catch (_) {
      return { path, label, status: 0, len: 0, preview: '', resUrl: url };
    }
  }

  async function probePathsInParallel(origin, pathsToProbe) {
    const pathResults = [];
    for (let i = 0; i < pathsToProbe.length; i += PROBE_CONCURRENCY) {
      const batch = pathsToProbe.slice(i, i + PROBE_CONCURRENCY);
      const results = await Promise.all(batch.map(({ path, label }) => probeOnePath(origin, path, label)));
      pathResults.push(...results);
    }
    return pathResults;
  }

  async function runOptionScan(targetUrl, goal) {
    const key = (goal || '').toLowerCase().trim();
    const start = Date.now();

    if (key === 'headers' || key === 'ssl' || key === '') {
      const findings = [];
      let finalUrl = targetUrl;
      try {
        const response = await fetch(targetUrl, { method: 'GET', redirect: 'follow', credentials: 'omit', mode: 'cors' });
        finalUrl = response.url || targetUrl;
        findings.push(...analyzeHeaders(finalUrl, response));
      } catch (err) {
        findings.push(finding('Scan request failed', 'Info', targetUrl, 'Scan', err.message || String(err), 'Headers check could not complete.', 'Ensure the target is reachable.', err.stack || ''));
      }
      const duration_ms = Date.now() - start;
      return finalizeScanOutput(finalUrl, 'option', findings, { goal: key || 'headers', headers_only: true, duration_ms, request_count: 1 });
    }

    const base = await runStandardScan(targetUrl);
    const findings = [...(base.findings || [])];
    const finalUrl = base.target_url || targetUrl;
    const origin = new URL(finalUrl).origin;
    const pathsToProbe = getPathsForGoal(goal);
    const pathResults = pathsToProbe.length ? await probePathsInParallel(origin, pathsToProbe) : [];
    const pathsProbed = pathResults.length;
    let pathsHit = 0;
    const EXPECTED_PUBLIC_PATHS = new Set(['/robots.txt', '/sitemap.xml', '/.well-known/security.txt', '/.well-known/change-password', '/health', '/status']);
    const SENSITIVE_PATHS = new Set(['/.env', '/.env.local', '/.git/config', '/config.json', '/.htaccess', '/web.config', '/.DS_Store', '/backup', '/backups', '/phpmyadmin', '/server-status', '/debug', '/actuator', '/console', '/manager/html']);

    for (const p of pathResults) {
      if (p.status >= 200 && p.status < 400) {
        pathsHit++;
        const isExpected = EXPECTED_PUBLIC_PATHS.has(p.path);
        const isSensitive = SENSITIVE_PATHS.has(p.path);
        const sev = isSensitive ? 'High' : (isExpected ? 'Info' : (p.status === 200 ? 'Low' : 'Info'));
        const ftype = isSensitive ? 'vulnerability' : (isExpected ? 'informational' : 'hardening');
        const ctx = isSensitive
          ? 'This path should never be publicly accessible. It may expose credentials, source code, or internal configuration. Restrict or remove immediately.'
          : isExpected
            ? 'This is a standard public file. Its presence is expected and not a security issue.'
            : 'This path returned a response. Verify whether it should be publicly accessible or if it reveals internal functionality.';
        findings.push(finding(
          `Path accessible: ${p.path} (${p.label}) → ${p.status}`,
          sev,
          p.resUrl,
          'Path probe',
          `GET ${p.path} returned ${p.status}. Label: ${p.label}.${isExpected ? ' This is expected.' : ' Verify if this path should be public.'}`,
          isSensitive ? 'Sensitive internal path is exposed; may leak credentials or config.' : (isExpected ? 'Standard public resource.' : 'Internal paths may reveal application structure.'),
          isSensitive ? 'Block access immediately via server config or firewall.' : (isExpected ? 'No action needed.' : 'Restrict access if not intended to be public.'),
          `Status: ${p.status}. First 120 chars:\n${p.preview}`,
          { finding_type: ftype, context: ctx }
        ));
      }
    }

    if (pathsProbed > 0) {
      findings.push(finding(
        'Option scan path summary',
        'Info',
        finalUrl,
        'Scan',
        `Probed ${pathsProbed} paths for "${goal}"; ${pathsHit} returned 2xx/3xx.`,
        'Use this to see which paths exist for this focus.',
        'Restrict or remove unnecessary endpoints.',
        pathResults.map((p) => `${p.path} (${p.label}): ${p.status}`).join('\n')
      ));
    }

    const duration_ms = Date.now() - start;
    return finalizeScanOutput(finalUrl, 'option', findings, { goal: key, paths_probed: pathsProbed, paths_with_2xx_3xx: pathsHit, duration_ms, request_count: 1 + pathsProbed });
  }

  async function runStandardScan(targetUrl) {
    const findings = [];
    let finalUrl = targetUrl;
    const start = Date.now();

    try {
      const response = await fetch(targetUrl, { method: 'GET', redirect: 'follow', credentials: 'omit', mode: 'cors' });
      finalUrl = response.url || targetUrl;
      findings.push(...analyzeHeaders(finalUrl, response));
      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('text/html')) {
        const html = await response.text();
        findings.push(...analyzeHtml(finalUrl, html));
      }
    } catch (err) {
      findings.push(finding(
        'Scan request failed',
        'Info',
        targetUrl,
        'Scan',
        err.message || String(err),
        'Header and page checks could not be completed (e.g. CORS or network error).',
        'Ensure the target is reachable; some checks require same-origin or permissive CORS.',
        err.stack || ''
      ));
    }

    const duration_ms = Date.now() - start;
    return finalizeScanOutput(finalUrl, 'standard', findings, { headers_checked: true, paths_probed: 0, duration_ms, request_count: 1 });
  }

  async function runExtendedScan(targetUrl) {
    const start = Date.now();
    const base = await runStandardScan(targetUrl);
    const findings = [...(base.findings || [])];
    const finalUrl = base.target_url || targetUrl;
    const origin = new URL(finalUrl).origin;

    try {
      const optRes = await fetch(finalUrl, { method: 'OPTIONS', redirect: 'follow', credentials: 'omit', mode: 'cors' });
      const allow = optRes.headers.get('Allow');
      if (allow) {
        findings.push(finding(
          'Base URL allows HTTP methods (OPTIONS)',
          'Info',
          finalUrl,
          'Headers',
          `OPTIONS request returned Allow: ${allow}. Use this to see which methods the server accepts.`,
          'Knowing allowed methods helps assess attack surface (e.g. PUT/DELETE without auth).',
          'Restrict to GET/POST only if other methods are not needed.',
          `Allow: ${allow}`
        ));
      }
    } catch (_) {}

    const pathResults = await probePathsInParallel(origin, PROBE_PATHS);
    const pathsProbed = pathResults.length;
    const pathsHit = pathResults.filter((p) => p.status >= 200 && p.status < 400).length;
    for (const p of pathResults) {
      if (p.status >= 200 && p.status < 400) {
        findings.push(finding(
          `Path accessible: ${p.path} (${p.label}) → ${p.status}`,
          p.status === 200 ? 'Low' : 'Info',
          p.resUrl,
          'Path probe',
          `GET ${p.path} returned ${p.status}. Label: ${p.label}. Verify if this path should be public. Response length: ${p.len} chars.`,
          'Sensitive or internal paths may be exposed; review each for necessity.',
          'Restrict access (auth, IP, or remove) for sensitive routes.',
          `Status: ${p.status}. First 120 chars of body:\n${p.preview}`
        ));
      }
    }

    const lenCounts = {};
    pathResults.filter(p => p.status === 200 && p.len > 0).forEach(p => {
      lenCounts[p.len] = (lenCounts[p.len] || 0) + 1;
    });
    const sameLenCount = Math.max(0, ...Object.values(lenCounts));
    if (sameLenCount >= 4) {
      findings.push(finding(
        'Path probe: possible SPA — many paths returned same response size',
        'Info',
        finalUrl,
        'Path probe',
        `${sameLenCount} paths returned the same response size. The site may be a single-page app (SPA) where every path serves the same shell; verify whether 2xx path findings are real backend endpoints or client-side routes.`,
        'Reduces confidence that each "path accessible" finding is a distinct backend endpoint.',
        'If the site is an SPA, treat path probe 2xx as "app shell" unless response content clearly differs (e.g. API JSON).',
        `Same response size seen for ${sameLenCount} paths.`
      ));
    }

    const duration_ms = Date.now() - start;
    findings.push(finding(
      'Path probe summary',
      'Info',
      finalUrl,
      'Scan',
      `Probed ${pathsProbed} paths; ${pathsHit} returned 2xx/3xx. Full list of probed paths and status in detail.`,
      'Use this to see which common paths exist on the server.',
      'Restrict or remove unnecessary endpoints.',
      pathResults.map(p => `${p.path} (${p.label}): ${p.status}`).join('\n')
    ));

    return finalizeScanOutput(finalUrl, 'extended', findings, {
      headers_checked: true,
      paths_probed: pathsProbed,
      paths_with_2xx_3xx: pathsHit,
      duration_ms,
      request_count: 1 + pathsProbed,
    });
  }

  const api = { runStandardScan, runExtendedScan, runOptionScan };
  global.DivergScan = api;
  if (typeof window !== 'undefined') window.DivergScan = api;
  } catch (e) {
    const msg = (e && e.message) ? e.message : String(e);
    const stub = async function () { throw new Error('Scan engine failed: ' + msg); };
    global.DivergScan = { runStandardScan: stub, runExtendedScan: stub, runOptionScan: stub };
    if (typeof window !== 'undefined') window.DivergScan = global.DivergScan;
  }
})(typeof window !== 'undefined' ? window : self);
