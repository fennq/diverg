/**
 * Diverg — harvest Solana + EVM-shaped addresses from the active tab; open dashboard or call blockchain-full API.
 * Requires scripting permission (manifest already includes activeTab + scripting).
 */
(function () {
  const btn = document.getElementById('diverg-harvest-addresses');
  const out = document.getElementById('diverg-harvest-out');
  if (!btn || !out) return;

  function dashboardBaseUrl() {
    return new Promise((resolve) => {
      chrome.storage.local.get(['diverg_api_base_url'], (raw) => {
        const b = (raw.diverg_api_base_url || '').trim().replace(/\/+$/, '');
        resolve(b || 'http://127.0.0.1:5000');
      });
    });
  }

  function openInvestigation(address, chain) {
    dashboardBaseUrl().then((base) => {
      const u = `${base}/dashboard/?page=investigation&inv_address=${encodeURIComponent(address)}&inv_chain=${encodeURIComponent(chain)}`;
      chrome.tabs.create({ url: u });
    });
  }

  async function runBlockchainFullApi(address, chain) {
    const raw = await chrome.storage.local.get(['diverg_api_base_url', 'diverg_auth_token']);
    const token = (raw.diverg_auth_token || '').trim();
    if (!token) {
      out.textContent = 'Save a dashboard JWT in Extension Options (Chain investigation) to run Full API from here.';
      return;
    }
    let base = (raw.diverg_api_base_url || '').trim().replace(/\/+$/, '');
    if (!base && typeof window.DivergAPI !== 'undefined' && window.DivergAPI.detectApiBase) {
      base = await window.DivergAPI.detectApiBase();
    }
    if (!base) base = 'http://127.0.0.1:5000';
    out.textContent = 'Running full investigation (may take up to ~2 min)…';
    try {
      const res = await fetch(`${base}/api/investigation/blockchain-full`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer ' + token,
        },
        body: JSON.stringify({
          address,
          deployer_address: address,
          chain: chain || 'solana',
          flow_depth: 'full',
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        out.textContent = data.error || 'HTTP ' + res.status;
        return;
      }
      const cr = data.crime_report || {};
      const lines = [];
      if (cr.verdict) lines.push('Verdict: ' + String(cr.verdict));
      if (cr.summary) lines.push(String(cr.summary).slice(0, 800));
      if (data._truncated_findings != null) lines.push('(Truncated response — open dashboard for full JSON.)');
      const pre = document.createElement('pre');
      pre.style.cssText = 'font-size:10px;white-space:pre-wrap;word-break:break-word;margin:8px 0 0;text-align:left';
      pre.textContent = lines.join('\n\n') || JSON.stringify(data, null, 2).slice(0, 4000);
      out.innerHTML = '';
      out.appendChild(pre);
      const p = document.createElement('p');
      p.style.cssText = 'font-size:11px;margin-top:8px';
      const a = document.createElement('a');
      a.href = `${base}/dashboard/?page=investigation`;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = 'Open Investigation in dashboard';
      p.appendChild(a);
      out.appendChild(p);
    } catch (e) {
      out.textContent = e.message || 'Request failed';
    }
  }

  btn.addEventListener('click', async () => {
    out.textContent = 'Scanning page…';
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || tab.id == null) {
      out.textContent = 'No active tab.';
      return;
    }
    const proto = (tab.url || '').split(':')[0];
    if (proto !== 'http' && proto !== 'https') {
      out.textContent = 'Open an http(s) page to scan for addresses.';
      return;
    }
    try {
      const injected = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const text = document.body ? document.body.innerText.slice(0, 400000) : '';
          const evm = [];
          const sol = [];
          const seenE = new Set();
          const seenS = new Set();
          const evmRe = /0x[a-fA-F0-9]{40}/g;
          let m;
          while ((m = evmRe.exec(text)) !== null && evm.length < 28) {
            const x = m[0].toLowerCase();
            if (!seenE.has(x)) {
              seenE.add(x);
              evm.push(m[0]);
            }
          }
          const solRe = /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g;
          while ((m = solRe.exec(text)) !== null && sol.length < 28) {
            const x = m[0];
            if (!/^0x/i.test(x) && !seenS.has(x)) {
              seenS.add(x);
              sol.push(x);
            }
          }
          return { evm, sol };
        },
      });
      const r = injected && injected[0] ? injected[0].result : { evm: [], sol: [] };
      if (!r.evm.length && !r.sol.length) {
        out.textContent = 'No Solana (base58) or EVM (0x…) addresses found in visible text.';
        return;
      }
      out.innerHTML = '';

      function addRows(addrs, chain) {
        addrs.slice(0, 14).forEach((addr) => {
          const row = document.createElement('div');
          row.style.cssText =
            'display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:6px 0;font-size:10px;font-family:ui-monospace,monospace';
          const lab = document.createElement('span');
          lab.textContent = addr.length > 22 ? addr.slice(0, 20) + '…' : addr;
          lab.style.flex = '1';
          lab.style.minWidth = '120px';
          const bDash = document.createElement('button');
          bDash.type = 'button';
          bDash.textContent = 'Dashboard';
          bDash.style.cssText = 'font-size:10px;padding:4px 8px;cursor:pointer';
          bDash.addEventListener('click', () => openInvestigation(addr, chain));
          const bApi = document.createElement('button');
          bApi.type = 'button';
          bApi.textContent = 'Full API';
          bApi.style.cssText = 'font-size:10px;padding:4px 8px;cursor:pointer';
          bApi.addEventListener('click', () => runBlockchainFullApi(addr, chain));
          row.appendChild(lab);
          row.appendChild(bDash);
          row.appendChild(bApi);
          out.appendChild(row);
        });
      }

      if (r.evm.length) {
        const h = document.createElement('div');
        h.textContent = 'EVM (0x…)';
        h.style.cssText = 'font-weight:600;margin-top:4px;font-size:11px';
        out.appendChild(h);
        addRows(r.evm, 'ethereum');
      }
      if (r.sol.length) {
        const h = document.createElement('div');
        h.textContent = 'Solana-shaped (base58)';
        h.style.cssText = 'font-weight:600;margin-top:8px;font-size:11px';
        out.appendChild(h);
        addRows(r.sol, 'solana');
      }
    } catch (e) {
      out.textContent = 'Script injection failed. ' + (e && e.message ? e.message : String(e));
    }
  });
})();
