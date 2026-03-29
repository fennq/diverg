/**
 * Solana bundle snapshot — runs entirely in the extension (Helius BYOK).
 * Parity with Sectester investigation/solana_bundle.py + solana_bundle_signals.py:
 * DAS getTokenAccounts (paginated holders), largest-accounts fallback, LP skip, up to 120 wallets,
 * 2-hop ultimate-funder clustering, parallel Helius fetches, deeper coordination defaults.
 */
(function (global) {
  var ADDR_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
  /** Official Helius Solana RPC (OpenAPI); api-mainnet.* can return method not found for some calls. */
  var HELIUS_RPC = 'https://mainnet.helius-rpc.com';
  var HELIUS_WALLET = 'https://api.helius.xyz';
  /** Wrapped SOL — treat inbound wSOL as SOL for "who funded" (matches explorers / Axiom-style views). */
  var WSOL_MINT = 'So11111111111111111111111111111111111111112';

  function normalizeAddress(s) {
    if (!s || typeof s !== 'string') return null;
    var t = s.trim().replace(/\s+/g, '');
    return ADDR_RE.test(t) ? t : null;
  }

  function sleep(ms) {
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  }

  function heliusRpc(apiKey, method, params) {
    var url = HELIUS_RPC + '/?api-key=' + encodeURIComponent(apiKey);
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: method, params: params }),
    })
      .then(function (r) {
        return r.text().then(function (text) {
          var data;
          try {
            data = text ? JSON.parse(text) : {};
          } catch (parseErr) {
            return {
              result: null,
              error: (r.ok ? 'Invalid JSON from RPC' : 'HTTP ' + r.status) + (text ? ': ' + String(text).slice(0, 200) : ''),
            };
          }
          if (!r.ok) {
            var httpMsg =
              (data.error && (data.error.message || data.error)) ||
              (typeof data === 'object' && data.message) ||
              'HTTP ' + r.status;
            return { result: null, error: String(httpMsg) };
          }
          if (data.error) {
            var msg = (data.error && data.error.message) || JSON.stringify(data.error);
            return { result: null, error: msg };
          }
          return { result: data.result, error: null };
        });
      })
      .catch(function (e) {
        return { result: null, error: e.message || 'RPC network error' };
      });
  }

  /** DAS methods (getTokenAccounts, getAsset) require object `params`, not a JSON array. */
  function heliusDasRpc(apiKey, method, paramsObj) {
    var url = HELIUS_RPC + '/?api-key=' + encodeURIComponent(apiKey);
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: method, params: paramsObj || {} }),
    })
      .then(function (r) {
        return r.text().then(function (text) {
          var data;
          try {
            data = text ? JSON.parse(text) : {};
          } catch (parseErr) {
            return {
              result: null,
              error: (r.ok ? 'Invalid JSON from RPC' : 'HTTP ' + r.status) + (text ? ': ' + String(text).slice(0, 200) : ''),
            };
          }
          if (!r.ok) {
            var httpMsg =
              (data.error && (data.error.message || data.error)) ||
              (typeof data === 'object' && data.message) ||
              'HTTP ' + r.status;
            return { result: null, error: String(httpMsg) };
          }
          if (data.error) {
            var msg = (data.error && data.error.message) || JSON.stringify(data.error);
            return { result: null, error: msg };
          }
          return { result: data.result, error: null };
        });
      })
      .catch(function (e) {
        return { result: null, error: e.message || 'DAS RPC network error' };
      });
  }

  function heliusFundedBy(apiKey, address) {
    var url = HELIUS_WALLET + '/v1/wallet/' + encodeURIComponent(address) + '/funded-by';
    return fetch(url, { headers: { 'X-Api-Key': apiKey } })
      .then(function (r) {
        if (r.status === 404) return null;
        if (!r.ok) return null;
        return r.json();
      })
      .catch(function () {
        return null;
      });
  }

  function heliusWalletBalances(apiKey, address) {
    var q = '?limit=200&page=1&showNfts=false&showZeroBalance=true';
    var url = HELIUS_WALLET + '/v1/wallet/' + encodeURIComponent(address) + '/balances' + q;
    return fetch(url, { headers: { 'X-Api-Key': apiKey } })
      .then(function (r) {
        if (!r.ok) return null;
        return r.json();
      })
      .catch(function () {
        return null;
      });
  }

  function heliusBatchIdentity(apiKey, addresses) {
    if (!addresses || addresses.length === 0) return Promise.resolve(null);
    var slice = addresses.slice(0, 100);
    var url = HELIUS_WALLET + '/v1/wallet/batch-identity?api-key=' + encodeURIComponent(apiKey);
    return fetch(url, {
      method: 'POST',
      headers: { 'X-Api-Key': apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ addresses: slice }),
    })
      .then(function (r) {
        if (!r.ok) return null;
        return r.json();
      })
      .catch(function () {
        return null;
      });
  }

  /** Parity with investigation/onchain_clients.normalize_batch_identity_map */
  function normalizeBatchIdentityMap(raw) {
    var out = {};
    if (!raw) return out;
    var rows = Array.isArray(raw) ? raw : raw.identities || raw.data || raw.results || [];
    if (!Array.isArray(rows)) return out;
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      if (!row || typeof row !== 'object') continue;
      var addr = row.address || row.wallet;
      if (typeof addr !== 'string' || !addr.trim()) continue;
      addr = addr.trim();
      var name = row.name || row.displayName || row.label;
      var typ = row.type || row.entityType;
      var cat = row.category;
      var et = row.entityType || row.entity_type;
      var tags = Array.isArray(row.tags) ? row.tags : [];
      var domains = row.domainNames || row.domain_names || [];
      if (!Array.isArray(domains)) domains = [];
      var risk = row.risk != null ? row.risk : row.riskLevel != null ? row.riskLevel : row.risk_level;
      var parts = [];
      if (typeof name === 'string' && name.trim()) parts.push(name.trim());
      if (typeof cat === 'string' && cat.trim()) parts.push(cat.trim());
      if (typeof typ === 'string' && typ.trim()) parts.push(typ.trim());
      var primary = parts.length ? parts[0].slice(0, 120) : null;
      out[addr] = {
        primary_label: primary,
        type: typeof typ === 'string' && typ.trim() ? typ.trim().slice(0, 64) : null,
        entity_type: typeof et === 'string' && et.trim() ? et.trim().slice(0, 64) : null,
        category: typeof cat === 'string' && cat.trim() ? cat.trim().slice(0, 120) : null,
        tags: tags
          .slice(0, 12)
          .map(function (t) {
            return String(t).slice(0, 80);
          })
          .filter(Boolean),
        domain_names: domains
          .slice(0, 8)
          .map(function (d) {
            return String(d).slice(0, 80);
          })
          .filter(Boolean),
        risk_level: risk != null && String(risk).trim() ? String(risk).trim().slice(0, 32) : null,
        verified: typeof row.verified === 'boolean' ? row.verified : null,
      };
    }
    return out;
  }

  function identityPayloadFromMap(map, w) {
    var idrow = map[w];
    if (!idrow) return null;
    var fl = { cex_tagged: isCexIdentity(idrow), privacy_mixer_tagged: isMixerPrivacyIdentity(idrow) };
    var base = null;
    if (idrow.primary_label) {
      base = {
        label: idrow.primary_label,
        type: idrow.type,
        category: idrow.category,
        tags: idrow.tags || [],
        domain_names: idrow.domain_names || [],
        intel_flags: fl,
      };
    } else if (idrow.category || idrow.type) {
      base = {
        label: String(idrow.category || idrow.type || '').slice(0, 120),
        type: idrow.type,
        category: idrow.category,
        tags: idrow.tags || [],
        domain_names: idrow.domain_names || [],
        intel_flags: fl,
      };
    }
    if (base) return base;
    if (fl.cex_tagged || fl.privacy_mixer_tagged) {
      return {
        label: null,
        type: idrow.type,
        category: idrow.category,
        tags: idrow.tags || [],
        domain_names: idrow.domain_names || [],
        intel_flags: fl,
      };
    }
    return null;
  }

  /** Parity with investigation/onchain_clients.token_metadata_from_das_asset */
  function tokenMetadataFromDas(asset) {
    if (!asset || typeof asset !== 'object') return null;
    var content = asset.content && typeof asset.content === 'object' ? asset.content : {};
    var cmeta = content.metadata && typeof content.metadata === 'object' ? content.metadata : {};
    var tokenInfo = asset.token_info && typeof asset.token_info === 'object' ? asset.token_info : {};
    var name = cmeta.name || asset.name || tokenInfo.name;
    var symbol = cmeta.symbol || asset.symbol || tokenInfo.symbol;
    var image = null;
    var links = content.links && typeof content.links === 'object' ? content.links : {};
    if (typeof links.image === 'string' && links.image.trim()) image = links.image.trim().slice(0, 800);
    if (!image && Array.isArray(content.files)) {
      for (var fi = 0; fi < content.files.length; fi++) {
        var f = content.files[fi];
        if (!f || typeof f !== 'object') continue;
        var uri = f.cdn_uri || f.uri;
        if (typeof uri === 'string' && uri.trim()) {
          image = uri.trim().slice(0, 800);
          break;
        }
      }
    }
    var meta = {};
    if (typeof name === 'string' && name.trim()) meta.name = name.trim().slice(0, 200);
    if (typeof symbol === 'string' && symbol.trim()) meta.symbol = symbol.trim().slice(0, 32);
    if (image) meta.image = image;
    return Object.keys(meta).length ? meta : null;
  }

  function parseTokenAccountOwner(acc) {
    if (!acc || typeof acc !== 'object') return null;
    var v = acc.value;
    if (!v) return null;
    var data = v.data;
    var parsed = data && typeof data === 'object' ? data.parsed : null;
    if (!parsed || parsed.type !== 'account') return null;
    var owner = (parsed.info && parsed.info.owner) || null;
    return typeof owner === 'string' && ADDR_RE.test(owner) ? owner : null;
  }

  function parseTokenAccountUiAmount(acc) {
    if (!acc || typeof acc !== 'object') return 0;
    var v = acc.value;
    if (!v) return 0;
    var data = v.data;
    var parsed = data && typeof data === 'object' ? data.parsed : null;
    if (!parsed || !parsed.info) return 0;
    var ta = parsed.info.tokenAmount || {};
    if (ta.uiAmount != null) {
      var u = parseFloat(ta.uiAmount);
      return isNaN(u) ? 0 : u;
    }
    var amt = ta.amount;
    var dec = parseInt(ta.decimals, 10) || 0;
    if (amt != null && dec >= 0) {
      return parseFloat(amt) / Math.pow(10, dec);
    }
    return 0;
  }

  function balanceUiForMint(apiKey, owner, mint) {
    return heliusWalletBalances(apiKey, owner).then(function (out) {
      if (!out || typeof out !== 'object') return null;
      var tokens = out.tokens;
      if (!Array.isArray(tokens)) return null;
      for (var i = 0; i < tokens.length; i++) {
        var t = tokens[i];
        if (!t || typeof t !== 'object') continue;
        var m = t.mint || (t.token && t.token.mint);
        if (m !== mint) continue;
        if (t.uiAmount != null) {
          var u = parseFloat(t.uiAmount);
          return isNaN(u) ? 0 : u;
        }
        var raw = t.amount;
        var dec = parseInt(t.decimals, 10) || 0;
        if (raw != null) return parseFloat(raw) / Math.pow(10, dec);
      }
      return 0;
    });
  }

  function supplyPct(amount, totalUi) {
    if (totalUi <= 0) return 0;
    return Math.round((10000 * amount) / totalUi) / 100;
  }

  /** Defaults match investigation/solana_bundle_signals.py (deep scan). */
  var BUNDLE_SIGNAL_DEFAULTS = {
    fundingBucketSec: 5,
    lamportsRelTol: 0.002,
    maxTransferFetch: 72,
    maxEnhancedFetch: 32,
    maxFunderIdentity: 56,
    maxFunderRootIdentity: 24,
    signalTransfersLimit: 100,
    enhancedTxLimit: 55,
  };

  var BUNDLE_DEEP_DEFAULTS = {
    maxHolders: 100,
    maxFundedBy: 120,
    maxFundedByCap: 150,
    dasMaxPages: 45,
    lpSkipMinPct: 12,
    funderTransfersLimit: 100,
    funderHop2Max: 56,
    holderFetchConcurrency: 10,
    hopFetchConcurrency: 10,
  };

  function safeInt(x) {
    if (x == null || x === '') return null;
    var t = parseInt(String(x), 10);
    return isNaN(t) ? null : t;
  }

  function safeFloat(x) {
    if (x == null || x === '') return null;
    var t = parseFloat(x);
    return isNaN(t) ? null : t;
  }

  function heliusTransfers(apiKey, address, limit) {
    var url =
      HELIUS_WALLET +
      '/v1/wallet/' +
      encodeURIComponent(address) +
      '/transfers?limit=' +
      encodeURIComponent(String(Math.min(100, Math.max(1, limit || 80)))) +
      '&api-key=' +
      encodeURIComponent(apiKey);
    return fetch(url, { headers: { 'X-Api-Key': apiKey } })
      .then(function (r) {
        if (!r.ok) return null;
        return r.json();
      })
      .catch(function () {
        return null;
      });
  }

  function heliusWalletIdentity(apiKey, address) {
    var url =
      HELIUS_WALLET +
      '/v1/wallet/' +
      encodeURIComponent(address) +
      '/identity?api-key=' +
      encodeURIComponent(apiKey);
    return fetch(url, { headers: { 'X-Api-Key': apiKey } })
      .then(function (r) {
        if (r.status === 404) return null;
        if (!r.ok) return null;
        return r.json();
      })
      .catch(function () {
        return null;
      });
  }

  function heliusEnhancedTransactions(apiKey, address, limit) {
    var url =
      HELIUS_RPC +
      '/v0/addresses/' +
      encodeURIComponent(address) +
      '/transactions?limit=' +
      encodeURIComponent(String(limit || 35)) +
      '&token-accounts=balanceChanged&api-key=' +
      encodeURIComponent(apiKey);
    return fetch(url, { headers: { 'X-Api-Key': apiKey } })
      .then(function (r) {
        if (!r.ok) return null;
        return r.json();
      })
      .catch(function () {
        return null;
      });
  }

  function parseFundedByRow(fb) {
    var out = { funder: null, lamports: null, signature: null, timestamp_unix: null, slot: null };
    if (!fb || typeof fb !== 'object') return out;
    var fk = ['funder', 'fundingWallet', 'funding_wallet', 'from', 'fromAddress', 'from_address', 'sender', 'fundingAddress'];
    for (var fi = 0; fi < fk.length; fi++) {
      var fv = fb[fk[fi]];
      if (typeof fv === 'string' && ADDR_RE.test(fv)) {
        out.funder = fv;
        break;
      }
    }
    var kLp = ['lamports', 'amountLamports', 'amount_lamports'];
    for (var i = 0; i < kLp.length; i++) {
      var lp = safeInt(fb[kLp[i]]);
      if (lp != null) {
        out.lamports = lp;
        break;
      }
    }
    if (out.lamports == null) {
      var sol = safeFloat(fb.amountSol != null ? fb.amountSol : fb.solAmount != null ? fb.solAmount : fb.amount);
      if (sol != null) out.lamports = Math.round(sol * 1e9);
    }
    if (typeof fb.signature === 'string') out.signature = fb.signature;
    var ts = fb.timestamp != null ? fb.timestamp : fb.blockTime != null ? fb.blockTime : fb.time;
    if (typeof ts === 'number') {
      out.timestamp_unix = ts > 1e12 ? Math.floor(ts / 1000) : Math.floor(ts);
    }
    out.slot = safeInt(fb.slot);
    return out;
  }

  function iterTransferRows(raw) {
    if (!raw) return [];
    if (Array.isArray(raw)) return raw.filter(function (x) {
      return x && typeof x === 'object';
    });
    if (typeof raw !== 'object') return [];
    var keys = ['transfers', 'data', 'items', 'results'];
    for (var i = 0; i < keys.length; i++) {
      var v = raw[keys[i]];
      if (Array.isArray(v) && v.length && typeof v[0] === 'object') {
        return v.filter(function (x) {
          return x && typeof x === 'object';
        });
      }
    }
    var merged = [];
    ['nativeTransfers', 'tokenTransfers'].forEach(function (k) {
      var arr = raw[k];
      if (Array.isArray(arr)) {
        for (var j = 0; j < arr.length; j++) {
          if (arr[j] && typeof arr[j] === 'object') merged.push(arr[j]);
        }
      }
    });
    if (merged.length) return merged;
    return [];
  }

  function mintFromTransferRow(t) {
    var m = t.mint;
    if (m && typeof m === 'object') m = m.mint || m.address;
    var tok = t.token;
    if (tok && typeof tok === 'object') m = m || tok.mint || tok.address;
    else if (typeof tok === 'string') m = m || tok;
    return String(m || '').trim();
  }

  function extractFirstInboundSolFromTransfers(raw) {
    var rows = iterTransferRows(raw);
    var candidates = [];
    var wsolL = WSOL_MINT.toLowerCase();
    for (var i = 0; i < rows.length; i++) {
      var t = rows[i];
      var direction = String(t.direction || t.type || t.transferType || '').toLowerCase();
      if (direction === 'out' || direction === 'outgoing' || direction === 'sent' || direction === 'send' || direction === 'withdraw') continue;
      var mintS = mintFromTransferRow(t).toLowerCase();
      var sym = String(t.symbol || '').toUpperCase();
      var tokS =
        t.token && typeof t.token === 'object'
          ? String((t.token.symbol || t.token.mint || '') + '').toLowerCase()
          : String(t.token || '').toLowerCase();
      var isSol =
        t.isNative === true ||
        t.native === true ||
        sym === 'SOL' ||
        tokS.indexOf('sol') >= 0 ||
        mintS === wsolL ||
        (!mintS && !t.mint) ||
        (!mintS && (direction === 'in' || direction === 'incoming' || direction === 'received' || direction === 'receive'));
      if (!isSol && mintS && mintS !== wsolL) continue;
      if (
        direction !== 'in' &&
        direction !== 'incoming' &&
        direction !== 'received' &&
        direction !== 'receive' &&
        direction !== 'inbound' &&
        direction !== 'credit' &&
        direction !== '' &&
        direction !== 'transfer' &&
        direction !== 'unknown' &&
        direction !== 'nft'
      ) {
        if (direction !== '' && !isSol) continue;
      }
      var ts = t.timestamp != null ? t.timestamp : t.blockTime != null ? t.blockTime : t.time;
      var tu = null;
      if (typeof ts === 'number') {
        tu = Math.floor(ts);
        if (tu > 1e12) tu = Math.floor(tu / 1000);
      }
      var lam = safeInt(t.lamports != null ? t.lamports : t.amountLamports != null ? t.amountLamports : null);
      if (lam == null && t.amountRaw != null) {
        try {
          lam = parseInt(String(t.amountRaw).split('.')[0], 10);
          if (isNaN(lam)) lam = null;
        } catch (e) {
          lam = null;
        }
      }
      if (lam == null) {
        var amt = safeFloat(t.amount != null ? t.amount : t.uiAmount != null ? t.uiAmount : t.tokenAmount);
        var dec = safeInt(t.decimals);
        if (amt != null) {
          if (dec != null && dec >= 0) lam = Math.round(amt * Math.pow(10, Math.min(dec, 18)));
          else lam = Math.round(amt * 1e9);
        }
      }
      var sig = t.signature || t.tx || t.transactionSignature;
      var fromA =
        t.from ||
        t.fromUserAccount ||
        t.fromAddress ||
        t.fromUser ||
        t.sender ||
        t.source ||
        t.sourceAccount ||
        t.counterparty;
      if (fromA && typeof fromA === 'object') fromA = fromA.address || fromA.pubkey;
      if (lam == null || tu == null) continue;
      if (typeof fromA !== 'string' || !ADDR_RE.test(fromA)) continue;
      candidates.push({
        lamports: lam,
        timestamp_unix: tu,
        signature: typeof sig === 'string' ? sig : null,
        from_address: fromA,
      });
    }
    if (!candidates.length) return null;
    candidates.sort(function (a, b) {
      return a.timestamp_unix - b.timestamp_unix;
    });
    return candidates[0];
  }

  function funderAddressFromApi(funded) {
    if (!funded || typeof funded !== 'object') return null;
    var keys = ['funder', 'fundingWallet', 'funding_wallet', 'from', 'fromAddress', 'from_address', 'sender', 'fundingAddress'];
    for (var i = 0; i < keys.length; i++) {
      var f = funded[keys[i]];
      if (typeof f === 'string' && ADDR_RE.test(f)) return f;
    }
    return null;
  }

  function effectiveFunderAddress(funded, transfersRaw) {
    var ex = extractFirstInboundSolFromTransfers(transfersRaw);
    if (ex && typeof ex.from_address === 'string' && ADDR_RE.test(ex.from_address)) return ex.from_address;
    return funderAddressFromApi(funded);
  }

  function clusterKeyFromSources(wallet, funded, transfersRaw, hopCtx) {
    hopCtx = hopCtx || {};
    var hopF = hopCtx.hopFunded || {};
    var hopT = hopCtx.hopTransfers || {};
    var direct = effectiveFunderAddress(funded, transfersRaw);
    if (!direct) return 'singleton:' + wallet;
    var root = effectiveFunderAddress(hopF[direct], hopT[direct]);
    if (root && root !== wallet && root !== direct) return 'funder:' + root;
    return 'funder:' + direct;
  }

  function directAndRootFunder(wallet, funded, transfersRaw, hopF, hopT) {
    hopF = hopF || {};
    hopT = hopT || {};
    var direct = effectiveFunderAddress(funded, transfersRaw);
    if (!direct) return { direct: null, root: null };
    var root = effectiveFunderAddress(hopF[direct], hopT[direct]);
    if (root && root !== wallet && root !== direct) return { direct: direct, root: root };
    return { direct: direct, root: null };
  }

  async function asyncPool(concurrency, items, fn) {
    var results = new Array(items.length);
    var next = 0;
    async function worker() {
      while (true) {
        var i = next++;
        if (i >= items.length) break;
        results[i] = await fn(items[i], i);
      }
    }
    var n = Math.min(concurrency, Math.max(1, items.length));
    var workers = [];
    for (var w = 0; w < n; w++) workers.push(worker());
    await Promise.all(workers);
    return results;
  }

  async function fetchDasTokenAccountsForMint(apiKey, mint, maxPages, pageLimit) {
    var rows = [];
    var cursor = null;
    var pages = Math.max(1, maxPages);
    var lim = Math.min(100, Math.max(1, pageLimit || 100));
    var lastErr = null;
    for (var p = 0; p < pages; p++) {
      var params = { mint: mint, limit: lim };
      if (cursor) params.cursor = cursor;
      var das = await heliusDasRpc(apiKey, 'getTokenAccounts', params);
      if (das.error) {
        lastErr = das.error;
        if (!rows.length) return { rows: [], error: das.error };
        break;
      }
      var result = das.result;
      if (!result || typeof result !== 'object') break;
      var accounts = result.token_accounts;
      if (!Array.isArray(accounts)) break;
      for (var i = 0; i < accounts.length; i++) {
        var a = accounts[i];
        if (!a || typeof a !== 'object') continue;
        var owner = a.owner;
        var amt = a.amount;
        if (typeof owner !== 'string' || !owner || amt == null) continue;
        var raw = parseInt(String(amt), 10);
        if (isNaN(raw)) continue;
        rows.push({ owner: owner, amount: raw });
      }
      cursor = result.cursor;
      if (!cursor || !accounts.length) break;
    }
    return { rows: rows, error: lastErr };
  }

  function ownerAmountFromDasRows(rows, decimals) {
    var dec = Math.max(0, parseInt(String(decimals), 10) || 0);
    var scale = Math.pow(10, dec);
    var map = {};
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      if (!r || !r.owner || r.amount == null) continue;
      var ui = r.amount / scale;
      map[r.owner] = (map[r.owner] || 0) + ui;
    }
    return map;
  }

  async function holdersViaLargestAccountsAsync(apiKey, mintNorm, mh) {
    var lg = await heliusRpc(apiKey, 'getTokenLargestAccounts', [mintNorm]);
    if (lg.error) return { ownerAmount: null, error: 'getTokenLargestAccounts: ' + lg.error };
    var list = lg.result && lg.result.value;
    if (!Array.isArray(list)) return { ownerAmount: null, error: 'Unexpected getTokenLargestAccounts shape' };
    var entries = list.slice(0, mh);
    var tokenAccountAddrs = [];
    var uiFromLargest = {};
    entries.forEach(function (e) {
      if (!e || !e.address) return;
      tokenAccountAddrs.push(e.address);
      if (e.uiAmount != null) {
        var u = parseFloat(e.uiAmount);
        uiFromLargest[e.address] = isNaN(u) ? 0 : u;
      } else uiFromLargest[e.address] = 0;
    });
    var ownerAmount = {};
    for (var start = 0; start < tokenAccountAddrs.length; start += 100) {
      var batch = tokenAccountAddrs.slice(start, start + 100);
      var mult = await heliusRpc(apiKey, 'getMultipleAccounts', [batch, { encoding: 'jsonParsed' }]);
      if (mult.error) return { ownerAmount: null, error: 'getMultipleAccounts: ' + mult.error };
      var accList = mult.result && mult.result.value;
      if (!Array.isArray(accList)) return { ownerAmount: null, error: 'getMultipleAccounts missing value list' };
      for (var j = 0; j < accList.length; j++) {
        var acc = accList[j];
        var ta = batch[j];
        var owner = parseTokenAccountOwner(acc);
        if (!owner) continue;
        var uiTa = uiFromLargest[ta];
        var parsedAmt = parseTokenAccountUiAmount(acc);
        var amt =
          uiTa != null && !isNaN(parseFloat(uiTa)) && parseFloat(uiTa) > 0
            ? parseFloat(uiTa)
            : parsedAmt;
        ownerAmount[owner] = (ownerAmount[owner] || 0) + amt;
      }
    }
    return { ownerAmount: ownerAmount, error: null };
  }

  function enrichWalletFunding(wallet, fundedByRow, transfersRaw) {
    var fb = parseFundedByRow(fundedByRow);
    var ex = extractFirstInboundSolFromTransfers(transfersRaw);
    var lamports = fb.lamports;
    var ts = fb.timestamp_unix;
    if (ex) {
      if (lamports == null) lamports = ex.lamports;
      if (ts == null) ts = ex.timestamp_unix;
    }
    var eff = null;
    if (ex && typeof ex.from_address === 'string' && ADDR_RE.test(ex.from_address)) eff = ex.from_address;
    if (!eff) eff = funderAddressFromApi(fundedByRow);
    return {
      wallet: wallet,
      funder: eff,
      first_fund_lamports: lamports,
      first_fund_timestamp_unix: ts,
      first_fund_signature: fb.signature || (ex && ex.signature) || null,
      first_inbound_from_transfer: ex ? ex.from_address : null,
    };
  }

  function timeBucket(ts, bucketSec) {
    if (ts == null) return null;
    return Math.floor(ts / bucketSec);
  }

  function lamportsClose(a, b, relTol) {
    if (a == null || b == null || a <= 0 || b <= 0) return false;
    return Math.abs(a - b) / Math.max(a, b) <= relTol;
  }

  function clusterWalletsByTimeBucket(metaByWallet, bucketSec) {
    var byBucket = {};
    Object.keys(metaByWallet).forEach(function (w) {
      var ts = metaByWallet[w].first_fund_timestamp_unix;
      var b = ts != null ? timeBucket(ts, bucketSec) : null;
      if (b == null) return;
      var key = String(b);
      if (!byBucket[key]) byBucket[key] = [];
      byBucket[key].push(w);
    });
    var out = [];
    Object.keys(byBucket).forEach(function (bid) {
      var wallets = byBucket[bid];
      if (wallets.length >= 2) {
        out.push({
          bucket_id: bid,
          bucket_sec: bucketSec,
          wallets: wallets.slice().sort(),
          count: wallets.length,
        });
      }
    });
    out.sort(function (a, b) {
      return b.count - a.count;
    });
    return out;
  }

  function clusterWalletsBySameLamports(metaByWallet, relTol) {
    var byLam = {};
    Object.keys(metaByWallet).forEach(function (w) {
      var lp = metaByWallet[w].first_fund_lamports;
      if (lp == null) return;
      lp = parseInt(String(lp), 10);
      if (!byLam[lp]) byLam[lp] = [];
      byLam[lp].push(w);
    });
    var sortedLams = Object.keys(byLam)
      .map(function (x) {
        return parseInt(x, 10);
      })
      .sort(function (a, b) {
        return a - b;
      });
    var reps = [];
    var used = {};
    for (var i = 0; i < sortedLams.length; i++) {
      var lam = sortedLams[i];
      if (used[lam]) continue;
      var group = byLam[lam].slice();
      for (var j = 0; j < sortedLams.length; j++) {
        var other = sortedLams[j];
        if (other <= lam || used[other]) continue;
        if (lamportsClose(lam, other, relTol)) {
          group = group.concat(byLam[other]);
          used[other] = true;
        }
      }
      var uniq = {};
      group.forEach(function (x) {
        uniq[x] = true;
      });
      var wlist = Object.keys(uniq).sort();
      reps.push({ lamports: lam, wallets: wlist, count: wlist.length });
      used[lam] = true;
    }
    var out = [];
    for (var r = 0; r < reps.length; r++) {
      if (reps[r].count >= 2) out.push(reps[r]);
    }
    out.sort(function (a, b) {
      return b.count - a.count;
    });
    return out;
  }

  var CEX_VENUE_LABEL_MARKERS = [
    'binance',
    'coinbase',
    'kraken',
    'okx',
    'bybit',
    'kucoin',
    'gate.io',
    'gate io',
    'gemini',
    'bitfinex',
    'mexc',
    'htx',
    'huobi',
    'crypto.com',
    'bitstamp',
    'upbit',
    'bitget',
    'deribit',
    'bingx',
  ];
  var MIXER_DEX_BLOCKLIST = [
    'jupiter',
    'raydium',
    'orca',
    'uniswap',
    'meteora',
    'phoenix',
    'lifinity',
    'pump.fun',
    'pumpswap',
    'curve',
    'balancer',
  ];

  function identityTextBlob(o) {
    if (!o || typeof o !== 'object') return '';
    var parts = [];
    var cands = [
      o.primary_label,
      o.name,
      o.displayName,
      o.label,
      o.category,
      o.type,
      o.entityType,
      o.entity_type,
    ];
    for (var ci = 0; ci < cands.length; ci++) {
      if (typeof cands[ci] === 'string' && cands[ci].trim()) parts.push(cands[ci].toLowerCase());
    }
    var tags = o.tags;
    if (Array.isArray(tags)) {
      for (var ti = 0; ti < tags.length; ti++) {
        if (tags[ti] != null && String(tags[ti]).trim()) parts.push(String(tags[ti]).toLowerCase());
      }
    }
    return parts.join(' ');
  }

  function identityLabelBlob(o) {
    if (!o || typeof o !== 'object') return '';
    var parts = [];
    var cands = [o.primary_label, o.name, o.displayName, o.label];
    for (var li = 0; li < cands.length; li++) {
      if (typeof cands[li] === 'string' && cands[li].trim()) parts.push(cands[li].toLowerCase());
    }
    return parts.join(' ');
  }

  function structuralCexHit(ident) {
    if (!ident || typeof ident !== 'object') return null;
    var keys = ['type', 'category', 'entity_type', 'entityType'];
    for (var ki = 0; ki < keys.length; ki++) {
      var v = ident[keys[ki]];
      if (typeof v !== 'string' || !v.trim()) continue;
      var vl = v.toLowerCase();
      if (vl.indexOf('exchange') >= 0 || /\bcex\b/.test(vl) || vl.indexOf('custodial') >= 0) return 'struct:' + keys[ki];
    }
    var tags = ident.tags;
    if (Array.isArray(tags)) {
      for (var tj = 0; tj < tags.length; tj++) {
        var tl = String(tags[tj] || '').toLowerCase();
        if (tl.indexOf('exchange') >= 0 || /\bcex\b/.test(tl) || tl.indexOf('custodial') >= 0) return 'struct:tag';
      }
    }
    return null;
  }

  function classifyCexTier(ident) {
    var reasons = [];
    if (!ident || typeof ident !== 'object') return { tier: 'none', reasons: reasons };
    var hit = structuralCexHit(ident);
    if (hit) {
      reasons.push(hit);
      return { tier: 'strong', reasons: reasons };
    }
    var lbl = identityLabelBlob(ident);
    for (var vi = 0; vi < CEX_VENUE_LABEL_MARKERS.length; vi++) {
      if (lbl.indexOf(CEX_VENUE_LABEL_MARKERS[vi]) >= 0) {
        reasons.push('venue:' + CEX_VENUE_LABEL_MARKERS[vi]);
        return { tier: 'strong', reasons: reasons };
      }
    }
    var blob = identityTextBlob(ident);
    var weakM = ['hot wallet', 'cold wallet', 'deposit wallet', 'withdraw'];
    for (var wi = 0; wi < weakM.length; wi++) {
      if (blob.indexOf(weakM[wi]) >= 0) {
        reasons.push('weak_custodial_language');
        return { tier: 'weak', reasons: reasons };
      }
    }
    if (/\bdeposit\b/.test(blob) && blob.indexOf('exchange') < 0) {
      reasons.push('weak_deposit_keyword');
      return { tier: 'weak', reasons: reasons };
    }
    return { tier: 'none', reasons: reasons };
  }

  function classifyMixerTier(ident) {
    var reasons = [];
    if (!ident || typeof ident !== 'object') return { tier: 'none', reasons: reasons };
    var blob = identityTextBlob(ident);
    var dexNoise = false;
    for (var di = 0; di < MIXER_DEX_BLOCKLIST.length; di++) {
      if (blob.indexOf(MIXER_DEX_BLOCKLIST[di]) >= 0) {
        dexNoise = true;
        break;
      }
    }
    if (/\bmixer\b/.test(blob) || blob.indexOf('tumbler') >= 0 || blob.indexOf('tornado') >= 0) {
      reasons.push('mixer_keyword');
      return { tier: 'strong', reasons: reasons };
    }
    if (/obfuscat|blender|sanction|laundr|anon surf/.test(blob)) {
      reasons.push('obfuscation_sanction_language');
      return { tier: 'strong', reasons: reasons };
    }
    if (blob.indexOf('privacy pool') >= 0 || (blob.indexOf('privacy') >= 0 && blob.indexOf('shield') >= 0)) {
      reasons.push('privacy_pool_or_shield');
      return { tier: 'strong', reasons: reasons };
    }
    if (blob.indexOf('relayer') >= 0 && blob.indexOf('privacy') >= 0) {
      reasons.push('privacy_relayer');
      return { tier: 'strong', reasons: reasons };
    }
    if (dexNoise) return { tier: 'none', reasons: reasons };
    if (blob.indexOf('privacy') >= 0 && /pool|cash|shield/.test(blob)) {
      reasons.push('privacy_companion_weak');
      return { tier: 'weak', reasons: reasons };
    }
    return { tier: 'none', reasons: reasons };
  }

  function cexTierStr(ident) {
    return classifyCexTier(ident).tier;
  }

  function mixerTierStr(ident) {
    return classifyMixerTier(ident).tier;
  }

  function isCexIdentity(ident) {
    var t = classifyCexTier(ident).tier;
    return t === 'weak' || t === 'strong';
  }

  function isMixerPrivacyIdentity(ident) {
    var t = classifyMixerTier(ident).tier;
    return t === 'weak' || t === 'strong';
  }

  function walletsFundingCorroborated(wallets, metaByWallet, bucketSec, relTol) {
    var corroborated = {};
    var wset = [];
    var seen = {};
    for (var si = 0; si < wallets.length; si++) {
      var wx = wallets[si];
      if (!seen[wx]) {
        seen[wx] = true;
        wset.push(wx);
      }
    }
    if (wset.length < 2) return corroborated;
    var byBucket = {};
    for (var bi = 0; bi < wset.length; bi++) {
      var wb = wset[bi];
      var m = metaByWallet[wb] || {};
      var ts = m.first_fund_timestamp_unix;
      var bkt =
        ts != null && bucketSec > 0 ? Math.floor(ts / bucketSec) : null;
      if (bkt != null) {
        if (!byBucket[bkt]) byBucket[bkt] = [];
        byBucket[bkt].push(wb);
      }
    }
    Object.keys(byBucket).forEach(function (bk) {
      var ws = byBucket[bk];
      var u = {};
      ws.forEach(function (x) {
        u[x] = true;
      });
      if (Object.keys(u).length >= 2) {
        Object.keys(u).forEach(function (k) {
          corroborated[k] = true;
        });
      }
    });
    var lams = [];
    for (var lj = 0; lj < wset.length; lj++) {
      var wl = wset[lj];
      var lp = (metaByWallet[wl] || {}).first_fund_lamports;
      if (lp != null) {
        var ln = parseInt(String(lp), 10);
        if (!isNaN(ln)) lams.push({ w: wl, lam: ln });
      }
    }
    function lamClose(a, b) {
      if (a <= 0 || b <= 0) return false;
      return Math.abs(a - b) / Math.max(a, b) <= relTol;
    }
    for (var i = 0; i < lams.length; i++) {
      for (var j = i + 1; j < lams.length; j++) {
        if (lamClose(lams[i].lam, lams[j].lam)) {
          corroborated[lams[i].w] = true;
          corroborated[lams[j].w] = true;
        }
      }
    }
    return corroborated;
  }

  function walletTaggedClusterKey(wallet, metaByWallet, rootMap, funderIdents, tierStrFn) {
    var d = (metaByWallet[wallet] || {}).funder;
    if (typeof d === 'string' && tierStrFn(funderIdents[d]) !== 'none') return d;
    var r = rootMap[wallet];
    if (typeof r === 'string' && tierStrFn(funderIdents[r]) !== 'none') return r;
    return null;
  }

  function buildTaggedParallelGroups(lookupOrder, metaByWallet, rootMap, funderIdents, tierStrFn) {
    var keyToWallets = {};
    for (var qi = 0; qi < lookupOrder.length; qi++) {
      var wq = lookupOrder[qi];
      var k = walletTaggedClusterKey(wq, metaByWallet, rootMap, funderIdents, tierStrFn);
      if (!k) continue;
      if (!keyToWallets[k]) keyToWallets[k] = [];
      keyToWallets[k].push(wq);
    }
    var groups = [];
    Object.keys(keyToWallets).forEach(function (fnd) {
      var ws = keyToWallets[fnd];
      var u = {};
      ws.forEach(function (x) {
        u[x] = true;
      });
      var ul = Object.keys(u).sort();
      if (ul.length >= 2) {
        groups.push({
          funder: fnd,
          wallet_count: ul.length,
          wallets: ul.slice(0, 40),
          funder_tier: tierStrFn(funderIdents[fnd]),
        });
      }
    });
    groups.sort(function (a, b) {
      return b.wallet_count - a.wallet_count;
    });
    return groups;
  }

  function strictFromLoose(loose, metaByWallet, bucketSec, relTol) {
    var strict = [];
    for (var gi = 0; gi < loose.length; gi++) {
      var g = loose[gi];
      var ws = g.wallets || [];
      var corr = walletsFundingCorroborated(ws, metaByWallet, bucketSec, relTol);
      var u = Object.keys(corr).sort();
      if (u.length < 2) continue;
      strict.push({
        funder: g.funder,
        wallet_count: u.length,
        wallets: u.slice(0, 40),
        funder_tier: g.funder_tier,
        confidence: 'high',
      });
    }
    strict.sort(function (a, b) {
      return b.wallet_count - a.wallet_count;
    });
    return strict;
  }

  function sharedInboundSenders(metaByWallet) {
    var senderCounts = {};
    Object.keys(metaByWallet).forEach(function (w) {
      var m = metaByWallet[w];
      var s = m.first_inbound_from_transfer || m.funder;
      if (typeof s === 'string' && s.length > 32) {
        if (!senderCounts[s]) senderCounts[s] = [];
        senderCounts[s].push(w);
      }
    });
    var hot = {};
    Object.keys(senderCounts).forEach(function (k) {
      if (senderCounts[k].length >= 2) hot[k] = senderCounts[k].slice().sort();
    });
    var topShared = Object.keys(hot).sort(function (a, b) {
      return hot[b].length - hot[a].length;
    });
    return { shared_sender_to_wallets: hot, top_shared: topShared.slice(0, 12) };
  }

  function sharedOutboundReceivers(lookupOrder, transfersCache) {
    var recvToWallets = {};
    for (var wi = 0; wi < lookupOrder.length; wi++) {
      var w = lookupOrder[wi];
      var rows = iterTransferRows(transfersCache[w]);
      if (!rows.length) continue;
      var seenForWallet = {};
      for (var i = 0; i < rows.length; i++) {
        var t = rows[i];
        var direction = String(t.direction || t.type || t.transferType || '').toLowerCase();
        if (direction !== 'out' && direction !== 'outgoing' && direction !== 'sent' && direction !== 'send' && direction !== 'withdraw') continue;
        var toA =
          t.to ||
          t.toUserAccount ||
          t.toAddress ||
          t.toUser ||
          t.recipient ||
          t.destination ||
          t.destinationAccount ||
          t.counterparty;
        if (toA && typeof toA === 'object') toA = toA.address || toA.pubkey;
        if (typeof toA !== 'string' || !ADDR_RE.test(toA)) continue;
        if (toA === w || seenForWallet[toA]) continue;
        if (!recvToWallets[toA]) recvToWallets[toA] = {};
        recvToWallets[toA][w] = true;
        seenForWallet[toA] = true;
      }
    }
    var hot = {};
    Object.keys(recvToWallets).forEach(function (k) {
      var wallets = Object.keys(recvToWallets[k]).sort();
      if (wallets.length >= 2) hot[k] = wallets;
    });
    var top = Object.keys(hot).sort(function (a, b) {
      return hot[b].length - hot[a].length;
    }).slice(0, 20);
    return { shared_receiver_to_wallets: hot, top_shared_receivers: top };
  }

  function programsFromEnhanced(tx) {
    var progs = {};
    function fromList(arr) {
      if (!Array.isArray(arr)) return;
      for (var i = 0; i < arr.length; i++) {
        var ins = arr[i];
        if (!ins || typeof ins !== 'object') continue;
        var pid = ins.programId || ins.program;
        if (typeof pid === 'string') progs[pid] = true;
      }
    }
    fromList(tx.instructions);
    fromList(tx.parsedInstructions);
    var inner = tx.innerInstructions;
    if (Array.isArray(inner)) {
      for (var b = 0; b < inner.length; b++) {
        var block = inner[b];
        if (block && typeof block === 'object') fromList(block.instructions);
      }
    }
    return progs;
  }

  function unwrapEnhancedTxs(raw) {
    if (Array.isArray(raw)) return raw;
    if (raw && typeof raw === 'object' && Array.isArray(raw.transactions)) return raw.transactions;
    return null;
  }

  function enhancedCoMovementMint(apiKey, mint, wallet, limit) {
    return heliusEnhancedTransactions(apiKey, wallet, limit).then(function (raw) {
      var txs = unwrapEnhancedTxs(raw);
      if (!txs) return null;
      var slots = [];
      var programMap = {};
      for (var i = 0; i < txs.length; i++) {
        var tx = txs[i];
        if (!tx || typeof tx !== 'object') continue;
        var slot = safeInt(tx.slot);
        var tts = tx.tokenTransfers;
        var hit = false;
        if (Array.isArray(tts)) {
          for (var j = 0; j < tts.length; j++) {
            var tt = tts[j];
            if (!tt || typeof tt !== 'object') continue;
            var m = tt.mint || tt.tokenMint;
            if (m === mint) {
              hit = true;
              break;
            }
          }
        }
        if (hit && slot != null) slots.push(slot);
        var pm = programsFromEnhanced(tx);
        Object.keys(pm).forEach(function (p) {
          programMap[p] = true;
        });
      }
      var slotSet = {};
      slots.forEach(function (s) {
        slotSet[s] = true;
      });
      var slotList = Object.keys(slotSet)
        .map(function (x) {
          return parseInt(x, 10);
        })
        .sort(function (a, b) {
          return a - b;
        })
        .slice(0, 20);
      var progSample = Object.keys(programMap).sort().slice(0, 40);
      return {
        wallet: wallet,
        mint_touch_slots: slotList,
        programs_sample: progSample,
      };
    });
  }

  function jaccard(aSet, bSet) {
    var inter = 0;
    var union = 0;
    var ak = Object.keys(aSet);
    var bk = Object.keys(bSet);
    if (!ak.length && !bk.length) return 0;
    var u = {};
    ak.forEach(function (k) {
      u[k] = true;
    });
    bk.forEach(function (k) {
      u[k] = true;
    });
    union = Object.keys(u).length;
    ak.forEach(function (k) {
      if (bSet[k]) inter++;
    });
    return union ? inter / union : 0;
  }

  async function computeCoordinationBundleAsync(apiKey, opts) {
    var cfg = BUNDLE_SIGNAL_DEFAULTS;
    var bucketSec = cfg.fundingBucketSec;
    var relTol = cfg.lamportsRelTol;
    var maxTransferFetch = cfg.maxTransferFetch;
    var maxEnhancedFetch = cfg.maxEnhancedFetch;
    var maxFunderIdentity = cfg.maxFunderIdentity;
    var signalTrLimit = cfg.signalTransfersLimit != null ? cfg.signalTransfersLimit : 100;
    var enhancedLim = cfg.enhancedTxLimit != null ? cfg.enhancedTxLimit : 55;

    var lookupOrder = opts.lookupOrder || [];
    var fundedBy = opts.fundedBy || {};
    var mint = opts.mint;
    var focusWallets = opts.focusWallets || [];
    var pre = opts.transfersCache || {};
    var rootMap = opts.funderRootByWallet || {};
    var maxRootId = cfg.maxFunderRootIdentity != null ? cfg.maxFunderRootIdentity : 24;

    var transfersCache = {};
    Object.keys(pre).forEach(function (k) {
      transfersCache[k] = pre[k];
    });
    var nFetch = Math.min(lookupOrder.length, maxTransferFetch);
    var pending = [];
    for (var pi = 0; pi < nFetch; pi++) {
      var pw = lookupOrder[pi];
      if (transfersCache[pw] == null) pending.push(pw);
    }
    for (var ti = 0; ti < pending.length; ti++) {
      var w = pending[ti];
      transfersCache[w] = await heliusTransfers(apiKey, w, signalTrLimit);
      if (ti < pending.length - 1) await sleep(45);
    }

    var metaByWallet = {};
    for (var mi = 0; mi < lookupOrder.length; mi++) {
      var w2 = lookupOrder[mi];
      metaByWallet[w2] = enrichWalletFunding(w2, fundedBy[w2], transfersCache[w2]);
    }

    var timeClusters = clusterWalletsByTimeBucket(metaByWallet, bucketSec);
    var amountClusters = clusterWalletsBySameLamports(metaByWallet, relTol);

    var fundersSet = {};
    for (var fi = 0; fi < lookupOrder.length; fi++) {
      var wf = lookupOrder[fi];
      var fu = metaByWallet[wf] && metaByWallet[wf].funder;
      if (fu) fundersSet[fu] = true;
    }
    var funders = Object.keys(fundersSet).sort();

    var funderIdents = {};
    var sliceF = funders.slice(0, maxFunderIdentity);
    for (var ii = 0; ii < sliceF.length; ii++) {
      var fa = sliceF[ii];
      if (!fa) continue;
      funderIdents[fa] = await heliusWalletIdentity(apiKey, fa);
      if (ii < sliceF.length - 1) await sleep(40);
    }

    var rootAddrs = [];
    var rootSeen = {};
    Object.keys(rootMap).forEach(function (wk) {
      var r = rootMap[wk];
      if (typeof r !== 'string' || !r || funderIdents[r] !== undefined) return;
      if (rootSeen[r]) return;
      rootSeen[r] = true;
      rootAddrs.push(r);
    });
    rootAddrs.sort();
    rootAddrs = rootAddrs.slice(0, Math.max(0, maxRootId));
    for (var ri = 0; ri < rootAddrs.length; ri++) {
      var ra = rootAddrs[ri];
      funderIdents[ra] = await heliusWalletIdentity(apiKey, ra);
      if (ri < rootAddrs.length - 1) await sleep(40);
    }

    var cexFunders = {};
    var mixerFunders = {};
    for (var ci = 0; ci < funders.length; ci++) {
      var cf = funders[ci];
      cexFunders[cf] = isCexIdentity(funderIdents[cf]);
      mixerFunders[cf] = isMixerPrivacyIdentity(funderIdents[cf]);
    }

    var funderCexTier = {};
    var funderMixerTier = {};
    Object.keys(funderIdents).forEach(function (addr) {
      funderCexTier[addr] = cexTierStr(funderIdents[addr]);
      funderMixerTier[addr] = mixerTierStr(funderIdents[addr]);
    });

    var parallelCexFundingLoose = buildTaggedParallelGroups(
      lookupOrder,
      metaByWallet,
      rootMap,
      funderIdents,
      cexTierStr
    ).slice(0, 12);
    var parallelCexFunding = strictFromLoose(parallelCexFundingLoose, metaByWallet, bucketSec, relTol).slice(0, 12);
    var privacyMixerFundingLoose = buildTaggedParallelGroups(
      lookupOrder,
      metaByWallet,
      rootMap,
      funderIdents,
      mixerTierStr
    ).slice(0, 12);
    var privacyMixerFunding = strictFromLoose(privacyMixerFundingLoose, metaByWallet, bucketSec, relTol).slice(0, 12);

    var sharedInc = sharedInboundSenders(metaByWallet);
    var sharedOut = sharedOutboundReceivers(lookupOrder, transfersCache);

    var coSlotsByW = {};
    var programSets = {};
    var mw = [];
    var srcList = focusWallets.length ? focusWallets : lookupOrder;
    for (var qi = 0; qi < srcList.length && mw.length < maxEnhancedFetch; qi++) {
      var wx = srcList[qi];
      if (metaByWallet[wx]) mw.push(wx);
    }
    for (var ei = 0; ei < mw.length; ei++) {
      var we = mw[ei];
      var em = await enhancedCoMovementMint(apiKey, mint, we, enhancedLim);
      if (em) {
        coSlotsByW[we] = em.mint_touch_slots || [];
        var ps = {};
        (em.programs_sample || []).forEach(function (p) {
          ps[p] = true;
        });
        programSets[we] = ps;
      }
      if (ei < mw.length - 1) await sleep(85);
    }

    var enhancedSample = { wallets_analyzed: mw, mint_touch_slots_by_wallet: coSlotsByW };

    var slotToW = {};
    Object.keys(coSlotsByW).forEach(function (w3) {
      var sl = coSlotsByW[w3];
      for (var si = 0; si < sl.length; si++) {
        var s = sl[si];
        if (!slotToW[s]) slotToW[s] = [];
        slotToW[s].push(w3);
      }
    });
    var coMovePairs = [];
    Object.keys(slotToW).forEach(function (slotStr) {
      var ws = slotToW[slotStr];
      var u = {};
      ws.forEach(function (x) {
        u[x] = true;
      });
      var ul = Object.keys(u).sort();
      if (ul.length >= 2) coMovePairs.push({ slot: parseInt(slotStr, 10), wallets: ul });
    });

    var pOverlap = [];
    var pKeys = Object.keys(programSets);
    for (var pi = 0; pi < pKeys.length; pi++) {
      for (var pj = pi + 1; pj < pKeys.length; pj++) {
        var a = pKeys[pi];
        var b = pKeys[pj];
        pOverlap.push({
          wallet_a: a,
          wallet_b: b,
          program_jaccard: Math.round(jaccard(programSets[a] || {}, programSets[b] || {}) * 1e4) / 1e4,
        });
      }
    }
    pOverlap.sort(function (x, y) {
      return y.program_jaccard - x.program_jaccard;
    });

    var score = 0;
    var reasons = [];

    var sampleAddrs = {};
    for (var sai = 0; sai < lookupOrder.length; sai++) {
      var sw0 = lookupOrder[sai];
      var d0 = (metaByWallet[sw0] || {}).funder;
      if (typeof d0 === 'string') sampleAddrs[d0] = true;
      var r0 = rootMap[sw0];
      if (typeof r0 === 'string') sampleAddrs[r0] = true;
    }
    var anyStrongCex = false;
    var anyCexSample = false;
    Object.keys(sampleAddrs).forEach(function (a) {
      if ((funderCexTier[a] || '') === 'strong') anyStrongCex = true;
      if (isCexIdentity(funderIdents[a])) anyCexSample = true;
    });

    if (timeClusters.length) {
      score += Math.min(22, 6 + Math.max(0, timeClusters[0].wallets.length - 2) * 4);
      reasons.push('funding_time_sync');
    }
    if (amountClusters.length) {
      score += Math.min(18, 5 + Math.max(0, amountClusters[0].wallets.length - 2) * 3);
      reasons.push('same_first_fund_amount');
    }
    if (anyStrongCex) {
      score += 10;
      reasons.push('cex_strong_funder_in_sample');
    } else if (anyCexSample) {
      score += 4;
      reasons.push('cex_weak_funder_in_sample');
    }
    if (parallelCexFunding.length) {
      var topG = parallelCexFunding[0];
      var topN = topG.wallet_count;
      var ft = String(topG.funder_tier || '');
      if (ft === 'strong') {
        score += Math.min(16, 6 + Math.max(0, topN - 2) * 3);
        reasons.push('parallel_cex_funder_cluster_strict');
      } else {
        score += Math.min(10, 4 + Math.max(0, topN - 2) * 2);
        reasons.push('parallel_cex_funder_cluster_strict_weak_tier');
      }
    } else if (parallelCexFundingLoose.length) {
      var topL = parallelCexFundingLoose[0].wallet_count;
      score += Math.min(6, 2 + Math.max(0, topL - 2) * 2);
      reasons.push('parallel_cex_funder_cluster_loose_only');
    }
    if (privacyMixerFunding.length) {
      var topGm = privacyMixerFunding[0];
      var topM = topGm.wallet_count;
      var mt = String(topGm.funder_tier || '');
      if (mt === 'strong') {
        score += Math.min(14, 5 + Math.max(0, topM - 2) * 2);
        reasons.push('privacy_mixer_shared_funder_strict');
      } else {
        score += Math.min(9, 3 + Math.max(0, topM - 2) * 2);
        reasons.push('privacy_mixer_shared_funder_strict_weak_tier');
      }
    } else if (privacyMixerFundingLoose.length) {
      var topMl = privacyMixerFundingLoose[0].wallet_count;
      score += Math.min(5, 2 + Math.max(0, topMl - 2));
      reasons.push('privacy_mixer_funder_cluster_loose_only');
    }
    if (sharedInc.top_shared && sharedInc.top_shared.length) {
      score += Math.min(15, 5 + sharedInc.top_shared.length * 2);
      reasons.push('shared_inbound_counterparty');
    }
    if (sharedOut.top_shared_receivers && sharedOut.top_shared_receivers.length) {
      score += Math.min(16, 6 + sharedOut.top_shared_receivers.length * 2);
      reasons.push('shared_outbound_receiver');
    }
    if (coMovePairs.length) {
      score += Math.min(18, 6 + Math.min(coMovePairs.length, 4) * 3);
      reasons.push('mint_activity_same_slot');
    }
    if (pOverlap.length && pOverlap[0].program_jaccard >= 0.15) {
      score += Math.min(15, 5 + pOverlap[0].program_jaccard * 40);
      reasons.push('program_fingerprint_overlap');
    }

    score = Math.round(Math.min(100, score) * 100) / 100;

    var archetypeHints = [];
    if (parallelCexFunding.length) {
      archetypeHints.push(
        'High-confidence parallel CEX: shared CEX-labeled funder (direct or 2-hop root) plus aligned first-fund time or amount.'
      );
    } else if (parallelCexFundingLoose.length) {
      archetypeHints.push(
        'Loose parallel CEX: same CEX-tagged funder among sampled wallets without funding-time/amount corroboration.'
      );
    }
    if (privacyMixerFunding.length) {
      archetypeHints.push(
        'High-confidence privacy/mixer cluster: shared tagged funder plus aligned first-fund timing or lamports.'
      );
    } else if (privacyMixerFundingLoose.length) {
      archetypeHints.push('Loose privacy/mixer: same tagged funder path without funding corroboration.');
    }

    var tierKeySet = {};
    Object.keys(sampleAddrs).forEach(function (k) {
      tierKeySet[k] = true;
    });
    funders.forEach(function (f) {
      tierKeySet[f] = true;
    });
    rootAddrs.forEach(function (ra) {
      tierKeySet[ra] = true;
    });
    var funderCexTierOut = {};
    var funderMixerTierOut = {};
    Object.keys(tierKeySet)
      .sort()
      .forEach(function (k) {
        if (funderCexTier[k] !== undefined) funderCexTierOut[k] = funderCexTier[k];
        if (funderMixerTier[k] !== undefined) funderMixerTierOut[k] = funderMixerTier[k];
      });

    return {
      funding_metadata_by_wallet: metaByWallet,
      funding_time_clusters: timeClusters,
      funding_same_amount_clusters: amountClusters,
      funder_cex_flags: cexFunders,
      funder_mixer_flags: mixerFunders,
      funder_cex_tier: funderCexTierOut,
      funder_mixer_tier: funderMixerTierOut,
      parallel_cex_funding: parallelCexFunding,
      parallel_cex_funding_loose: parallelCexFundingLoose,
      privacy_mixer_funding: privacyMixerFunding,
      privacy_mixer_funding_loose: privacyMixerFundingLoose,
      bundle_archetype_hints: archetypeHints,
      shared_inbound_senders: sharedInc,
      shared_outbound_receivers: sharedOut,
      mint_co_movement: { same_slot_groups: coMovePairs.slice(0, 15), enhanced: enhancedSample },
      program_overlap_pairs: pOverlap.slice(0, 20),
      coordination_score: score,
      coordination_reasons: reasons,
      params: {
        funding_bucket_sec: bucketSec,
        lamports_rel_tol: relTol,
        max_transfer_fetch: nFetch,
        max_enhanced_fetch: mw.length,
        signal_transfers_limit: signalTrLimit,
        enhanced_tx_limit: enhancedLim,
        funder_root_identity_lookups: rootAddrs.length,
      },
    };
  }

  function runBundleSnapshot(apiKey, mint, opts) {
    opts = opts || {};
    return runBundleSnapshotAsync(apiKey, mint, opts).catch(function (e) {
      return { ok: false, error: e.message || String(e) };
    });
  }

  async function runBundleSnapshotAsync(apiKey, mint, opts) {
    opts = opts || {};
    var BD = BUNDLE_DEEP_DEFAULTS;
    var sw = opts.wallet ? normalizeAddress(opts.wallet) : null;
    if (opts.wallet && !sw) {
      return { ok: false, error: 'Invalid wallet address' };
    }
    var mh = opts.maxHolders != null ? opts.maxHolders : BD.maxHolders;
    var mf = opts.maxFundedBy != null ? opts.maxFundedBy : BD.maxFundedBy;
    var capMf = opts.maxFundedByCap != null ? opts.maxFundedByCap : BD.maxFundedByCap;
    mh = Math.max(5, Math.min(mh, 200));
    mf = Math.max(5, Math.min(mf, capMf));
    var dasPages = opts.dasMaxPages != null ? opts.dasMaxPages : BD.dasMaxPages;
    var lpMinPct = opts.lpSkipMinPct != null ? opts.lpSkipMinPct : BD.lpSkipMinPct;
    var trLimit = opts.funderTransfersLimit != null ? opts.funderTransfersLimit : BD.funderTransfersLimit;
    trLimit = Math.min(100, Math.max(1, trLimit));
    var hop2Max = opts.funderHop2Max != null ? opts.funderHop2Max : BD.funderHop2Max;
    var conc = opts.holderFetchConcurrency != null ? opts.holderFetchConcurrency : BD.holderFetchConcurrency;
    var hopConc = opts.hopFetchConcurrency != null ? opts.hopFetchConcurrency : BD.hopFetchConcurrency;

    var excludeNorm = {};
    if (opts.excludeWallets && Array.isArray(opts.excludeWallets)) {
      for (var exi = 0; exi < opts.excludeWallets.length; exi++) {
        var ax = normalizeAddress(String(opts.excludeWallets[exi]));
        if (ax) excludeNorm[ax] = true;
      }
    }

    var mintNorm = normalizeAddress(mint);
    if (!mintNorm) return { ok: false, error: 'Invalid mint address' };
    if (!apiKey || typeof apiKey !== 'string' || !apiKey.trim()) {
      return { ok: false, error: 'Missing Helius API key' };
    }
    var key = apiKey.trim();
    if (ADDR_RE.test(key)) {
      return {
        ok: false,
        error:
          'Options → Helius key looks like a Solana address (often a token mint was pasted there by mistake). Use your API key from dashboard.helius.dev. Put the mint address only in the Mint field.',
      };
    }

    var sup = await heliusRpc(key, 'getTokenSupply', [mintNorm]);
    if (sup.error) return { ok: false, error: 'getTokenSupply: ' + sup.error };
    var supplyVal = sup.result && sup.result.value;
    if (!supplyVal) return { ok: false, error: 'getTokenSupply returned empty' };

    var supplyDecimals = parseInt(supplyVal.decimals, 10) || 0;

    var totalUi = 0;
    if (supplyVal.uiAmount != null) {
      totalUi = parseFloat(supplyVal.uiAmount);
      if (isNaN(totalUi)) totalUi = 0;
    } else {
      var amt0 = parseFloat(supplyVal.amount || 0);
      var dec0 = supplyDecimals;
      totalUi = dec0 >= 0 ? amt0 / Math.pow(10, dec0) : 0;
    }
    if (totalUi <= 0) {
      return {
        ok: false,
        error:
          'Token supply is zero or unreadable. This mint may be invalid, not an SPL token on mainnet, or the RPC returned no data.',
      };
    }

    var holderSource = 'das';
    var dasFetch = await fetchDasTokenAccountsForMint(key, mintNorm, dasPages, 100);
    var dasRows = dasFetch.rows || [];
    var ownerAmount = ownerAmountFromDasRows(dasRows, supplyDecimals);
    if (!Object.keys(ownerAmount).length) {
      holderSource = 'largest_accounts';
      var fbLa = await holdersViaLargestAccountsAsync(key, mintNorm, mh);
      if (fbLa.error) {
        var errMsg = fbLa.error;
        if (dasFetch.error) errMsg = 'Holders (DAS): ' + dasFetch.error + '; fallback: ' + fbLa.error;
        return { ok: false, error: errMsg };
      }
      ownerAmount = fbLa.ownerAmount;
    }

    var ownersSorted = Object.keys(ownerAmount).sort(function (a, b) {
      return ownerAmount[b] - ownerAmount[a];
    });

    var excludedLp = null;
    var scanExclude = {};
    Object.keys(excludeNorm).forEach(function (ek) {
      scanExclude[ek] = true;
    });
    var skipLp = opts.skipLiquidityWallet !== false;
    if (skipLp && ownersSorted.length && totalUi > 0) {
      var topH = ownersSorted[0];
      if (!excludeNorm[topH]) {
        var pctTop = (100 * (ownerAmount[topH] || 0)) / totalUi;
        if (pctTop >= lpMinPct) {
          excludedLp = topH;
          scanExclude[topH] = true;
        }
      }
    }

    var lookupOrder = [];
    if (sw) lookupOrder.push(sw);
    ownersSorted.forEach(function (w) {
      if (scanExclude[w]) return;
      if (lookupOrder.indexOf(w) === -1) lookupOrder.push(w);
    });
    lookupOrder = lookupOrder.slice(0, mf);

    if (!lookupOrder.length) {
      return {
        ok: false,
        error:
          'No holder wallets to scan after liquidity / manual exclusions. Set skipLiquidityWallet: false or raise lpSkipMinPct (e.g. 100+ to disable LP skip).',
      };
    }

    var fundedBy = {};
    var transfersBy = {};
    var intelRows = await asyncPool(conc, lookupOrder, async function (w) {
      var fb = await heliusFundedBy(key, w);
      var tr = await heliusTransfers(key, w, trLimit);
      return { w: w, fb: fb, tr: tr };
    });
    for (var ir = 0; ir < intelRows.length; ir++) {
      var row = intelRows[ir];
      fundedBy[row.w] = row.fb;
      transfersBy[row.w] = row.tr;
    }

    var hopFundedBy = {};
    var hopTransfersBy = {};
    var hopCtxBase = { hopFunded: hopFundedBy, hopTransfers: hopTransfersBy };
    var hopTargetsFetched = 0;
    if (hop2Max > 0) {
      var funderCounts = {};
      lookupOrder.forEach(function (w) {
        var df = effectiveFunderAddress(fundedBy[w], transfersBy[w]);
        if (df) funderCounts[df] = (funderCounts[df] || 0) + 1;
      });
      var hopTargets = Object.keys(funderCounts)
        .sort(function (a, b) {
          return (funderCounts[b] || 0) - (funderCounts[a] || 0);
        })
        .slice(0, hop2Max);
      hopTargetsFetched = hopTargets.length;
      var hopRows = await asyncPool(hopConc, hopTargets, async function (addr) {
        var hfb = await heliusFundedBy(key, addr);
        var htr = await heliusTransfers(key, addr, trLimit);
        return { addr: addr, fb: hfb, tr: htr };
      });
      for (var hr = 0; hr < hopRows.length; hr++) {
        var hrw = hopRows[hr];
        hopFundedBy[hrw.addr] = hrw.fb;
        hopTransfersBy[hrw.addr] = hrw.tr;
      }
    }

    var clusterMembers = {};
    function addToCluster(fk, w) {
      if (!clusterMembers[fk]) clusterMembers[fk] = [];
      if (clusterMembers[fk].indexOf(w) === -1) clusterMembers[fk].push(w);
    }
    lookupOrder.forEach(function (w) {
      addToCluster(clusterKeyFromSources(w, fundedBy[w], transfersBy[w], hopCtxBase), w);
    });

    var focusClusterKey = null;
    if (sw) {
      focusClusterKey = clusterKeyFromSources(sw, fundedBy[sw], transfersBy[sw], hopCtxBase);
    } else {
      var bestKey = null;
      var bestSupply = 0;
      Object.keys(clusterMembers).forEach(function (ck) {
        if (ck.indexOf('funder:') !== 0) return;
        var members = clusterMembers[ck];
        if (members.length < 2) return;
        var s = 0;
        members.forEach(function (x) {
          s += ownerAmount[x] || 0;
        });
        if (s > bestSupply) {
          bestSupply = s;
          bestKey = ck;
        }
      });
      focusClusterKey = bestKey;
    }

    var focusMembers =
      focusClusterKey && clusterMembers[focusClusterKey] ? clusterMembers[focusClusterKey].slice() : [];

    var seedBalanceUi = null;
    if (sw) {
      seedBalanceUi = await balanceUiForMint(key, sw, mintNorm);
      if (seedBalanceUi == null) seedBalanceUi = ownerAmount[sw];
      if (focusClusterKey && focusMembers.indexOf(sw) === -1) {
        if (clusterKeyFromSources(sw, fundedBy[sw], transfersBy[sw], hopCtxBase) === focusClusterKey) focusMembers.push(sw);
      }
    }

    var clusterSupplyUi = 0;
    focusMembers.forEach(function (w) {
      var bal = ownerAmount[w] || 0;
      if (sw && w === sw && seedBalanceUi != null) {
        bal = Math.max(bal, seedBalanceUi);
      }
      clusterSupplyUi += bal;
    });

    var seedPct = null;
    if (sw && seedBalanceUi != null) {
      seedPct = supplyPct(seedBalanceUi, totalUi);
    }

    var idSet = {};
    focusMembers.forEach(function (w) {
      idSet[w] = true;
    });
    ownersSorted.slice(0, 40).forEach(function (w) {
      idSet[w] = true;
    });
    if (sw) idSet[sw] = true;
    var idAddrList = Object.keys(idSet).sort().slice(0, 100);

    var dasMetaRes = await heliusDasRpc(key, 'getAsset', { id: mintNorm });
    var identitiesRaw = await heliusBatchIdentity(key, idAddrList);
    var idMap = normalizeBatchIdentityMap(identitiesRaw);
    var token_metadata = tokenMetadataFromDas(dasMetaRes && dasMetaRes.result ? dasMetaRes.result : null);

    var holdersOut = ownersSorted.slice(0, 20).map(function (w) {
      var dr = directAndRootFunder(w, fundedBy[w], transfersBy[w], hopFundedBy, hopTransfersBy);
      return {
        wallet: w,
        amount_ui: Math.round(ownerAmount[w] * 1e8) / 1e8,
        pct_supply: supplyPct(ownerAmount[w], totalUi),
        funder: dr.direct,
        funder_root: dr.root,
        in_focus_cluster: focusMembers.indexOf(w) >= 0,
        identity: identityPayloadFromMap(idMap, w),
      };
    });

    var focusNote = null;
    if (!focusClusterKey && !sw) {
      focusNote =
        'No multi-wallet cluster with a shared ultimate funder in this sample. Optional: enter a wallet to focus that address’s funder-linked group.';
    }

    var identities = identitiesRaw;

    var funderRootByWallet = {};
    lookupOrder.forEach(function (w) {
      var dr = directAndRootFunder(w, fundedBy[w], transfersBy[w], hopFundedBy, hopTransfersBy);
      funderRootByWallet[w] = dr.root && dr.direct && dr.root !== dr.direct ? dr.root : null;
    });

    var bundleSignals = null;
    try {
      bundleSignals = await computeCoordinationBundleAsync(key, {
        lookupOrder: lookupOrder,
        fundedBy: fundedBy,
        mint: mintNorm,
        focusWallets: focusMembers.slice().sort(),
        transfersCache: transfersBy,
        funderRootByWallet: funderRootByWallet,
      });
    } catch (e) {
      bundleSignals = {
        coordination_score: 0,
        coordination_reasons: [],
        error: String((e && e.message) || e),
      };
    }

    return {
      ok: true,
      mint: mintNorm,
      token_metadata: token_metadata,
      token_supply_ui: totalUi,
      seed_wallet: sw || null,
      seed_balance_ui: seedBalanceUi != null ? Math.round(seedBalanceUi * 1e8) / 1e8 : null,
      seed_pct_supply: seedPct,
      focus_cluster_key: focusClusterKey,
      focus_cluster_wallets: focusMembers.slice().sort(),
      focus_cluster_supply_ui: Math.round(clusterSupplyUi * 1e8) / 1e8,
      focus_cluster_pct_supply: supplyPct(clusterSupplyUi, totalUi),
      focus_cluster_note: focusNote,
      top_holders: holdersOut,
      identities: identities,
      excluded_liquidity_wallet: excludedLp,
      params: {
        max_holders: mh,
        max_funded_by_lookups: mf,
        funder_transfers_limit: trLimit,
        holder_fetch_source: holderSource,
        das_max_pages: dasPages,
        das_token_account_rows: dasRows.length,
        unique_holders_sampled: ownersSorted.length,
        lp_skip_min_pct: lpMinPct,
        funder_hop2_max: hop2Max,
        funder_hop2_wallets_fetched: hopTargetsFetched,
        deep_bundle_scan: true,
      },
      disclaimer:
        'Heuristic only: clusters prefer a shared 2-hop ultimate funder when Helius returns data for intermediate wallets (else direct first inbound SOL / funded-by). Deep scan uses more API calls and time. Not financial advice.',
      pnl_note: 'PnL not computed here; use an explorer or portfolio tool for full buy/sell history.',
      bundle_signals: bundleSignals,
    };
  }

  global.divergSolanaBundle = { runBundleSnapshot: runBundleSnapshot };
})(typeof globalThis !== 'undefined' ? globalThis : self);
