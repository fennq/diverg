/**
 * Solana bundle snapshot — runs entirely in the extension (Helius BYOK).
 * Mirrors investigation/solana_bundle.py: top holders + shared direct-funder clustering.
 */
(function (global) {
  var ADDR_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
  var HELIUS_RPC = 'https://api-mainnet.helius-rpc.com';
  var HELIUS_WALLET = 'https://api.helius.xyz';

  function normalizeAddress(s) {
    if (!s || typeof s !== 'string') return null;
    var t = s.trim();
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
        return r.json();
      })
      .then(function (data) {
        if (data.error) {
          var msg = (data.error && data.error.message) || JSON.stringify(data.error);
          return { result: null, error: msg };
        }
        return { result: data.result, error: null };
      })
      .catch(function (e) {
        return { result: null, error: e.message || 'RPC failed' };
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

  function funderAddress(funded) {
    if (!funded || typeof funded !== 'object') return null;
    var f = funded.funder;
    return typeof f === 'string' && ADDR_RE.test(f) ? f : null;
  }

  function clusterKey(wallet, funded) {
    var f = funderAddress(funded);
    if (f) return 'funder:' + f;
    return 'singleton:' + wallet;
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

  function runBundleSnapshot(apiKey, mint, opts) {
    opts = opts || {};
    return runBundleSnapshotAsync(apiKey, mint, opts).catch(function (e) {
      return { ok: false, error: e.message || String(e) };
    });
  }

  async function runBundleSnapshotAsync(apiKey, mint, opts) {
    var sw = opts.wallet ? normalizeAddress(opts.wallet) : null;
    if (opts.wallet && !sw) {
      return { ok: false, error: 'Invalid wallet address' };
    }
    var mh = opts.maxHolders != null ? opts.maxHolders : 50;
    var mf = opts.maxFundedBy != null ? opts.maxFundedBy : 40;
    mh = Math.max(5, Math.min(mh, 100));
    mf = Math.max(5, Math.min(mf, 100));

    var mintNorm = normalizeAddress(mint);
    if (!mintNorm) return { ok: false, error: 'Invalid mint address' };
    if (!apiKey || typeof apiKey !== 'string' || !apiKey.trim()) {
      return { ok: false, error: 'Missing Helius API key' };
    }
    var key = apiKey.trim();

    var sup = await heliusRpc(key, 'getTokenSupply', [mintNorm]);
    if (sup.error) return { ok: false, error: 'getTokenSupply: ' + sup.error };
    var supplyVal = sup.result && sup.result.value;
    if (!supplyVal) return { ok: false, error: 'getTokenSupply returned empty' };

    var totalUi = 0;
    if (supplyVal.uiAmount != null) {
      totalUi = parseFloat(supplyVal.uiAmount);
      if (isNaN(totalUi)) totalUi = 0;
    } else {
      var amt0 = parseFloat(supplyVal.amount || 0);
      var dec0 = parseInt(supplyVal.decimals, 10) || 0;
      totalUi = dec0 >= 0 ? amt0 / Math.pow(10, dec0) : 0;
    }

    var lg = await heliusRpc(key, 'getTokenLargestAccounts', [mintNorm]);
    if (lg.error) return { ok: false, error: 'getTokenLargestAccounts: ' + lg.error };
    var list = lg.result && lg.result.value;
    if (!Array.isArray(list)) return { ok: false, error: 'Unexpected getTokenLargestAccounts shape' };

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
      var mult = await heliusRpc(key, 'getMultipleAccounts', [batch, { encoding: 'jsonParsed' }]);
      if (mult.error) return { ok: false, error: 'getMultipleAccounts: ' + mult.error };
      var accList = mult.result && mult.result.value;
      if (!Array.isArray(accList)) return { ok: false, error: 'getMultipleAccounts missing value list' };
      for (var j = 0; j < accList.length; j++) {
        var acc = accList[j];
        var ta = batch[j];
        var owner = parseTokenAccountOwner(acc);
        if (!owner) continue;
        var uiTa = uiFromLargest[ta] || 0;
        var amt = uiTa || parseTokenAccountUiAmount(acc);
        ownerAmount[owner] = (ownerAmount[owner] || 0) + amt;
      }
    }

    var ownersSorted = Object.keys(ownerAmount).sort(function (a, b) {
      return ownerAmount[b] - ownerAmount[a];
    });

    var lookupOrder = [];
    if (sw) lookupOrder.push(sw);
    ownersSorted.forEach(function (w) {
      if (lookupOrder.indexOf(w) === -1) lookupOrder.push(w);
    });
    lookupOrder = lookupOrder.slice(0, mf);

    var fundedBy = {};
    for (var i = 0; i < lookupOrder.length; i++) {
      var w = lookupOrder[i];
      fundedBy[w] = await heliusFundedBy(key, w);
      if (i < lookupOrder.length - 1) await sleep(50);
    }

    var clusterMembers = {};
    function addToCluster(fk, w) {
      if (!clusterMembers[fk]) clusterMembers[fk] = [];
      if (clusterMembers[fk].indexOf(w) === -1) clusterMembers[fk].push(w);
    }
    lookupOrder.forEach(function (w) {
      addToCluster(clusterKey(w, fundedBy[w]), w);
    });

    var focusClusterKey = null;
    if (sw) {
      focusClusterKey = clusterKey(sw, fundedBy[sw]);
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
        if (clusterKey(sw, fundedBy[sw]) === focusClusterKey) focusMembers.push(sw);
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

    var holdersOut = ownersSorted.slice(0, 20).map(function (w) {
      return {
        wallet: w,
        amount_ui: Math.round(ownerAmount[w] * 1e8) / 1e8,
        pct_supply: supplyPct(ownerAmount[w], totalUi),
        funder: funderAddress(fundedBy[w]),
        in_focus_cluster: focusMembers.indexOf(w) >= 0,
      };
    });

    var focusNote = null;
    if (!focusClusterKey && !sw) {
      focusNote =
        'No multi-wallet cluster with a shared direct funder in this sample. Optional: enter a wallet to focus that address’s funder-linked group.';
    }

    var identities = await heliusBatchIdentity(key, focusMembers.slice(0, 100));

    return {
      ok: true,
      mint: mintNorm,
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
      params: { max_holders: mh, max_funded_by_lookups: mf },
      disclaimer:
        'Heuristic only: clusters use the same *direct* funder from Helius funded-by. Wallets not in the sampled top holders may be missing. Not financial advice.',
      pnl_note: 'PnL not computed here; use an explorer or portfolio tool for full buy/sell history.',
    };
  }

  global.divergSolanaBundle = { runBundleSnapshot: runBundleSnapshot };
})(typeof globalThis !== 'undefined' ? globalThis : self);
