/**
 * Solana bundle snapshot — runs entirely in the extension (Helius BYOK).
 * Mirrors investigation/solana_bundle.py: top holders, shared direct-funder clustering,
 * and multi-signal coordination heuristics (see investigation/solana_bundle_signals.py).
 */
(function (global) {
  var ADDR_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
  /** Official Helius Solana RPC (OpenAPI); api-mainnet.* can return method not found for some calls. */
  var HELIUS_RPC = 'https://mainnet.helius-rpc.com';
  var HELIUS_WALLET = 'https://api.helius.xyz';

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

  /** Defaults match investigation/solana_bundle_signals.py env defaults. */
  var BUNDLE_SIGNAL_DEFAULTS = {
    fundingBucketSec: 5,
    lamportsRelTol: 0.002,
    maxTransferFetch: 18,
    maxEnhancedFetch: 10,
    maxFunderIdentity: 24,
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
      encodeURIComponent(String(limit || 80)) +
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
    if (typeof fb.funder === 'string') out.funder = fb.funder;
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
    if (!raw || typeof raw !== 'object') return [];
    var keys = ['transfers', 'data', 'items', 'results'];
    for (var i = 0; i < keys.length; i++) {
      var v = raw[keys[i]];
      if (Array.isArray(v)) return v.filter(function (x) {
        return x && typeof x === 'object';
      });
    }
    return [];
  }

  function extractFirstInboundSolFromTransfers(raw) {
    var rows = iterTransferRows(raw);
    var candidates = [];
    for (var i = 0; i < rows.length; i++) {
      var t = rows[i];
      var direction = String(t.direction || t.type || '').toLowerCase();
      var token = String(t.token || t.mint || '').toLowerCase();
      var sym = String(t.symbol || '').toUpperCase();
      var isSol =
        token.indexOf('sol') >= 0 ||
        sym === 'SOL' ||
        t.isNative === true ||
        t.native === true ||
        (!t.mint && (direction === 'in' || direction === 'incoming' || direction === 'received' || direction === 'receive' || direction === 'inbound' || direction === ''));
      if (direction === 'out' || direction === 'outgoing' || direction === 'sent') continue;
      if (!isSol && t.mint) continue;
      var ts = t.timestamp != null ? t.timestamp : t.blockTime != null ? t.blockTime : t.time;
      var tu = null;
      if (typeof ts === 'number') {
        tu = Math.floor(ts);
        if (tu > 1e12) tu = Math.floor(tu / 1000);
      }
      var lam = safeInt(t.lamports != null ? t.lamports : t.amountLamports);
      if (lam == null) {
        var amt = safeFloat(t.amount != null ? t.amount : t.uiAmount);
        if (amt != null) lam = Math.round(amt * 1e9);
      }
      var sig = t.signature || t.tx || t.transactionSignature;
      var fromA = t.from || t.fromUserAccount || t.sender || t.source;
      if (fromA && typeof fromA === 'object') fromA = fromA.address || fromA.pubkey;
      if (lam == null || tu == null) continue;
      candidates.push({
        lamports: lam,
        timestamp_unix: tu,
        signature: typeof sig === 'string' ? sig : null,
        from_address: typeof fromA === 'string' ? fromA : null,
      });
    }
    if (!candidates.length) return null;
    candidates.sort(function (a, b) {
      return a.timestamp_unix - b.timestamp_unix;
    });
    return candidates[0];
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
    return {
      wallet: wallet,
      funder: fb.funder || null,
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

  function isCexIdentity(ident) {
    if (!ident || typeof ident !== 'object') return false;
    var cat = String(ident.category || '').toLowerCase();
    var name = String(ident.name || '').toLowerCase();
    if (cat.indexOf('exchange') >= 0 || cat.indexOf('cex') >= 0) return true;
    var tags = ['exchange', 'binance', 'coinbase', 'kraken', 'okx', 'bybit', 'kucoin'];
    for (var i = 0; i < tags.length; i++) {
      if (name.indexOf(tags[i]) >= 0) return true;
    }
    return false;
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

    var lookupOrder = opts.lookupOrder || [];
    var fundedBy = opts.fundedBy || {};
    var mint = opts.mint;
    var focusWallets = opts.focusWallets || [];

    var transfersCache = {};
    var nFetch = Math.min(lookupOrder.length, maxTransferFetch);
    for (var ti = 0; ti < nFetch; ti++) {
      var w = lookupOrder[ti];
      transfersCache[w] = await heliusTransfers(apiKey, w, 80);
      if (ti < nFetch - 1) await sleep(50);
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

    var cexFunders = {};
    for (var ci = 0; ci < funders.length; ci++) {
      var cf = funders[ci];
      cexFunders[cf] = isCexIdentity(funderIdents[cf]);
    }

    var sharedInc = sharedInboundSenders(metaByWallet);

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
      var em = await enhancedCoMovementMint(apiKey, mint, we, 35);
      if (em) {
        coSlotsByW[we] = em.mint_touch_slots || [];
        var ps = {};
        (em.programs_sample || []).forEach(function (p) {
          ps[p] = true;
        });
        programSets[we] = ps;
      }
      if (ei < mw.length - 1) await sleep(80);
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

    if (timeClusters.length) {
      score += Math.min(22, 6 + Math.max(0, timeClusters[0].wallets.length - 2) * 4);
      reasons.push('funding_time_sync');
    }
    if (amountClusters.length) {
      score += Math.min(18, 5 + Math.max(0, amountClusters[0].wallets.length - 2) * 3);
      reasons.push('same_first_fund_amount');
    }
    var anyCex = false;
    Object.keys(cexFunders).forEach(function (k) {
      if (cexFunders[k]) anyCex = true;
    });
    if (anyCex) {
      score += 12;
      reasons.push('cex_tagged_funder_present');
    }
    if (sharedInc.top_shared && sharedInc.top_shared.length) {
      score += Math.min(15, 5 + sharedInc.top_shared.length * 2);
      reasons.push('shared_inbound_counterparty');
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

    return {
      funding_metadata_by_wallet: metaByWallet,
      funding_time_clusters: timeClusters,
      funding_same_amount_clusters: amountClusters,
      funder_cex_flags: cexFunders,
      shared_inbound_senders: sharedInc,
      mint_co_movement: { same_slot_groups: coMovePairs.slice(0, 15), enhanced: enhancedSample },
      program_overlap_pairs: pOverlap.slice(0, 20),
      coordination_score: score,
      coordination_reasons: reasons,
      params: {
        funding_bucket_sec: bucketSec,
        lamports_rel_tol: relTol,
        max_transfer_fetch: nFetch,
        max_enhanced_fetch: mw.length,
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

    var totalUi = 0;
    if (supplyVal.uiAmount != null) {
      totalUi = parseFloat(supplyVal.uiAmount);
      if (isNaN(totalUi)) totalUi = 0;
    } else {
      var amt0 = parseFloat(supplyVal.amount || 0);
      var dec0 = parseInt(supplyVal.decimals, 10) || 0;
      totalUi = dec0 >= 0 ? amt0 / Math.pow(10, dec0) : 0;
    }
    if (totalUi <= 0) {
      return {
        ok: false,
        error:
          'Token supply is zero or unreadable. This mint may be invalid, not an SPL token on mainnet, or the RPC returned no data.',
      };
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
        var uiTa = uiFromLargest[ta];
        var parsedAmt = parseTokenAccountUiAmount(acc);
        var amt =
          uiTa != null && !isNaN(parseFloat(uiTa)) && parseFloat(uiTa) > 0
            ? parseFloat(uiTa)
            : parsedAmt;
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

    var bundleSignals = null;
    try {
      bundleSignals = await computeCoordinationBundleAsync(key, {
        lookupOrder: lookupOrder,
        fundedBy: fundedBy,
        mint: mintNorm,
        focusWallets: focusMembers.slice().sort(),
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
      bundle_signals: bundleSignals,
    };
  }

  global.divergSolanaBundle = { runBundleSnapshot: runBundleSnapshot };
})(typeof globalThis !== 'undefined' ? globalThis : self);
