# Running Diverg on axiom.trade (Crypto Trading / Solana)

Authorized engagement: full security run including user leakage and financial flows.

## How Diverg adapts

- **Profile:** When the target URL contains `axiom`, `crypto`, `.trade`, `solana`, `exchange`, or the objective contains `crypto`, `trading`, `user leakage`, `full security`, or `wallet`, Diverg sets the **crypto-trading-surface** profile.
- **Skills run:** payment_financial, high_value_flaws, data_leak_risks, crypto_security, api_test (discovery), race_condition — with trading-specific paths and params.

## What gets tested

| Area | What Diverg checks |
|------|--------------------|
| **User leakage** | IDOR on wallet_id, wallet_address, position_id, trade_id; distinct user/wallet/balance data between responses → CONFIRMED IDOR |
| **Financial flows** | /api/trades, /api/positions, /api/portfolio, /api/wallet, /api/orderbook, /api/fills, /api/swap, /api/solana; amount/balance tampering, zero payment |
| **Data leak risks** | /api/wallet, /api/positions, /api/trades in cache/PII checks; wallet_address, public_key, balance in JSON responses; client-side wallet/balance in __NEXT_DATA__ or storage |
| **Crypto** | JWT alg:none/weak, weak TLS, weak crypto in frontend (e.g. Math.random, keys in JS) |
| **Race conditions** | trade, swap, execute, fill endpoints — duplicate transaction/order IDs from concurrent requests |
| **History / activity** | /api/history, /api/activity, /api/export, /api/trades/history — IDOR and cache/PII on history/export |
| **Market / quote** | /api/market, /api/quote — discovery and tampering (slippage, price params) |
| **Webhooks / notifications** | /api/webhooks, /api/notifications — IDOR, SSRF, or hijack to another user |
| **Referral / affiliate** | referral_id, affiliate_id — IDOR or credit theft |
| **Versioned / lifecycle** | /api/v1/, /api/v2/, /api/account/delete, /api/revoke, /api/logout — weaker auth on old versions or revoke not invalidating |
| **Invite / team / org** | /api/invite, /api/team, /api/members — IDOR on invite_id, member_id, team_id |
| **Data rights** | /api/consent, /api/data-export — IDOR or over-exposure in export |
| **Health / WebSocket** | /api/health, /api/ready, /api/version, /ws, /socket.io — info leak or unauthenticated WS |

## History, market influence, and sneaky angles

Diverg now probes these explicitly; manual follow-ups are still worth it.

- **History / activity IDOR** — Changing user_id, wallet_id, or pagination on `/api/history`, `/api/activity`, `/api/trades/history` can leak other users’ trade/order history. Export endpoints (e.g. “export my trades” CSV) may have the same IDOR.
- **Market influence** — `/api/market`, `/api/quote`, or price-feed endpoints might accept client-supplied price/slippage. We tamper `slippage`, `max_slippage`, `slippage_bps`; check if the server enforces bounds. Oracle or internal price endpoints that are writable or leaky are high impact.
- **Webhooks** — If the app has “notify me on trade” or “API webhook URL”: (1) IDOR so we register a webhook for another user; (2) SSRF (webhook URL = internal or cloud metadata); (3) callback URL override in params. We discover `/api/webhooks` and `/api/notifications`; manual tests for register/update/delete and URL validation.
- **Referral / affiliate** — `referral_id` or `affiliate_id` in signup or trade flow: we probe IDOR (steal credit for another referrer) and whether the server ties referral to the authenticated user.
- **Parameter pollution** — Sending e.g. `wallet_id=victim&wallet_id=attacker` or duplicate params; some stacks take first vs last. Worth a quick manual check on critical flows (trade, withdraw, export).
- **Manual follow-ups** — WebSocket channels that might leak live orders/trades to the wrong client; replay of signed messages if the backend doesn’t enforce nonce/expiry; front-running if orderbook or “pending” orders are exposed per user.

## How to run

1. **Full adaptive scan (recommended)**  
   In Telegram:  
   `/attack https://axiom.trade full security run user leakage`  
   or  
   `Run a full security assessment on axiom.trade including user leakage and financial flows`

2. **With authenticated (post-login) checks**  
   - Set auth once: `/setauth cookies=session=...` or `/setauth bearer_token=...`  
   - Then: `/attack https://axiom.trade full security run`  
   Payment and wallet/position checks will use the stored session.

3. **Discover first, then choose tools**  
   - `run_discover_surface` with target `https://axiom.trade`  
   - If the domain/URL matches, `crypto-trading-surface` will be in `profiles_detected` and `recommended_skills` will include the above skills.  
   - Run the recommended skills or `run_full_attack` for the full run.

## Under-scope / “shifty” emphasis

- Use an **objective** that explicitly asks for user leakage and full coverage, e.g.  
  `full security run including user leakage, wallet/position IDOR, and financial flows`.  
  That keeps the crypto-trading profile and reporting focus on those areas.
- Stored auth (`/setauth`) ensures post-login wallet/position/trade endpoints are tested.
- All findings are tied to evidence; CONFIRMED vs UNCONFIRMED and proof (e.g. distinct wallet/balance data) are in the report.

## Underplayed risks (easy to miss)

Surfaces we now discover; manual checks still matter.

- **Pagination / limit abuse** — List endpoints often accept `limit`, `offset`, `per_page`. Try `limit=999999` or `limit=-1`; uncapped bulk export can leak huge datasets or DoS. We fuzz these params; confirm the server enforces a max.
- **Sort / order column leak** — `?sort=password`, `sort=internal_id`, `orderBy=email` can reveal column names, internal fields, or even values if the API echoes the sort key. We fuzz sort/order; check responses for info leak.
- **Deprecated / versioned APIs** — `/api/v1/` vs `/api/v2/` sometimes have different auth or weaker checks. We probe `/api/v1/me`, `/api/v2/me`, `/api/v1/wallet`, etc.; manual: confirm v1 is locked down or deprecated.
- **Logout / revoke not invalidating** — After `/api/logout` or `/api/revoke`, reuse the same token. If the API still returns 200 with data, tokens aren’t invalidated (session fixation or token reuse). We discover these paths; manual: test token after revoke.
- **WebSocket auth** — `/ws`, `/socket.io`, `/api/ws` might accept unauthenticated connections or leak another user’s channel if the subscription key is guessable. We discover; manual: connect without auth and with another user’s token/subscription id.
- **Invite / team / org IDOR** — `/api/invite`, `/api/team`, `/api/members`. We probe invite_id, member_id, team_id; check (1) accept invite for another user, (2) list members of another team, (3) change role in another org.
- **Account delete / data export** — `/api/account/delete`, `/api/data-export`, `/api/consent`. Often under-tested: (1) delete or export another user’s data via IDOR; (2) export includes more than intended (tokens, internal ids); (3) delete doesn’t actually purge (soft delete, backups). We discover; manual: verify scope and actual deletion.
- **Health / version info leak** — `/api/health`, `/api/ready`, `/api/version` often return stack name, env, or internal service URLs. We add them to discovery and cache checks; manual: flag if response body reveals internal architecture or versions.
- **Error amplification** — Trigger 500/403/429 and compare response size or content to normal 200. Sometimes error paths leak stack traces, internal hostnames, or DB details that normal responses don’t. data_leak_risks triggers verbose errors; manual: compare error vs success response.
- **Third-party scripts** — On sensitive pages (dashboard, wallet), note any external script origins (analytics, chat, CDN). They often receive DOM or URL context; data exfil or script compromise = session/wallet at risk. Recon/source review.
- **Time-based** — Session or token expiry: if expiry is long or not enforced, stolen tokens live longer. Rate-limit reset window: e.g. 100 req/min resets at :00; burst at :59 and :00 = 200 in 1s. Manual.
- **Parameter pollution** — `wallet_id=victim&wallet_id=attacker`; some stacks take first, others last. Quick manual on critical flows (trade, withdraw, export).
