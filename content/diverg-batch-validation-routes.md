# Diverg batch validation methodology — 100+ reusable exploit routes

Batch vs single path validation gaps, account/subaccount ID substitution, and parameter trust. Use as scan routes, checklist items, and test plans for high-value or sensitive APIs and apps.

## Prior art (external reference)

- **Batch path skipping ownership:** A batch message path can skip ownership validation that the single-message path enforces. Attacker may specify a victim's subaccount ID in batch operations; if the server does not verify the signer owns that subaccount, the operation can be abused (e.g. orders or transfers on victim's behalf).
- **Method:** Compare every code path that performs the same logical operation. If one path validates and another does not, the unvalidated path is a candidate for abuse.

---

## How to find these issues

### 1. **Differential validation analysis (single vs batch path)**

- Trace the **single-operation path**: identify where ownership/authorization is enforced (e.g. ValidateBasic, auth middleware).
- Trace the **batch path**: same logical operation (create order, transfer, etc.). Check whether each sub-item gets the same ownership check.
- **Method:** Compare every code path that performs the same logical operation. If one path validates and another does not, the unvalidated path is a candidate for abuse.

### 2. **Authorization boundary identification**

- The critical invariant: **account/subaccount ID must belong to the transaction signer or session.** Find the canonical authorization check, then enumerate all entry points that accept that attribute and ensure every path calls the check.
- **Method:** Find the canonical authorization check for a sensitive attribute (account/subaccount/user ID, role, resource ID). Then enumerate all entry points that accept that attribute and ensure every path calls the check.

### 3. **Composition and permissionless primitives**

- Combine missing validation with permissionless or low-trust primitives (create token, create market, bridge) to turn an authorization bug into full impact.
- **Method:** Combine missing validation with permissionless or low-trust primitives to turn an authorization bug into full impact.

---

## Route quality

**Strong (batch vs single, parameter substitution, type confusion):** A (batch vs single), B (parameter substitution), D (type confusion). These are the ones most likely to find the same class of bug.

**Solid (real bug classes):** C (alternate endpoints), E (races/reentrancy), F (mass assignment), H (API param sources), I (signing/session). Use these on every relevant surface.

**Niche but valuable:** M (chain-specific). J (numeric/bounds) for financial/crypto surfaces.

**Weaker (process/meta):** K (logging), L (config), N (docs/tests). Use for process improvement, not as primary scan routes.

**Bottom line:** Prioritize batch-vs-single and "who is the signer vs who is in the request body" on every path.

---

## 100+ ways to find or replicate similar issues

Use these as **scan routes**, **checklist items**, and **test plans**. **Priority:** A, B, D, then C, E, F, H, I; then M if chain-specific; K, L, N for process.

### A. Batch vs single path (differential validation)

1. **Batch endpoint skips validation** — Batch/create-many API or chain message validates fewer fields than single-create.
2. **Bulk update skips ownership check** — Update many records by ID; single update checks owner, bulk does not.
3. **Batch transfer vs single transfer** — Single transfer checks balance/signer; batch transfer does not check one or more items.
4. **Multi-send / batch send** — Same as above for native token or token transfers.
5. **Batch order submission** — Orders in batch path not validated for account/subaccount ownership.
6. **Batch cancel vs single cancel** — Single cancel checks "you own this order"; batch cancel does not.
7. **Batch approve/allowance** — Single approve checks spender; batch approve skips check for some entries.
8. **Batch swap/route** — Single swap validates route and user; batch swap skips user or route validation.
9. **Batch claim rewards** — Single claim checks beneficiary; batch claim allows arbitrary beneficiary.
10. **Batch stake/delegate** — Single stake checks delegator; batch allows other delegator IDs.

### B. Parameter / field substitution (IDOR and account confusion)

11. **Subaccount ID in request body** — Client sends subaccount_id; server uses it without verifying it belongs to signer/session.
12. **Account ID in request body** — Same for account_id, wallet_id, user_id.
13. **Beneficiary / recipient in batch** — Batch operation accepts beneficiary per item; no check that signer is allowed to assign that beneficiary.
14. **Sender override** — Request carries "sender" or "from"; server trusts it instead of deriving from auth/signature.
15. **Wallet address in API** — API accepts wallet address for balance/transfer; no check that authenticated user owns that wallet.
16. **Order owner in order payload** — Order object contains "owner" or "subaccount"; not overwritten from signer.
17. **Referral ID / affiliate ID** — Referral credited to arbitrary ID in batch or single request.
18. **Vault ID / strategy ID** — Withdraw from vault by ID; no check that caller owns the vault position.
19. **Position ID** — Close or modify position by ID; ownership not validated.
20. **Withdrawal address in batch** — Batch withdrawal allows different destination per row; one row could be victim's deposit address to confuse or abuse.

### C. Alternate endpoints / message types

21. **New message type forgets validation** — New chain message or API (e.g. "v2" order type) does not call existing ValidateBasic or auth middleware.
22. **REST vs GraphQL** — Same operation: REST checks ownership; GraphQL resolver does not.
23. **Web vs API** — Web form validates; API used by mobile or script does not.
24. **WebSocket vs HTTP** — HTTP endpoint validates; WebSocket handler does not.
25. **Internal RPC vs public API** — Internal RPC skips auth "because it's internal"; exposed or callable by mistake.
26. **Admin endpoint reused** — Admin "impersonate user" or "act as" endpoint callable without admin check in one path.
27. **Callback / webhook** — Webhook updates state; no verification that the event belongs to the account being updated.
28. **Event handler** — Event-driven path (e.g. "on order filled") updates balances without re-checking ownership.
29. **Cron / scheduled job** — Job processes "pending" items; does not verify current ownership before transfer.
30. **Queue consumer** — Consumer processes message with user_id/subaccount_id; trusts message instead of re-deriving from auth.

### D. Type or variant confusion

31. **Market vs limit order** — Limit order validated, market order not.
32. **Spot vs derivative** — One product type has full validation, other has a gap.
33. **Order type enum** — New enum value (e.g. "market_v2") not handled in validation switch.
34. **Token type** — Native vs IBC vs factory token; one path skips check.
35. **Chain ID / network** — Operation validated on chain A, not on chain B in cross-chain path.
36. **Message version** — v1 message validated; v2 message has extra fields that bypass check.
37. **Encoding** — Same message in JSON vs Protobuf; one decoding path drops a field used for auth.
38. **Wrapped vs native** — Wrapped asset path uses different logic and misses ownership check.

### E. Order of operations / state

39. **Check-then-use race** — Check ownership then do transfer in two steps; attacker changes state between check and use.
40. **Reentrancy** — Callback or re-entry into same contract/API before state finalized; double spend or wrong owner.
41. **Delayed execution** — Order or message executed later; ownership checked at submit time but not at execution time.
42. **Cross-contract call** — Contract A checks; calls B which performs action without re-checking.
43. **Delegate call / proxy** — Proxy forwards to implementation; implementation assumes msg.sender is user, but it's proxy.
44. **Batch order of operations** — In batch, order of apply matters; one permutation bypasses a check.
45. **State dependency** — Validation depends on global state that attacker can change before batch is processed.

### F. Mass assignment / server-set vs client-set

46. **Client sends "role" or "is_admin"** — Server trusts body and grants privilege.
47. **Client sends "balance" or "amount"** — Server uses it instead of computing from ledger.
48. **Client sends "owner"** — Server sets resource owner from request.
49. **Client sends "approved" or "allowance"** — Server sets approval without checking approver.
50. **Client sends "status"** — Order or withdrawal marked success by client-supplied status.
51. **Client sends "nonce" or "timestamp"** — Replay or ordering abuse.
52. **Client sends "chain_id"** — Server uses it for replay protection but not for routing; wrong chain.
53. **Client sends "fee_recipient"** — Fee sent to attacker-chosen address.

### G. Cross-module / cross-service

54. **Module A assumes Module B validated** — Exchange module assumes auth module already checked; auth not called in batch path.
55. **Two modules share state** — One module updates balance, other updates "positions"; only one checks owner.
56. **Bridge / cross-chain** — Source chain validates; destination chain does not validate beneficiary or amount.
57. **Token factory + exchange** — Permissionless token + permissionless market + missing order validation.
58. **Oracle + lending** — Oracle price used for liquidation; oracle path does not validate who can trigger liquidation.
59. **Governance + treasury** — Proposal execution transfers funds; executor does not re-validate proposal params.
60. **Staking + rewards** — Claim path uses "delegator" from request instead of signer.

### H. API and client-surface

61. **Parameter in query string** — Same parameter in body is validated; in query it is not.
62. **Parameter in header** — X-User-Id or X-Account-Id trusted without verification.
63. **Parameter in cookie** — Cookie holds account_id; server trusts it.
64. **Multiple sources** — Account from JWT, body, and header; server uses wrong one in one path.
65. **Default value** — Missing account_id defaults to "first" or "admin" account.
66. **Array vs single** — API accepts single object with owner check; array of objects uses first object's check for all.
67. **Pagination** — Endpoint returns other users' data when page or offset is tampered.
68. **Filter by user_id** — List endpoint accepts user_id filter; returns data of any user if filter not enforced.
69. **Export / report** — Export "my data" but parameter allows export of another user's data.
70. **Webhook registration** — Register webhook for arbitrary user_id or account_id.

### I. Authentication and signing

71. **Signature over hash only** — Message signed does not include subaccount_id; attacker can reuse signature with different subaccount.
72. **Signer not in message** — Signed payload does not bind signer; replay on another account.
73. **Multiple signers** — Batch allows mixed signers; one entry signed by victim (e.g. phishing) and used in attacker's batch.
74. **Session vs signer** — Web session has user A; API uses signer from key; inconsistency allows A to act as B.
75. **JWT sub vs body** — JWT has sub; body has user_id; server uses body in batch path.
76. **API key scope** — Key has scope "read"; batch write endpoint does not check scope.
77. **No replay protection** — Same signed message accepted twice (different nonce/chain_id).
78. **Cross-account replay** — Message replayed on different account with same structure.

### J. Numeric and bounds

79. **Zero amount** — Transfer 0 or order 0; bypasses some checks.
80. **Negative amount** — Interpreted as large positive (signed/unsigned).
81. **Overflow** — Amount * price overflows; wrong credit.
82. **Precision** — Round down in user's detriment in one path only.
83. **Slippage** — MinOut or maxSlippage in batch not validated per item.
84. **Cap bypass** — Single operation has cap; batch sums above cap without per-batch cap.
85. **Rate limit** — Per-request limit enforced; per-batch not.
86. **Quota** — Daily quota checked for single; not for batch.

### K. Visibility and logging

87. **No audit log** — Batch path does not log who did what; hard to detect abuse.
88. **Log wrong ID** — Log shows subaccount from request, not from signer.
89. **Alert threshold** — Alert on single large transfer; batch of small transfers not alerted.
90. **Metrics** — Dashboards only track single-path volume; batch path invisible.

### L. Configuration and deployment

91. **Feature flag** — New "batch" feature enabled without enabling same validation as single.
92. **Env-specific** — Validation enabled in prod for single path; disabled in staging for batch and same code deployed.
93. **Split backend** — Single path on service A (validates); batch on service B (does not).
94. **Version skew** — Old client sends batch; server expects new validation; old validation used.
95. **Proxy** — Reverse proxy strips or overwrites auth header for batch endpoint.
96. **Cache** — Cached "user owns subaccount" result; ownership changed after cache set.
97. **Database replica lag** — Read from replica for ownership check; write to primary; stale read.
98. **Shard by account** — Batch spans shards; only one shard's check applied.

### M. Chain-specific patterns

99. **Cosmos SDK message** — New message type not given ValidateBasic.
100. **EVM contract** — New function or contract forwards call without checking msg.sender against stored owner.
101. **Solana instruction** — New instruction does not validate account ownership (AccountMeta).
102. **Move resource** — Resource moved or copied without checking signer capability.
103. **UTXO** — Spend path does not verify that inputs belong to signer.
104. **Light client / bridge** — Relay path trusts header without verifying proof for beneficiary.
105. **Multisig** — Batch of actions approved; one action has different "executor" not checked against signers.
106. **Vesting / lock** — Claim or transfer from vesting uses "beneficiary" from event without re-check.
107. **Governance proposal** — Execute proposal with params that specify recipient; executor does not validate recipient.
108. **Permissionless pool** — Create pool permissionless; join/exit path assumes "creator" or "owner" validated elsewhere.
109. **Flash loan** — Flash loan callback performs action; callback does not re-validate initiator ownership of position.
110. **MEV / bundle** — Bundle contains order with victim subaccount; searcher's bundle validation skips ownership.

### N. Documentation and process

111. **Docs say "batch is same as N singles"** — Implementer assumes same checks without verifying.
112. **Single path has comment "must validate owner"** — Batch path has no such comment and no check.
113. **Test only single path** — Integration tests cover single create; batch create untested.
114. **Fuzzer** — Fuzzer generates single messages; not batch messages with mixed account IDs.
115. **Static analysis** — Rule "all paths that use subaccount_id must call CheckValid" not implemented or not run on batch handler.

---

## Using this in Diverg scans

- **High-value targets:** Run main scans (recon, API, auth, payment, workflow, etc.) **and** a batch-validation pass that:
  - Detects batch vs single endpoints and compares validation.
  - Probes for parameter substitution (account_id, subaccount_id, beneficiary) in every sensitive endpoint.
  - Checks for type/variant confusion (market vs limit, spot vs derivative, v1 vs v2).
- **Automation:** Use this list as a **goal checklist** so the engine can prioritize routes that match the site's surface (e.g. if batch API exists, run batch-vs-single checks first).
- **Manual audit:** Treat each numbered item as a question: "Does our batch path skip a check that our single path has?" "Do we trust account_id from the body in any path?"

---

## Summary

Diverg's batch validation methodology: compare validation on the **single-message path** vs the **batch-message path**, identify the **authorization boundary** (e.g. subaccount ownership), and combine gaps with **permissionless primitives** where relevant. The 100+ routes above generalize that approach so the same class of issue can be hunted systematically across APIs and applications.
