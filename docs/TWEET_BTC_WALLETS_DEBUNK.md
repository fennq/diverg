# Tweet — $119M BTC Wallets vs Drift Exploit (Debunk)

---

## Thread (2 tweets)

### Tweet 1

Two new wallets received 1,781 $BTC ($119.36M) from #BitGo. Related to the #Drift exploit?

We traced every tx. No.

The source wallets were funded on March 30 — two days BEFORE the April 1 exploit. You can't launder money from an exploit that hasn't happened yet.

Pre-exploit funding TX: mempool.space/tx/f5adb378ed8847890c1694ed3a25738380205141eb130af91ed92b4a1b321288

### Tweet 2

More proof:

• Source wallets processed 44,750–114,671 BTC across hundreds of txs — exchange/custodial scale, not attacker infra
• The confirmed Drift attacker (0xFcC478) has zero BTC bridge activity — no WBTC, renBTC, or tBTC transfers
• Drift attacker holdings ($100.55M ETH across two wallets) are untouched — nonce 0, zero outbound txs

Wallets: mempool.space/address/bc1qsntkw2akr9qm2sktfng2wf4qhjw6rgwn9ezww72c5c0ms3sux0cq5hpwh5

Not every large movement is an exploit. Verify before you speculate.

@DivergSec

---

## Evidence Summary Table

| # | Claim | Evidence | Link |
|---|---|---|---|
| 1 | Source wallet 1 funded March 30 (pre-exploit) | TX f5adb378... shows 1,562.78 BTC loaded 2 days before April 1 exploit | [mempool.space](https://mempool.space/tx/f5adb378ed8847890c1694ed3a25738380205141eb130af91ed92b4a1b321288) |
| 2 | Source wallet 2 funded March 20 (pre-exploit) | TX 16600fe7... shows first 185 BTC deposit 12 days before exploit | [mempool.space](https://mempool.space/tx/16600fe7a4129005700f9059797940b01cea52a16b3980bfd5b4aad61fca9ec6) |
| 3 | Source is exchange-scale | bc1qle99f93...: 44,750 BTC / 420 txs; bc1qnlg5h3...: 114,671 BTC / 128 txs | [blockchain.info](https://blockchain.info/address/bc1qle99f93vzvr2sn28al7vnwrgews6clw5f2a8zl) |
| 4 | No BTC bridge from attacker | 0xFcC478 has 0 WBTC/renBTC/tBTC transfers | [etherscan](https://etherscan.io/address/0xFcC4780a76318E1B15391F2e784FA53407ceB7A2#tokentxns) |
| 5 | Drift holdings untouched | Both holding wallets: nonce=0, combined 48,811 ETH ($100.55M) | [holding1](https://etherscan.io/address/0xAa843eD65C1f061F111B5289169731351c5e57C1) / [holding2](https://etherscan.io/address/0xbDdAE987FEe930910fCC5aa403D5688fB440561B) |
| 6 | Wallet 1 funded Apr 2 20:13 UTC | TX f47032af... single input from bc1qv5qrthvw... | [mempool.space](https://mempool.space/tx/f47032af413ad386de6e36ad4c30baa6d287f04f585c1e02bd5c63e6b6ff1f43) |
| 7 | Wallet 2 funded Apr 2 20:57 UTC | TX 13c2a1ab... single input from bc1qf24czc... | [mempool.space](https://mempool.space/tx/13c2a1abe23d5cf917e6ce9f300172c40513e73fea92f1c3f2b5c87e045c1e04) |

## Key Transaction Hashes

```
Wallet 1 deposit:     f47032af413ad386de6e36ad4c30baa6d287f04f585c1e02bd5c63e6b6ff1f43
Wallet 2 deposit:     13c2a1abe23d5cf917e6ce9f300172c40513e73fea92f1c3f2b5c87e045c1e04
Source 1 pre-exploit: f5adb378ed8847890c1694ed3a25738380205141eb130af91ed92b4a1b321288
Source 2 pre-exploit: 16600fe7a4129005700f9059797940b01cea52a16b3980bfd5b4aad61fca9ec6
Source 2 Mar 30:      be12512ecf2ade39e6ad992ea3676e96074ae5019840dc9656354cfb8bf4be6e
Source 2 Mar 31 (1):  c1f7a4e4f7e09dbdb1222ba5f8e714d999d29cc8020b76e427c41bda7f6cebec
Source 2 Mar 31 (2):  4c06426ea4c69c3d5ea525c9de2541a0ae651bcfa7618bbd9f0ff57f32c9f250
Source 2 Mar 31 (3):  772460b7f5de60c2314047abb2c515496f50f9d43936752faf5441adea3b9687
```
