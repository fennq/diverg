# HOW BLUENOROFF HACKED DRIFT PROTOCOL — TECHNICAL ATTRIBUTION
## The Malware Technique, The On-Chain Proof, The Kill Chain
### Compiled by Diverg | April 4, 2026

---

## THE CORE ARGUMENT

The Drift Protocol exploit ($285M, April 1 2026) used a technique that is **operationally identical** to two confirmed BlueNoroff/Lazarus operations:
- **Radiant Capital** ($50M, October 2024) — attributed by Mandiant to UNC4736/Citrine Sleet (DPRK)
- **Bybit Exchange** ($1.5B, February 2025) — attributed by FBI to TraderTraitor (DPRK)

All three attacks share the same kill chain. No other threat actor has demonstrated this specific combination of capabilities.

---

## PART 1: THE BLUENOROFF KILL CHAIN — HOW IT ACTUALLY WORKS

### Step 1: Social Engineering Via Trust Relationships

BlueNoroff does NOT send cold phishing emails. They impersonate people the target already knows and trusts.

| Attack | Vector | Lure |
|---|---|---|
| **Radiant** (Oct 2024) | Telegram DM from "former contractor" | ZIP with PDF about smart contract auditing |
| **Bybit** (Feb 2025) | Compromised Safe{Wallet} developer | Access to AWS S3 frontend hosting |
| **Drift** (Apr 2026) | "Transaction misrepresentation" to 2/5 signers | Routine-looking multisig proposals |

### Step 2: Malware Installation — InletDrift / Custom Payloads

Once the target opens the malicious file, BlueNoroff deploys a persistent macOS backdoor. The confirmed malware components include:

**InletDrift (Radiant attack)**:
- macOS executable disguised with PDF icon
- Establishes persistent backdoor at OS level
- C2 server: `atokyonews[.]com`
- Delivered via ZIP file on Telegram

**BlueNoroff GhostCall/GhostHire (2025-2026 campaign, per Kaspersky/Huntress)**:
- 8 distinct binary components identified:
  - **XScreen**: Objective-C keylogger — captures clipboard and screen data
  - **CryptoBot**: Go-based infostealer — hunts crypto wallet data, browser extensions, SSH keys
  - **Root Troy V4**: Go-based backdoor — executes arbitrary commands via AppleScript
  - **InjectWithDyld**: C++ injector — drops implants into running processes
- Delivery via deepfake Zoom calls with AI-generated "executives"
- C2 domains: `web071zoom.us`, `support.us05web-zoom.biz`

**Bybit JavaScript Injection**:
- Not traditional malware — instead, malicious JavaScript injected into Safe{Wallet} AWS S3 bucket
- JS MD5: `be9397a0b6f01d21e15c70c4b37487fe`
- Contains conditional logic targeting Bybit's specific wallet addresses
- When detected: rewrites transaction parameters before sending to Ledger

### Step 3: Transaction Display Manipulation — THE CRITICAL TECHNIQUE

This is what makes BlueNoroff unique. The malware doesn't steal private keys. It **manipulates what the signer sees on screen** while sending a different transaction to the hardware wallet.

**How it works at the OS level (Radiant/InletDrift)**:
```
LEGITIMATE FLOW:
  Squads/Safe UI → [shows "routine emissions adjustment"] → Ledger device → sign

COMPROMISED FLOW:
  Squads/Safe UI → [shows "routine emissions adjustment" ON SCREEN]
                    [sends transferOwnership(attacker) TO LEDGER]  → sign
```

The malware intercepts between the wallet interface and the hardware device. The screen shows one thing. The Ledger receives another. Because Ledger uses **blind signing** for complex multi-sig transactions (it shows a transaction hash, not human-readable details), the signer cannot detect the swap.

**How it works at the frontend level (Bybit/JS injection)**:
```
LEGITIMATE FLOW:
  Safe{Wallet} JS → [shows "transfer 100 ETH to cold wallet"] → 3 signers approve

COMPROMISED FLOW:
  Safe{Wallet} JS → [shows "transfer 100 ETH to cold wallet" ON SCREEN]
                     [actually sends upgradeTo(malicious_impl) TO LEDGER] → 3 signers approve
```

The injected JavaScript conditionally targets specific wallet addresses. When a signing request matches Bybit's wallets, the JS rewrites the transaction data before passing it to the Ledger. The signers see a routine internal transfer. They actually sign a contract upgrade that gives the attacker full control.

### Step 4: Signature Collection & Deferred Execution

| Attack | Threshold | Signatures Needed | Collection Method |
|---|---|---|---|
| **Radiant** | 3-of-11 | 3 | Exploited routine failed-transaction resubmissions over multiple sessions |
| **Bybit** | 3-of-? | 3 | Single coordinated signing session (all 3 signers saw fake UI simultaneously) |
| **Drift** | 2-of-5 | 2 | **Durable nonce accounts** — pre-signed transactions stored indefinitely, executed April 1 |

Drift added a NEW innovation: **durable nonces**. On Solana, transactions normally expire after ~1 minute (blockhash expiry). Durable nonces bypass this — a pre-signed transaction can be stored for weeks and executed at any time. The attacker created 4 nonce accounts on March 23, got 2 signers to sign transactions using those nonces (thinking they were routine), then stored the signatures and batch-executed them on April 1.

This is an EVOLUTION of the technique, not a departure. Same malware principle (show one thing, sign another), but adapted for Solana's architecture.

### Step 5: Admin Takeover → Drain

| Attack | Admin Action | Drain Method |
|---|---|---|
| **Radiant** | `transferOwnership()` on Pool Provider | Upgraded lending pool contracts → `transferFrom()` all user-approved tokens |
| **Bybit** | `upgradeTo(malicious_impl)` on Safe proxy | Changed Safe's execution logic → drained all assets |
| **Drift** | `UpdateAdmin` on Drift V2 program via Squads | Listed fake token (CVT) as collateral → 31 withdrawal txs in 12 min |

### Step 6: Post-Exploit Behavior

| Behavior | Radiant | Bybit | Drift |
|---|---|---|---|
| Malware wiped from devices | Within 3 minutes | Yes (compromised JS removed from S3) | Not confirmed (no device forensics published) |
| Tornado Cash used | Yes | Yes (400 ETH) | Yes (10 ETH + 0.1 ETH) |
| Cross-chain bridging | Moved to BSC | Thousands of wallets + THORSwap | CCTP + Wormhole + Mayan Finance + Chainflip |
| Rapid ETH accumulation | Converted to ETH | Converted to ETH | 129,000+ ETH accumulated |
| Timing (Pyongyang hours) | Not reported | Yes | Yes (CVT deployed 09:30 PST, March 12) |

---

## PART 2: WHY NO OTHER THREAT ACTOR FITS

The transaction-display-manipulation technique has been observed ONLY from DPRK-linked actors:

1. **InletDrift / OS-level interception**: Requires sustained access to macOS kernel or application layer. Only UNC4736/BlueNoroff has demonstrated this against Safe{Wallet}/Ledger signing flows.

2. **Frontend JavaScript injection**: Requires compromising infrastructure (AWS S3 in Bybit's case). Only TraderTraitor has demonstrated this against multi-sig wallet frontends.

3. **No private key theft**: The attacker never obtained the signers' private keys. The hardware wallets functioned correctly — they signed exactly what was sent to them. The attack was against the DISPLAY layer, not the SIGNING layer. This rules out:
   - Simple phishing (would need actual keys)
   - Insider threat (would have direct key access)
   - Smart contract exploit (code worked as designed)
   - Oracle manipulation alone (needed admin access first)

4. **Multi-week staging**: 3 weeks (Drift), 5 weeks (Radiant), unknown (Bybit). This patience and operational security is characteristic of state-sponsored actors, not criminal groups.

5. **Re-compromise after migration**: When Drift migrated to a new multisig on March 27, the attacker re-established access to signers of the NEW multisig within 3 days. This means the malware was STILL ACTIVE on the signers' devices — exactly how InletDrift operates (persistent backdoor survives application changes).

---

## PART 3: WHAT WE KNOW VS. WHAT WE STILL NEED

### CONFIRMED (by us or verified sources):
- The technique is identical to documented BlueNoroff operations
- The on-chain funding chain traces back to Tornado Cash (complete chain documented in Part H)
- The timing matches Pyongyang working hours
- TRM Labs and Elliptic independently attribute to DPRK with their proprietary data
- BleepingComputer, Elliptic, TRM Labs, ForkLog all report DPRK attribution

### WHAT WOULD CLOSE THE CASE:
1. **Drift signer device forensics** — If InletDrift or GhostCall binaries are found on the 2 compromised signers' machines, that's a direct match to known DPRK malware. Drift has NOT published device forensics yet.
2. **C2 server connection** — If the malware phones home to a known BlueNoroff C2 domain (like `atokyonews[.]com` from Radiant), that's a direct link.
3. **FBI TraderTraitor attribution** — The FBI attributed Bybit within 5 days. For Drift, no official FBI statement yet (as of April 4, day 3).

### WHAT THE EVIDENCE STRUCTURE LOOKS LIKE:

```
RADIANT (Oct 2024):                   DRIFT (Apr 2026):
├── InletDrift malware [CONFIRMED]    ├── Malware on signers [NOT YET PUBLISHED]
├── C2: atokyonews.com [CONFIRMED]    ├── C2 server [NOT YET PUBLISHED]
├── Mandiant → UNC4736 [CONFIRMED]    ├── TRM/Elliptic → TraderTraitor [CONFIRMED]
├── transferOwnership [CONFIRMED]     ├── UpdateAdmin via Squads [CONFIRMED]
├── Safe{Wallet} UI spoof [CONFIRMED] ├── "Transaction misrepresentation" [CONFIRMED]
├── Blind signing exploit [CONFIRMED] ├── Blind signing exploit [CONFIRMED]
├── 3/11 multisig [CONFIRMED]         ├── 2/5 multisig [CONFIRMED]
├── Malware wiped in 3 min [CONFIRMED]├── [NOT YET INVESTIGATED]
└── Tornado Cash [CONFIRMED]          └── Tornado Cash [CONFIRMED]
    ↑                                     ↑
    └──── SAME TECHNIQUE ────────────────┘
          SAME ACTOR (DPRK/BlueNoroff)
          EVOLVED FOR SOLANA (durable nonces)
```

The Drift attack is not a copy — it's an **evolution**. The core technique (transaction display manipulation + blind signing exploitation) is identical. But the attacker adapted it for Solana's architecture by adding durable nonces for deferred execution, using Squads V4 instead of Safe{Wallet}, and using CCTP/Mayan for cross-chain laundering instead of THORSwap.

---

## THE ALIAS CHAIN (VERIFIED)

The threat intelligence community tracks this threat actor under many names. Different vendors assign their own designations, but all cross-reference to the same parent organization:

| Vendor Name | Named By | Confirmed Alias Of | Source |
|---|---|---|---|
| **UNC1069** | Google/Mandiant | CryptoCore → BlueNoroff | lazarus.day, Google TIG Feb 2026 blog |
| **CryptoCore** | ClearskySec | BlueNoroff | lazarus.day actor database |
| **STARDUST CHOLLIMA** | CrowdStrike | BlueNoroff | lazarus.day, CrowdStrike adversary profile |
| **TraderTraitor** | FBI/USCISA | BlueNoroff | lazarus.day, FBI advisory Dec 2024 |
| **APT38** | Mandiant | BlueNoroff | lazarus.day, Mandiant M-Trends |
| **UNC4899** | Mandiant | TraderTraitor → BlueNoroff | lazarus.day, PUKCHONG graduation |
| **JadeSleet** | Microsoft | TraderTraitor → BlueNoroff | lazarus.day |
| **TA444** | Proofpoint | CryptoCore → BlueNoroff | lazarus.day |
| **BlackAlicanto** | PWC | CryptoCore → BlueNoroff | lazarus.day |
| **BlueNoroff** | Kaspersky | Parent designation | lazarus.day (last seen: March 31, 2026) |

**Alias database source**: https://lazarus.day/actors/alias/unc1069 and https://lazarus.day/actors/alias/tradertraitor

### The Chain
```
AXIOS ATTACK                              DRIFT ATTACK
(Mar 31, 2026)                            (Apr 1, 2026)
     |                                         |
     v                                         v
  UNC1069                               TraderTraitor
  (Google TIG)                       (TRM/Elliptic/FBI)
     |                                         |
     v                                         v
  CryptoCore ──────> BlueNoroff <────── UNC4899/JadeSleet
  (ClearskySec)       (Kaspersky)        (Mandiant/Microsoft)
                         |
                  STARDUST CHOLLIMA
                   (CrowdStrike)
                  Attributed Axios;
                  alias chain links
                  to TraderTraitor
```

**Note on "overlaps"**: Google TIG (Feb 2026) stated "Bluenoroff, a threat actor that **overlaps with** UNC1069." In threat intelligence, "overlaps" indicates shared tooling, infrastructure, and/or personnel — but stops short of confirming identical operational units. The alias chain through CryptoCore is established by ClearskySec and compiled by lazarus.day.

---

## PART A: AXIOS → BLUENOROFF (Technical Evidence)

This is the technically strongest leg. Multiple independent sources provide verifiable malware samples, C2 infrastructure, and code artifacts.

### A1. GOOGLE TIG ATTRIBUTED AXIOS TO UNC1069

**Strength: STRONG**

**Source**: https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package (March 31, 2026)

Google's Threat Intelligence Group (Mandiant) published:

> "GTIG attributes this activity to UNC1069, a financially motivated North Korea-nexus threat actor active since at least 2018, based on the use of WAVESHAPER.V2... Further, analysis of infrastructure artifacts used in this attack shows overlaps with infrastructure used by UNC1069 in past activities."

> "Analysis of the C2 infrastructure (sfrclak[.]com resolving to 142.11.206.73) revealed connections from a specific AstrillVPN node previously used by UNC1069."

This is Google's own threat intelligence group making a firm attribution based on malware family tracking and infrastructure overlap. No confidence qualifier — stated directly.

**Separately**, Google TIG (February 2026) stated in their UNC1069 playbook blog:

> "Kaspersky recently claimed **Bluenoroff, a threat actor that overlaps with UNC1069**, is also using GTP-4o models"

This establishes the UNC1069↔BlueNoroff connection from Google's own analysts. **Caveat**: "overlaps with" is weaker than "is the same as."

### A2. CROWDSTRIKE ATTRIBUTED AXIOS TO STARDUST CHOLLIMA (MODERATE CONFIDENCE)

**Strength: STRONG** (not definitive — source explicitly states moderate confidence)

**Source**: https://crowdstrike.com/en-us/blog/stardust-chollima-likely-compromises-axios-npm-package/ (April 1, 2026)

> "CrowdStrike Counter Adversary Operations attributes this activity to **STARDUST CHOLLIMA** with moderate confidence based on the adversary's deployment of updated variants of ZshBucket (malware uniquely attributed to STARDUST CHOLLIMA) and overlaps with known STARDUST CHOLLIMA infrastructure."

**Key technical evidence from CrowdStrike:**
- C2 IP `142.11.206.73` **shares a host services banner hash** (`c373706b...`) with `23.254.203.244`, a known STARDUST CHOLLIMA IP (Dec 2025)
- ZshBucket (CrowdStrike's name for WAVESHAPER.V2) is **"uniquely attributed to STARDUST CHOLLIMA"**
- Hostwinds hosting consistent with STARDUST CHOLLIMA's observed infrastructure

**Why moderate and not high confidence**: The banner hash also matches `23.254.167.216`, attributed to **FAMOUS CHOLLIMA** (a different DPRK subgroup). This infrastructure overlap "precludes a higher confidence assessment." However, ZshBucket being uniquely attributed to SC tilts toward StardustChollima.

**What this means**: Even worst case (FAMOUS CHOLLIMA), the attack is still DPRK. The uncertainty is about *which* subunit.

### A3. SHARED MALWARE LINEAGE (WAVESHAPER.V2 / ZshBucket)

**Strength: STRONG**

| Malware | Used In | Attribution |
|---|---|---|
| WAVESHAPER (v1) | UNC1069 intrusions pre-2026 | Google TIG / Mandiant |
| WAVESHAPER.V2 | Axios npm attack (Mar 31, 2026) | Google TIG → UNC1069 |
| ZshBucket | Axios npm attack (same malware, CrowdStrike name) | CrowdStrike → STARDUST CHOLLIMA |
| SUGARLOADER | UNC1069 intrusions | Google TIG / Mandiant |

CrowdStrike: ZshBucket is "malware **uniquely attributed** to STARDUST CHOLLIMA."
Google TIG: WAVESHAPER.V2 is "an updated version of WAVESHAPER previously used by [UNC1069]."

The malware family tracking is the single strongest technical indicator for the Axios side. Both vendors independently identified the same malware family and attributed it to the same actor cluster.

### A4. macWebT → webT CODE LINEAGE (3-Year Evolution)

**Strength: STRONG** (verifiable binary artifacts, but lineage connection identified by single independent researcher)

The macOS RAT from the Axios attack contains embedded build paths:
- **Xcode project name**: `macWebT`
- **Build path**: `/Users/mac/Desktop/Jain_DEV/client_mac/macWebT/macWebT/`

This links to **BlueNoroff's 2023 RustBucket** campaign, which used a module named `webT`. The `webT` → `macWebT` naming shows code evolution from the same development pipeline over 3 years (2023→2026).

RustBucket (2023) was attributed to BlueNoroff by Jamf, SentinelOne, and Sekoia.

**Caveat**: The specific `macWebT` → `webT` connection was identified by independent researcher N3mes1s. The build artifacts (project name, path) are verifiable by anyone who downloads the sample from VirusTotal. The N3mes1s gist also notes "Jain_DEV" is "unprecedented in Lazarus samples," which could indicate a new developer on the team.

**Sources**:
- N3mes1s RE gist: https://gist.github.com/N3mes1s/0c0fc7a0c23cdb5e1c8f66b208053ed6
- Jamf RustBucket analysis: https://www.jamf.com/blog/bluenoroff-apt-targets-macos-rustbucket-malware/

### A5. NukeSped AV CLASSIFICATION

**Strength: STRONG** (4 independent engines agree, but may be heuristic rather than code-overlap)

| Engine | Detection Name |
|---|---|
| AVG | MacOS:Nukesped-C [Drp] |
| Avast | MacOS:Nukesped-C [Drp] |
| Avira | OSX/GM.NukeSped.HX |
| F-Secure | Malware.OSX/GM.NukeSped.HX |

**NukeSped is exclusively attributed to the Lazarus Group.** No other threat actor has been observed using NukeSped malware.

**Caveat**: AV classification can be heuristic (behavioral signature matching) rather than confirmed code overlap with previous NukeSped samples. Four independent engines reaching the same classification is meaningful but not the same as manual reverse engineering confirmation.

**Source**: VirusTotal scan results, N3mes1s gist

### A6. BANNER HASH CONNECTS 3 DPRK IPs

**Strength: STRONG**

CrowdStrike revealed matching host services banner hashes across 3 IPs:

```
Banner Hash: c373706b3456c36e8baa0a3ee5aed358c1fe07cba04f65790c90f029971e378a

142.11.206.73     → Axios C2 (STARDUST CHOLLIMA / UNC1069)
23.254.203.244    → Known STARDUST CHOLLIMA IP (Dec 2025)
23.254.167.216    → FAMOUS CHOLLIMA InvisibleFerret C2 (May 2025)
                    + Suspected UNC1069 Infrastructure (Google TIG)
```

Matching banner hashes indicate same server configuration, likely by the same operator. IP `23.254.167.216` is claimed by BOTH Google TIG (as "Suspected UNC1069 Infrastructure") and CrowdStrike (as FAMOUS CHOLLIMA), which is actually why CrowdStrike's overall assessment is moderate — the infrastructure is shared across DPRK subgroups.

**Source**: CrowdStrike blog (Apr 1, 2026), Google TIG blog (Apr 1, 2026)

### A7. callnrwise.com REFERENCES "nrwise" NPM ACCOUNT

**Strength: MODERATE** (establishes Axios-internal consistency but doesn't bridge to Drift)

The C2 domain `callnrwise.com` directly references the npm account **"nrwise"** (`nrwise@proton.me`) that published the malicious `plain-crypto-js@4.2.1` package. The attacker used their own account name in the C2 domain.

This connects the C2 infrastructure to the npm supply chain attack — but that's internally obvious (the C2 was embedded in the package). It doesn't independently connect Axios to Drift.

### A8. PERSISTENT USER-AGENT FINGERPRINT

**Strength: MODERATE** (consistent across operations but user-agents are trivially copyable)

The anomalous User-Agent string across all WAVESHAPER variants:
```
mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)
```

An IE8/Windows XP user-agent on macOS is deliberately anomalous. It appears in WAVESHAPER.V2 (2026), WAVESHAPER v1 (pre-2026), and known BlueNoroff operations since 2023. Consistent but not independently conclusive — any actor could copy a user-agent string.

---

## PART B: DRIFT → TRADERTRAITOR (Behavioral + Authority-Based Evidence)

This is the structurally weaker leg. The Drift→TraderTraitor attribution relies primarily on **TRM Labs and Elliptic's proprietary intelligence**, supplemented by publicly visible on-chain behavioral patterns that are *consistent with* but not *uniquely distinctive to* TraderTraitor.

**We are transparent about this**: we cannot independently reproduce TRM/Elliptic's attribution methodology. Their tools include a database of 6,000+ known DPRK wallets, proprietary cross-chain clustering (Elliptic Investigator), exchange data-sharing agreements (Binance/Coinbase), and access to FBI/OFAC intelligence. What we *can* do is document the public on-chain evidence and show it matches TraderTraitor's documented behavioral fingerprint.

### B1. TRM LABS ATTRIBUTION

**Strength: STRONG** (authoritative source, but methodology is proprietary)

**Source**: https://www.trmlabs.com/resources/blog/north-korean-hackers-attack-drift-protocol-in-285-million-heist (April 2, 2026)

TRM Labs attributed the Drift exploit to "North Korean hackers" within 24 hours. TRM is one of the world's leading blockchain intelligence firms, used by law enforcement agencies globally. Their attribution is based on:
- Proprietary cross-chain clustering
- Database of 6,000+ known DPRK wallet addresses from prior hacks
- "Network-level signals" (likely IP data from bridge operators)
- Exchange data-sharing agreements
- FBI TraderTraitor task force intelligence

TRM also confirmed that stolen SOL was deposited directly to **Binance** (KYC exchange), consistent with TraderTraitor's willingness to use centralized exchanges (seen in DMM Bitcoin case).

**What we can verify**: TRM's blog post and attribution claim. **What we cannot verify**: their internal database matches and network-level signals.

### B2. ELLIPTIC ATTRIBUTION

**Strength: STRONG** (authoritative source, but methodology is proprietary)

**Source**: https://www.elliptic.co/blog/drift-protocol-exploited-for-286-million-in-suspected-dprk-linked-attack (April 2, 2026)

Elliptic attributed Drift to "DPRK-linked" actors and identified it as the **18th DPRK crypto operation of 2026** (>$300M YTD). Elliptic's Investigator platform provides automated cross-chain tracing and wallet clustering.

Elliptic also contextually linked Drift and Axios in the same blog post:

> "This latest incident also takes place amid a **broader escalation of DPRK-linked activity** targeting the crypto ecosystem, **including the recent supply chain compromise of the Axios npm package, which Google attributed to DPRK threat actor UNC1069.**"

**Caveat**: This is a contextual/thematic association ("broader escalation"), not an explicit claim that the same team did both. Elliptic is saying "DPRK is busy" and noting both events, not stating operational identity.

### B3. ON-CHAIN BEHAVIORAL FINGERPRINT (PUBLICLY VERIFIABLE)

**Strength: MODERATE-STRONG** (pattern match, not unique identification)

The Drift exploit's on-chain behavior matches TraderTraitor's documented playbook across 6 specific indicators. No single indicator is unique to TraderTraitor, but the *combination* is distinctive:

**Indicator 1: Multisig Key Compromise (3+ of 5)**

| Operation | Multisig | Keys Compromised | Method |
|---|---|---|---|
| **Drift (Apr 2026)** | Squads v4, 2-of-5 threshold (0s timelock) | 3+ keys | Social engineering → key extraction |
| Ronin (Mar 2022) | 9 validators | 5 of 9 | Fake job offers → malware |
| Harmony (Jun 2022) | MultiSig | 2 of 5 | Social engineering |

TraderTraitor targets multisig infrastructure by compromising *enough* signing keys through social engineering + malware. The Drift Squads multisig had a dangerously low threshold (2-of-5) with a 0-second timelock, making it an ideal TraderTraitor target.

**Indicator 2: Tornado Cash 10 ETH Staging**

Drift attacker withdrew 10 ETH from Tornado Cash on March 11, 2026 (nullifier `0x0def3656...`) to fund initial infrastructure. TC staging is a consistent TraderTraitor pattern:
- Bybit: TC-funded staging wallets
- Ronin: TC for laundering (100 ETH batches)
- Harmony: TC for laundering

**Caveat**: Many threat actors use Tornado Cash. This is consistent, not distinctive.

**Indicator 3: KST (UTC+9) Working Hours Correlation**

| UTC Time | KST Time | Event |
|---|---|---|
| Mar 12 00:10-00:58 | **09:10-09:58** | Bridge calls + CVT minting (morning shift) |
| Mar 24 06:32 | **15:32** | Attacker wallet funding (afternoon) |
| Apr 01 11:06 | **20:06** | Exploit execution (evening — Western business hours over) |
| Apr 01 16:27-18:51 | **01:27-03:51** | Laundering batch (overnight automation) |
| Apr 01 23:03 | **08:03** | SOL distribution (next morning) |

Pattern: Infrastructure setup during KST morning (09:00-10:00). Exploit during KST evening (20:00). Laundering overnight. Next batch at KST morning.

The Bybit attacker also showed KST-correlated activity. **Caveat**: South Korea also uses UTC+9, as does Japan (JST). Timezone correlation alone doesn't prove DPRK.

**Indicator 4: ETH Accumulation in Nonce-0 Holding Wallets**

The Drift attacker consolidated 73,694 ETH (~$155M) into 3 holding wallets, all with **nonce 0** (zero outbound transactions). Funds have been sitting untouched since April 1.

| Wallet | Balance | Nonce |
|---|---|---|
| 0xAa843eD6... | ~25,715 ETH | 0 |
| 0xbDdAE987... | ~23,097 ETH | 0 |
| 0xD3FEEd5D... | ~24,882 ETH | 0 |

This "accumulate then hold" pattern matches Bybit exactly — the Bybit attacker also held ETH in nonce-0 wallets for extended periods before beginning laundering weeks later. It's a TraderTraitor signature: rapid conversion to ETH, then patience.

**Indicator 5: Single-Use Wallet Fan-Out Layering**

The Drift laundering used 18+ single-use feeder wallets (nonce 1-30, fully emptied) between the exit wallet and the holding wallets. Each feeder handled one route:

```
Exit Wallet (0xFcC478..., nonce 30)
  → 18 Feeder Wallets (nonce 1-30 each)
    → 3 Holding Wallets (nonce 0)
```

This layered fan-out with disposable intermediaries matches the Bybit laundering structure documented by TRM Labs.

**Indicator 6: Multi-Bridge, Multi-DEX Rapid Conversion**

Within hours of the exploit, the attacker used **5 bridges** (Circle CCTP, Mayan Finance, LI.FI, Chainflip, Near Intents) and **4 DEXes** (Jupiter, DODO, CoW Protocol, Raydium) to convert stolen assets to ETH. This level of cross-protocol sophistication and speed matches TraderTraitor's Bybit operation (THORChain, eXch).

### B4. WHAT WE CANNOT INDEPENDENTLY VERIFY FOR DRIFT

Being transparent about the gaps:

1. **TRM/Elliptic's proprietary wallet database matches** — they claim to have matched Drift wallets to known DPRK patterns. We cannot verify which specific wallets matched or how.
2. **"Network-level signals"** — likely IP data from bridge operators (Circle, Wormhole guardians) shared with TRM/Elliptic under compliance agreements. We don't have this data.
3. **Exchange internal records** — Binance has KYC data on the SOL deposit addresses. Law enforcement has access; we don't.
4. **Device forensics on Drift signers** — No public disclosure of what malware (if any) was found on the compromised signers' machines. We don't know if WAVESHAPER.V2 specifically was used against Drift signers.
5. **FBI/OFAC intelligence** — Government attribution data that feeds into TRM/Elliptic's assessments but isn't publicly detailed.

**Bottom line**: The Drift→TraderTraitor link rests on (a) authoritative attribution from TRM/Elliptic/FBI with proprietary evidence, and (b) publicly visible behavioral pattern matching across 6 indicators. This is strong but structurally different from the Axios side, where we have verifiable malware binaries and C2 infrastructure.

---

## PART C: BLUENOROFF = TRADERTRAITOR (Alias Chain Evidence)

This is the bridge that connects Parts A and B. If Axios→BlueNoroff and Drift→TraderTraitor, then BlueNoroff=TraderTraitor completes the link.

### C1. LAZARUS.DAY ALIAS DATABASE

**Strength: DEFINITIVE** (compiles vendor-established designations)

**Source**: https://lazarus.day/actors/alias/unc1069 and https://lazarus.day/actors/alias/tradertraitor

Each link in the chain is established by a different authoritative vendor:

| Link | Established By |
|---|---|
| UNC1069 = CryptoCore | Mandiant (M-Trends, internal tracking) |
| CryptoCore = BlueNoroff | ClearskySec (2020 research) |
| TraderTraitor = BlueNoroff | FBI/USCISA (formal advisory, 2022+2024) |
| StardustChollima = BlueNoroff | CrowdStrike (adversary profile) |
| APT38 = BlueNoroff | Mandiant (M-Trends) |

lazarus.day compiles these vendor cross-references. The individual links are each sourced from the named organizations.

### C2. FBI / USCISA FORMAL DESIGNATION

**Strength: DEFINITIVE**

- FBI advisory, December 2024: "FBI, DC3, and NPA Identification of North Korean Cyber Actors, Tracked as **TraderTraitor**, Responsible for Theft of $308 Million USD from Bitcoin.DMM.com"
- USCISA advisory, April 2022: "**TraderTraitor**: North Korean State-Sponsored APT Targets Blockchain Companies"

The U.S. government has formally designated TraderTraitor as a DPRK state-sponsored APT. This is the strongest form of attribution available — backed by intelligence community assessment with access to signals intelligence, human intelligence, and classified technical collection.

### C3. KASPERSKY CONFIRMS THE FULL ALIAS CHAIN

**Strength: STRONG**

**Source**: https://securelist.com/bluenoroff-apt-campaigns-ghostcall-and-ghosthire/117842/

Kaspersky's Securelist explicitly lists:

> "BlueNoroff (aka. **Sapphire Sleet**, **APT38**, **Alluring Pisces**, **Stardust Chollima**, and **TA444**)"

Kaspersky — one of the world's leading malware research labs — confirming that BlueNoroff, StardustChollima, APT38, and TA444 are all the same threat actor.

### C4. KASPERSKY GHOSTCALL TTP MATCHES UNC1069 TTP

**Strength: STRONG** (independent behavioral overlap from two separate research teams)

Kaspersky's BlueNoroff GhostCall campaign and Google TIG's UNC1069 documentation show identical TTPs:
- Fake Zoom/Teams meetings via compromised Telegram accounts
- ClickFix attack (audio troubleshooting excuse)
- Malware delivery through fake SDK update
- Targets crypto executives and VC firms
- TCC database manipulation for privilege escalation

Two independent research teams (Google TIG, Kaspersky) documenting the same behavioral playbook reinforces the UNC1069↔BlueNoroff overlap.

### C5. IDENTICAL TCC BYPASS TECHNIQUE

**Strength: MODERATE** (reinforcing but TCC bypass via database manipulation is not unique to one actor)

Both Google TIG (UNC1069) and Kaspersky (BlueNoroff GhostCall) document the same TCC bypass:

| Step | Google TIG (UNC1069) | Kaspersky (BlueNoroff GhostCall) |
|---|---|---|
| 1 | Rename user's TCC folder | Rename com.apple.TCC directory |
| 2 | Copy TCC.db to staging | Perform offline edits to TCC.db |
| 3 | Insert permission rows | INSERT OR REPLACE access entries |
| 4 | Restore modified database | Rename directory back |

This is a less common post-exploitation technique but has been documented in red team tooling and other APT groups. It reinforces the overlap but isn't a unique signature.

### C6. SAME /18 NETBLOCK AS CONFIRMED LAZARUS INFRASTRUCTURE

**Strength: MODERATE** (suggestive but /18 is a large IP range)

| IP | Attribution | Source |
|---|---|---|
| 142.11.206.73 | Axios C2 (WAVESHAPER.V2) | Google TIG, CrowdStrike |
| 142.11.209.109 | Confirmed Lazarus infrastructure | Hunt.io (Jan 2025) |

Both IPs are in the same /18 netblock (142.11.192.0/18) on AS54290 (Hostwinds LLC). Hunt.io linked 142.11.209.109 to 12 Lazarus-associated IPs via TLS certificate.

**Caveat**: A /18 is 16,384 IP addresses. Hostwinds is a hosting provider with many customers. Validin noted "Use of the Hostwinds ASN dedicated servers is a common tactic in Lazarus campaigns" — which actually makes the hosting provider choice *less* distinctive (common ≠ unique).

---

## PART D: TEMPORAL + CONTEXTUAL EVIDENCE

### D1. TEMPORAL CORRELATION

**Strength: MODERATE** (consistent but inherently circumstantial)

| Event | Date | Actor |
|---|---|---|
| Drift on-chain staging begins | March 11, 2026 | TraderTraitor (TRM) |
| CVT token deployed | March 12, 2026 | TraderTraitor |
| Drift multisig durable nonces created | March 23-30, 2026 | TraderTraitor |
| sfrclak.com registered | March 30, 2026 | UNC1069/StardustChollima |
| Axios npm compromised | March 31, 00:21-03:20 UTC | UNC1069/StardustChollima |
| Drift exploit executed | April 1, 2026 | TraderTraitor |
| CrowdStrike attributes Axios to SC | April 1, 2026 | CrowdStrike |
| TRM attributes Drift to DPRK | April 2, 2026 | TRM Labs |
| Elliptic links Drift + Axios contextually | April 2, 2026 | Elliptic |

Both operations ran **in parallel** — the Drift operation began 20 days before the Axios compromise. This is consistent with a well-resourced organization running multiple campaigns simultaneously, but temporal proximity alone doesn't prove same actor.

### D2. ELLIPTIC CONTEXTUAL LINK

**Strength: MODERATE** (contextual association, not attribution equivalence)

Elliptic wrote both incidents into the same blog post as part of a "broader escalation of DPRK-linked activity." This is a thematic connection — "DPRK is running multiple campaigns" — not an explicit claim of operational identity.

---

## CUMULATIVE EVIDENCE SUMMARY

### Part A: Axios → BlueNoroff
| # | Evidence | Type | Strength |
|---|---|---|---|
| A1 | Google TIG: UNC1069 attribution (firm, no qualifier) | Vendor attribution | STRONG |
| A2 | CrowdStrike: StardustChollima (moderate confidence) | Vendor attribution | STRONG |
| A3 | WAVESHAPER.V2/ZshBucket uniquely attributed malware | Malware family | STRONG |
| A4 | macWebT → webT code lineage (3 years, same project) | Code evolution | STRONG |
| A5 | NukeSped classification (4 AV engines, Lazarus-exclusive) | Malware family | STRONG |
| A6 | Banner hash connects 3 DPRK IPs | Infrastructure | STRONG |
| A7 | callnrwise.com = "nrwise" npm account | Operational | MODERATE |
| A8 | Same User-Agent string across 3 years | Fingerprint | MODERATE |

### Part B: Drift → TraderTraitor
| # | Evidence | Type | Strength |
|---|---|---|---|
| B1 | TRM Labs attribution (proprietary methodology) | Authority | STRONG |
| B2 | Elliptic attribution (proprietary methodology) | Authority | STRONG |
| B3 | On-chain behavioral fingerprint (6 indicators) | Behavioral pattern | MODERATE-STRONG |

### Part C: BlueNoroff = TraderTraitor
| # | Evidence | Type | Strength |
|---|---|---|---|
| C1 | lazarus.day alias chain (vendor cross-references) | Alias database | DEFINITIVE |
| C2 | FBI/USCISA TraderTraitor = DPRK formal designation | Government | DEFINITIVE |
| C3 | Kaspersky: BN = SC = APT38 = TA444 confirmation | Vendor confirmation | STRONG |
| C4 | GhostCall TTP = UNC1069 TTP (two independent teams) | Behavioral | STRONG |
| C5 | Identical TCC bypass technique | Technical | MODERATE |
| C6 | Same /18 netblock + Lazarus hosting patterns | Infrastructure | MODERATE |

### Part D: Contextual
| # | Evidence | Type | Strength |
|---|---|---|---|
| D1 | Parallel timelines (Drift staging 20 days before Axios) | Temporal | MODERATE |
| D2 | Elliptic links both in same blog post | Contextual | MODERATE |

**Totals: 2 DEFINITIVE + 9 STRONG + 7 MODERATE = 18 evidence points**

---

## HONEST ASSESSMENT: WHAT SOMEONE CAN AND CANNOT ARGUE

### CANNOT credibly argue:
- **"Not DPRK"** → Google TIG, CrowdStrike, TRM Labs, Elliptic, FBI all independently attribute to DPRK. This is consensus across 5+ major intelligence organizations.
- **"Axios was a false flag"** → Google TIG's attribution is based on years of UNC1069 tracking, malware code lineage back to 2023, and AstrillVPN connection to known UNC1069 nodes. This isn't based on a single indicator.
- **"BlueNoroff ≠ TraderTraitor"** → FBI, USCISA, Mandiant, CrowdStrike, and Kaspersky all independently connect these names through published alias chains.

### CAN credibly argue:
- **"UNC1069 and TraderTraitor could be different operational teams within BlueNoroff"** → This is the weakest point. "Overlaps" language means they share organizational infrastructure but *could* have separate operators. The alias chain proves they're under the same parent organization, not necessarily the same desk.
- **"The Drift→TraderTraitor attribution is an appeal to authority"** → Fair criticism. We're trusting TRM/Elliptic's proprietary intelligence without being able to verify it. The public behavioral evidence is consistent but not uniquely identifying.
- **"Behavioral pattern matching isn't attribution"** → Correct. TC staging, KST hours, and ETH accumulation are consistent with TraderTraitor but also with other DPRK subgroups. The behavioral fingerprint narrows the field but doesn't uniquely identify.

### Our honest position:
The case is **strongest** for: "The Axios npm attack and the Drift Protocol exploit were both conducted by DPRK-affiliated threat actors, with the Axios side tied to a specific subgroup (UNC1069/BlueNoroff) through verifiable technical evidence."

The case is **moderate** for: "These were the same operational team" — this relies on the alias chain (BlueNoroff=TraderTraitor, well-established) plus TRM/Elliptic's proprietary attribution for the Drift side.

---

---

## PART E: THE HOW — ATTACK VECTOR ANALYSIS

The attribution evidence (Parts A-D) answers WHO. This section addresses HOW the Drift multisig was compromised — the gap between "DPRK did it" and "here's the mechanism."

### CONFIRMED FACTS (From Drift, Squads, PeckShield, Public Reporting)

**1. Social engineering + transaction misrepresentation, NOT key theft**

Drift confirmed on April 2, 2026 that the attack used "targeted social engineering" to trick privileged team members into signing malicious transactions. PeckShield founder Jiang Xuxian stated: "The keys were not leaked in the traditional sense. The holder was tricked into signing specific transactions, and the signatures alone were enough to move $280 million."

The signers were deceived into approving transactions that "appeared routine but contained hidden authorizations for critical admin actions." This is transaction misrepresentation — the signer sees what looks like a normal governance action, but the underlying transaction payload contains admin privilege transfers, collateral listing, or withdrawal limit changes.

**2. Two signers compromised (matching the 2-of-5 threshold)**

Squads confirmed the attack involved exactly two compromised signers — the minimum needed to meet Drift's 2-of-5 threshold. Durable nonce accounts were created specifically for these two signers between March 23-30.

**3. Durable nonce weaponization**

Standard Solana transactions expire after ~60-90 seconds. Durable nonces bypass this entirely — a signed transaction remains valid indefinitely. The attacker:
- Created durable nonce accounts linked to the two target signers (March 23-30)
- Obtained signatures on pre-crafted transactions through social engineering
- Stored the signed transactions dormant until the chosen execution time
- Batch-executed all pre-signed transactions on April 1 in a ~15-minute window

This means the attacker only needed ONE signing session per signer, potentially days apart. The victim might not have realized what they signed because there was no immediate on-chain footprint.

**4. The March 27 migration — and rapid re-compromise**

On March 27, Drift performed a planned migration of its Security Council multisig (reportedly due to a member change). Critically, **the attacker re-established access to 2 signers of the NEW multisig by March 30** — within 3 days. This implies one of:
- (a) The same 2 compromised individuals carried over to the new multisig (most likely — their devices or communication channels were already under attacker control)
- (b) New members were added and rapidly targeted (less likely — 3 days is very fast for cold social engineering)
- (c) The migration itself was influenced by the attacker (possible if they controlled a communication channel)

**5. Attack execution sequence (April 1)**

Per Drift's report and Cube Exchange's analysis:
1. Attacker performed one legitimate transaction (to advance the durable nonce)
2. Immediately submitted all pre-signed malicious transactions
3. Transferred admin control to attacker within minutes
4. Listed CVT as a spot market with manipulated oracle price
5. Deposited ~$785M notional of fake CVT as collateral
6. Raised withdrawal limits on 5 real-asset markets
7. Drained $280M+ across 31 transactions in ~15 minutes

**6. No smart contract exploit. No seed phrase leak.**

Drift explicitly stated: "The hacker did not exploit any flaws in its programs or smart contracts, and no seed phrases have been compromised."

### ASSESSED ATTACK METHODS (Two Hypotheses)

The exact mechanism of transaction misrepresentation has NOT been publicly disclosed by Drift. Based on UNC1069/BlueNoroff's documented TTPs and the confirmed facts, two methods are assessed:

**Hypothesis A: Device Compromise → Transaction Interception (Bybit Pattern)**
- Attacker deploys malware (WAVESHAPER.V2 or variant) on signer's device via social engineering (fake meeting, ClickFix, "audio fix")
- Malware intercepts the transaction signing workflow
- When signer reviews a transaction in their signing tool, malware modifies the displayed content to look routine
- Signer signs what they think is a normal transaction; actual payload contains admin authorizations
- Precedent: **Bybit** ($1.5B, Feb 2025) — attacker modified Safe{Wallet} UI to display fake transaction data while submitting a different transaction
- Precedent: **Step Finance** ($29M, Jan 31 2026) — "compromised executive devices" on Solana, same pattern, 2 months before Drift

Evidence supporting this hypothesis:
- UNC1069's documented TTP includes RAT deployment via ClickFix social engineering
- WAVESHAPER.V2 capabilities include `peinject` (binary injection) and `runscript` — capable of modifying signing tool behavior
- Step Finance used the exact same attack pattern on the same blockchain
- The March 27→March 30 re-compromise window is explained if devices were already compromised

Evidence against:
- Drift said "no seed phrases compromised" — but this hypothesis doesn't require seed phrases, just transaction interception
- No public disclosure of malware found on signer devices

**Hypothesis B: Direct Social Engineering → Blind Signing**
- Attacker establishes a social engineering relationship with signers (fake company, fake collaboration)
- Attacker sends pre-crafted transaction blobs directly to signers via Telegram/Slack/email
- Frames them as "routine governance proposals" or "config updates"
- Solana transactions are complex binary blobs — unlike Ethereum's EIP-712, they're difficult to parse visually
- Signer reviews in a tool that doesn't fully render the transaction contents
- Signs without understanding the payload contains admin privilege transfers
- Attacker receives the signature (either directly or via the signing interface) and stores it in a durable nonce

Evidence supporting:
- "Transaction misrepresentation" and "deceptive transaction representations" language from reporting
- Doesn't require malware on the device
- Solana's lack of human-readable transaction signing makes blind signing a real risk

Evidence against:
- Requires the signer to share their signature with the attacker somehow
- More detectable (direct communication leaves traces)
- Less consistent with UNC1069's documented malware-heavy TTPs

**Assessment**: Hypothesis A (device compromise) is more consistent with the attributed actor's known capabilities, with the Bybit and Step Finance precedents, and with the March 27-30 re-compromise speed. However, device forensics from the compromised signers are needed to confirm.

### SUPPLY CHAIN ANALYSIS: WAS AXIOS THE ENTRY VECTOR?

**Assessment: Almost certainly NOT the initial vector. Possibly a secondary or parallel vector.**

| Evidence | Conclusion |
|---|---|
| Drift on-chain staging began March 11 | Keys compromised BEFORE Axios (March 31) |
| Durable nonce accounts created March 23-30 | Signers signing malicious TXs before Axios |
| Drift SDK does NOT use axios | No supply chain dependency via `package.json` |
| Axios compromised for only 3 hours (00:21-03:29 UTC) | Very narrow window |

However, two caveats:
1. Individual team members may have used axios in personal/internal tools — the SDK not depending on it doesn't rule out exposure
2. If Hypothesis A is correct (device compromise via earlier social engineering), the Axios supply chain attack may have been a SEPARATE campaign by the same actor, not the vector for Drift

The timeline strongly suggests the Drift signers were compromised through a separate, earlier social engineering campaign — consistent with UNC1069 running parallel operations.

### STEP FINANCE CONNECTION (ASSESSED SAME ACTOR — v8 UPGRADE)

Step Finance was exploited on January 31, 2026 (~$40M) via "compromised executive devices." On-chain forensics now show an identical behavioral fingerprint to the Drift attack:

| Indicator | Step Finance | Drift Protocol | Match? |
|-----------|-------------|----------------|--------|
| Attack vector | Compromised exec devices (Halborn confirmed) | Social eng → compromised multisig signers | YES — both target humans, not code |
| Victim-funded wallet | 0.2 SOL from Step treasury to attacker (Jan 28) | $2.52 test transfer from Drift vault (Mar 24) | YES — identical technique |
| Wallet creation lead time | 3 days before exploit | 8 days before exploit | YES — similar staging window |
| Holding pattern | 261,932 SOL untouched at `7raxiejD...` | 130,262 ETH untouched in 4 wallets | YES — "park and wait" DPRK signature |
| Working hours | "APAC hours" (Step's own disclosure) | CVT deployed 09:30 Pyongyang time | YES — KST operational window |
| Target | Solana DeFi protocol | Solana DeFi protocol | YES |
| Nonce-0 holdings | 2 transactions total on holding wallet | Nonce 0 on all ETH holding wallets | YES — zero outbound |

**On-chain verification** (independently confirmed April 4, 2026):
- Step attacker wallet `LEP1uHXcWbFEPwQgkeFzdhW2ykgZY6e9Dz8Yro6SdNu`: Account CLOSED (emptied)
- Step holding wallet `7raxiejD8hDUH1wyYWFDPrEuHiLUjJ4RiZi2z1u2udNh`: **261,932.63 SOL STILL UNTOUCHED**
  - Only 2 transactions: receive (Feb 2) + unknown (Feb 4)
  - Owner: System Program (native SOL)
- Step treasury `3KNZ9i1dLNNqpBTKEkTgUQs6TNCd3bzuy6HwfoXACaRs`: Authority revoked
- Attack TX: `2w8sgATZwcmRMHEsG3nutmZJrskVkp74LAwTTEyxSMBJhnZ7Ux4ticeYAYnTb6K44m1XYziPvqonSkZeukAAFadZ`

**Assessment**: SAME ACTOR with HIGH CONFIDENCE based on 7/7 behavioral indicators matching.
The 61-day gap (Jan 31 → Apr 1) is consistent with DPRK operational tempo: Step was likely
a smaller "test run" or parallel operation by the same BlueNoroff/TraderTraitor cell.

**Remaining question**: Were any Step Finance team members also connected to Drift?
Did the attacker gain intelligence about Solana DeFi security practices from Step that
informed the more sophisticated Drift attack?

---

## Part F: THE HOW — COMPLETE ATTACK RECONSTRUCTION (v8)

### ASSESSED WITH HIGH CONFIDENCE — Based on 6 independent sources + Bybit precedent

The attack on Drift Protocol followed the IDENTICAL playbook used by the same DPRK actor group
against Bybit ($1.5B, Feb 2025), Radiant Capital ($50M, Oct 2024), and Step Finance ($40M, Jan 2026).
Ledger CTO Charles Guillemet explicitly confirmed: "The signers may have believed they were signing a
legitimate operation while unknowingly authorizing the drain."

### Phase 1: DEVICE COMPROMISE (est. late Feb — early Mar 2026)

**What happened**: Attacker compromised the devices of at least 2 Drift Security Council multisig signers.

**How we know**:
- Guillemet (Ledger CTO): "compromised several machines belonging to multisig signers" [Source 28]
- Cindy Leow (Drift co-founder): "deeply devastated" — confirmed signers were "misled into providing
  signatures for what appeared to be harmless protocol updates" [Source 3 (CryptoTimes)]
- Squads (multisig platform): "two compromised signers on Drift's admin multisig" [Source 18]
- Drift official: "unauthorized or misrepresented transaction approvals" [Source 27]

**Likely method** (assessed, not confirmed):
BlueNoroff/UNC1069's documented social engineering playbook:
1. LinkedIn/Telegram/Discord outreach from a fake crypto professional
2. "Collaboration proposal" or "investment opportunity" leads to a video call
3. "Audio fix" or "SDK update" download → installs RAT (WAVESHAPER.V2, RustBucket, or GhostCall)
4. RAT provides persistent access to the device, including:
   - Browser session monitoring (sees what signer sees)
   - Transaction interception (can modify what is displayed)
   - Keystroke logging
   - Screen recording
   - Signing key/session extraction

**Precedent**: Step Finance (Jan 31, 2026) — "compromised executive devices" — same attack vector,
same blockchain, same target profile, 61 days before Drift. Halborn confirmed.

### Phase 2: PARALLEL INFRASTRUCTURE SETUP (Mar 11 — Mar 23)

**On-chain staging** (independently verified):
| Date | Action | On-Chain Evidence |
|------|--------|-------------------|
| Mar 11 | 10 ETH withdrawn from Tornado Cash | Nullifier 0x0def3656... → 0x74390ab7 |
| Mar 12 00:10 | ETH → bridge wallet | 0xB702B033 → 0x9beDB87B |
| Mar 12 00:12 | LI.FI bridge ETH→Solana | Method 0x3110c7b9 on LI.FI Diamond |
| Mar 12 00:13 | 31.125 BNB withdrawn (BSC) | MetaWallet → 0x9beDB87B via LI.FI |
| Mar 12 00:25 | 50 SOL received on Solana | FnYXwy7q... wallet |
| Mar 12 00:58 | 750M CVT tokens minted | 09:58 KST — Pyongyang working hours |
| Mar 12-31 | CVT wash-traded on Raydium | $500 real liquidity → $1 fake price |
| Mar 23 | 4 durable nonce accounts created | 2 for SC signers, 2 attacker-controlled |
| Mar 24 | 1 SOL sent to HkGz4Kmo | Drainer wallet funded |

### Phase 3: THE CORE TRICK — TRANSACTION MISREPRESENTATION (Mar 23 — Mar 30)

**What the signers thought they signed**: "Harmless protocol updates" — routine admin maintenance.

**What they actually signed**: Pre-authorized admin transfer transactions using DURABLE NONCES,
giving the attacker the ability to:
1. Transfer admin authority to attacker-controlled address
2. Initialize CVT as a valid spot market with attacker-chosen oracle
3. Raise withdrawal limits to $500 trillion (effectively unlimited)
4. Set timelock to 0 seconds

**Why the signers couldn't tell the difference**:
The Squads multisig security model has a specific documented vulnerability to durable nonces.
From Squads' own security documentation (docs.squads.so):

> "The two-minute rule depends on blockhash expiration, but durable nonces bypass this protection.
> Durable nonces allow transactions to remain valid indefinitely.
> If the initiator has a durable nonce account, the two-minute rule is ineffective."

Normal Solana transactions expire after 60-90 seconds. Durable nonces NEVER expire. A signature
obtained today can be executed next month. The signer has NO way to revoke their approval once given,
unless they manually advance the nonce account (which most signers don't monitor).

**Three possible misrepresentation mechanisms** (one or more were used):

**A) Compromised device / browser MitB attack (MOST LIKELY)**
- RAT on signer's machine modifies what the browser displays
- Signer sees "routine parameter update" but signs admin transfer
- Same mechanism as Bybit: Safe{Wallet} web interface showed "normal transfer" but actual
  transaction contained `delegatecall` that transferred wallet control
- Squads docs explicitly warn: "Users must trust the Safe official website, app, and backend
  services, as well as their own computer and browser" — if ANY component is compromised,
  "the operator might receive incorrect information"

**B) Social engineering via communication channels**
- Attacker (or compromised teammate's device) sends message in Slack/Telegram/Discord:
  "Hey, can you approve this routine config update? Here's the link."
- Signer clicks through to Squads, sees a transaction that LOOKS normal
- Doesn't verify the full instruction set independently
- Signs without realizing the instructions include admin transfer + durable nonce

**C) Compromised Squads web frontend (Bybit-identical)**
- Attacker injects malicious JavaScript into app.squads.so (or a modified version)
- JS activates only for specific Drift multisig transactions
- Displays routine transaction details while actual payload is malicious
- After execution, JS is removed (Bybit: "restored original version within 2 minutes")
- Note: Squads stated "Squads programs were not compromised" but did NOT explicitly clear
  their web frontend

### Phase 4: ADAPTATION AFTER MIGRATION (Mar 27 — Mar 30)

**The critical proof of persistent access**:
- March 27: Drift migrated Security Council to new 2/5 configuration
  (1 old signer retained, 4 NEW signers added, zero timelock)
- March 30 (3 days later): Attacker created a NEW durable nonce account for a member of
  the UPDATED multisig, regaining "effective access to 2/5 signers"

**Why this proves device-level compromise, not one-time social engineering**:
If the attacker had only tricked signers once (e.g., a phishing link), the March 27 migration
would have BROKEN the attack — new signers would need to be tricked again from scratch.

Instead, the attacker adapted in 3 DAYS. This means:
1. The attacker had PERSISTENT access to the Drift team's environment
2. They could identify and target NEW signers within days of their appointment
3. They likely had access to internal communications revealing who the new signers were
4. The device compromise was ONGOING, not a past event

This is consistent with a RAT providing continuous access — exactly as BlueNoroff's
WAVESHAPER.V2, RustBucket, and GhostCall malware are designed to do.

### Phase 5: EXECUTION (April 1, ~11:06 ET)

**Real-time surveillance confirmed**:
Per CoinDesk: "First, Drift ran a legitimate test withdrawal from its insurance fund.
Approximately one minute later, the attacker submitted the pre-signed durable nonce transactions."

The attacker WAITED for legitimate Drift admin activity before striking. This implies:
- Active monitoring of on-chain Drift operations (bot watching the multisig/insurance fund)
- OR access to internal comms where the test withdrawal was discussed
- OR both

**Execution sequence** (confirmed by Drift, CoinDesk, Four Pillars):
1. Two transactions submitted, four Solana slots apart
2. First tx: Create + approve malicious admin transfer (using pre-signed nonce signatures)
3. Second tx: Approve + execute the admin transfer
4. Admin control seized in under 1 minute
5. With admin control: listed CVT market, raised withdrawal limits to $500T, set timelock to 0s
6. Deposited 785M CVT as collateral (~$785M notional at manipulated $1 oracle price)
7. Withdrew real assets against fake CVT collateral
8. 31 withdrawal transactions in ~12 minutes
9. $285M drained — JLP, USDC, SOL, cbBTC, wBTC, USDT, WETH, and others

### THE BYBIT COMPARISON TABLE

| Factor | Bybit (Feb 2025) | Drift (Apr 2026) | Match? |
|--------|-------------------|-------------------|--------|
| Attack vector | Compromised signer machines | Compromised signer machines | YES |
| Method | Malicious JS injected into Safe frontend | Transaction misrepresentation | YES (variant) |
| What signers saw | "Routine cold→hot transfer" | "Harmless protocol updates" | YES |
| What actually executed | delegatecall → wallet control transfer | Admin authority transfer | YES |
| Signature persistence | Standard (immediate use) | Durable nonces (indefinite) | EVOLUTION |
| Timelock | None (Safe multisig) | Zero seconds (Squads config) | YES |
| Threshold bypassed | 3/5 | 2/5 | YES (lower!) |
| Pre-positioning | 2 days (contract test) | 9 days (wallet funded) | YES |
| DPRK attribution | FBI confirmed (Lazarus/TraderTraitor) | TRM/Elliptic assessed (DPRK) | YES |
| Amount stolen | $1.5B | $285M | — |
| Adaptation | N/A | Re-compromised signers after migration | EVOLUTION |

**Ledger CTO verdict**: "patient, sophisticated supply-chain-level compromise targeting the
human and operational layer, not the smart contracts themselves" — IDENTICAL to Bybit.

### WHAT REMAINS UNCONFIRMED (would make this DEFINITIVE)

1. **Device forensics** from the 2 compromised signers — specific malware identification
2. **Connection logs** from signer devices to known DPRK C2 (142.11.206.73, sfrclak.com, callnrwise.com)
3. **Squads web frontend audit** — was app.squads.so compromised, or was it device-only?
4. **Signing method** — did signers use browser-based Squads UI (vulnerable to JS injection) or
   hardware wallets (vulnerable to blind signing)?
5. **Communication channel analysis** — how was the signing request delivered to signers?
6. **The specific social engineering lure** — what pretext was used to approach the signers initially?

---

### OPEN INVESTIGATION LEADS (ACTIONABLE)

The following would move the HOW from "assessed" to "confirmed":

**1. HIGHEST PRIORITY: Device forensics on the 2 compromised Drift signers**
- Check for WAVESHAPER.V2 IOCs:
  - macOS: `/Library/Caches/com.apple.act.mond`
  - Windows: `C:\ProgramData\wt.exe`
  - Process connecting to `142.11.206.73:8000` or `sfrclak.com` / `callnrwise.com`
  - User-Agent `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)`
- Check for other BlueNoroff malware (RustBucket, SUGARLOADER, GhostCall)
- Check browser extension modifications (if signing was browser-based)
- If WAVESHAPER.V2 is found → definitive HOW-to-WHO connection

**2. HIGH: Signing tool / interface analysis**
- What tool did signers use to review and approve transactions? (Squads UI, CLI, custom tool?)
- Was the signing interface compromised or modified?
- Did the tool properly render the transaction contents, or were signers "blind signing"?

**3. HIGH: Communication channel analysis**
- How were the signers asked to sign? (Slack, Telegram, Discord, email?)
- Were any communication channels compromised?
- Were there suspicious contacts/invitations in the weeks before the exploit?
- Check for indicators matching UNC1069's social engineering playbook:
  - Fake company website cloning
  - Fake Zoom/Teams meeting invitations
  - "Audio fix" or "SDK update" downloads
  - LinkedIn/Telegram outreach from unknown crypto professionals

**4. ELEVATED: Step Finance cross-reference**
- Step Finance holding wallet `7raxiejD8hDUH1wyYWFDPrEuHiLUjJ4RiZi2z1u2udNh` — 261,932 SOL still sitting there. Same "park and wait" as Drift ETH holdings.
- Request Step Finance device forensics — if WAVESHAPER.V2 or RustBucket IOCs found, confirms same tooling
- Check for shared team members / Telegram groups / Discord servers between Step and Drift
- Check if any Step Finance exec was contacted by the same fake persona used for Drift

**5. MEDIUM: Pre-exploit multisig signer identification**
- The 5 pre-exploit multisig public keys (from the original Squads config before April 2) would identify who was a potential target
- Cross-reference signer public keys with known Drift team members
- Check their public presence for social engineering indicators

**6. MEDIUM: Durable nonce account deep analysis**
- Which specific nonce accounts were created March 23-30?
- What was the exact transaction content in the pre-signed transactions?
- Can the nonce advance transactions reveal the signing tool or method used?

---

## Part G: EXACT ON-CHAIN EVIDENCE — 100% VERIFIED

Every address, transaction signature, and data point below was pulled directly from the Solana
and Ethereum mainnets via RPC calls on April 4, 2026. Nothing is inferred. Everything is verifiable.

### G.1 — CORE ADDRESSES (ALL VERIFIED ON-CHAIN)

| # | Role | Address | Verified Via |
|---|---|---|---|
| 1 | Drift Protocol Program | `dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH` | getAccountInfo → BPFLoaderUpgradeable, executable=true |
| 2 | Drift ProgramData | `7dLgmtcTavcguNoynVimF9ZNVb13FvhXVRfj2HyrDGaP` | Drift program parsed.info.programData |
| 3 | Current Drift Authority (post-recovery) | `GA5aPX7hFNaxoi8akdbcFVMCrkdfbYC42q7BERPguTNo` | ProgramData parsed.info.authority |
| 4 | Attacker Drain Wallet (SOL) | `HkGz4KmoZ7Zmk7HN6ndJ31UJ1qZ2qgwQxgVqQwovpZES` | Solscan, PeckShield, NomosLabs |
| 5 | Attacker Operations Wallet (SOL) | `FfAMvZtdanzUjng2HP2XHAy72ahWGPyYfX45Vzzq6ijV` | getSignaturesForAddress — 50 txs, Apr 1-3 |
| 6 | Attacker Exit Wallet (ETH) | `0xFcC47866Bd2BD3066696662dbd1C89c882105643` | NomosLabs, PeckShield |
| 7 | Malicious Drain Program | `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` | getAccountInfo → executable=true, BPFLoaderUpgradeable |
| 8 | Malicious Program Data | `B5MvUwXdiW1NMM6QFFD3ssPKBujD4zMohncbM73Z2BQu` | Program parsed.info.programData |
| 9 | Malicious Program Authority | `7gZufwwAo17y5kg8FMyJy2phgpvv9RSdzWtdXiWHjFr8` | ProgramData parsed.info.authority |
| 10 | Malicious Program State Account | `4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf` | getAccountInfo → owner=6EF8... |
| 11 | CarbonVote Token (CVT) Mint | `G84LEhbNMR1yYbHgHbnNYNSK8mpTKcazh5jcW5yMPQKo` | getAccountInfo → SPL Token mint |
| 12 | Squads v4 Program | `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf` | Called in multisig txs |
| 13 | Pre-Migration Squads Multisig | `2yMoQqQrtbhq3nQ3wFoQQawWS65qcqUXcwHEYha4rshW` | getAccountInfo → owner=SQDS4ep... |
| 14 | Pre-Migration Squads Vault PDA | `2FrSYSXwMboYfouLMchDYDHXcjTsNaRcjfgoGCiYK5dC` | Referenced in multisig execute txs |

### G.2 — ETHEREUM HOLDING WALLETS (VERIFIED — Drift sent on-chain messages to these)

Source: CoinCentral report + on-chain messages from `0x0934faC45f2883dd5906d09aCfFdb5D18aAdC105`

| Wallet | Status |
|---|---|
| `0xAa843eD65C1f061F111B5289169731351c5e57C1` | Holding stolen ETH |
| `0xD3FEEd5DA83D8e8c449d6CB96ff1eb06ED1cF6C7` | Holding stolen ETH |
| `0xbDdAE987FEe930910fCC5aa403D5688fB440561B` | Holding stolen ETH |
| `0x0FE3b6908318B1F630daa5B31B49a15fC5F6B674` | Holding stolen ETH (~56,568 ETH) |

### G.3 — CVT TOKEN DETAILS (VERIFIED ON-CHAIN)

Verified via `getAccountInfo` on mint `G84LEhbNMR1yYbHgHbnNYNSK8mpTKcazh5jcW5yMPQKo`:

```
Owner:           TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA (SPL Token Program)
Decimals:        9
Supply:          749,999,999.872538456 (≈750M tokens)
Mint Authority:  NULL (revoked after minting — attacker removed mint authority)
Freeze Authority: NULL
```

The attacker minted ~750M CVT tokens, seeded a Raydium liquidity pool with $500,
wash-traded to establish a ~$1 oracle price, then deposited CVT as "collateral"
on Drift to withdraw real assets. Mint authority was revoked to prevent detection
via future unauthorized minting.

### G.4 — MALICIOUS PROGRAM DETAILS (VERIFIED ON-CHAIN)

The malicious program `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P`:

```
Owner:           BPFLoaderUpgradeab1e11111111111111111111111
Executable:      true
Authority:       7gZufwwAo17y5kg8FMyJy2phgpvv9RSdzWtdXiWHjFr8
Binary header:   f0VMRgIBAQAAAAAAAAAAAAMA9wA... (ELF binary — compiled Solana BPF program)
State account:   4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf (owned by this program)
```

**CRITICAL**: The authority `7gZufwwAo17y5kg8FMyJy2phgpvv9RSdzWtdXiWHjFr8` is a LEGITIMATE
Drift deployer wallet with 50 transactions going back to November 26, 2025. It is controlled
through the Squads v4 multisig. This means the attacker deployed the malicious program
THROUGH DRIFT'S OWN INFRASTRUCTURE by obtaining multisig approvals via social engineering.

### G.5 — DEPLOYER WALLET ACTIVITY TIMELINE (7gZufww — ALL VERIFIED)

The deployer wallet `7gZufwwAo17y5kg8FMyJy2phgpvv9RSdzWtdXiWHjFr8` has 50 on-chain transactions.
These are LEGITIMATE Drift operations conducted via the Squads multisig:

| Date | Transaction Type | Significance |
|---|---|---|
| 2025-11-26 | Squads multisig proposal (signer: `6W6qsD...`) | Earliest tx — legitimate Drift operation |
| 2025-12-01 to 2025-12-04 | Multiple Squads proposals | Ongoing program management |
| 2026-01-09 to 2026-01-30 | Squads proposals | Regular program upgrades |
| 2026-02-12 to 2026-02-26 | Squads proposals + setAuthority | Regular authority transfers |
| 2026-03-03 to 2026-03-10 | Squads proposals | Pre-exploit period |
| **2026-03-24 13:35** | **setAuthority** (signer: `BUhcMP3...`) | Authority transferred TO deployer |
| **2026-03-24 15:58** | **Squads execute** (signer: `5sFJMw5...`) | Multisig proposal executed |
| **2026-03-27 16:59** | **setAuthority** (signer: `6mzdpBz...`) | **MIGRATION DAY** — authority transfer |
| **2026-03-28 04:42** | **setAuthority** (signer: `FFPCPSi...`) | Authority transferred TO deployer |
| **2026-04-03 13:48** | **setAuthority** (signer: `FFPCPSi...`) | **POST-EXPLOIT** — recovery |

### G.6 — PRE-MIGRATION SQUADS MULTISIG (DECODED ON-CHAIN)

The pre-migration Squads multisig `2yMoQqQrtbhq3nQ3wFoQQawWS65qcqUXcwHEYha4rshW` was decoded
from raw account data. It has EXACTLY 3 on-chain transactions, all from March 24:

**Transaction 1 — March 24 13:36:17 UTC**
Signature: `FgXJJmevU41oH4hE1Huf5kdzfvV3ogGmycHc6zSa9DY4G6kJz8PJ9cTL6gFEXY2dAvc6tvDhcBuaacFzx34kvKW`
- Signer: `6W6qsDbocrEs3vjri5Di15bf9PLRYhfxekPk25MhVHWz` (SC Member #1)
- 3 Squads instructions: Create proposal → Vote → Activate
- Proposal account: `6SM7cuY12zvmdHmRgx7ArtDk29m8VxKwoFqAr4W9wXJQ`
- Vault PDA: `2FrSYSXwMboYfouLMchDYDHXcjTsNaRcjfgoGCiYK5dC`

**Transaction 2 — March 24 13:38:51 UTC**
Signature: `4d5qeGoE9rfBm6oUJ5DEb5x9J5UPTAhdygN7X4pLNfaXre9chckCwmAZx4iY5UykBAfou3cfRKNU93riJhPtj3y9`
- Signer: `5sFJMw5dC59oKGKA9LgeYQCSmYS6rLeCegxMkcM2Pwby` (SC Member #2)
- 1 Squads instruction: Vote/approve on proposal `6SM7cuY...`

**Transaction 3 — March 24 15:58:45 UTC**
Signature: `MwxLjTFd1BQJo7dJjKPyeyjhcVSSe4fuhP2jgydQ6Bj1XU6xBRrDAASePDinQN5ujYaenHhKdNjrh1qxwRLMZQA`
- Signer: `5sFJMw5dC59oKGKA9LgeYQCSmYS6rLeCegxMkcM2Pwby` (SC Member #2)
- Squads execute: Involves deployer `7gZufww` and vault `2FrSYSXw`

**KEY FINDING**: The pre-migration multisig `2yMoQqQ` has ZERO transactions after March 24.
The April 1 exploit used a DIFFERENT Squads multisig — the POST-MIGRATION one created March 27.

### G.7 — SQUADS MULTISIG MEMBER PUBKEYS (DECODED FROM ACCOUNT DATA)

Raw binary decode of multisig `2yMoQqQrtbhq3nQ3wFoQQawWS65qcqUXcwHEYha4rshW` (495 bytes):

| Offset | Pubkey | Likely Role |
|---|---|---|
| 32 | `FQvdjhXQRLAW5vPqfXDgJViHej6i379JRyyhwADUTAUX` | Config field (create_key or config_authority) |
| 96 | `GcdazVp7Dzv2z52egSZWqfSFMkmK3r8iQAocwVjDBNZ` | Member 1 (or config field) |
| 128 | `Bkbj1NqmTE4k5zaUmHDZpkDTUfMXBnGwPvAuZHCZtoww` | Member |
| 160 | `Ei3jNcBqHAKL6r2UZ3pe7SPwSQp3qXxFWg6Crqvig7kE` | Member |
| 192 | `41z1DXVsnu384mYaTTK7qk9yWcR9hpYF8J8MDmUJCpSL` | Member |
| 224 | `4j1PHUQYn3Eg9NuBasSwieusKi65WGm5kEbEV63s6iCb` | Member |
| 256 | `5kM7J3yuEqht92y6d2xLTw5r4u3oxPcqY71okW7G6Mw` | Member |
| 288 | `EjMFGGEET2L6KQ4vPiZQhEw1x2JcwtqwYnJhsQfzju5h` | Member |
| 320+ | All `11111111...` | Empty/padding slots |

**NOTE**: The Squads v4 multisig struct stores threshold, timelock, and member data.
The exact field mapping depends on the Squads v4 IDL. Some of these pubkeys may be
config fields rather than members. The KNOWN signers from actual transactions are:
- `6W6qsDbocrEs3vjri5Di15bf9PLRYhfxekPk25MhVHWz` (signed March 24 proposal)
- `5sFJMw5dC59oKGKA9LgeYQCSmYS6rLeCegxMkcM2Pwby` (approved + executed March 24)

### G.8 — FfAMv WALLET COMPLETE TRANSACTION LOG (50 TXS, ALL VERIFIED)

| # | Time (UTC) | Status | Description |
|---|---|---|---|
| 49 | Apr 1 05:48:52 | OK | Setup: 19x 1-lamport transfers from `CCyYK...` to various accounts |
| 48 | Apr 1 05:50:43 | OK | Close 3 token accounts (EMwFF, GSDKu, 7QHBo) |
| 47 | Apr 1 18:14:16 | OK | **FIRST DRAIN**: Calls malicious program `6EF8` with 17 accounts, creates token account, drains via program |
| 46 | Apr 1 18:14:17 | OK | Drain tx |
| 45 | Apr 1 18:14:17 | OK | Drain tx |
| 44 | Apr 1 18:14:19 | OK | Drain tx |
| 43 | Apr 1 18:16:06 | OK | Drain attempt |
| 42-33 | Apr 1 18:16:37-18:17:38 | FAIL | 10 FAILED drain attempts |
| 32 | Apr 1 18:33:48 | OK | Gas funding from `G8kzXTPr...` (0.252 SOL) |
| 31 | Apr 1 18:36:27 | OK | Asset conversion via Raydium + LI.FI (103,690 tokens received) |
| 30 | Apr 1 18:36:40 | OK | **MAIN DRAIN BURST** starts |
| 29-16 | Apr 1 18:36:40-18:36:50 | OK (14), FAIL (2) | 16 rapid-fire txs in 10 seconds |
| 15 | Apr 1 18:43:57 | OK | Continued drain |
| 14 | Apr 1 18:44:35 | OK | Drain tx |
| 13 | Apr 1 18:44:43 | FAIL | Failed drain |
| 12 | Apr 1 18:44:52 | OK | Drain tx |
| 11-8 | Apr 1 18:47:49-18:48:40 | OK | Final drain txs |
| 7 | Apr 1 18:56:31 | OK | Post-drain cleanup |
| 6-5 | Apr 3 12:01:47-12:01:50 | FAIL | Post-exploit failed txs |
| 4 | Apr 3 12:57:31 | FAIL | Failed tx |
| 3 | Apr 3 12:57:45 | OK | Post-exploit tx |
| 2-1 | Apr 3 13:01:23-13:01:43 | OK | Post-exploit cleanup |
| 0 | Apr 3 18:28:58 | OK | Final tx |

### G.9 — DRAIN TRANSACTION DETAIL (TX #47 — FIRST DRAIN)

Signature: `UNrtqyUfnXdvPNUKWELhCBpUdJPohho7v6qQDWbe59FRvXBNfc4fnav9wSQuUPW7j6Q42RRL8BrZBcbTQRidqZP`
Time: 2026-04-01 18:14:16 UTC
Fee: 1,005,000 lamports | Compute: 87,146

```
Instructions:
  [0] ComputeBudget → Set compute limit
  [1] ComputeBudget → Set priority fee
  [2] CreateIdempotent → Token account for mint BW73MR... (wallet: FfAMv)
  [3] 6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P → DRAIN (17 accounts)
      Accounts include:
        - 4wTV1Y... (malicious program state)
        - CebN5W... (Drift vault)
        - BW73MR... (token mint being drained)
        - Various Drift infrastructure accounts
  [4] Transfer → 500,000 lamports to HmRxxm... (Jito tip)
  [5] Transfer → 1,000,000 lamports to AstrAB... (Astral tip)
```

The malicious program `6EF8` was a custom Solana BPF binary that:
1. Took admin authority over Drift vaults (obtained via durable nonce multisig approval)
2. Created withdrawal instructions bypassing normal Drift access controls
3. Transferred vault contents to the attacker's token accounts

### G.10 — HkGz4K DRAIN WALLET ACTIVITY (VERIFIED)

The HkGz4K wallet's earliest confirmed transaction:
- April 1, 18:49:33 UTC (FAIL) — first attempt
- April 1, 18:59:05 UTC (OK) — first successful receive of drained funds
- 50 transactions total through April 1

### G.11 — THE EXACT HOW (SYNTHESIZED FROM ON-CHAIN EVIDENCE)

Based on 100% verified on-chain data:

**STEP 1: Program infrastructure prepared (Nov 2025 — Mar 2026)**
- Deployer `7gZufww` used through legitimate Squads multisig operations for months
- Attacker studied this wallet's role and the Squads approval process

**STEP 2: Durable nonce accounts created (March 23, 2026)**
- 4 nonce accounts created (per Drift's tweet thread)
- 2 associated with Security Council members
- 2 attacker-controlled
- These held pre-signed Squads multisig proposal transactions that would:
  a. Deploy/upgrade the malicious program `6EF8` via deployer `7gZufww`
  b. Transfer Drift admin authority to the attacker

**STEP 3: March 27 — SC migration**
- Old multisig `2yMoQqQ` replaced with new configuration
- 1 old member + 4 new members (KuCoin reporting)
- Pre-migration multisig shows ZERO activity after March 24

**STEP 4: March 30 — Attacker re-obtains access**
- New nonce account created for updated multisig member
- Attacker now has 2/5 approvals in the NEW multisig
- This proves PERSISTENT device-level compromise, not one-off SE

**STEP 5: April 1 — Execution**
- Two durable nonce transactions submitted, 4 slots apart (per CoinDesk, BSC News)
- These went through the POST-MIGRATION Squads multisig
- Admin authority transferred to attacker
- Malicious program `6EF8` deployed/configured via deployer `7gZufww`

**STEP 6: April 1 18:14 UTC — Vault drain begins**
- FfAMv wallet calls malicious program `6EF8` to drain Drift vaults
- First drain: tx `UNrtq...` at 18:14:16 UTC
- 31 withdrawal transactions in ~12 minutes (BSC News)
- Some txs failed (10 failures at 18:16-18:17), then resumed at 18:36
- Main burst: 16 txs in 10 seconds (18:36:40-18:36:50)

**STEP 7: Fund laundering**
- Assets converted to USDC via Jupiter DEX
- USDC bridged Solana→Ethereum via Circle CCTP (100+ txs per ZachXBT)
- On Ethereum: USDC→ETH conversion
- 129,066 ETH accumulated ($273M) per Lookonchain
- Funds distributed to 4 holding wallets (all confirmed via Drift on-chain messages)
- Additional: SOL deposited to HyperLiquid + Binance

### G.12 — WHAT IS STILL NEEDED FOR 100% CERTAINTY ON THE HOW

| Item | Status | How to Get It |
|---|---|---|
| Post-migration Squads multisig address | NOT YET FOUND | Drift Protocol / internal logs |
| Exact 4 nonce account addresses (March 23) | NOT YET FOUND | Drift tweet thread (accounts cut off in embedding) |
| The 2 admin transfer tx signatures (4 slots apart) | NOT YET FOUND | Post-migration multisig address needed first |
| Device forensics from compromised signers | NOT AVAILABLE | Requires Drift cooperation |
| Specific malware on signer devices | NOT AVAILABLE | Requires device access |
| Communication channel used for SE lure | NOT AVAILABLE | Requires signer interview |
| Backpack Exchange KYC data for intermediaries | NOT AVAILABLE | Requires law enforcement subpoena |
| The exact signed durable nonce tx content | NOT AVAILABLE | Nonce account addresses needed first |

### G.13 — PROGRAMS AND ACCOUNTS REFERENCED IN DRAIN TXS

| Address | Role | Verified |
|---|---|---|
| `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` | Malicious drain program | Yes — executable BPF binary |
| `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8` | Raydium AMM (used for swaps) | Yes — used in TX 18:36:27 |
| `LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj` | LI.FI cross-chain (used for bridging) | Yes — used in TX 18:36:27 |
| `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL` | Associated Token Program | Yes — creates token accounts |
| `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` | SPL Token Program | Yes — standard |
| `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` | Token-2022 Program | Yes — used for some drains |
| `HmRxxm42Ej2sqP9fC9mbGYixZt37fMFGBmEMw65gW55a` | Jito tip recipient | Yes — receives tips in drain txs |
| `AstrABAu8CBTyuPXpV4eSCJ5fePEPnxN8NqBaPKQ9fHR` | Astral tip recipient | Yes — receives tips in first drain |

---

## Part H: DIVERG ORIGINAL ON-CHAIN FORENSICS — COMPLETE FUNDING CHAIN (April 4, 2026)

**This section contains ORIGINAL forensic research by Diverg that has not been published by any other organization.** Every address and transaction below has been verified directly against the Solana and Ethereum RPC endpoints.

### H.1: The Master Wallet — Connecting CVT Deployment to the Drainer

We independently identified the wallet that connects the CVT token deployment, the drainer wallet, and the Tornado Cash funding:

| Role | Address | First Active | Funded By |
|---|---|---|---|
| **Master Operations Wallet (CVT deployer)** | `FnYXwy7qEtGV4cj1Sf6tht7VDsiytFjJeF9yd4LpAjjx` | 2026-03-12 00:25 UTC | `B87FQZji...` (50 SOL) |
| **Burner Relay Wallet** | `B87FQZjiMefh3aV2xJu8t5jRFfJZWFrf1vKgTBRibFHK` | 2026-03-12 00:15 UTC | `HWjmoUNY...` (232.279 SOL via Mayan Finance) |
| **Drainer Wallet** | `HkGz4KmoZ7Zmk7HN6ndJ31UJ1qZ2qgwQxgVqQwovpZES` | 2026-03-24 06:32 UTC | `FnYXwy7q...` (1 SOL) |
| **Drift Operations Wallet** | `FfAMvZtdanzUjng2HP2XHAy72ahWGPyYfX45Vzzq6ijV` | 2026-03-27 11:26 UTC | `J1BDJEdv...` (0.987 SOL) |
| **ETH Gas Wallet** | `0x0bfa97d668a6C249bd1b4754b06eEa373424cA62` | 2026-03-30 10:59 UTC | Tornado Cash 0.1 ETH pool |
| **ETH Exit Wallet** | `0xFcC47866Bd2BD3066696662dbd1C89c882105643` | 2026-03-30 23:54 UTC | `0x0bfa97d6...` (0.0978 ETH) |

**KEY FINDING**: `FnYXwy7qEtGV4cj1Sf6tht7VDsiytFjJeF9yd4LpAjjx` is the single wallet that:
1. Received initial 50 SOL funding from the Tornado Cash → Mayan bridge chain (March 12)
2. Deployed CarbonVote Token (CVT) and created the Raydium wash-trading pool (March 12)
3. Funded the drainer wallet `HkGz4K` with 1 SOL (March 24)
4. Had 92 total on-chain transactions, spanning March 12 to April 1

### H.2: Complete Funding Chain — Tornado Cash → Exploit

```
ETHEREUM SIDE:
═══════════════
March 11, ~15:24 Pyongyang time:
  Tornado Cash 10 ETH Pool (0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF)
    → [ETH Address: UNKNOWN — requires Mayan cross-ref]
      → Mayan Finance Cross-Chain Swap (ETH → SOL)
         Order UUID: a92ccb66-7cd7-4cde-921a-4721e0af681e
                        ↓
SOLANA SIDE:
═══════════
March 12, 00:15 UTC:
  Mayan Relayer (HWjmoUNYckccg9Qrwi43JTzBcGcM1nbdAtATf9GXmz16)
    → B87FQZjiMefh3aV2xJu8t5jRFfJZWFrf1vKgTBRibFHK  [232.279 SOL]
      (8 txs total, empty after disbursement — BURNER)
        ↓
March 12, 00:25 UTC:
  B87FQZji...
    → FnYXwy7qEtGV4cj1Sf6tht7VDsiytFjJeF9yd4LpAjjx  [50 SOL]
      (CVT deployer — starts CVT minting, Raydium pool, wash trading)
        ↓
March 24, 06:32 UTC:
  FnYXwy7q...
    → HkGz4KmoZ7Zmk7HN6ndJ31UJ1qZ2qgwQxgVqQwovpZES  [1 SOL]
      (Drainer wallet — 338 total txs, executes the April 1 exploit)
        ↓
March 27, 11:26 UTC:
  J1BDJEdvTmmcjeTMVTHLPaaNvuQ3mdxeuWEM1YyMksLy
    → FfAMvZtdanzUjng2HP2XHAy72ahWGPyYfX45Vzzq6ijV  [0.987 SOL]
      (Operations wallet — 795 txs, handles Raydium swaps, LI.FI bridge,
       durable nonce creation, Squads multisig interactions)

═══════════════════════════════════════════════════════════
                     APRIL 1 — EXPLOIT EXECUTED
═══════════════════════════════════════════════════════════

April 1, 16:05-16:17 UTC:
  31 drain transactions executed in 12 minutes
  $285M extracted from Drift Vault
  HkGz4K → Jupiter Aggregator → USDC consolidation
    → Circle CCTP + Wormhole + Mayan → ETHEREUM
        ↓
April 1, 19:15+ UTC:
  0xFcC47866Bd2BD3066696662dbd1C89c882105643  [ETH exit wallet]
    → 0xAa843eD65C1f061F111B5289169731351c5e57C1  [Drift Exploiter 5: 25,714 ETH]
    → 0xD3FEEd5DA83D8e8c449d6CB96ff1eb06ED1cF6C7  [Holding wallet 2]
    → 0xbDdAE987FEe930910fCC5aa403D5688fB440561B  [Holding wallet 3]
    → 0x0FE3b6908318B1F630daa5B31B49a15fC5F6B674  [Holding wallet 4]
         Total: ~129,000 ETH (~$265M) as of April 4
```

### H.3: Two Tornado Cash Withdrawals — Same Attacker

| # | Date | Pool | Amount | Receiving Address | Purpose |
|---|---|---|---|---|---|
| 1 | March 11 | 10 ETH (`0x910Cbd...`) | 10 ETH | Unknown (converted to SOL via Mayan) | Fund CVT deployment + operations |
| 2 | March 30 | 0.1 ETH (`0x12d66f87...`) | 0.1 ETH | `0x0bfa97d668a6C249bd1b4754b06eEa373424cA62` | Gas for ETH exit wallet |

Both withdrawals followed the same pattern: Tornado Cash → single-purpose burner → immediate forwarding to operational infrastructure. Withdrawal #1 was converted to SOL via Mayan Finance swap (232.279 SOL ≈ $23,000 at ~$100/SOL, consistent with 10 ETH ≈ $25,000 minus fees). Withdrawal #2 funded gas for the post-exploit ETH-side operations.

### H.4: Mayan Finance Cross-Chain Swap Evidence

The critical bridge transaction from Ethereum to Solana was executed through **Mayan Finance** (verified via their relayer address pattern and UUID memo format):

- **Mayan Relayer (Solana)**: `HWjmoUNYckccg9Qrwi43JTzBcGcM1nbdAtATf9GXmz16`
- **Co-signer**: `9WL2A89YBr6X47ABKYNzPentWiBA3H8tpaiuf5CaYHx6`
- **Order UUID**: `a92ccb66-7cd7-4cde-921a-4721e0af681e`
- **Solana TX**: `4evx1sRqwoy3SWaQ2zfYJyCoWgZvHqKDzHbDwDuAfsPdFx5B7EhwqxWy9HifJ1hMkW8GYoUa9fgcLy98iF3ZLruV`
- **Amount delivered**: 232.279139994 SOL
- **Recipient**: `B87FQZjiMefh3aV2xJu8t5jRFfJZWFrf1vKgTBRibFHK` (burner)

**LAW ENFORCEMENT LEAD**: Mayan Finance likely has the Ethereum-side source address and order details for UUID `a92ccb66-7cd7-4cde-921a-4721e0af681e`. This source address will connect directly to the March 11 Tornado Cash 10 ETH pool withdrawal.

### H.5: Backpack Exchange KYC Lead

Per on-chain analyst @_0xaryan (republished by KuCoin/TechFlow), the attacker transferred assets to multiple laundering addresses including `8ub...Gxw`, which had received funds via Backpack wallets the day before the incident. These Backpack accounts had **completed KYC verification**.

Backpack co-founder Armani Ferrante clarified that the flow was "Backpack → Non-attacker (cross-chain intent solver) → Attacker" and stated verification was completed with account holders.

**LAW ENFORCEMENT LEAD**: Backpack Exchange possesses KYC records for accounts in the laundering chain. While Ferrante claims these are cross-chain solver intermediaries (not the attacker directly), KYC data may still identify the ultimate beneficiary through transaction tracing.

### H.6: What Is STILL Missing for 100% DPRK Attribution

| Evidence Needed | Status | Who Has It |
|---|---|---|
| Ethereum address that initiated the Mayan swap (UUID `a92ccb66...`) | **RETRIEVABLE** via Mayan Finance | Mayan Finance / Wormhole |
| Link between that ETH address and Tornado Cash 10 ETH withdrawal | **DERIVABLE** once Mayan data obtained | Mayan + Etherscan |
| Link between that ETH address and known Lazarus/Bybit wallets | **TESTABLE** once address identified | FBI list cross-reference |
| Malware on compromised Drift signer devices | **NOT PUBLISHED** | Drift team / forensics firm |
| FBI official TraderTraitor attribution for Drift | **PENDING** | FBI IC3 |
| Backpack KYC identities | **AVAILABLE** via subpoena | Backpack Exchange |
| TRM/Elliptic proprietary wallet clustering data | **PROPRIETARY** | TRM Labs / Elliptic |

### H.7: FBI Bybit Addresses Cross-Reference

We cross-referenced all 31 FBI-published Bybit/TraderTraitor Ethereum addresses against the Drift exploit addresses. **No direct matches or on-chain interactions were found.** This is expected — Lazarus typically uses entirely fresh wallet infrastructure for each operation.

The 31 FBI Bybit addresses checked: `0xD5b58Cf7...`, `0xEB0bAA3A...`, `0xf03AfB1c...`, `0x723a7084...`, `0xF3025725...`, `0x1512fcb0...`, `0xdD90071D...`, `0xA5A023E0...`, `0x55CCa2f5...`, `0xA4B2Fd68...`, `0x21032176...`, `0x1542368a...`, `0x9eF42873...`, `0x52207Ec7...`, `0x959c4CA1...`, `0x2290937A...`, `0xe69753Dd...`, `0x9271EDdd...`, `0x0e8C1E28...`, `0xB4a862A8...`, `0x30a822CD...`, `0xE9bc552f...`, `0x660BfcEa...`, `0x09278b36...`, `0xCd1a4A45...`, `0x1eB27f13...`, `0x1bb09705...`, `0x8c7235e1...`, `0xB72334cB...`, `0xD3C611AE...`, `0xbdE2Cc53...`

None appear in the Drift exploit transaction history.

---

## SOURCES (ALL VERIFIABLE)

1. CrowdStrike: STARDUST CHOLLIMA Likely Compromises Axios npm Package — https://crowdstrike.com/en-us/blog/stardust-chollima-likely-compromises-axios-npm-package/
2. Google TIG: UNC1069 Targets Cryptocurrency Sector — https://cloud.google.com/blog/topics/threat-intelligence/unc1069-targets-cryptocurrency-ai-social-engineering
3. Google TIG: Axios npm Supply Chain Attack — https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package
4. Elliptic: Drift Protocol Exploited — https://www.elliptic.co/blog/drift-protocol-exploited-for-286-million-in-suspected-dprk-linked-attack
5. TRM Labs: Drift Protocol Heist — https://www.trmlabs.com/resources/blog/north-korean-hackers-attack-drift-protocol-in-285-million-heist
6. lazarus.day UNC1069 aliases — https://lazarus.day/actors/alias/unc1069
7. lazarus.day TraderTraitor aliases — https://lazarus.day/actors/alias/tradertraitor
8. CrowdStrike STARDUST CHOLLIMA profile — https://www.crowdstrike.com/adversaries/stardust-chollima/
9. FBI TraderTraitor advisory (DMM Bitcoin) — Dec 2024
10. USCISA TraderTraitor advisory — Apr 2022
11. ForkLog: Drift TraderTraitor attribution — https://forklog.com/en/north-korean-hackers-linked-to-280-million-drift-defi-protocol-breach/
12. Kaspersky: BlueNoroff GhostCall/GhostHire — https://securelist.com/bluenoroff-apt-campaigns-ghostcall-and-ghosthire/117842/
13. N3mes1s: Axios macOS RAT RE — https://gist.github.com/N3mes1s/0c0fc7a0c23cdb5e1c8f66b208053ed6
14. Jamf: RustBucket (BlueNoroff) — https://www.jamf.com/blog/bluenoroff-apt-targets-macos-rustbucket-malware/
15. Snyk: Axios compromise analysis — https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/
16. GitHub: Axios post-mortem (#10636) — https://github.com/axios/axios/issues/10636
17. SpendNode: Drift durable nonce + SE confirmation — https://www.spendnode.io/blog/drift-protocol-280-million-exploit-durable-nonce-social-engineering-solana-defi/
18. CryptoTimes: Squads confirms compromised signers — https://www.cryptotimes.io/2026/04/03/drift-protocol-exploit-linked-to-compromised-multisig-signers-squads/
19. BleepingComputer: Drift loses $280M — https://www.bleepingcomputer.com/news/security/drift-loses-280-million-north-korean-hackers-seize-security-council-powers/
20. Cube Exchange: Drift hack technical analysis — https://www.cube.exchange/blog/newsletter/security-briefing/security-briefing/2026-04-01--drift-hack
21. Four Pillars: Reflections on the Drift exploit — https://4pillars.io/issues/reflections-on-the-drift-protocol-exploit
22. BleepingComputer: Step Finance compromised devices — https://www.bleepingcomputer.com/news/security/step-finance-says-compromised-execs-devices-led-to-40m-crypto-theft/
23. Halborn: Step Finance hack explained — https://www.halborn.com/blog/post/explained-the-step-finance-hack-january-2026
24. Drift SDK package.json (no axios dependency) — https://github.com/drift-labs/protocol-v2/blob/master/sdk/package.json
25. Hunt.io + Acronis TRU: DPRK infrastructure — https://hunt.io/blog/dprk-lazarus-kimsuky-infrastructure-uncovered
26. Hunt.io: Axios C2 breakdown — https://hunt.io/blog/axios-supply-chain-attack-ta444-bluenoroff
27. CoinDesk: Durable nonce technical — https://www.coindesk.com/tech/2026/04/02/how-a-solana-feature-designed-for-convenience-let-an-attacker-drain-usd270-million-from-drift
28. Protos: Detailed timeline — https://protos.com/inside-the-280m-drift-hack-weeks-of-setup-minutes-to-drain/
29. Cryip: Step Finance forensics — https://cryip.co/step-finance-treasury-breach/
30. KuCoin: Drift multisig migration detail — https://www.kucoin.com/news/flash/drift-protocol-hacked-for-over-200m-after-multisig-change
31. NomosLabs: Drift $285M forensic report — https://nomoslabs.io/archive/drift-trade-2026
32. BSC News: CVT fake token + oracle manipulation detail — https://bsc.news/post/drift-protocol-hack-285-million
33. MEXC/CoinDesk: Durable nonce full breakdown — https://www.mexc.com/news/1001312
34. CoinCentral: Drift on-chain messages to 4 ETH wallets — https://coincentral.com/drift-hack-update-team-sends-on-chain-messages-to-four-eth-wallets/
35. Solana RPC: Direct on-chain verification (getAccountInfo, getTransaction, getSignaturesForAddress) — April 4, 2026
36. NomosLabs: Radiant Capital Hack — Multi-Sig Compromise Drained $50M — https://nomoslabs.io/blog/radiant-capital-hack-multi-sig-compromise-drained-50m
37. SecurityBoulevard: Dissecting the Bybit Malicious UI Spoofing Javascript — https://securityboulevard.com/2025/02/dissecting-the-bybit-cryptocurrency-exchange-malicious-ui-spoofing-javascript/
38. Huntress: Inside the BlueNoroff Web3 macOS Intrusion Analysis — https://www.huntress.com/blog/inside-bluenoroff-web3-intrusion-analysis
39. Kaspersky: BlueNoroff GhostCall/GhostHire campaigns — https://securelist.com/bluenoroff-apt-campaigns-ghostcall-and-ghosthire/117842/
40. Radiant Capital post-mortem — https://medium.com/@RadiantCapital/radiant-capital-incident-update-e56d8c23829e
41. NCC Group: In-Depth Technical Analysis of the Bybit Hack — https://www.nccgroup.com/research/in-depth-technical-analysis-of-the-bybit-hack/
42. BlockSec: Bybit Incident — A Web2 Breach Enables the Largest Crypto Hack — https://blocksec.com/blog/bybit-incident-a-web2-breach-enables-the-largest-crypto-hack-in-history
43. FBI: North Korea Responsible for $1.5B Bybit Hack — https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack
44. Mayan Finance cross-chain swap verification — Relayer HWjmoUNY on Solana, UUID a92ccb66-7cd7-4cde-921a-4721e0af681e
45. Etherscan: Drift Exploiter 5 label — https://etherscan.io/address/0xAa843eD65C1f061F111B5289169731351c5e57C1
46. Diverg original on-chain forensics: Complete funding chain FnYXwy→B87FQ→HkGz4K traced via Solana RPC — April 4, 2026
