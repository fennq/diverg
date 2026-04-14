# Solana program upgrade / immutability — feasibility spike (time-boxed)

Purpose: orient product and investigations toward what on-chain **upgrade authority** and **program data** mean for risk, without shipping chain automation in this pass.

## What to read (order)

1. Solana docs: **deploying programs**, **upgradeable BPF loader**, and **closing / transferring upgrade authority**.
2. Anchor book (if applicable to your targets): `declare_id!`, upgradeable deployments, and common multisig patterns for authority.
3. One real program per tier: a known immutable program (no upgrade path), a DAO-governed upgrade, and a single-key upgrade authority.

## Product-relevant questions

- **Who can change logic?** Single key, multisig, timelock, or none (immutable).
- **Is the program verified?** Explorer links, verified source, reproducible builds.
- **Data accounts:** PDA ownership and signer constraints that prevent arbitrary takeover when program upgrades.

## Diverg integration ideas (future)

- Surface **upgrade authority** and **immutable** flag in Solana depth / bundle context when RPC or indexer provides program account layout.
- Investigation narrative: “upgradeable program — confirm governance and timelock expectations with the project.”

## Outcome of this spike

- **Feasible:** Read-only enrichment from RPC `getAccountInfo` on the program account (loader-specific parsing required; not all deployments expose the same layout).
- **Non-trivial:** Reliable labeling across Custom / BPF Loader / Upgradeable loader variants and deprecated loaders; cache and rate limits on public RPC.
- **Recommendation:** Prototype one helper against mainnet-beta for a small allowlist of program IDs before generalizing.

## Exit criteria (spike done)

- This note exists; team agrees whether **v1** is “manual analyst checklist only” vs “automated RPC probe for top N programs.”
