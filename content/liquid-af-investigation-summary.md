# liquid.af — Investigation Summary (Website + Blockchain)

**Target:** https://liquid.af  
**Scope:** Full website scan + blockchain investigation (Solscan + Arkham).  
**Date:** 2026-03-12

---

## The bad stuff

### Website & app exposure

- **Admin surfaces wide open.** `/admin`, `/console`, `/dashboard`, `/backoffice`, `/administrator`, `/manage` all return 200. No auth required. Anyone can hit management-style endpoints.
- **Identity and login exposed.** `.well-known/jwks.json`, openid-configuration, `/auth/realms/master`, `/sso`, `/login`, `/oauth/authorize` are public. Easier recon for credential and token attacks.
- **Debug and observability public.** `__debug__/`, `/debug`, `/actuator`, `/actuator/env`, `/trace.axd`, `/debug/pprof`, `/metrics`, `/health`, `/grafana`, `/kibana`, `/actuator/prometheus`, `/status`. Internal state and metrics reachable from the internet.
- **API docs and schema public.** `/redoc`, `/graphql/schema`, `/openapi.json`, `/swagger`, `/swagger-ui.html`, `/v3/api-docs`. Full mapping of APIs for abuse.
- **Weak TLS.** Server still accepts TLS 1.0 and TLS 1.1. Deprecated and unsafe; intercept and downgrade risk.
- **Subdomains.** devnet, www, metadata, docs — more surface; metadata/docs can expose config or internal tooling.

### Blockchain side (Solscan + Arkham)

- **Launchpad = high risk.** liquid.af is a token-creation / launchpad-style platform. Launchpads are where sniper bots, liquidity pulls, and fee abuse show up. Our pipeline is built to flag: same wallet buying early across multiple tokens (sniper), deployer pulling LP (rug), and fee vs on-chain mismatch.
- **Connected wallets are the story.** The critical output is **linked wallets**: who sent funds to whom, who was funded by the same source, and who is linked through other wallets. Solscan gives us **token/transfer** and **account/transfer** (from/to, amount, time). Arkham gives us **counterparties** and **labels** (CEX, mixer, entity). So we can surface:
  - Wallets that **sent funds to each other** (direct flow).
  - Wallets **funded by the same source** (same deployer or same inflow).
  - Wallets **linked by other wallets** (intermediaries, same CEX, same mixer).
- **Why it matters.** Connected wallets = potential insiders, same bad actor, or off-ramp chain. One deployer paying multiple “retail” wallets, or many launch wallets funded by one source, is a red flag. We map that with Solscan + Arkham and put it in the flow diagram.
- **What we run.** Solscan Pro: token/transfer (per mint), account/transfer (deployer), token/holders, account/defi/activities (REMOVE_LIQ), token/meta (mint/freeze authority), account/balance_change (outflows). Arkham Intel: batch labels for deployer + sniper + holders, counterparties for deployer (who they send to / receive from). From that we build: **risk score**, **crime report**, **linked_wallets**, **flow_graph** (nodes = addresses, edges = transfers with amount/date). Any wallet tied to a main source (deployer, CEX, mixer) is included so the diagram shows who’s connected and how.

### Summary line

- **Web:** Open admin, identity, debug, and API docs; weak TLS; broad subdomain surface.
- **Chain:** Launchpad risk; connected wallets (sent to each other, same funder, or linked via others) are the major finding — Solscan + Arkham feed the flow and the tweet-ready diagrams.
