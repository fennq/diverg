# Phase 2 context skills

Primary source lives in `docs/diagrams/phase2-context-flow.mmd`.

![Phase 2 context skills flow](phase2-context-flow.svg)

**SVG file:** [`phase2-context-flow.svg`](phase2-context-flow.svg) (open in browser or VS Code preview)

Use this in GitHub, Notion, or [mermaid.live](https://mermaid.live).

```mermaid
flowchart LR
  P2["Phase 2: Context Skills"] --> CI["Context Intake"]

  CI --> CS["client_surface JSON"]
  CI --> RJ["recon JSON"]
  CI --> OJ["osint JSON"]
  CI --> AJ["api_test JSON"]

  CS --> SE["Skill Execution"]
  RJ --> SE
  OJ --> SE
  AJ --> SE

  SE --> DA["dependency_audit"]
  SE --> LA["logic_abuse"]
  SE --> ER["entity_reputation"]

  DA --> FN["Finding Normalization"]
  LA --> FN
  ER --> FN

  FN --> C1["confidence: high/medium/low"]
  FN --> C2["source attribution"]
  FN --> C3["proof artifact"]
  FN --> C4["verified flag"]
  FN --> RO["Report Output"]

  RO --> R1["ordered findings with evidence"]
  RO --> R2["evidence summary"]
  RO --> R3["verified vs unverified counts"]
  RO --> R4["source breakdown"]
  RO --> DQ["Decision Quality"]

  DQ --> Q1["less noise"]
  DQ --> Q2["more factual signals"]
  DQ --> Q3["faster operator validation"]
```

Optional PNG export: `docs/assets/phase2-context-flow-diagram.png`
