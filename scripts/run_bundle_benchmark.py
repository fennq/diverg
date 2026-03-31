#!/usr/bin/env python3
"""
Run Solana bundle benchmark packs and emit evidence-backed metrics.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class SignalEval:
    signal: str
    expected: bool
    predicted: bool
    outcome: str


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        t = line.strip()
        if not t:
            continue
        out.append(json.loads(t))
    return out


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(json.dumps(r, ensure_ascii=True) for r in rows)
    path.write_text(body + ("\n" if body else ""), encoding="utf-8")


def _safe_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return bool(v)


def _predict_from_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    bs = snapshot.get("bundle_signals") or {}
    fcbm = bs.get("funding_cluster_bridge_mixer") or {}
    cm = bs.get("confidence_model") or {}
    wash = bs.get("wash_flow_patterns") or {}
    return {
        "bundle_present": float(bs.get("coordination_score") or 0.0) >= 25.0,
        "bridge_path_present": int(fcbm.get("wallets_with_bridge_touching_funder") or 0) >= 1,
        "mixer_path_present": int(fcbm.get("wallets_with_mixer_touching_funder") or 0) >= 1,
        "wash_flow_present": int(wash.get("pattern_count") or 0) >= 1,
        "confidence_tier": str(cm.get("tier") or "low"),
        "coordination_score": float(bs.get("coordination_score") or 0.0),
    }


def _eval_signal(signal: str, expected: bool, predicted: bool) -> SignalEval:
    if expected and predicted:
        outcome = "tp"
    elif (not expected) and predicted:
        outcome = "fp"
    elif expected and (not predicted):
        outcome = "fn"
    else:
        outcome = "tn"
    return SignalEval(signal=signal, expected=expected, predicted=predicted, outcome=outcome)


def _tier_pr(expected: list[bool], predicted: list[bool]) -> dict[str, float]:
    tp = sum(1 for e, p in zip(expected, predicted) if e and p)
    fp = sum(1 for e, p in zip(expected, predicted) if (not e) and p)
    fn = sum(1 for e, p in zip(expected, predicted) if e and (not p))
    precision = (tp / (tp + fp)) if (tp + fp) else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(precision, 4), "recall": round(recall, 4)}


def build_report(rows: list[dict[str, Any]]) -> dict[str, Any]:
    signals = ("bundle_present", "bridge_path_present", "mixer_path_present", "wash_flow_present")
    signal_metrics: dict[str, dict[str, float]] = {}
    for s in signals:
        exp = [_safe_bool((r.get("expected") or {}).get(s)) for r in rows]
        pred = [_safe_bool((r.get("predicted") or {}).get(s)) for r in rows]
        signal_metrics[s] = _tier_pr(exp, pred)

    tiers = ("low", "medium", "high")
    tier_metrics: dict[str, dict[str, float]] = {}
    for t in tiers:
        subset = [r for r in rows if str((r.get("predicted") or {}).get("confidence_tier") or "low") == t]
        if not subset:
            tier_metrics[t] = {"cases": 0, "bundle_precision": 0.0, "bundle_recall": 0.0}
            continue
        exp = [_safe_bool((r.get("expected") or {}).get("bundle_present")) for r in subset]
        pred = [_safe_bool((r.get("predicted") or {}).get("bundle_present")) for r in subset]
        pr = _tier_pr(exp, pred)
        tier_metrics[t] = {"cases": len(subset), "bundle_precision": pr["precision"], "bundle_recall": pr["recall"]}

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case_count": len(rows),
        "signal_metrics": signal_metrics,
        "confidence_tier_metrics": tier_metrics,
        "needs_adjudication_count": sum(1 for r in rows if r.get("needs_adjudication")),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Run bundle benchmark + queue.")
    ap.add_argument("--cases", required=True)
    ap.add_argument("--results-out", required=True)
    ap.add_argument("--report-out", required=True)
    ap.add_argument("--queue-out", required=True)
    args = ap.parse_args()

    cases = _read_jsonl(Path(args.cases))
    results: list[dict[str, Any]] = []
    queue: list[dict[str, Any]] = []

    for case in cases:
        cid = str(case.get("case_id") or "").strip()
        expected = case.get("expected") or {}
        snapshot = case.get("snapshot") if isinstance(case.get("snapshot"), dict) else {"ok": False, "error": "missing snapshot"}
        pred = _predict_from_snapshot(snapshot if isinstance(snapshot, dict) else {})
        sig_outcomes: list[dict[str, Any]] = []
        needs_adj = False
        for s in ("bundle_present", "bridge_path_present", "mixer_path_present", "wash_flow_present"):
            se = _eval_signal(s, _safe_bool(expected.get(s)), _safe_bool(pred.get(s)))
            sig_outcomes.append(se.__dict__)
            if se.outcome in ("fp", "fn"):
                needs_adj = True
                queue.append({
                    "queue_id": f"{cid}:{s}",
                    "case_id": cid,
                    "signal": s,
                    "expected": se.expected,
                    "predicted": se.predicted,
                    "outcome": se.outcome,
                    "status": "pending",
                    "adjudication": None,
                })
        exp_tier = str(expected.get("confidence_tier") or "").strip().lower()
        pred_tier = str(pred.get("confidence_tier") or "").strip().lower()
        if exp_tier and pred_tier and exp_tier != pred_tier:
            needs_adj = True
            queue.append({
                "queue_id": f"{cid}:confidence_tier",
                "case_id": cid,
                "signal": "confidence_tier",
                "expected": exp_tier,
                "predicted": pred_tier,
                "outcome": "mismatch",
                "status": "pending",
                "adjudication": None,
            })
        results.append({
            "case_id": cid,
            "mint": case.get("mint"),
            "wallet": case.get("wallet"),
            "expected": expected,
            "predicted": pred,
            "signal_outcomes": sig_outcomes,
            "needs_adjudication": needs_adj,
            "snapshot_ok": bool(snapshot.get("ok")) if isinstance(snapshot, dict) else False,
            "snapshot_error": snapshot.get("error") if isinstance(snapshot, dict) else "invalid snapshot",
        })

    report = build_report(results)
    _write_jsonl(Path(args.results_out), results)
    Path(args.report_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report_out).write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    _write_jsonl(Path(args.queue_out), queue)
    print(json.dumps(report, ensure_ascii=True))


if __name__ == "__main__":
    main()

