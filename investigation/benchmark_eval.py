from __future__ import annotations

from dataclasses import dataclass
from typing import Any


_TIER_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def _safe_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def extract_confidence_features(bundle_signals: dict[str, Any]) -> dict[str, Any]:
    cm = bundle_signals.get("confidence_model") if isinstance(bundle_signals, dict) else {}
    if not isinstance(cm, dict):
        cm = {}
    observed = _safe_list(cm.get("observed_signals"))
    corroborated = _safe_list(cm.get("corroborated_signals"))
    high_conf = _safe_list(cm.get("high_confidence_signals"))
    tier = str(cm.get("tier") or "none").strip().lower()
    if tier not in _TIER_ORDER:
        tier = "none"
    return {
        "tier": tier,
        "observed_count": len(observed),
        "corroborated_count": len(corroborated),
        "high_conf_count": len(high_conf),
        "observed_signals": observed,
        "corroborated_signals": corroborated,
        "high_conf_signals": high_conf,
    }


def passes_threshold(features: dict[str, Any], threshold: str) -> bool:
    t = str(threshold or "").strip().lower()
    if t == "observed":
        return int(features.get("observed_count") or 0) > 0 or _TIER_ORDER.get(str(features.get("tier") or "none"), 0) >= 1
    if t == "corroborated":
        return int(features.get("corroborated_count") or 0) > 0 or _TIER_ORDER.get(str(features.get("tier") or "none"), 0) >= 2
    if t == "high_confidence":
        return int(features.get("high_conf_count") or 0) > 0 or _TIER_ORDER.get(str(features.get("tier") or "none"), 0) >= 3
    raise ValueError(f"Unknown threshold: {threshold}")


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def as_dict(self) -> dict[str, Any]:
        p = self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0
        r = self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0
        f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": round(p, 6),
            "recall": round(r, 6),
            "f1": round(f1, 6),
        }


def update_confusion(conf: Confusion, *, expected_positive: bool, predicted_positive: bool) -> None:
    if expected_positive and predicted_positive:
        conf.tp += 1
    elif (not expected_positive) and predicted_positive:
        conf.fp += 1
    elif expected_positive and (not predicted_positive):
        conf.fn += 1
    else:
        conf.tn += 1

