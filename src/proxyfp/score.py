"""Score targets based on their probes.

Rules:
  * score = max(detector weight), plus +0.1 if two or more weak signals agree.
  * Output buckets:
      - score >= 0.8 and strong-signal present -> auto_submit
      - 0.5 <= score < 0.8                     -> review
      - score < 0.5                            -> drop
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

AUTO_THRESHOLD = 0.8
REVIEW_THRESHOLD = 0.5
STRONG_WEIGHT = 0.85


@dataclass
class Scored:
    target: str
    score: float
    bucket: str  # "auto_submit" | "review" | "drop"
    contributing: list[dict[str, Any]]


def score_target(probes: list[dict[str, Any]]) -> Scored:
    target = probes[0]["target"]

    weights = [(p["detector"], p["signal"], float(p.get("weight", 0.0))) for p in probes]
    max_w = max((w for _, _, w in weights), default=0.0)
    strong = any(w >= STRONG_WEIGHT for _, _, w in weights)
    corroborators = sum(1 for _, _, w in weights if 0.3 <= w < STRONG_WEIGHT)
    bonus = 0.1 if corroborators >= 2 else 0.0
    score = min(1.0, max_w + bonus)

    if score >= AUTO_THRESHOLD and strong:
        bucket = "auto_submit"
    elif score >= REVIEW_THRESHOLD:
        bucket = "review"
    else:
        bucket = "drop"

    return Scored(
        target=target,
        score=score,
        bucket=bucket,
        contributing=[{"detector": d, "signal": s, "weight": w} for d, s, w in weights if w > 0],
    )


def group_by_target(probes: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for p in probes:
        out[p["target"]].append(p)
    return out
