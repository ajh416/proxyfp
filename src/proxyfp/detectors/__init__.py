from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProbeResult:
    target: str
    detector: str
    signal: str  # short identifier e.g. "glype", "favicon_match", "canary_egress"
    weight: float  # [0.0, 1.0] — confidence contributed by this detector
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_row(self, run_at: str) -> dict[str, Any]:
        return {
            "target": self.target,
            "detector": self.detector,
            "run_at": run_at,
            "signal": self.signal,
            "weight": self.weight,
            "evidence": self.evidence,
            "error": self.error,
        }
