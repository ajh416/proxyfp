from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

STATE_DIR = Path("state")
PROBES = STATE_DIR / "probes.jsonl"
SUBMISSIONS = STATE_DIR / "submissions.jsonl"
REVIEW = STATE_DIR / "review.jsonl"


def append(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, separators=(",", ":"), sort_keys=True))
        f.write("\n")


def read(path: Path) -> Iterator[dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                # Partial trailing line from a crash; tolerate silently.
                continue


def load_keys(path: Path, *fields: str) -> set[tuple]:
    """Load a set of tuples of the given fields from an existing JSONL file."""
    return {tuple(row.get(f) for f in fields) for row in read(path)}
