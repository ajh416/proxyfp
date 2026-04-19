from pathlib import Path

from proxyfp import store


def test_append_and_read_roundtrip(tmp_path: Path):
    p = tmp_path / "probes.jsonl"
    store.append(p, {"target": "http://a", "detector": "x", "weight": 0.5})
    store.append(p, {"target": "http://b", "detector": "y", "weight": 0.0})

    rows = list(store.read(p))
    assert [r["target"] for r in rows] == ["http://a", "http://b"]


def test_partial_trailing_line_is_tolerated(tmp_path: Path):
    p = tmp_path / "probes.jsonl"
    p.write_text('{"target":"ok","detector":"d"}\n{"target":"broken"')
    rows = list(store.read(p))
    assert len(rows) == 1
    assert rows[0]["target"] == "ok"


def test_load_keys(tmp_path: Path):
    p = tmp_path / "probes.jsonl"
    store.append(p, {"target": "a", "detector": "x"})
    store.append(p, {"target": "b", "detector": "x"})
    store.append(p, {"target": "a", "detector": "y"})

    keys = store.load_keys(p, "target", "detector")
    assert keys == {("a", "x"), ("b", "x"), ("a", "y")}
