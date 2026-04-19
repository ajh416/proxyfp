from proxyfp.score import score_target


def test_canary_hit_forces_auto_submit():
    probes = [
        {"target": "http://x", "detector": "canary", "signal": "canary_emitted", "weight": 0.0,
         "evidence": {"nonce": "abc"}},
        {"target": "http://x", "detector": "landing", "signal": "no_match", "weight": 0.0, "evidence": {}},
    ]
    result = score_target(probes, canary_hits={"abc": [{"source_ip": "1.2.3.4"}]})
    assert result.score == 1.0
    assert result.bucket == "auto_submit"


def test_strong_landing_signal_auto_submits():
    probes = [
        {"target": "http://x", "detector": "landing", "signal": "glype", "weight": 0.95, "evidence": {}},
    ]
    result = score_target(probes)
    assert result.bucket == "auto_submit"


def test_weak_signals_go_to_review():
    probes = [
        {"target": "http://x", "detector": "landing", "signal": "generic_url_form", "weight": 0.45,
         "evidence": {}},
        {"target": "http://x", "detector": "favicon", "signal": "favicon_unknown", "weight": 0.3,
         "evidence": {}},
    ]
    result = score_target(probes)
    assert result.bucket == "review"


def test_nothing_drops():
    probes = [
        {"target": "http://x", "detector": "landing", "signal": "no_match", "weight": 0.0, "evidence": {}},
    ]
    result = score_target(probes)
    assert result.bucket == "drop"
