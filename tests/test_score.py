from proxyfp.score import score_target


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
