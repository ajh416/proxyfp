from pathlib import Path

from proxyfp.signatures.landing_patterns import match

FIXTURES = Path(__file__).parent / "fixtures"


def test_glype_is_detected():
    matches = match((FIXTURES / "glype.html").read_text())
    names = {m[0].name for m in matches}
    assert "glype" in names
    glype = next(m for m in matches if m[0].name == "glype")
    assert glype[0].weight >= 0.9


def test_phproxy_is_detected():
    matches = match((FIXTURES / "phproxy.html").read_text())
    names = {m[0].name for m in matches}
    assert "phproxy" in names


def test_github_is_not_flagged():
    matches = match((FIXTURES / "github.html").read_text())
    strong = [m for m in matches if m[0].weight >= 0.7]
    assert strong == []
