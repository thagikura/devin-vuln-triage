import json

from app.classifier import _extract_lower_bound, parse_dependabot_payload


def test_parse_created_alert():
    with open("examples/pyjwt-alert.json") as f:
        payload = json.load(f)

    alert = parse_dependabot_payload(payload)
    assert alert is not None
    assert alert.package_name == "pyjwt"
    assert alert.ecosystem == "pip"
    assert alert.fix_version == "2.13.0"
    assert alert.current_version == "2.0.0"
    assert alert.severity == "high"
    assert alert.repo == "thagikura/superset-fork"
    assert "PYSEC-2026-179" in alert.cve_ids


def test_parse_no_fix_alert():
    with open("examples/paramiko-alert.json") as f:
        payload = json.load(f)

    alert = parse_dependabot_payload(payload)
    assert alert is not None
    assert alert.package_name == "paramiko"
    assert alert.fix_version is None


def test_parse_malware_alert():
    with open("examples/eslint-malware-alert.json") as f:
        payload = json.load(f)

    alert = parse_dependabot_payload(payload)
    assert alert is not None
    assert alert.package_name == "eslint-plugin-i18n-strings"
    assert alert.severity == "critical"
    assert alert.fix_version is None


def test_ignore_dismissed_action():
    payload = {"action": "dismissed", "alert": {}, "repository": {"full_name": "test/repo"}}
    alert = parse_dependabot_payload(payload)
    assert alert is None


def test_parse_breaking_change_alert():
    with open("examples/flask-alert.json") as f:
        payload = json.load(f)

    alert = parse_dependabot_payload(payload)
    assert alert is not None
    assert alert.package_name == "flask"
    assert alert.fix_version == "3.1.3"
    assert alert.current_version == "2.0.0"


def test_extract_lower_bound():
    assert _extract_lower_bound(">= 2.0.0, < 2.13.0") == "2.0.0"
    assert _extract_lower_bound(">= 20.0.0, < 23.0.1") == "20.0.0"
    assert _extract_lower_bound("< 3.1.3") == "unknown"
    assert _extract_lower_bound("") == "unknown"
