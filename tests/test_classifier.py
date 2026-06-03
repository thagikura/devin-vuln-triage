from app.classifier import VulnerabilityAlert, classify
from app.models import TriageCategory


def test_simple_bump_same_major():
    alert = VulnerabilityAlert(
        alert_number=1,
        repo="thagikura/superset-fork",
        package_name="pyjwt",
        ecosystem="pip",
        current_version="2.12.0",
        fix_version="2.13.0",
        severity="high",
        cve_ids=["PYSEC-2026-179"],
    )
    result = classify(alert)
    assert result.category == TriageCategory.SIMPLE_BUMP
    assert result.fix_version == "2.13.0"


def test_breaking_change_different_major():
    alert = VulnerabilityAlert(
        alert_number=2,
        repo="thagikura/superset-fork",
        package_name="flask",
        ecosystem="pip",
        current_version="2.3.3",
        fix_version="3.1.3",
        severity="medium",
        cve_ids=["CVE-2026-27205"],
    )
    result = classify(alert)
    assert result.category == TriageCategory.BREAKING_CHANGE
    assert "BREAKING" in result.recommended_action or "major" in result.recommended_action.lower()


def test_breaking_change_large_major_jump():
    alert = VulnerabilityAlert(
        alert_number=3,
        repo="thagikura/superset-fork",
        package_name="pyarrow",
        ecosystem="pip",
        current_version="20.0.0",
        fix_version="23.0.1",
        severity="medium",
        cve_ids=["PYSEC-2026-113"],
    )
    result = classify(alert)
    assert result.category == TriageCategory.BREAKING_CHANGE


def test_no_fix_null_version():
    alert = VulnerabilityAlert(
        alert_number=4,
        repo="thagikura/superset-fork",
        package_name="paramiko",
        ecosystem="pip",
        current_version="3.5.1",
        fix_version=None,
        severity="medium",
        cve_ids=["CVE-2026-44405"],
    )
    result = classify(alert)
    assert result.category == TriageCategory.NO_FIX
    assert result.fix_version is None


def test_no_fix_malware():
    alert = VulnerabilityAlert(
        alert_number=5,
        repo="thagikura/superset-fork",
        package_name="eslint-plugin-i18n-strings",
        ecosystem="npm",
        current_version="unknown",
        fix_version=None,
        severity="critical",
        cve_ids=["GHSA-55h3-fm53-wq99"],
    )
    result = classify(alert)
    assert result.category == TriageCategory.NO_FIX


def test_code_audit_override():
    alert = VulnerabilityAlert(
        alert_number=101,
        repo="thagikura/superset-fork",
        package_name="pickle.loads (unsafe deserialization)",
        ecosystem="pip",
        current_version="N/A",
        fix_version=None,
        severity="high",
        cve_ids=["CWE-502"],
        category_override="code_audit",
        vuln_description="Uses pickle.loads() for deserialization which allows RCE.",
    )
    result = classify(alert)
    assert result.category == TriageCategory.CODE_AUDIT
    assert result.vuln_description != ""


def test_code_audit_with_fix_version():
    """code_audit override takes precedence even if fix_version is set."""
    alert = VulnerabilityAlert(
        alert_number=102,
        repo="thagikura/superset-fork",
        package_name="yaml.load",
        ecosystem="pip",
        current_version="6.0",
        fix_version="6.1",
        severity="medium",
        cve_ids=["CWE-502"],
        category_override="code_audit",
    )
    result = classify(alert)
    assert result.category == TriageCategory.CODE_AUDIT


def test_vuln_description_propagated():
    """vuln_description passes through to TriageResult for all categories."""
    desc = "HMAC key confusion allows token forgery via public key."
    alert = VulnerabilityAlert(
        alert_number=1,
        repo="test/repo",
        package_name="pyjwt",
        ecosystem="pip",
        current_version="2.12.0",
        fix_version="2.13.0",
        severity="high",
        cve_ids=["PYSEC-2026-179"],
        vuln_description=desc,
    )
    result = classify(alert)
    assert result.category == TriageCategory.SIMPLE_BUMP
    assert result.vuln_description == desc


def test_invalid_version_falls_to_breaking():
    alert = VulnerabilityAlert(
        alert_number=99,
        repo="test/repo",
        package_name="weird-pkg",
        ecosystem="pip",
        current_version="not-a-version",
        fix_version="also-not-a-version",
        severity="low",
        cve_ids=[],
    )
    result = classify(alert)
    assert result.category == TriageCategory.BREAKING_CHANGE
