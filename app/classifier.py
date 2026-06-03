import logging
import re

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel

from app.models import TriageCategory

logger = logging.getLogger(__name__)


class VulnerabilityAlert(BaseModel):
    alert_number: int
    repo: str
    package_name: str
    ecosystem: str
    manifest_path: str | None = None
    current_version: str = "unknown"
    fix_version: str | None = None
    severity: str = "unknown"
    cve_ids: list[str] = []
    advisory_url: str | None = None
    summary: str = ""
    vuln_description: str = ""
    category_override: str | None = None


class TriageResult(BaseModel):
    category: TriageCategory
    package_name: str
    ecosystem: str
    current_version: str
    fix_version: str | None
    cve_ids: list[str]
    severity: str
    advisory_url: str | None
    recommended_action: str
    vuln_description: str = ""


def classify(alert: VulnerabilityAlert) -> TriageResult:
    if alert.category_override == "code_audit":
        return TriageResult(
            category=TriageCategory.CODE_AUDIT,
            package_name=alert.package_name,
            ecosystem=alert.ecosystem,
            current_version=alert.current_version,
            fix_version=alert.fix_version,
            cve_ids=alert.cve_ids,
            severity=alert.severity,
            advisory_url=alert.advisory_url,
            recommended_action=(
                f"Code-level fix required for {alert.package_name}. "
                "Audit the codebase for the insecure pattern and remediate."
            ),
            vuln_description=alert.vuln_description,
        )

    if not alert.fix_version:
        return TriageResult(
            category=TriageCategory.NO_FIX,
            package_name=alert.package_name,
            ecosystem=alert.ecosystem,
            current_version=alert.current_version,
            fix_version=None,
            cve_ids=alert.cve_ids,
            severity=alert.severity,
            advisory_url=alert.advisory_url,
            recommended_action=(
                f"No fix available for {alert.package_name}. "
                "Investigate codebase exposure, assess risk, and recommend workarounds."
            ),
            vuln_description=alert.vuln_description,
        )

    try:
        current = Version(alert.current_version)
        fix = Version(alert.fix_version)
    except InvalidVersion:
        return TriageResult(
            category=TriageCategory.BREAKING_CHANGE,
            package_name=alert.package_name,
            ecosystem=alert.ecosystem,
            current_version=alert.current_version,
            fix_version=alert.fix_version,
            cve_ids=alert.cve_ids,
            severity=alert.severity,
            advisory_url=alert.advisory_url,
            recommended_action=(
                f"Upgrade {alert.package_name} from {alert.current_version} "
                f"to {alert.fix_version}. Version comparison failed — treat as breaking change."
            ),
            vuln_description=alert.vuln_description,
        )

    if current.major == fix.major:
        return TriageResult(
            category=TriageCategory.SIMPLE_BUMP,
            package_name=alert.package_name,
            ecosystem=alert.ecosystem,
            current_version=alert.current_version,
            fix_version=alert.fix_version,
            cve_ids=alert.cve_ids,
            severity=alert.severity,
            advisory_url=alert.advisory_url,
            recommended_action=(
                f"Bump {alert.package_name} from {alert.current_version} "
                f"to {alert.fix_version} (same major version)."
            ),
            vuln_description=alert.vuln_description,
        )

    return TriageResult(
        category=TriageCategory.BREAKING_CHANGE,
        package_name=alert.package_name,
        ecosystem=alert.ecosystem,
        current_version=alert.current_version,
        fix_version=alert.fix_version,
        cve_ids=alert.cve_ids,
        severity=alert.severity,
        advisory_url=alert.advisory_url,
        recommended_action=(
            f"Upgrade {alert.package_name} from {alert.current_version} "
            f"to {alert.fix_version} (BREAKING — major version change "
            f"{current.major} → {fix.major}). Check CHANGELOG for migration notes."
        ),
    )


_VERSION_RE = re.compile(r"(\d+\.\d+[\.\d]*)")


def _extract_lower_bound(version_range: str) -> str:
    """Extract the lower-bound version from a vulnerable_version_range string.

    Examples: ">= 2.0.0, < 2.13.0" → "2.0.0", "< 3.1.3" → "unknown"
    """
    if not version_range:
        return "unknown"
    parts = [p.strip() for p in version_range.split(",")]
    for part in parts:
        if ">=" in part:
            m = _VERSION_RE.search(part)
            if m:
                return m.group(1)
    return "unknown"


def parse_dependabot_payload(payload: dict) -> VulnerabilityAlert | None:
    """Parse a GitHub dependabot_alert webhook payload into a VulnerabilityAlert."""
    action = payload.get("action")
    if action not in ("created", "reopened", "reintroduced"):
        logger.info("Ignoring dependabot_alert action: %s", action)
        return None

    alert_data = payload.get("alert", {})
    dep = alert_data.get("dependency", {})
    pkg = dep.get("package", {})
    advisory = alert_data.get("security_advisory", {})
    vuln = alert_data.get("security_vulnerability", {})
    repo = payload.get("repository", {}).get("full_name", "")

    fix_version = None
    patched = vuln.get("first_patched_version")
    if patched and isinstance(patched, dict):
        fix_version = patched.get("identifier")

    cve_ids = []
    cve_id = advisory.get("cve_id")
    if cve_id:
        cve_ids.append(cve_id)
    ghsa_id = advisory.get("ghsa_id")
    if ghsa_id:
        cve_ids.append(ghsa_id)

    current_version = _extract_lower_bound(vuln.get("vulnerable_version_range", ""))

    return VulnerabilityAlert(
        alert_number=alert_data.get("number", 0),
        repo=repo,
        package_name=pkg.get("name", "unknown"),
        ecosystem=pkg.get("ecosystem", "unknown"),
        manifest_path=dep.get("manifest_path"),
        current_version=current_version,
        fix_version=fix_version,
        severity=advisory.get("severity", vuln.get("severity", "unknown")),
        cve_ids=cve_ids,
        advisory_url=advisory.get("permalink", ""),
        summary=advisory.get("summary", ""),
        vuln_description=advisory.get("description", ""),
    )
