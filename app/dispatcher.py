import logging

import httpx

from app.classifier import TriageResult
from app.config import settings
from app.models import TriageCategory

logger = logging.getLogger(__name__)

PROMPT_SIMPLE_BUMP = """You are remediating a security vulnerability in the repository {repo}.

Vulnerability: {cve_ids} in {package_name}
Fix: Upgrade to {fix_version}
Severity: {severity}
Ecosystem: {ecosystem}
Manifest: {manifest_path}

Instructions:
1. Find the current version of {package_name} in the repository (check {manifest_path} or dependency files)
2. Update {package_name} to {fix_version}
3. If Python (pip ecosystem): update the pinned version in requirements files
4. If npm: run npm install to update the lockfile
5. Run the relevant test suite to verify no regressions
6. Create a PR titled "fix(security): bump {package_name} to {fix_version} ({cve_ids})"
7. In the PR description, reference the CVE(s) and explain the vulnerability
"""

PROMPT_BREAKING_CHANGE = """You are remediating a security vulnerability in the repository {repo} that requires a MAJOR version upgrade.

Vulnerability: {cve_ids} in {package_name}
Fix: Upgrade to {fix_version} (BREAKING CHANGE — major version bump)
Severity: {severity}
Ecosystem: {ecosystem}
Manifest: {manifest_path}

Instructions:
1. Check the CHANGELOG or release notes for {package_name} {fix_version} for breaking changes
2. Find and note the current version of {package_name} in the repository
3. Update {package_name} to {fix_version} in the dependency files
4. Search the codebase for usage of {package_name} APIs that may have changed
5. Update any code that uses deprecated or changed APIs
6. Run the test suite and fix any failures caused by the upgrade
7. Create a PR titled "fix(security): upgrade {package_name} to {fix_version} [BREAKING] ({cve_ids})"
8. In the PR description, document:
   - The vulnerability being fixed
   - Breaking changes encountered
   - Code migrations performed
   - Test results
"""

PROMPT_NO_FIX = """You are investigating a security vulnerability in the repository {repo} that has NO available fix.

Vulnerability: {cve_ids} in {package_name}
Status: No patched version available
Severity: {severity}
Ecosystem: {ecosystem}
Advisory: {advisory_url}

Instructions:
1. Analyze how {package_name} is used in this codebase (grep for imports and usage patterns)
2. Assess the exposure: is the vulnerable code path reachable in production?
3. Research if there are alternative packages or workarounds
4. Create a PR that adds a comment or documentation about the vulnerability with:
   - Exposure analysis (which files/functions use the vulnerable API)
   - Risk level for this specific codebase
   - Recommended workarounds or alternative packages
   - Whether the dependency can be removed or replaced
5. Title the PR "docs(security): risk assessment for {package_name} ({cve_ids})"
"""

PROMPTS = {
    TriageCategory.SIMPLE_BUMP: PROMPT_SIMPLE_BUMP,
    TriageCategory.BREAKING_CHANGE: PROMPT_BREAKING_CHANGE,
    TriageCategory.NO_FIX: PROMPT_NO_FIX,
}


def build_prompt(triage: TriageResult, repo: str, manifest_path: str | None = None) -> str:
    template = PROMPTS[triage.category]
    return template.format(
        repo=repo,
        package_name=triage.package_name,
        fix_version=triage.fix_version or "N/A",
        cve_ids=", ".join(triage.cve_ids) if triage.cve_ids else "N/A",
        severity=triage.severity,
        ecosystem=triage.ecosystem,
        manifest_path=manifest_path or "dependency files",
        advisory_url=triage.advisory_url or "N/A",
    )


async def create_devin_session(
    prompt: str,
) -> dict:
    """Create a Devin session via the v3 API. Returns {session_id, url, status}."""
    url = f"{settings.devin_api_base_url}/organizations/{settings.devin_org_id}/sessions"
    headers = {
        "Authorization": f"Bearer {settings.devin_api_token}",
        "Content-Type": "application/json",
    }
    body = {"prompt": prompt}

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        logger.info("Created Devin session: %s", data.get("session_id"))
        return data


async def get_devin_session(session_id: str) -> dict:
    """Poll a Devin session for its current status."""
    url = (
        f"{settings.devin_api_base_url}/organizations/{settings.devin_org_id}"
        f"/sessions/{session_id}"
    )
    headers = {"Authorization": f"Bearer {settings.devin_api_token}"}

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        return resp.json()
