import logging

import httpx

from app.classifier import TriageResult
from app.config import settings
from app.models import TriageCategory

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompt templates
#
# These prompts differentiate Devin from Dependabot by requiring
# codebase-level reasoning — not just version bumps.  Each template asks
# Devin to: (1) understand the vulnerability, (2) audit the code for the
# specific vulnerable pattern, (3) make targeted changes, and (4) prove
# the fix in the PR description.
# ---------------------------------------------------------------------------

PROMPT_SIMPLE_BUMP = """\
You are a security engineer remediating a vulnerability in {repo}.

## Vulnerability

| Field | Value |
|-------|-------|
| Package | {package_name} |
| CVE(s) | {cve_ids} |
| Severity | {severity} |
| Ecosystem | {ecosystem} |
| Manifest | {manifest_path} |
| Fix version | {fix_version} |

{vuln_description}

## Your task — Bump + Audit

A simple version bump fixes this at the library level, but you must also
verify the codebase is not using the *specific vulnerable pattern* described
above.  Dependabot can bump a version number; you need to prove the code
is safe.

### Step 1: Upgrade the dependency
- Update {package_name} to {fix_version} in all relevant files \
(requirements/*.txt, pyproject.toml, setup.cfg, package.json, etc.).
- For Python: update every pinned requirements file that references \
{package_name} (base.txt, development.txt, etc.).
- For npm: run `npm install` / `yarn install` to update the lockfile.

### Step 2: Audit the codebase for the vulnerable pattern
- Search for all imports and usages of {package_name}.
- For each call site, check whether it exercises the vulnerable code path \
described in the CVE details above.
- Document each call site you inspected and whether it was affected.

### Step 3: Harden the code (if applicable)
- If any call site lacks recommended safeguards (e.g. algorithm pinning, \
input validation, explicit parameter settings), add them — even if the \
version bump alone resolves the CVE.
- Add inline code comments citing the CVE where you make defensive changes.

### Step 4: Test
- Run the project's test suite.  Fix any regressions.
- If the repo has no test for the affected code path, add a targeted test \
that would fail against the old vulnerable version.

### Step 5: Create the PR
- Title: `fix(security): bump {package_name} to {fix_version} + audit \
({cve_ids})`
- PR body must include:
  - **Vulnerability summary** — one paragraph describing the CVE.
  - **Affected call sites** — table of file:line, function, and whether \
the pattern was vulnerable.
  - **Changes made** — version bump AND any code hardening.
  - **Test results** — paste or link the relevant test output.
"""

PROMPT_BREAKING_CHANGE = """\
You are a security engineer performing a breaking-change migration in {repo}.

## Vulnerability

| Field | Value |
|-------|-------|
| Package | {package_name} |
| CVE(s) | {cve_ids} |
| Severity | {severity} |
| Ecosystem | {ecosystem} |
| Manifest | {manifest_path} |
| Fix version | {fix_version} (MAJOR version bump — breaking change) |

{vuln_description}

## Your task — Full Migration

This is a major-version upgrade.  The fix *cannot* be a one-line version \
bump; you must migrate the codebase to the new API surface.

### Step 1: Research the breaking changes
- Read the CHANGELOG / release notes / migration guide for {package_name} \
from the current version to {fix_version}.
- List every breaking change that is relevant to this codebase.

### Step 2: Inventory usage across the codebase
- `grep -rn` for all imports of {package_name} and its submodules.
- For each file, note which APIs are used and whether they changed.
- Pay special attention to:
  - Removed or renamed functions/classes
  - Changed function signatures or default values
  - Removed compatibility shims
  - Changed behavior (e.g. stricter validation, different return types)

### Step 3: Perform the migration
- Update {package_name} to {fix_version} in all dependency files.
- For **every** affected call site found in Step 2:
  - Update imports.
  - Migrate deprecated API calls to their replacements.
  - Handle any behavioral changes (e.g. new exceptions, changed defaults).
- Update related dependencies that might need to be co-upgraded.

### Step 4: Test and fix
- Run the full test suite.  Expect failures — fix them.
- If tests import or mock parts of {package_name}, update those too.
- Run linters / type checkers if configured.

### Step 5: Create the PR
- Title: `fix(security): upgrade {package_name} to {fix_version} \
[BREAKING] ({cve_ids})`
- PR body must include:
  - **Vulnerability summary** — what the CVE is and why a major upgrade \
is required.
  - **Breaking changes encountered** — list with before/after code.
  - **Files modified** — grouped by type of change (import fix, API \
migration, test update).
  - **Migration risks** — anything you could not fully verify.
  - **Test results** — paste or link output.
"""

PROMPT_NO_FIX = """\
You are a security engineer investigating a vulnerability in {repo} \
that has **no available fix**.

## Vulnerability

| Field | Value |
|-------|-------|
| Package | {package_name} |
| CVE(s) | {cve_ids} |
| Severity | {severity} |
| Ecosystem | {ecosystem} |
| Advisory | {advisory_url} |

{vuln_description}

## Your task — Deep Exposure Analysis

No patched version exists, so the goal is a thorough codebase audit \
that a human engineer can act on.

### Step 1: Map all usage of {package_name}
- Find every import and transitive usage.
- For each call site, document: file, line, function, and what it does.

### Step 2: Assess exposure for each call site
- Is the vulnerable code path reachable from user-controlled input?
- Is it reachable in production, or only in dev/test/CI?
- What permissions / authentication are required to reach it?
- Could an attacker trigger the vulnerable behavior?

### Step 3: Research alternatives and workarounds
- Are there drop-in replacement packages?
- Can the dependency be removed entirely?
- Are there configuration changes or wrapper functions that mitigate \
the risk without replacing the package?
- Check if upstream has a planned fix timeline.

### Step 4: Produce a risk assessment PR
- Create a `SECURITY_ASSESSMENT_{package_name}.md` file in the repo root \
(or a `docs/security/` directory if one exists) with:
  - **Executive summary** — 2-3 sentence risk statement.
  - **Affected code paths** — table of file:line, reachability, and risk.
  - **Risk rating** — Critical / High / Medium / Low for this specific \
codebase (may differ from the CVE's generic severity).
  - **Recommended actions** — ordered by effort and impact.
  - **Decision needed** — clearly state what a human engineer must decide.
- Title: `docs(security): risk assessment for {package_name} ({cve_ids})`
"""

PROMPT_CODE_AUDIT = """\
You are a security engineer fixing a code-level vulnerability in {repo}.

## Vulnerability

| Field | Value |
|-------|-------|
| Pattern | {package_name} |
| CVE(s) / ID | {cve_ids} |
| Severity | {severity} |
| Category | Code-level — no version bump fixes this |

{vuln_description}

## Your task — Fix the Code

This is not a dependency version issue.  The vulnerability is in how the \
application *uses* a library or implements a pattern.  Dependabot cannot \
detect or fix this.

### Step 1: Understand the vulnerability
- Read the description above carefully.
- Identify the specific insecure pattern (e.g. unsafe deserialization, \
weak hashing, missing input validation).

### Step 2: Find all instances in the codebase
- Search for the vulnerable pattern across the entire codebase.
- Document every instance: file, line number, surrounding context.
- Check whether each instance is reachable from untrusted input.

### Step 3: Implement the fix
- Replace the insecure pattern with its safe alternative.
- Preserve backward compatibility where possible.
- If a migration is needed (e.g. changing a serialization format), \
implement it or add a compatibility layer.
- Add inline code comments explaining the security rationale.

### Step 4: Test
- Run existing tests — ensure nothing breaks.
- Add a new test that exercises the fix (e.g. verifying that the \
unsafe path is no longer reachable or raises an error).

### Step 5: Create the PR
- Title: `fix(security): remediate {package_name} ({cve_ids})`
- PR body must include:
  - **Vulnerability description** — what the insecure pattern is.
  - **Instances found** — table of file:line and fix applied.
  - **Fix approach** — why this approach was chosen over alternatives.
  - **Backward compatibility** — any risks or migration steps.
  - **Test results**.
"""

PROMPT_LIBRARY_REPLACEMENT = """\
You are a security engineer replacing a vulnerable library in {repo}.

## Vulnerability

| Field | Value |
|-------|-------|
| Package (remove) | {package_name} |
| Replace with | {alternative_package} |
| CVE(s) | {cve_ids} |
| Severity | {severity} |
| Ecosystem | {ecosystem} |
| Manifest | {manifest_path} |

{vuln_description}

## Your task — Library Replacement

There is no safe version of {package_name} available.  Instead of filing \
an issue for a human to deal with, you will **replace it** with \
{alternative_package} and prove the migration works.

### Step 1: Understand the API surface of {package_name}
- Search for every import and usage of {package_name} across the codebase.
- For each call site, document: file, line, function/class, and how \
the library is used (which API, what arguments, what return type).

### Step 2: Research the replacement library
- Read the docs for {alternative_package}.
- Map each {package_name} API call to its {alternative_package} equivalent.
- Identify any behavioral differences (defaults, exceptions, edge cases).

### Step 3: Perform the migration
- Remove {package_name} from all dependency files \
(requirements/*.txt, pyproject.toml, setup.cfg, package.json, etc.).
- Add {alternative_package} to the same dependency files.
- For **every** call site found in Step 1:
  - Update imports.
  - Migrate API calls to {alternative_package} equivalents.
  - Handle any behavioral differences.
- Add inline comments where the migration is non-obvious.

### Step 4: Test thoroughly
- Run the full test suite.  Fix any failures.
- If tests mock or patch {package_name}, update them to use \
{alternative_package}.
- If no tests exist for the affected code paths, add targeted tests.

### Step 5: Create the PR
- Title: `fix(security): replace {package_name} with \
{alternative_package} ({cve_ids})`
- PR body must include:
  - **Why**: {package_name} has an unfixed vulnerability — \
no patched version exists.
  - **Migration map**: table of {package_name} API → {alternative_package} \
API for every call site changed.
  - **Files modified**: grouped by type of change.
  - **Behavioral differences**: any subtle changes in behavior \
(e.g. different defaults, changed exception types).
  - **Test results**: paste or link output.
"""

PROMPTS = {
    TriageCategory.SIMPLE_BUMP: PROMPT_SIMPLE_BUMP,
    TriageCategory.BREAKING_CHANGE: PROMPT_BREAKING_CHANGE,
    TriageCategory.NO_FIX: PROMPT_NO_FIX,
    TriageCategory.CODE_AUDIT: PROMPT_CODE_AUDIT,
    TriageCategory.LIBRARY_REPLACEMENT: PROMPT_LIBRARY_REPLACEMENT,
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
        vuln_description=triage.vuln_description or "",
        alternative_package=triage.alternative_package or "(see description)",
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
