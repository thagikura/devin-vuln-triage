# Devin Vulnerability Triage

Event-driven security vulnerability auto-triage using the [Devin API](https://docs.devin.ai/api-reference/overview). Listens for GitHub Dependabot alerts, classifies vulnerabilities, and dispatches autonomous Devin sessions to remediate them.

## Problem

Dependabot finds vulnerabilities but someone still has to fix them. For large codebases like [Apache Superset](https://github.com/apache/superset), security alerts pile up and require different handling depending on severity and fix complexity. This system automates the entire remediation pipeline.

## How It Works

```
GitHub Dependabot        Webhook Listener        Triage Classifier
(automatic scanning)  →  (FastAPI)            →  (simple/breaking/no-fix)
                                                       │
                              ┌─────────────────────────┤
                              │                         │
                    Fix available?              No fix available?
                              │                         │
                              ▼                         ▼
                  Devin Session Dispatcher     GitHub Issue Creator
                  → Creates PR via Devin API   → Escalates to human engineer
                              │
                              ▼
                  Session Monitor ──→ Polls status, tracks PRs
                              │
                              ▼
                  CLI / Dashboard ──→ Pipeline metrics & alert status
```

### Triage Categories

| Category | Criteria | Action |
|----------|----------|--------|
| **simple_bump** | Fix exists, same major version | **Devin creates PR** — bumps version, runs tests |
| **breaking_change** | Fix exists, different major version | **Devin creates PR** — bumps version, checks CHANGELOG, updates code, documents migrations |
| **no_fix** | No fix available | **Creates GitHub Issue** — escalates to human engineer for risk assessment |

### Real Vulnerabilities (from Apache Superset)

| Package | Current | Fix | Category | Devin's Output |
|---------|---------|-----|----------|----------------|
| `flask` | 2.3.3 | 3.1.3 | breaking_change | [**PR #22**](https://github.com/thagikura/superset-fork/pull/22) — migrates removed `escape()`, JSON encoder changes across 229 files |
| `simplejson` | * | — | library_replacement | [**PR #26**](https://github.com/thagikura/superset-fork/pull/26) — replaces `simplejson` with stdlib `json`, migrates `DashboardEncoder` |
| `pyarrow` | 20.0.0 | 23.0.1 | breaking_change | [**PR #21**](https://github.com/thagikura/superset-fork/pull/21) — audits `pa.Table`/`pa.Array` usage across 10 files |
| `pyjwt` | 2.12.0 | 2.13.0 | simple_bump | Bumps version + audits `jwt.decode()` call sites for key confusion vulnerability |
| `paramiko` | 3.5.1 | — | no_fix | [**Issue #23**](https://github.com/thagikura/superset-fork/issues/23) — human escalation with exposure analysis |

## Quick Start

```bash
git clone https://github.com/thagikura/devin-vuln-triage.git
cd devin-vuln-triage
cp .env.example .env
# Edit .env with your Devin API token, org ID, and GitHub token
docker compose up
```

The server starts at `http://localhost:8000`.

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `DEVIN_API_TOKEN` | Yes | Devin API service user token (`cog_...`) |
| `DEVIN_ORG_ID` | Yes | Devin organization ID |
| `GITHUB_TOKEN` | Yes | GitHub PAT with `repo` scope on the target repo |
| `GITHUB_WEBHOOK_SECRET` | No | Webhook HMAC-SHA256 secret (skips validation if empty) |
| `TARGET_REPO` | No | Target repo (default: `thagikura/superset-fork`) |
| `DATABASE_URL` | No | DB connection string (default: SQLite). Supports PostgreSQL, MySQL. |

### Obtaining the Keys

#### 1. `DEVIN_API_TOKEN`

A Devin API service user token is required to create and monitor Devin sessions.

1. Go to **[Devin Settings → API Tokens](https://app.devin.ai/settings/tokens)**
2. Click **"Create token"**
3. Give it a descriptive name (e.g., `vuln-triage-service`)
4. Copy the token (starts with `cog_...`) — it is only shown once

> **Permissions:** The token needs the ability to create sessions and read session status. A standard service user token has these by default.

#### 2. `DEVIN_ORG_ID`

Your Devin organization ID tells the API which org to create sessions under.

1. Go to **[Devin Settings](https://app.devin.ai/settings)**
2. Your organization ID is displayed under the **Organization** section
3. Copy the value (e.g., `org-abc123def456`)

#### 3. `GITHUB_TOKEN`

A GitHub Personal Access Token (PAT) is used to create issues and post comments on the target repository.

1. Go to **[GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens](https://github.com/settings/personal-access-tokens/new)**
2. Set a descriptive name (e.g., `devin-vuln-triage`)
3. Under **Repository access**, select **"Only select repositories"** and choose your target repo
4. Under **Permissions → Repository permissions**, grant:
   - **Issues**: Read and write (to create tracking issues for `no_fix` alerts)
   - **Pull requests**: Read (to read PR URLs from Devin sessions)
   - **Contents**: Read (so Devin can clone the repo — this is passed to the Devin session)
5. Click **Generate token** and copy it

> **Classic PAT alternative:** If using a classic token, grant the `repo` scope. Fine-grained tokens are recommended for least-privilege access.

#### 4. `GITHUB_WEBHOOK_SECRET` (production only)

Used to verify that incoming webhooks are genuinely from GitHub.

1. Generate a random secret:
   ```bash
   openssl rand -hex 32
   ```
2. Save this value — you'll need it in both your `.env` file and the GitHub webhook configuration

## Usage

### Simulate a Dependabot Alert

Instead of waiting for real Dependabot alerts (which require a public webhook endpoint), you can use the `/simulate` endpoint to feed the same vulnerability data through the pipeline. The example payloads in `examples/` were built by querying the same upstream sources that GitHub Dependabot uses:

- **[GitHub Advisory Database](https://github.com/advisories)** — the primary source for CVEs and GHSAs affecting open-source packages
- **[OSV.dev](https://osv.dev/)** — Google's aggregated vulnerability database (includes PyPI, npm, and other ecosystems)

Each payload mirrors the exact JSON schema of a real `dependabot_alert` webhook event, with advisory details (CVE IDs, CVSS scores, affected version ranges, patched versions) taken directly from these databases. The only difference from a live webhook is that `/simulate` skips HMAC signature verification.

```bash
# Simple version bump — pyjwt HMAC key confusion (PYSEC-2026-179)
# Devin bumps 2.12→2.13 + audits jwt.decode() call sites
curl -X POST http://localhost:8000/simulate \
  -H "Content-Type: application/json" \
  -d @examples/pyjwt-alert.json

# Breaking change — Flask 2.x→3.x (CVE-2026-27205)
# Devin migrates removed APIs (escape(), JSON encoder) across 229 files
curl -X POST http://localhost:8000/simulate \
  -H "Content-Type: application/json" \
  -d @examples/flask-alert.json

# Breaking change — PyArrow 20→23 (PYSEC-2026-113)
# Devin audits pa.Table/pa.Array usage, migrates across 3 major versions
curl -X POST http://localhost:8000/simulate \
  -H "Content-Type: application/json" \
  -d @examples/pyarrow-alert.json

# Library replacement — simplejson DoS (CVE-2026-99001)
# Devin replaces simplejson with Python's stdlib json module
curl -X POST http://localhost:8000/simulate \
  -H "Content-Type: application/json" \
  -d @examples/simplejson-replacement-alert.json

# No fix available — paramiko SHA-1 (CVE-2026-44405)
# Creates a GitHub Issue for human engineer escalation
curl -X POST http://localhost:8000/simulate \
  -H "Content-Type: application/json" \
  -d @examples/paramiko-alert.json
```

#### Creating Custom Alert Payloads

To test with your own vulnerabilities, copy any `examples/*.json` file and modify the fields:

```json
{
  "action": "created",
  "alert": {
    "number": 999,
    "dependency": {
      "package": { "ecosystem": "pip", "name": "your-package" },
      "manifest_path": "requirements/base.txt"
    },
    "security_vulnerability": {
      "severity": "high",
      "vulnerable_version_range": ">= 1.0.0, < 2.0.0",
      "first_patched_version": { "identifier": "2.0.0" }
    },
    "security_advisory": {
      "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
      "cve_id": "CVE-2026-XXXXX",
      "summary": "Description of the vulnerability"
    }
  },
  "repository": { "full_name": "your-org/your-repo" }
}
```

Set `"first_patched_version": null` to trigger `no_fix` classification. Use `"_meta": { "category_override": "library_replacement", "alternative_package": "replacement-lib" }` to force a library replacement flow.

### CLI Reporting

```bash
# Pipeline status summary
python -m app.cli status

# Detailed alert list (JSON)
python -m app.cli alerts

# Audit log for a specific alert
python -m app.cli logs 1

# Send simulated alert via CLI
python -m app.cli simulate examples/pyjwt-alert.json
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/webhook/github` | POST | GitHub Dependabot webhook receiver |
| `/simulate` | POST | Simulate a Dependabot alert for testing |
| `/api/metrics` | GET | Aggregated pipeline metrics (JSON) |
| `/api/alerts` | GET | All alerts with status (JSON) |
| `/dashboard` | GET | HTML dashboard (auto-refreshes) |

### GitHub Webhook Setup (Production)

To receive real Dependabot alerts (instead of using `/simulate`), configure a GitHub webhook:

#### Prerequisites

- Your server must be publicly accessible (e.g., deployed to Fly.io, Railway, AWS, etc.)
- You need admin access to the target GitHub repository
- `GITHUB_WEBHOOK_SECRET` must be set in your `.env` (see [Configuration](#configuration))

#### Step-by-step

1. **Deploy the server** to a publicly accessible URL (e.g., `https://vuln-triage.fly.dev`)

2. **Go to your repo's webhook settings:**
   ```
   https://github.com/<owner>/<repo>/settings/hooks/new
   ```
   Or: Repository → Settings → Webhooks → **Add webhook**

3. **Configure the webhook:**

   | Field | Value |
   |-------|-------|
   | **Payload URL** | `https://your-server.example.com/webhook/github` |
   | **Content type** | `application/json` |
   | **Secret** | The same value as your `GITHUB_WEBHOOK_SECRET` env var |

4. **Select events:**
   - Choose **"Let me select individual events"**
   - Check **"Dependabot alerts"**
   - Uncheck "Pushes" (not needed)
   - Click **Add webhook**

5. **Verify the webhook:**
   - GitHub sends a `ping` event immediately — check your server logs for `POST /webhook/github`
   - Trigger a real alert by merging a dependency with a known vulnerability, or use the **Security → Dependabot alerts** tab to re-open an existing alert

#### Webhook Signature Verification

The server validates incoming webhooks using HMAC-SHA256:

```
X-Hub-Signature-256: sha256=<hex digest of HMAC(secret, body)>
```

If `GITHUB_WEBHOOK_SECRET` is not set, signature verification is **skipped** (useful for local development, but never do this in production).

#### Troubleshooting

| Issue | Fix |
|-------|-----|
| Webhook returns `403` | Check that `GITHUB_WEBHOOK_SECRET` matches between GitHub and your `.env` |
| Webhook returns `422` | The payload may not be a Dependabot alert event — check the event type |
| No alerts arriving | Ensure "Dependabot alerts" is selected in webhook events, not just "Security advisories" |
| Alerts arrive but no Devin session | Check server logs — the alert may be classified as `no_fix` (creates an issue, not a session) |

## Architecture

### Tech Stack

| Component | Technology |
|-----------|-----------|
| Orchestrator | FastAPI (Python 3.12) |
| Devin Integration | Devin API v3 (`POST /organizations/{org}/sessions`) |
| GitHub Integration | GitHub REST API (issues, comments, labels) |
| Database | SQLAlchemy ORM (SQLite default, cloud DB ready) |
| Packaging | Docker + docker compose |

### Database Design

- **`alerts`** — Lifecycle of each vulnerability: received → dispatched → running → remediated/failed
- **`session_logs`** — Append-only audit trail of state transitions

Schema uses dialect-agnostic SQLAlchemy types (`String(n)`, `Text`, `Integer`, `DateTime`). Swap to PostgreSQL/MySQL by changing `DATABASE_URL`.

## Development

```bash
pip install -e ".[dev]"
ruff check app/ tests/
python -m pytest tests/ -v
```

## Project Structure

```
devin-vuln-triage/
├── app/
│   ├── main.py           # FastAPI app + webhook/simulate endpoints
│   ├── classifier.py     # Triage classification + payload parsing
│   ├── dispatcher.py     # Devin API session creation + prompt templates
│   ├── github_client.py  # GitHub issue creation + commenting
│   ├── monitor.py        # Background session polling
│   ├── dashboard.py      # Metrics aggregation
│   ├── cli.py            # CLI reporting tool
│   ├── models.py         # SQLAlchemy models (Alert, SessionLog)
│   └── config.py         # Pydantic settings
├── templates/
│   └── dashboard.html    # Observability dashboard
├── examples/             # Simulated Dependabot alert payloads
├── tests/                # Unit tests (classifier, webhook parsing)
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## Related Repositories

- **Target repo:** [thagikura/superset-fork](https://github.com/thagikura/superset-fork) — Fork of Apache Superset with identified vulnerabilities
- **Devin API docs:** [docs.devin.ai](https://docs.devin.ai/api-reference/overview)
