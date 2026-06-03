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

| Package | Current | Fix | Category |
|---------|---------|-----|----------|
| `pyjwt` | 2.12.0 | 2.13.0 | simple_bump |
| `flask` | 2.3.3 | 3.1.3 | breaking_change |
| `pyarrow` | 20.0.0 | 23.0.1 | breaking_change |
| `paramiko` | 3.5.1 | — | no_fix |
| `eslint-plugin-i18n-strings` | * | — | no_fix (malware) |

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
| `GITHUB_TOKEN` | Yes | GitHub token with `issues:write` on target repo |
| `GITHUB_WEBHOOK_SECRET` | No | Webhook signature secret (skips validation if empty) |
| `TARGET_REPO` | No | Target repo (default: `thagikura/superset-fork`) |
| `DATABASE_URL` | No | DB connection string (default: SQLite). Supports PostgreSQL, MySQL. |

## Usage

### Simulate a Dependabot Alert

```bash
# Simple version bump (pyjwt)
curl -X POST http://localhost:8000/simulate \
  -H "Content-Type: application/json" \
  -d @examples/pyjwt-alert.json

# Breaking change (flask 2.x → 3.x)
curl -X POST http://localhost:8000/simulate \
  -H "Content-Type: application/json" \
  -d @examples/flask-alert.json

# No fix available (paramiko)
curl -X POST http://localhost:8000/simulate \
  -H "Content-Type: application/json" \
  -d @examples/paramiko-alert.json
```

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

### GitHub Webhook Setup

1. Go to your repo → Settings → Webhooks → Add webhook
2. **Payload URL:** `https://your-server/webhook/github`
3. **Content type:** `application/json`
4. **Secret:** (same as `GITHUB_WEBHOOK_SECRET`)
5. **Events:** Select "Dependabot alerts"

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
