# Devin Vulnerability Triage

Event-driven security vulnerability auto-triage using the [Devin API](https://docs.devin.ai/api-reference/overview). Listens for GitHub Dependabot alerts, classifies vulnerabilities, and dispatches autonomous Devin sessions to remediate them.

## Problem

Dependabot finds vulnerabilities and can bump version numbers, but it can't reason about **how a vulnerability affects your code**. For large codebases like [Apache Superset](https://github.com/apache/superset), security alerts require different handling: some need code audits, some need full API migrations, and some need human judgment. This system automates the entire remediation pipeline — going beyond version bumps to deliver codebase-aware fixes.

## How It Works

```
GitHub Dependabot        Webhook Listener        Triage Classifier
(automatic scanning)  →  (FastAPI)            →  (4 categories)
     +                                              │
Static Analysis                  ┌───────────┬──────┴──────┬───────────┐
(code-level findings)            │           │             │           │
                          simple_bump  breaking_change  code_audit   no_fix
                                 │           │             │           │
                                 ▼           ▼             ▼           ▼
                            Devin: bump  Devin: full   Devin: fix  GitHub Issue
                            + audit      migration     code        → human
                            + harden     + test        patterns    escalation
                                 │           │             │
                                 └─────────┬─┘─────────────┘
                                           ▼
                              Session Monitor ──→ Polls status, tracks PRs
                                           ▼
                              CLI / Dashboard ──→ Pipeline metrics
```

### Triage Categories

| Category | Criteria | Devin's Action | Why Dependabot Can't |
|----------|----------|----------------|---------------------|
| **simple_bump** | Fix exists, same major version | Bump version + **audit codebase** for the vulnerable pattern + harden code + add tests | Dependabot only changes the version number |
| **breaking_change** | Fix exists, different major version | Full migration: read CHANGELOG, inventory all API usage, update imports/code, fix tests | Dependabot can't handle breaking API changes |
| **code_audit** | Insecure code pattern (not a version issue) | Find all instances of the pattern, replace with safe alternative, ensure backward compatibility | Dependabot can't detect code-level issues |
| **no_fix** | No fix available | **Creates GitHub Issue** — deep exposure analysis for human engineer | Both escalate, but Devin provides file:line analysis |

### Real Vulnerabilities (from Apache Superset)

| Package | Category | What Devin Does (Beyond Dependabot) |
|---------|----------|-------------------------------------|
| **pyjwt** 2.12→2.13 | simple_bump | Bumps version + audits 3 `jwt.decode()` call sites for key confusion vulnerability + verifies algorithm pinning on guest token flow |
| **flask** 2.3→3.1 | breaking_change | Migrates 229 files importing Flask: fixes removed `escape()`, updates JSON encoder patterns, handles session API changes |
| **pyarrow** 20→23 | breaking_change | Audits 10 files using `pa.Table`/`pa.Array`/`pa.types`, migrates deprecated APIs across 3 major versions |
| **pickle.loads** | code_audit | Replaces unsafe `PickleKeyValueCodec` with JSON alternative, updates `metastore_cache.py` default codec |
| **yaml.load** | code_audit | Replaces `yaml.Loader` with `yaml.safe_load()`, removes `# noqa: S506` suppression |
| **paramiko** (SHA-1) | no_fix | Creates GitHub Issue with exposure analysis: traces `RSAKey` usage in SSH tunneling, assesses production reachability |
| **eslint-plugin-i18n-strings** | no_fix | Creates GitHub Issue noting this is a local `file:` package (not the malicious npm one), recommends renaming |

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
# Simple bump + audit (pyjwt — audits jwt.decode() call sites)
curl -X POST http://localhost:8000/simulate \
  -H "Content-Type: application/json" \
  -d @examples/pyjwt-alert.json

# Breaking change migration (flask 2.x → 3.x — 229 files)
curl -X POST http://localhost:8000/simulate \
  -H "Content-Type: application/json" \
  -d @examples/flask-alert.json

# Code audit (pickle.loads — fix insecure deserialization pattern)
curl -X POST http://localhost:8000/simulate \
  -H "Content-Type: application/json" \
  -d @examples/pickle-deserialization-alert.json

# No fix available (paramiko — human escalation)
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
