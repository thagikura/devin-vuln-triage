import hashlib
import hmac
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.classifier import VulnerabilityAlert, classify, parse_dependabot_payload
from app.config import settings
from app.dashboard import get_alert_list, get_metrics
from app.dispatcher import build_prompt, create_devin_session
from app.github_client import create_tracking_issue
from app.models import Alert, AlertStatus, SessionLocal, SessionLog, init_db
from app.monitor import start_monitoring

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

templates = Jinja2Templates(directory="templates")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("Database initialized")
    yield


app = FastAPI(
    title="Devin Vulnerability Triage",
    description="Event-driven security vulnerability auto-triage using Devin API",
    version="0.1.0",
    lifespan=lifespan,
)


def verify_github_signature(payload_body: bytes, signature: str | None) -> bool:
    """Verify the GitHub webhook signature using HMAC-SHA256."""
    if not settings.github_webhook_secret:
        return True  # skip verification if no secret configured (dev mode)
    if not signature:
        return False
    expected = "sha256=" + hmac.new(
        settings.github_webhook_secret.encode(), payload_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


async def process_alert(alert_data: VulnerabilityAlert) -> dict:
    """Core pipeline: classify → dispatch Devin (fixable) or create issue (no fix).

    - simple_bump / breaking_change / code_audit: Devin creates a PR directly
    - no_fix: Creates a GitHub Issue to escalate to a human engineer
    """
    triage = classify(alert_data)
    logger.info(
        "Classified %s as %s (fix: %s)",
        triage.package_name,
        triage.category.value,
        triage.fix_version,
    )

    from app.models import TriageCategory as TC

    is_fixable = triage.category in (
        TC.SIMPLE_BUMP,
        TC.BREAKING_CHANGE,
        TC.CODE_AUDIT,
    )

    db = SessionLocal()
    try:
        # Idempotency: check if we already have this alert
        existing = (
            db.query(Alert)
            .filter(
                Alert.repo == alert_data.repo,
                Alert.github_alert_number == alert_data.alert_number,
            )
            .first()
        )
        if existing:
            logger.info("Alert %d already exists, skipping", alert_data.alert_number)
            return {
                "status": "duplicate",
                "alert_id": existing.id,
                "message": "Alert already processed",
            }

        # Create DB record
        db_alert = Alert(
            github_alert_number=alert_data.alert_number,
            repo=alert_data.repo,
            package_name=triage.package_name,
            ecosystem=triage.ecosystem,
            current_version=triage.current_version,
            fix_version=triage.fix_version,
            severity=triage.severity,
            cve_ids=json.dumps(triage.cve_ids),
            advisory_url=triage.advisory_url,
            manifest_path=alert_data.manifest_path,
            category=triage.category.value,
            status=AlertStatus.RECEIVED.value,
        )
        db.add(db_alert)
        db.commit()
        db.refresh(db_alert)

        db.add(
            SessionLog(
                alert_id=db_alert.id,
                event="alert_received",
                details=json.dumps({"category": triage.category.value}),
            )
        )
        db.commit()

        if is_fixable:
            # Fixable: dispatch Devin to create a PR directly (no issue needed)
            try:
                prompt = build_prompt(
                    triage, alert_data.repo, alert_data.manifest_path
                )
                session = await create_devin_session(prompt)
                db_alert.devin_session_id = session.get("session_id")
                db_alert.devin_session_url = session.get("url")
                db_alert.status = AlertStatus.DISPATCHED.value
                db.add(
                    SessionLog(
                        alert_id=db_alert.id,
                        event="session_created",
                        details=json.dumps(
                            {
                                "session_id": session.get("session_id"),
                                "url": session.get("url"),
                            }
                        ),
                    )
                )
                db.commit()

                await start_monitoring(db_alert.id)

            except Exception as e:
                logger.error("Failed to create Devin session: %s", e)
                db_alert.status = AlertStatus.FAILED.value
                db_alert.error_message = str(e)
                db.add(
                    SessionLog(
                        alert_id=db_alert.id,
                        event="dispatch_failed",
                        details=json.dumps({"error": str(e)}),
                    )
                )
                db.commit()
        else:
            # No fix: escalate to human engineer via GitHub Issue
            try:
                issue = await create_tracking_issue(triage, alert_data.repo)
                db_alert.github_issue_number = issue["number"]
                db_alert.github_issue_url = issue["url"]
                db_alert.status = AlertStatus.DISPATCHED.value
                db.add(
                    SessionLog(
                        alert_id=db_alert.id,
                        event="issue_created",
                        details=json.dumps(issue),
                    )
                )
                db.commit()
                logger.info(
                    "No fix available for %s — created issue %s for human review",
                    triage.package_name,
                    issue["url"],
                )
            except Exception as e:
                logger.error("Failed to create GitHub issue: %s", e)
                db_alert.status = AlertStatus.FAILED.value
                db_alert.error_message = str(e)
                db.commit()

        return {
            "status": "processed",
            "alert_id": db_alert.id,
            "category": triage.category.value,
            "devin_session_id": db_alert.devin_session_id,
            "github_issue_url": db_alert.github_issue_url,
        }

    finally:
        db.close()


# --- API Endpoints ---


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(None),
    x_github_event: str | None = Header(None),
):
    """Receive GitHub Dependabot alert webhooks."""
    body = await request.body()

    if not verify_github_signature(body, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid signature")

    if x_github_event != "dependabot_alert":
        return {"status": "ignored", "event": x_github_event}

    payload = json.loads(body)
    alert_data = parse_dependabot_payload(payload)
    if not alert_data:
        return {"status": "ignored", "reason": "unsupported action"}

    result = await process_alert(alert_data)
    return result


@app.post("/simulate")
async def simulate(request: Request):
    """Accept a simulated Dependabot alert payload for testing/demo.

    Accepts either:
    - A full Dependabot webhook payload (with "action" and "alert" keys)
    - A simplified VulnerabilityAlert JSON for quick testing
    """
    payload = await request.json()

    if "alert" in payload:
        alert_data = parse_dependabot_payload(payload)
        if not alert_data:
            raise HTTPException(status_code=400, detail="Could not parse payload")
        # Support category_override from _meta (for code_audit alerts)
        meta = payload.get("_meta", {})
        if meta.get("category_override"):
            alert_data.category_override = meta["category_override"]
    else:
        try:
            alert_data = VulnerabilityAlert(**payload)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid payload: {e}")

    result = await process_alert(alert_data)
    return result


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Render the observability dashboard."""
    metrics = get_metrics()
    alerts = get_alert_list()
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "metrics": metrics, "alerts": alerts},
    )


@app.get("/api/metrics")
async def api_metrics():
    """JSON metrics endpoint for monitoring integration."""
    return get_metrics()


@app.get("/api/alerts")
async def api_alerts():
    """List all tracked alerts with current status."""
    return get_alert_list()
