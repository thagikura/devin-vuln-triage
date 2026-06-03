import asyncio
import datetime
import json
import logging

from app.config import settings
from app.dispatcher import get_devin_session
from app.github_client import comment_on_issue
from app.models import AlertStatus, SessionLocal, SessionLog

logger = logging.getLogger(__name__)


async def poll_session(alert_id: int) -> None:
    """Poll a single Devin session until it reaches a terminal state."""
    db = SessionLocal()
    try:
        from app.models import Alert

        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert or not alert.devin_session_id:
            logger.warning("No session to poll for alert %d", alert_id)
            return

        session_id = alert.devin_session_id
        logger.info(
            "Polling session %s for alert %d (%s)", session_id, alert_id, alert.package_name
        )

        while True:
            try:
                session_data = await get_devin_session(session_id)
            except Exception as e:
                logger.error("Error polling session %s: %s", session_id, e)
                await asyncio.sleep(settings.poll_interval_seconds)
                continue

            status = session_data.get("status", "unknown")
            logger.info("Session %s status: %s", session_id, status)

            if status == "running" and alert.status != AlertStatus.RUNNING.value:
                alert.status = AlertStatus.RUNNING.value
                alert.updated_at = datetime.datetime.utcnow()
                db.add(
                    SessionLog(
                        alert_id=alert_id,
                        event="status_changed",
                        details=json.dumps({"status": "running"}),
                    )
                )
                db.commit()

                if alert.github_issue_number:
                    try:
                        await comment_on_issue(
                            alert.repo,
                            alert.github_issue_number,
                            f"Devin session is now **running**: {alert.devin_session_url}",
                        )
                    except Exception as e:
                        logger.warning("Failed to update issue: %s", e)

            elif status in ("exit", "finished"):
                pr_urls = session_data.get("pull_request_urls", [])
                pr_url = pr_urls[0] if pr_urls else None

                alert.status = AlertStatus.REMEDIATED.value
                alert.pr_url = pr_url
                alert.resolved_at = datetime.datetime.utcnow()
                alert.updated_at = datetime.datetime.utcnow()
                db.add(
                    SessionLog(
                        alert_id=alert_id,
                        event="session_completed",
                        details=json.dumps({"status": status, "pr_url": pr_url}),
                    )
                )
                db.commit()

                if alert.github_issue_number:
                    try:
                        comment = "Devin session **completed**."
                        if pr_url:
                            comment += f"\n\nPR created: {pr_url}"
                        await comment_on_issue(alert.repo, alert.github_issue_number, comment)
                    except Exception as e:
                        logger.warning("Failed to update issue: %s", e)

                logger.info("Session %s completed. PR: %s", session_id, pr_url)
                return

            elif status in ("error", "failed", "stopped"):
                error_msg = session_data.get("error", status)
                alert.status = AlertStatus.FAILED.value
                alert.error_message = str(error_msg)
                alert.updated_at = datetime.datetime.utcnow()
                db.add(
                    SessionLog(
                        alert_id=alert_id,
                        event="session_failed",
                        details=json.dumps({"status": status, "error": str(error_msg)}),
                    )
                )
                db.commit()

                if alert.github_issue_number:
                    try:
                        await comment_on_issue(
                            alert.repo,
                            alert.github_issue_number,
                            f"Devin session **{status}**: {error_msg}",
                        )
                    except Exception as e:
                        logger.warning("Failed to update issue: %s", e)

                logger.warning("Session %s failed: %s", session_id, error_msg)
                return

            await asyncio.sleep(settings.poll_interval_seconds)

    finally:
        db.close()


async def start_monitoring(alert_id: int) -> None:
    """Launch background polling for a Devin session."""
    asyncio.create_task(poll_session(alert_id))
