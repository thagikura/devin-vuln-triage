import json

from sqlalchemy import func

from app.models import Alert, AlertStatus, SessionLocal, TriageCategory


def get_metrics() -> dict:
    """Compute aggregate pipeline metrics from the database."""
    db = SessionLocal()
    try:
        total = db.query(func.count(Alert.id)).scalar() or 0

        status_counts = {}
        for status in AlertStatus:
            count = (
                db.query(func.count(Alert.id))
                .filter(Alert.status == status.value)
                .scalar()
                or 0
            )
            status_counts[status.value] = count

        category_counts = {}
        for cat in TriageCategory:
            count = (
                db.query(func.count(Alert.id))
                .filter(Alert.category == cat.value)
                .scalar()
                or 0
            )
            category_counts[cat.value] = count

        prs_created = (
            db.query(func.count(Alert.id))
            .filter(Alert.pr_url.isnot(None))
            .scalar()
            or 0
        )

        # Compute average time-to-resolution for remediated alerts
        remediated = (
            db.query(Alert)
            .filter(Alert.status == AlertStatus.REMEDIATED.value)
            .filter(Alert.resolved_at.isnot(None))
            .all()
        )
        avg_time_seconds = 0.0
        if remediated:
            total_seconds = sum(
                (a.resolved_at - a.created_at).total_seconds()
                for a in remediated
                if a.resolved_at and a.created_at
            )
            avg_time_seconds = total_seconds / len(remediated)

        dispatched_or_done = status_counts.get("dispatched", 0) + status_counts.get(
            "running", 0
        ) + status_counts.get("remediated", 0) + status_counts.get("failed", 0)
        success_rate = 0.0
        if dispatched_or_done > 0:
            success_rate = status_counts.get("remediated", 0) / dispatched_or_done

        return {
            "total_alerts_received": total,
            "sessions_by_status": status_counts,
            "sessions_by_category": category_counts,
            "prs_created": prs_created,
            "avg_time_to_resolution_seconds": round(avg_time_seconds, 1),
            "success_rate": round(success_rate, 3),
        }
    finally:
        db.close()


def get_alert_list() -> list[dict]:
    """Return all alerts with their current status."""
    db = SessionLocal()
    try:
        alerts = db.query(Alert).order_by(Alert.created_at.desc()).all()
        result = []
        for a in alerts:
            result.append(
                {
                    "id": a.id,
                    "github_alert_number": a.github_alert_number,
                    "repo": a.repo,
                    "package_name": a.package_name,
                    "ecosystem": a.ecosystem,
                    "current_version": a.current_version,
                    "fix_version": a.fix_version,
                    "severity": a.severity,
                    "cve_ids": json.loads(a.cve_ids) if a.cve_ids else [],
                    "category": a.category,
                    "status": a.status,
                    "github_issue_url": a.github_issue_url,
                    "devin_session_id": a.devin_session_id,
                    "devin_session_url": a.devin_session_url,
                    "pr_url": a.pr_url,
                    "error_message": a.error_message,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                    "updated_at": a.updated_at.isoformat() if a.updated_at else None,
                    "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
                }
            )
        return result
    finally:
        db.close()
