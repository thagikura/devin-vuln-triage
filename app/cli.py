"""CLI reporting tool for pipeline observability.

Usage:
    python -m app.cli status          # Pipeline summary + alert table
    python -m app.cli alerts          # Detailed alert list
    python -m app.cli logs <alert_id> # Audit log for a specific alert
    python -m app.cli simulate <file> # Send a simulated alert payload
    python -m app.cli refresh         # Poll Devin API for all active sessions
"""

import argparse
import json

import httpx

from app.dashboard import get_alert_list, get_metrics
from app.models import SessionLocal, SessionLog, init_db


def print_status() -> None:
    """Print pipeline summary and alert table."""
    init_db()
    metrics = get_metrics()
    alerts = get_alert_list()

    active = (
        metrics["sessions_by_status"].get("running", 0)
        + metrics["sessions_by_status"].get("dispatched", 0)
    )
    remediated = metrics["sessions_by_status"].get("remediated", 0)
    failed = metrics["sessions_by_status"].get("failed", 0)

    print()
    print("=" * 60)
    print("  Devin Vuln Triage — Pipeline Status")
    print("=" * 60)
    print(f"  Total Alerts:     {metrics['total_alerts_received']}")
    print(f"  Active Sessions:  {active}")
    print(f"  Remediated:       {remediated}")
    print(f"  Failed:           {failed}")
    print(f"  PRs Created:      {metrics['prs_created']}")
    print(f"  Success Rate:     {metrics['success_rate'] * 100:.1f}%")
    print(f"  Avg Resolution:   {metrics['avg_time_to_resolution_seconds'] / 60:.1f} min")
    print("=" * 60)

    by_cat = metrics["sessions_by_category"]
    print(f"  Simple Bumps:     {by_cat.get('simple_bump', 0)}")
    print(f"  Breaking Changes: {by_cat.get('breaking_change', 0)}")
    print(f"  No Fix Available: {by_cat.get('no_fix', 0)}")
    print(f"  Code Audits:      {by_cat.get('code_audit', 0)}")
    print(f"  Lib Replacements: {by_cat.get('library_replacement', 0)}")
    print("=" * 60)
    print()

    if not alerts:
        print("  No alerts received yet.")
        print("  Run: python -m app.cli simulate examples/pyjwt-alert.json")
        print()
        return

    # Table header
    header = f"{'Package':<25} {'Severity':<10} {'Category':<18} {'Status':<12} {'PR / Error'}"
    print(header)
    print("-" * len(header))

    for a in alerts:
        pr_info = "—"
        if a["pr_url"]:
            pr_info = a["pr_url"].split("/")[-1] if "/" in a["pr_url"] else a["pr_url"]
            pr_info = f"PR #{pr_info}"
        elif a["error_message"]:
            pr_info = a["error_message"][:30]

        print(
            f"{a['package_name']:<25} "
            f"{a['severity']:<10} "
            f"{a['category']:<18} "
            f"{a['status']:<12} "
            f"{pr_info}"
        )

    print()


def print_alerts() -> None:
    """Print detailed alert list as JSON."""
    init_db()
    alerts = get_alert_list()
    print(json.dumps(alerts, indent=2))


def print_logs(alert_id: int) -> None:
    """Print audit log for a specific alert."""
    init_db()
    db = SessionLocal()
    try:
        logs = (
            db.query(SessionLog)
            .filter(SessionLog.alert_id == alert_id)
            .order_by(SessionLog.created_at)
            .all()
        )
        if not logs:
            print(f"No logs found for alert {alert_id}")
            return

        print(f"\nAudit log for alert #{alert_id}:")
        print("-" * 60)
        for log in logs:
            ts = log.created_at.strftime("%Y-%m-%d %H:%M:%S") if log.created_at else "?"
            details = log.details or ""
            print(f"  [{ts}] {log.event}: {details}")
        print()
    finally:
        db.close()


def simulate(file_path: str, base_url: str = "http://localhost:8000") -> None:
    """Send a simulated alert payload to the running server."""
    with open(file_path) as f:
        payload = json.load(f)

    resp = httpx.post(f"{base_url}/simulate", json=payload, timeout=30)
    print(f"Status: {resp.status_code}")
    print(json.dumps(resp.json(), indent=2))


def refresh_sessions() -> None:
    """Poll the Devin API for all active sessions and update DB."""
    import asyncio
    import datetime

    from app.dispatcher import get_devin_session
    from app.models import Alert, AlertStatus

    init_db()
    db = SessionLocal()
    try:
        active = (
            db.query(Alert)
            .filter(
                Alert.status.in_([
                    AlertStatus.DISPATCHED.value,
                    AlertStatus.RUNNING.value,
                ]),
                Alert.devin_session_id.isnot(None),
            )
            .all()
        )
        if not active:
            print("No active sessions to refresh.")
            return

        print(f"Refreshing {len(active)} active session(s)...")
        print()

        for alert in active:
            try:
                data = asyncio.run(
                    get_devin_session(alert.devin_session_id)
                )
            except Exception as e:
                print(
                    f"  {alert.package_name}: "
                    f"error polling ({e})"
                )
                continue

            status = data.get("status", "unknown")
            pr_urls = data.get("pull_request_urls", [])
            pr_url = pr_urls[0] if pr_urls else None

            if status in ("exit", "finished"):
                alert.status = AlertStatus.REMEDIATED.value
                alert.pr_url = pr_url
                alert.resolved_at = datetime.datetime.utcnow()
                alert.updated_at = datetime.datetime.utcnow()
                db.add(
                    SessionLog(
                        alert_id=alert.id,
                        event="session_completed",
                        details=json.dumps(
                            {"status": status, "pr_url": pr_url}
                        ),
                    )
                )
            elif status in ("error", "failed", "stopped"):
                error_msg = data.get("error", status)
                alert.status = AlertStatus.FAILED.value
                alert.error_message = str(error_msg)
                alert.updated_at = datetime.datetime.utcnow()
                db.add(
                    SessionLog(
                        alert_id=alert.id,
                        event="session_failed",
                        details=json.dumps(
                            {"status": status, "error": str(error_msg)}
                        ),
                    )
                )
            elif status == "running":
                alert.status = AlertStatus.RUNNING.value
                alert.updated_at = datetime.datetime.utcnow()

            db.commit()
            pr_info = f"PR: {pr_url}" if pr_url else ""
            print(
                f"  {alert.package_name:<25} "
                f"{status:<12} {pr_info}"
            )

        print()
        print("Done. Run 'python -m app.cli status' to see updated state.")
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Devin Vuln Triage CLI")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("status", help="Pipeline summary + alert table")
    subparsers.add_parser("alerts", help="Detailed alert list (JSON)")

    logs_parser = subparsers.add_parser("logs", help="Audit log for a specific alert")
    logs_parser.add_argument("alert_id", type=int)

    sim_parser = subparsers.add_parser("simulate", help="Send a simulated alert payload")
    sim_parser.add_argument("file", help="Path to JSON payload file")
    sim_parser.add_argument("--url", default="http://localhost:8000", help="Server base URL")

    subparsers.add_parser(
        "refresh",
        help="Poll Devin API for all active sessions and update DB",
    )

    args = parser.parse_args()

    if args.command == "status":
        print_status()
    elif args.command == "alerts":
        print_alerts()
    elif args.command == "logs":
        print_logs(args.alert_id)
    elif args.command == "simulate":
        simulate(args.file, args.url)
    elif args.command == "refresh":
        refresh_sessions()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
