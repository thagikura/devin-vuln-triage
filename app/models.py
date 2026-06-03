import datetime
from enum import Enum

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.config import settings


class Base(DeclarativeBase):
    pass


class TriageCategory(str, Enum):
    SIMPLE_BUMP = "simple_bump"
    BREAKING_CHANGE = "breaking_change"
    NO_FIX = "no_fix"


class AlertStatus(str, Enum):
    RECEIVED = "received"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    REMEDIATED = "remediated"
    FAILED = "failed"


class Alert(Base):
    """Tracks the full lifecycle of a Dependabot alert through the triage pipeline.

    All column types use dialect-agnostic SQLAlchemy types (String, Text, Integer,
    DateTime) so the schema works with SQLite, PostgreSQL, MySQL, etc. JSON data
    (e.g. cve_ids) is stored as Text and serialized/deserialized in application code.
    To migrate to a cloud DB, change DATABASE_URL — no schema changes needed.
    """

    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("repo", "github_alert_number", name="uq_repo_alert"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    github_alert_number: Mapped[int] = mapped_column(Integer, nullable=False)
    repo: Mapped[str] = mapped_column(String(255), nullable=False)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(50), nullable=False)
    current_version: Mapped[str] = mapped_column(String(100), nullable=False, default="unknown")
    fix_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    severity: Mapped[str] = mapped_column(String(50), nullable=False, default="unknown")
    cve_ids: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    advisory_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    manifest_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default=AlertStatus.RECEIVED.value
    )
    github_issue_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    github_issue_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    devin_session_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    devin_session_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    pr_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )
    resolved_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)


class SessionLog(Base):
    """Append-only event log for auditing state transitions on each alert."""

    __tablename__ = "session_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[int] = mapped_column(Integer, ForeignKey("alerts.id"), nullable=False)
    event: Mapped[str] = mapped_column(String(100), nullable=False)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )


engine = create_engine(settings.database_url, echo=False)
SessionLocal = sessionmaker(bind=engine)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_db() -> Session:
    db = SessionLocal()
    try:
        return db
    except Exception:
        db.close()
        raise
