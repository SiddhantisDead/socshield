from datetime import datetime, timezone

from sqlalchemy import String, DateTime, Text, Enum as SAEnum, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import IncidentStatus


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), default="")
    assigned_to_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    status: Mapped[IncidentStatus] = mapped_column(SAEnum(IncidentStatus), default=IncidentStatus.open, index=True)
    resolution: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )

    alert = relationship("Alert", back_populates="incident")
    assignee = relationship("User", back_populates="assigned_incidents")
    notes = relationship("IncidentNote", back_populates="incident", cascade="all, delete-orphan", order_by="IncidentNote.created_at")


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    author: Mapped[str] = mapped_column(String(64), default="")
    comment: Mapped[str] = mapped_column(Text, default="")
    next_action: Mapped[str] = mapped_column(Text, default="")
    status_at_time: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    incident = relationship("Incident", back_populates="notes")
