from datetime import datetime, timezone

from sqlalchemy import String, DateTime, Text, Enum as SAEnum, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import Severity, AlertStatus


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True, default="")
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), default=Severity.medium, index=True)
    status: Mapped[AlertStatus] = mapped_column(SAEnum(AlertStatus), default=AlertStatus.open, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True, default=lambda: datetime.now(timezone.utc))
    description: Mapped[str] = mapped_column(Text, default="")
    mitre_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    mitre_technique: Mapped[str] = mapped_column(String(255), default="")
    source_ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    log_id: Mapped[int | None] = mapped_column(ForeignKey("logs.id"), nullable=True)

    incident = relationship("Incident", back_populates="alert", uselist=False)
