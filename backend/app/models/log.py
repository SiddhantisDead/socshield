from datetime import datetime, timezone

from sqlalchemy import String, DateTime, Text, JSON, Enum as SAEnum, Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.enums import Severity, LogType


class Log(Base):
    __tablename__ = "logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), index=True, default="")
    source_ip: Mapped[str] = mapped_column(String(64), index=True, default="")
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), default=Severity.informational, index=True)
    event_id: Mapped[str] = mapped_column(String(32), index=True, default="")
    log_type: Mapped[LogType] = mapped_column(SAEnum(LogType), index=True, nullable=False)
    source_file: Mapped[str] = mapped_column(String(255), default="")
    raw_log: Mapped[str] = mapped_column(Text, default="")
    parsed_fields: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
