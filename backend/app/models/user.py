from datetime import datetime, timezone

from sqlalchemy import String, DateTime, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import UserRole


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(SAEnum(UserRole), default=UserRole.analyst, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    assigned_incidents = relationship("Incident", back_populates="assignee")
