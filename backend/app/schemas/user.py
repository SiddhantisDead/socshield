from datetime import datetime

from pydantic import BaseModel, EmailStr, ConfigDict

from app.models.enums import UserRole


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: UserRole = UserRole.analyst


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: UserRole
    created_at: datetime


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut
