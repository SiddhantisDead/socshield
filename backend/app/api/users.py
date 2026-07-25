from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.enums import UserRole
from app.schemas.user import UserCreate, UserOut, LoginRequest, TokenResponse
from app.auth.security import hash_password, verify_password, create_access_token
from app.auth.deps import get_current_user, require_admin

router = APIRouter(tags=["auth"])


@router.post("/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    token = create_access_token(subject=user.username, role=user.role.value)
    return TokenResponse(access_token=token, user=user)


@router.get("/auth/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(User).order_by(User.username).all()
