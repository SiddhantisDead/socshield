from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config import settings

# Some providers (Heroku Postgres, older docs) still hand out postgres:// URLs;
# SQLAlchemy 1.4+ requires the postgresql:// scheme.
_database_url = settings.database_url
if _database_url.startswith("postgres://"):
    _database_url = _database_url.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if _database_url.startswith("sqlite") else {}

engine = create_engine(_database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
