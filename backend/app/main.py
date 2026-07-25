import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import Base, engine
from app import models  # noqa: F401 - ensure models are registered on Base.metadata
from app.api import users, logs, alerts, incidents, dashboard, scan, threat_intel
from app.detection.sigma_engine import get_engine
from app.detection.yara_engine import get_yara_engine

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="SOCShield API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    get_engine(settings.sigma_rules_dir)
    get_yara_engine(settings.yara_rules_dir)


@app.get("/api/health")
def health():
    return {"status": "ok"}


app.include_router(users.router, prefix="/api")
app.include_router(logs.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(incidents.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(scan.router, prefix="/api")
app.include_router(threat_intel.router, prefix="/api")
