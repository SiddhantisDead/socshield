"""
Idempotent bootstrap script: creates tables, demo users, and (optionally)
ingests the bundled synthetic sample datasets + runs Sigma detection so a
fresh checkout has a populated dashboard to demo immediately.

Usage:
    python -m app.seed            # users + tables only
    python -m app.seed --with-data  # also ingest datasets/ and run detection
"""
import sys
from pathlib import Path

from app.database import Base, engine, SessionLocal
from app import models  # noqa: F401
from app.models.user import User
from app.models.log import Log
from app.models.alert import Alert
from app.models.enums import UserRole
from app.auth.security import hash_password
from app.config import settings
from app.parsers import parse_log_file
from app.detection.sigma_engine import get_engine
from app.detection.correlation import detect_brute_force

DATASET_MAP = {
    "windows": ["windows_logs"],
    "apache": ["apache_logs"],
    "firewall": ["firewall_logs"],
    "dns": ["dns_logs"],
    "linux": ["linux_logs"],
}


def seed_users(db):
    demo_users = [
        ("bladewasworthit", "bladewasworthit@socshield.local", "socblade", UserRole.admin),
        ("admin", "admin@socshield.local", "admin123", UserRole.admin),
        ("analyst", "analyst@socshield.local", "analyst123", UserRole.analyst),
    ]
    created = []
    for username, email, password, role in demo_users:
        if db.query(User).filter(User.username == username).first():
            continue
        user = User(username=username, email=email, hashed_password=hash_password(password), role=role)
        db.add(user)
        created.append(username)
    db.commit()
    return created


def ingest_datasets(db):
    datasets_dir = Path(settings.datasets_dir)
    total_ingested = 0

    for log_type, subfolders in DATASET_MAP.items():
        for sub in subfolders:
            folder = datasets_dir / sub
            if not folder.exists():
                continue
            for file_path in sorted(folder.iterdir()):
                if not file_path.is_file() or file_path.name.startswith("."):
                    continue
                content = file_path.read_bytes()
                try:
                    records = parse_log_file(log_type, content, file_path.name)
                except Exception as exc:
                    print(f"  ! failed to parse {file_path}: {exc}")
                    continue
                logs = [Log(**rec) for rec in records]
                db.add_all(logs)
                db.commit()
                total_ingested += len(logs)
                print(f"  ingested {len(logs)} records from {file_path.name}")

    return total_ingested


def run_detection(db):
    engine_ = get_engine(settings.sigma_rules_dir)
    logs = db.query(Log).all()
    created = 0
    for log in logs:
        fields = dict(log.parsed_fields)
        fields.setdefault("Hostname", log.hostname)
        for rule in engine_.evaluate(fields):
            alert = Alert(
                rule_id=rule.rule_id,
                rule_name=rule.title,
                severity=rule.severity,
                description=rule.description,
                mitre_id=rule.mitre_id,
                mitre_technique=rule.mitre_technique,
                source_ip=log.source_ip,
                hostname=log.hostname,
                log_id=log.id,
                timestamp=log.timestamp,
            )
            db.add(alert)
            created += 1
    db.commit()
    return created


def main():
    with_data = "--with-data" in sys.argv

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        created_users = seed_users(db)
        if created_users:
            print(f"Created demo users: {', '.join(created_users)}")
        else:
            print("Demo users already exist")

        if with_data:
            existing_logs = db.query(Log).count()
            if existing_logs > 0:
                print(f"Logs table already has {existing_logs} rows, skipping dataset ingestion")
            else:
                print("Ingesting sample datasets...")
                count = ingest_datasets(db)
                print(f"Ingested {count} log records total")
                print("Running Sigma detection over ingested logs...")
                alerts = run_detection(db)
                alerts += detect_brute_force(db)
                print(f"Generated {alerts} alerts")
    finally:
        db.close()


if __name__ == "__main__":
    main()
