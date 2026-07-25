"""
Frequency-based correlation detection: "N failed logins from the same IP
within a time window -> Brute Force alert" - the canonical SOC example
this platform is built to demonstrate. Sigma's own answer to this
(correlation rules) needs a stateful aggregation backend that's out of
scope here, so this is a small hand-rolled sliding-window pass over
already-ingested logs, run after per-event Sigma matching.
"""
from collections import defaultdict
from datetime import timedelta

from sqlalchemy.orm import Session

from app.models.log import Log
from app.models.alert import Alert
from app.models.enums import Severity, LogType

CORRELATION_RULE_ID = "CORR-T1110-BRUTEFORCE"
DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_MINUTES = 10


def _is_failed_login(log: Log) -> bool:
    if log.log_type == LogType.linux:
        return log.parsed_fields.get("Action") in ("Failed password", "Invalid user")
    if log.log_type == LogType.windows:
        return str(log.parsed_fields.get("EventID")) == "4625"
    return False


def detect_brute_force(
    db: Session, threshold: int = DEFAULT_THRESHOLD, window_minutes: int = DEFAULT_WINDOW_MINUTES
) -> int:
    logs = (
        db.query(Log)
        .filter(Log.log_type.in_([LogType.linux, LogType.windows]))
        .order_by(Log.timestamp)
        .all()
    )

    by_ip: dict[str, list[Log]] = defaultdict(list)
    for log in logs:
        if log.source_ip and _is_failed_login(log):
            by_ip[log.source_ip].append(log)

    already_alerted_ips = {
        a.source_ip for a in db.query(Alert).filter(Alert.rule_id == CORRELATION_RULE_ID).all()
    }

    window = timedelta(minutes=window_minutes)
    created = 0

    for ip, entries in by_ip.items():
        if ip in already_alerted_ips:
            continue
        entries.sort(key=lambda l: l.timestamp)

        for i in range(len(entries)):
            burst = [e for e in entries[i:] if e.timestamp <= entries[i].timestamp + window]
            if len(burst) >= threshold:
                last = burst[-1]
                db.add(
                    Alert(
                        rule_id=CORRELATION_RULE_ID,
                        rule_name="Brute Force Login Detected (Correlation)",
                        severity=Severity.high,
                        description=(
                            f"{len(burst)} failed login attempts from {ip} within "
                            f"{window_minutes} minutes (target host: {last.hostname or 'multiple hosts'})"
                        ),
                        mitre_id="T1110",
                        mitre_technique="Brute Force",
                        source_ip=ip,
                        hostname=last.hostname,
                        log_id=last.id,
                        timestamp=last.timestamp,
                    )
                )
                created += 1
                break

    if created:
        db.commit()
    return created
