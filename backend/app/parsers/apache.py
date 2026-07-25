"""Parses Apache/Nginx combined access log format."""
import re
from datetime import datetime, timezone

from app.models.enums import Severity

_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<uri>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)


def _parse_timestamp(ts: str) -> datetime:
    try:
        return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return datetime.now(timezone.utc)


def _severity_for_status(status: int) -> Severity:
    if status >= 500:
        return Severity.high
    if status >= 400:
        return Severity.medium
    return Severity.informational


def parse_apache_log(content: bytes, source_file: str) -> list[dict]:
    text = content.decode("utf-8", errors="replace")
    results = []

    for line in text.splitlines():
        if not line.strip():
            continue
        m = _COMBINED_RE.match(line)
        if not m:
            continue

        status = int(m.group("status"))
        bytes_sent = m.group("bytes")

        parsed_fields = {
            "ClientIp": m.group("ip"),
            "Method": m.group("method"),
            "Uri": m.group("uri"),
            "Protocol": m.group("protocol"),
            "StatusCode": status,
            "BytesSent": int(bytes_sent) if bytes_sent.isdigit() else 0,
            "Referer": m.group("referer") or "",
            "UserAgent": m.group("agent") or "",
            "RequestLine": f'{m.group("method")} {m.group("uri")} {m.group("protocol")}',
        }

        results.append(
            {
                "timestamp": _parse_timestamp(m.group("ts")),
                "hostname": "",
                "source_ip": m.group("ip"),
                "severity": _severity_for_status(status),
                "event_id": str(status),
                "log_type": "apache",
                "source_file": source_file,
                "raw_log": line,
                "parsed_fields": parsed_fields,
            }
        )

    return results
