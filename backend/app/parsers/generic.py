"""Parses firewall and DNS logs shipped as JSON (list of records) or CSV."""
import csv
import io
import json
from datetime import datetime, timezone

from app.models.enums import Severity


def _load_records(content: bytes) -> list[dict]:
    text = content.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    if text[0] in "[{":
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    reader = csv.DictReader(io.StringIO(text))
    return list(reader)


def _parse_ts(value) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def parse_firewall_log(content: bytes, source_file: str) -> list[dict]:
    results = []
    for rec in _load_records(content):
        action = str(rec.get("Action", rec.get("action", ""))).upper()
        severity = Severity.medium if action in ("DENY", "DROP", "BLOCK") else Severity.informational

        parsed_fields = {
            "SourceIp": rec.get("SourceIp", rec.get("src_ip", "")),
            "DestinationIp": rec.get("DestinationIp", rec.get("dst_ip", "")),
            "SourcePort": int(rec["SourcePort"]) if str(rec.get("SourcePort", "")).isdigit() else rec.get("SourcePort"),
            "DestinationPort": int(rec["DestinationPort"]) if str(rec.get("DestinationPort", "")).isdigit() else rec.get("DestinationPort"),
            "Protocol": rec.get("Protocol", ""),
            "Action": action,
            "Bytes": int(rec.get("Bytes", 0)) if str(rec.get("Bytes", "0")).isdigit() else 0,
            "Rule": rec.get("Rule", ""),
        }

        results.append(
            {
                "timestamp": _parse_ts(rec.get("timestamp")),
                "hostname": rec.get("hostname", ""),
                "source_ip": parsed_fields["SourceIp"] or "",
                "severity": severity,
                "event_id": action or "firewall",
                "log_type": "firewall",
                "source_file": source_file,
                "raw_log": json.dumps(rec),
                "parsed_fields": parsed_fields,
            }
        )
    return results


def parse_dns_log(content: bytes, source_file: str) -> list[dict]:
    results = []
    for rec in _load_records(content):
        response_code = str(rec.get("ResponseCode", rec.get("response_code", "NOERROR")))
        severity = Severity.low if response_code != "NOERROR" else Severity.informational

        parsed_fields = {
            "SourceIp": rec.get("SourceIp", rec.get("src_ip", "")),
            "QueryName": rec.get("QueryName", rec.get("query", "")),
            "QueryType": rec.get("QueryType", "A"),
            "ResponseCode": response_code,
            "Answer": rec.get("Answer", ""),
        }

        results.append(
            {
                "timestamp": _parse_ts(rec.get("timestamp")),
                "hostname": rec.get("hostname", ""),
                "source_ip": parsed_fields["SourceIp"] or "",
                "severity": severity,
                "event_id": "dns_query",
                "log_type": "dns",
                "source_file": source_file,
                "raw_log": json.dumps(rec),
                "parsed_fields": parsed_fields,
            }
        )
    return results
