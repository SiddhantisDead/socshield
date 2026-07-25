"""
Parses JSON-exported Windows Event Log records (the common portable format
produced by `wevtutil qe /f:json` or Sysmon-to-JSON exporters). Native binary
.evtx parsing is out of scope for this simulator - JSON export covers the
same fields analysts actually pivot on.
"""
import json
from datetime import datetime, timezone

from app.models.enums import Severity

_HIGH_SEVERITY_EVENTS = {"4625", "4648", "4720", "4732", "1102", "4697"}
_MEDIUM_SEVERITY_EVENTS = {"4624", "4688", "4104", "5140", "4703"}


def _severity_for_event(event_id: str) -> Severity:
    if event_id in _HIGH_SEVERITY_EVENTS:
        return Severity.high
    if event_id in _MEDIUM_SEVERITY_EVENTS:
        return Severity.medium
    return Severity.informational


def parse_windows_log(content: bytes, source_file: str) -> list[dict]:
    text = content.decode("utf-8", errors="replace")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = [json.loads(line) for line in text.splitlines() if line.strip()]

    records = data if isinstance(data, list) else [data]
    results = []

    for rec in records:
        event_id = str(rec.get("EventID", rec.get("event_id", "")))
        ts_raw = rec.get("TimeCreated") or rec.get("timestamp") or datetime.now(timezone.utc).isoformat()
        try:
            timestamp = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        except ValueError:
            timestamp = datetime.now(timezone.utc)

        source_ip = rec.get("IpAddress") or rec.get("SourceIp") or ""

        parsed_fields = {
            "EventID": int(event_id) if event_id.isdigit() else event_id,
            "Channel": rec.get("Channel", ""),
            "ProviderName": rec.get("ProviderName", ""),
            "Computer": rec.get("Computer", rec.get("hostname", "")),
            "LogonType": rec.get("LogonType"),
            "TargetUserName": rec.get("TargetUserName", ""),
            "IpAddress": source_ip,
            "SourceIp": source_ip,
            "WorkstationName": rec.get("WorkstationName", ""),
            "ProcessName": rec.get("ProcessName", ""),
            "Image": rec.get("Image", rec.get("NewProcessName", "")),
            "ParentImage": rec.get("ParentImage", rec.get("ParentProcessName", "")),
            "CommandLine": rec.get("CommandLine", ""),
            "ParentCommandLine": rec.get("ParentCommandLine", ""),
            "ScriptBlockText": rec.get("ScriptBlockText", ""),
            "Message": rec.get("Message", ""),
        }

        results.append(
            {
                "timestamp": timestamp,
                "hostname": rec.get("Computer", rec.get("hostname", "")),
                "source_ip": source_ip,
                "severity": _severity_for_event(event_id),
                "event_id": event_id,
                "log_type": "windows",
                "source_file": source_file,
                "raw_log": json.dumps(rec),
                "parsed_fields": parsed_fields,
            }
        )

    return results
