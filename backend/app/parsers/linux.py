"""Parses Linux syslog-style auth logs (/var/log/auth.log format)."""
import re
from datetime import datetime, timezone

from app.models.enums import Severity

_LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w.\-]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

_FAILED_PW_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
)
_ACCEPTED_PW_RE = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)")
_SUDO_RE = re.compile(r"(?P<user>\S+)\s*:.*COMMAND=(?P<command>.*)$")
_USERADD_RE = re.compile(r"new user: name=(?P<user>[\w.\-]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+)")
_INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")

_CURRENT_YEAR = datetime.now(timezone.utc).year


def _parse_timestamp(ts: str) -> datetime:
    try:
        dt = datetime.strptime(f"{_CURRENT_YEAR} {ts}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def parse_linux_log(content: bytes, source_file: str) -> list[dict]:
    text = content.decode("utf-8", errors="replace")
    results = []

    for line in text.splitlines():
        if not line.strip():
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue

        host = m.group("host")
        process = m.group("process")
        message = m.group("message")
        timestamp = _parse_timestamp(m.group("ts"))

        action = "info"
        user = ""
        source_ip = ""
        port = None
        command = ""
        uid = None
        severity = Severity.informational

        if (fm := _FAILED_PW_RE.search(message)):
            action, user, source_ip, port = "Failed password", fm.group("user"), fm.group("ip"), fm.group("port")
            severity = Severity.medium
        elif (am := _ACCEPTED_PW_RE.search(message)):
            action, user, source_ip, port = "Accepted password", am.group("user"), am.group("ip"), am.group("port")
            severity = Severity.low
        elif (im := _INVALID_USER_RE.search(message)):
            action, user, source_ip = "Invalid user", im.group("user"), im.group("ip")
            severity = Severity.medium
        elif (sm := _SUDO_RE.search(message)) and process == "sudo":
            action, user, command = "Command", sm.group("user"), sm.group("command")
            severity = Severity.medium
        elif (um := _USERADD_RE.search(message)):
            action, user, uid = "New user", um.group("user"), int(um.group("uid"))
            severity = Severity.high if uid == 0 else Severity.medium

        event_id = f"{process}:{action}".replace(" ", "_").lower()

        parsed_fields = {
            "Process": process,
            "Action": action,
            "User": user,
            "SourceIp": source_ip,
            "Port": int(port) if port else None,
            "Pid": m.group("pid") or "",
            "Command": command,
            "UID": uid,
            "Message": message,
        }

        results.append(
            {
                "timestamp": timestamp,
                "hostname": host,
                "source_ip": source_ip,
                "severity": severity,
                "event_id": event_id,
                "log_type": "linux",
                "source_file": source_file,
                "raw_log": line,
                "parsed_fields": parsed_fields,
            }
        )

    return results
