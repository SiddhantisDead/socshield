import enum


class UserRole(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"


class Severity(str, enum.Enum):
    critical = "Critical"
    high = "High"
    medium = "Medium"
    low = "Low"
    informational = "Informational"


class AlertStatus(str, enum.Enum):
    open = "Open"
    acknowledged = "Acknowledged"
    closed = "Closed"


class IncidentStatus(str, enum.Enum):
    open = "Open"
    investigating = "Investigating"
    resolved = "Resolved"
    closed = "Closed"


class LogType(str, enum.Enum):
    windows = "windows"
    linux = "linux"
    apache = "apache"
    firewall = "firewall"
    dns = "dns"
    json = "json"
    syslog = "syslog"
