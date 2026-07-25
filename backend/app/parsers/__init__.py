from app.parsers.windows import parse_windows_log
from app.parsers.linux import parse_linux_log
from app.parsers.apache import parse_apache_log
from app.parsers.generic import parse_firewall_log, parse_dns_log

PARSERS = {
    "windows": parse_windows_log,
    "linux": parse_linux_log,
    "apache": parse_apache_log,
    "firewall": parse_firewall_log,
    "dns": parse_dns_log,
}


def parse_log_file(log_type: str, content: bytes, source_file: str) -> list[dict]:
    parser = PARSERS.get(log_type)
    if parser is None:
        raise ValueError(f"Unsupported log_type: {log_type}")
    return parser(content, source_file)
