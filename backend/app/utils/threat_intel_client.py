"""
Threat intel adapters for VirusTotal and AbuseIPDB.

Real HTTP calls are made whenever an API key is configured in the
environment; otherwise a deterministic mock response is returned so the
UI/API contract is fully exercisable without paid API access. Both paths
return the same IpReputationResult shape.
"""
import hashlib
from datetime import datetime, timedelta, timezone

import httpx

from app.config import settings
from app.utils.geoip import lookup as geoip_lookup


def _mock_score(ip: str) -> int:
    digest = int(hashlib.sha256(ip.encode()).hexdigest(), 16)
    return digest % 101


def _is_private(ip: str) -> bool:
    """RFC1918/loopback/link-local only. Deliberately excludes the RFC5737
    TEST-NET documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24) - Python's ipaddress.is_private treats those as private
    too, but this simulator's synthetic attacker IPs are drawn from exactly
    those ranges and should still resolve to a reputation score."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback or addr.is_link_local or any(
            addr in ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        )
    except ValueError:
        return False


def _mock_reputation(ip: str) -> dict:
    geo = geoip_lookup(ip)
    score = 0 if _is_private(ip) else _mock_score(ip)
    tags = []
    if score > 75:
        tags = ["malicious", "botnet"]
    elif score > 40:
        tags = ["suspicious"]

    return {
        "ip": ip,
        "source": "mock",
        "is_mock": True,
        "malicious_score": score,
        "country": geo["country"],
        "asn": geo["asn"],
        "isp": geo["isp"],
        "total_reports": score // 5,
        "last_reported": (datetime.now(timezone.utc) - timedelta(hours=score)).isoformat() if score else None,
        "tags": tags,
    }


def _query_abuseipdb(ip: str) -> dict:
    resp = httpx.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
        timeout=10.0,
    )
    resp.raise_for_status()
    data = resp.json()["data"]
    return {
        "ip": ip,
        "source": "abuseipdb",
        "is_mock": False,
        "malicious_score": data.get("abuseConfidenceScore", 0),
        "country": data.get("countryCode", ""),
        "asn": "",
        "isp": data.get("isp", ""),
        "total_reports": data.get("totalReports", 0),
        "last_reported": data.get("lastReportedAt"),
        "tags": ["malicious"] if data.get("abuseConfidenceScore", 0) > 75 else [],
    }


def _query_virustotal(ip: str) -> dict:
    resp = httpx.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": settings.virustotal_api_key},
        timeout=10.0,
    )
    resp.raise_for_status()
    attrs = resp.json()["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) or 1
    return {
        "ip": ip,
        "source": "virustotal",
        "is_mock": False,
        "malicious_score": round(malicious / total * 100),
        "country": attrs.get("country", ""),
        "asn": str(attrs.get("asn", "")),
        "isp": attrs.get("as_owner", ""),
        "total_reports": malicious,
        "last_reported": None,
        "tags": attrs.get("tags", []),
    }


def get_ip_reputation(ip: str) -> dict:
    if settings.abuseipdb_api_key:
        try:
            return _query_abuseipdb(ip)
        except httpx.HTTPError:
            pass
    if settings.virustotal_api_key:
        try:
            return _query_virustotal(ip)
        except httpx.HTTPError:
            pass
    return _mock_reputation(ip)
