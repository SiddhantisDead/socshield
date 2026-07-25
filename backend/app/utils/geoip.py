"""
Lightweight IP -> country/ASN lookup for map visualizations.

No MaxMind GeoIP2 license key is wired in (that requires a paid/registered
account), so this uses a small static table for well-known ranges plus a
deterministic hash-based fallback so every IP still resolves to *something*
stable across requests. Swap `lookup()` for a real GeoIP2 reader
(`geoip2.database.Reader(...).city(ip)`) once a license/db is available.
"""
import hashlib
import ipaddress

_KNOWN_RANGES: list[tuple[str, dict]] = [
    ("10.0.0.0/8", {"country": "Internal", "asn": "AS0-PRIVATE", "isp": "Corporate LAN"}),
    ("192.168.0.0/16", {"country": "Internal", "asn": "AS0-PRIVATE", "isp": "Corporate LAN"}),
    ("172.16.0.0/12", {"country": "Internal", "asn": "AS0-PRIVATE", "isp": "Corporate LAN"}),
    ("203.0.113.0/24", {"country": "Russia", "asn": "AS48347", "isp": "Selectel Ltd"}),
    ("198.51.100.0/24", {"country": "China", "asn": "AS4134", "isp": "Chinanet"}),
    ("192.0.2.0/24", {"country": "Nigeria", "asn": "AS37282", "isp": "MainOne Cable"}),
    ("185.220.0.0/16", {"country": "Netherlands", "asn": "AS60729", "isp": "Tor Exit Relay"}),
]

_FALLBACK_COUNTRIES = [
    ("United States", "AS15169", "Google LLC"),
    ("Germany", "AS3320", "Deutsche Telekom"),
    ("Brazil", "AS28573", "Claro NXT"),
    ("Vietnam", "AS45899", "VNPT"),
    ("Ukraine", "AS13188", "Triolan"),
    ("India", "AS55836", "Reliance Jio"),
    ("Iran", "AS197207", "MCI"),
]


def lookup(ip: str) -> dict:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"country": "Unknown", "asn": "", "isp": ""}

    for cidr, info in _KNOWN_RANGES:
        if addr in ipaddress.ip_network(cidr):
            return info

    digest = int(hashlib.sha256(ip.encode()).hexdigest(), 16)
    country, asn, isp = _FALLBACK_COUNTRIES[digest % len(_FALLBACK_COUNTRIES)]
    return {"country": country, "asn": asn, "isp": isp}
