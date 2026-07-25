from pydantic import BaseModel


class IpReputationResult(BaseModel):
    ip: str
    source: str
    is_mock: bool
    malicious_score: int
    country: str = ""
    asn: str = ""
    isp: str = ""
    total_reports: int = 0
    last_reported: str | None = None
    tags: list[str] = []


class FileScanResult(BaseModel):
    filename: str
    sha256: str
    matched_rules: list[dict]
    severity: str
    is_malicious: bool
