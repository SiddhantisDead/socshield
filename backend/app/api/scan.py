from fastapi import APIRouter, Depends, UploadFile, File

from app.schemas.threat_intel import FileScanResult
from app.auth.deps import get_current_user
from app.detection.yara_engine import get_yara_engine
from app.config import settings

router = APIRouter(tags=["scan"])

MAX_SCAN_BYTES = 25 * 1024 * 1024  # 25MB


@router.post("/scan", response_model=FileScanResult)
async def scan_file(file: UploadFile = File(...), current_user=Depends(get_current_user)):
    data = await file.read(MAX_SCAN_BYTES + 1)
    if len(data) > MAX_SCAN_BYTES:
        data = data[:MAX_SCAN_BYTES]

    engine = get_yara_engine(settings.yara_rules_dir)
    result = engine.scan_bytes(data)

    return FileScanResult(
        filename=file.filename or "",
        sha256=result["sha256"],
        matched_rules=result["matched_rules"],
        severity=result["severity"],
        is_malicious=result["is_malicious"],
    )
