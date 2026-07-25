from fastapi import APIRouter, Depends, Query

from app.schemas.threat_intel import IpReputationResult
from app.auth.deps import get_current_user
from app.utils.threat_intel_client import get_ip_reputation

router = APIRouter(tags=["threat-intel"])


@router.get("/threat-intel", response_model=IpReputationResult)
def threat_intel(ip: str = Query(..., description="IP address to check reputation for"), current_user=Depends(get_current_user)):
    result = get_ip_reputation(ip)
    return IpReputationResult(**result)
