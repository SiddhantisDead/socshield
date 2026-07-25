import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/config.py -> repo root is two levels up from backend/
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./soc_shield.db"
    jwt_secret: str = "change-me-in-production-" + os.urandom(8).hex()
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 8

    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    upload_dir: str = "./uploads"
    sigma_rules_dir: str = str(_REPO_ROOT / "sigma_rules")
    yara_rules_dir: str = str(_REPO_ROOT / "yara_rules")
    datasets_dir: str = str(_REPO_ROOT / "datasets")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
