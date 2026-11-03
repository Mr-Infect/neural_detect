from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="ND_", extra="ignore")
    app_name: str = "NEURAL DETECT"
    environment: str = "development"
    api_prefix: str = "/api/v1"
    database_url: str = "postgresql+asyncpg://neural:neural@localhost:5432/neural_detect"
    elasticsearch_url: str = "http://localhost:9200"
    elasticsearch_api_key: SecretStr | None = None
    elasticsearch_username: str | None = None
    elasticsearch_password: SecretStr | None = None
    elasticsearch_verify_certs: bool = True
    elasticsearch_index_pattern: str = "neural-detect-*"
    kibana_url: str = "http://localhost:5601"
    log_level: str = "INFO"
    secret_key: SecretStr = SecretStr("development-only-change-me")
    detection_approval_token: SecretStr | None = None

@lru_cache
def get_settings() -> Settings:
    return Settings()
