from functools import lru_cache
from urllib.parse import urlsplit

from pydantic import SecretStr, model_validator
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
    opa_url: str = "http://opa:8181"
    soar_webhook_url: str | None = None
    soar_webhook_token: SecretStr | None = None
    bootstrap_admin_email: str = "admin@neural-detect.local"
    bootstrap_admin_password: SecretStr = SecretStr("")
    log_level: str = "INFO"
    secret_key: SecretStr = SecretStr("development-only-change-me")
    detection_approval_token: SecretStr | None = None

    @model_validator(mode="after")
    def validate_production_configuration(self) -> "Settings":
        if self.environment.strip().lower() not in {"production", "prod"}:
            return self
        secret = self.secret_key.get_secret_value()
        password = self.bootstrap_admin_password.get_secret_value()
        database = urlsplit(self.database_url)
        elastic = urlsplit(self.elasticsearch_url)
        has_elastic_auth = bool(self.elasticsearch_api_key and self.elasticsearch_api_key.get_secret_value()) or bool(self.elasticsearch_username and self.elasticsearch_password and self.elasticsearch_password.get_secret_value())
        if len(secret) < 32 or secret == "development-only-change-me":
            raise ValueError("Production requires ND_SECRET_KEY with at least 32 non-default characters.")
        if len(password) < 20:
            raise ValueError("Production requires ND_BOOTSTRAP_ADMIN_PASSWORD with at least 20 characters.")
        if not database.hostname or database.hostname in {"localhost", "127.0.0.1"} or database.password in {None, "", "neural"}:
            raise ValueError("Production requires a non-default database URL and password.")
        if elastic.scheme != "https" or not self.elasticsearch_verify_certs or not has_elastic_auth:
            raise ValueError("Production requires authenticated HTTPS Elasticsearch with certificate verification enabled.")
        return self
@lru_cache
def get_settings() -> Settings:
    return Settings()
