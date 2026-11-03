import pytest
from pydantic import SecretStr, ValidationError

from core.config.settings import Settings


def test_production_rejects_default_secrets_and_insecure_elasticsearch() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="production")


def test_production_accepts_explicit_secrets_and_authenticated_https_elasticsearch() -> None:
    settings = Settings(
        environment="production",
        secret_key=SecretStr("s" * 48),
        bootstrap_admin_password=SecretStr("a" * 24),
        database_url="postgresql+asyncpg://neural:unique-db-password@postgres:5432/neural_detect",
        elasticsearch_url="https://search.example.invalid:9200",
        elasticsearch_api_key=SecretStr("elasticsearch-test-api-key"),
        elasticsearch_verify_certs=True,
    )
    assert settings.environment == "production"
