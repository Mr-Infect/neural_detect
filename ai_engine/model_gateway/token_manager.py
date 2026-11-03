import os

from pydantic import SecretStr


def secret_for_provider(provider: str) -> SecretStr | None:
    env_name = {"openai_compatible": "ND_OPENAI_API_KEY", "anthropic": "ND_ANTHROPIC_API_KEY", "llama_cpp": "ND_LLAMA_CPP_API_KEY"}.get(provider)
    if not env_name:
        return None
    value = os.getenv(env_name)
    return SecretStr(value) if value else None
