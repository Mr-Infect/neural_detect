import asyncio
import json

import httpx
import pytest

from ai_engine.model_gateway.base import ProviderRequest
from ai_engine.model_gateway.policy import TenantPolicy, authorize_provider
from ai_engine.model_gateway.providers.anthropic import AnthropicProvider
from ai_engine.model_gateway.providers.ollama import OllamaProvider
from ai_engine.model_gateway.providers.openai_compatible import (
    OpenAICompatibleProvider,
    ProviderError,
)
from ai_engine.model_gateway.redaction import detect_raw_telemetry, redact_sensitive_data
from ai_engine.model_gateway.response_validator import validate_response
from ai_engine.model_gateway.router import RateLimitExceeded, TenantRateLimiter

INVESTIGATION = {"summary": "ok", "findings": [], "evidence_references": [], "confidence": 1, "recommended_next_steps": []}


def test_redaction_removes_credentials_contact_data_and_ips() -> None:
    result = redact_sensitive_data("password=hunter2 email alice@example.org host 10.1.2.3")
    assert "hunter2" not in result.text
    assert "alice@example.org" not in result.text
    assert "10.1.2.3" not in result.text
    assert set(result.categories) >= {"credential", "email", "ipv4"}


def test_raw_telemetry_is_detected_from_ecs_events():
    assert detect_raw_telemetry("{\"@timestamp\":\"now\",\"event\":{\"category\":\"process\"},\"host\":{\"name\":\"server\"}}")
    assert detect_raw_telemetry("Failed password for operator from 10.1.2.3")
    assert not detect_raw_telemetry("Write a query for failed authentication events")

def test_cloud_policy_requires_global_tenant_and_per_request_permission(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ND_AI_CLOUD_ENABLED", "true")
    policy = TenantPolicy(cloud_enabled=True)
    with pytest.raises(PermissionError):
        authorize_provider("openai_compatible", policy, cloud_consent=False, contains_raw_telemetry=False)
    with pytest.raises(PermissionError):
        authorize_provider("openai_compatible", TenantPolicy(), cloud_consent=True, contains_raw_telemetry=False)
    with pytest.raises(PermissionError):
        authorize_provider("openai_compatible", policy, cloud_consent=True, contains_raw_telemetry=True)
    authorize_provider("openai_compatible", policy, cloud_consent=True, contains_raw_telemetry=False)


def test_structured_output_validator_rejects_invalid_provider_json() -> None:
    assert validate_response("investigation", json.dumps(INVESTIGATION)).confidence == 1
    with pytest.raises(ValueError):
        validate_response("investigation", '{"summary":"missing required fields"}')


def test_rate_limiter_enforces_per_tenant_window() -> None:
    async def run() -> None:
        limiter = TenantRateLimiter()
        await limiter.check("tenant-a", 1)
        with pytest.raises(RateLimitExceeded):
            await limiter.check("tenant-a", 1)
        await limiter.check("tenant-b", 1)
    asyncio.run(run())


def test_openai_compatible_adapter_uses_chat_completions_and_parses_usage() -> None:
    seen: dict = {}
    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"model":"local-test", "choices":[{"message":{"content":json.dumps(INVESTIGATION)}}], "usage":{"prompt_tokens":11,"completion_tokens":5}})
    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        provider = OpenAICompatibleProvider("http://mock/v1", "mock-model", client=client)
        result = await provider.infer(ProviderRequest("mock-model", "Investigate", "{}", 128))
        assert result.model == "local-test"
        assert result.prompt_tokens == 11
        assert seen["url"] == "http://mock/v1/chat/completions"
        assert seen["body"]["response_format"] == {"type":"json_object"}
        await client.aclose()
    asyncio.run(run())


def test_ollama_adapter_uses_local_chat_api_and_tracks_token_usage() -> None:
    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"model":"local:latest", "message":{"content":json.dumps(INVESTIGATION)}, "prompt_eval_count":7,"eval_count":3})))
        provider = OllamaProvider("http://mock", "local:latest", client=client)
        result = await provider.infer(ProviderRequest("local:latest", "Investigate", "{}", 128))
        assert result.prompt_tokens == 7 and result.completion_tokens == 3
        await client.aclose()
    asyncio.run(run())


def test_anthropic_adapter_uses_messages_api_and_auth_headers() -> None:
    seen: dict = {}
    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["headers"] = request.headers
        return httpx.Response(200, json={"model":"claude-test", "id":"msg_123", "content":[{"type":"text","text":json.dumps(INVESTIGATION)}], "usage":{"input_tokens":13,"output_tokens":6}})
    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        provider = AnthropicProvider("http://mock", "claude-test", api_key="test-secret", client=client)
        result = await provider.infer(ProviderRequest("claude-test", "Investigate", "{}", 128))
        assert result.prompt_tokens == 13 and result.completion_tokens == 6
        assert seen["url"] == "http://mock/v1/messages"
        assert seen["headers"]["x-api-key"] == "test-secret"
        await client.aclose()
    asyncio.run(run())


def test_openai_adapter_retries_server_errors_and_surfaces_timeout() -> None:
    attempts = 0
    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(503)
        return httpx.Response(200, json={"model":"local-test", "choices":[{"message":{"content":json.dumps(INVESTIGATION)}}]})
    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        provider = OpenAICompatibleProvider("http://mock/v1", "mock-model", retries=1, client=client)
        await provider.infer(ProviderRequest("mock-model", "Investigate", "{}", 128))
        assert attempts == 2
        await client.aclose()
        timeout_client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("timed out"))))
        timeout_provider = OpenAICompatibleProvider("http://mock/v1", "mock-model", retries=0, client=timeout_client)
        with pytest.raises(ProviderError) as error:
            await timeout_provider.infer(ProviderRequest("mock-model", "Investigate", "{}", 128))
        assert error.value.code == "timeout"
        await timeout_client.aclose()
    asyncio.run(run())

