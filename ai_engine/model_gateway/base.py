from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ProviderRequest:
    model: str
    prompt: str
    output_schema: str
    max_tokens: int


@dataclass(frozen=True)
class ProviderResult:
    content: str
    model: str
    model_version: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class ModelProvider(Protocol):
    name: str
    cloud: bool

    async def infer(self, request: ProviderRequest) -> ProviderResult: ...
    async def health(self) -> dict[str, Any]: ...
