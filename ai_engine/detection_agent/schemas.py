from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

AgentInputType = Literal[
    "threat_report", "attack_techniques", "incident_description", "sample_logs", "existing_sigma"
]


class AgentRequestOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str = Field(
        default="default", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$"
    )
    provider: str | None = Field(default=None, max_length=40)
    model: str | None = Field(default=None, max_length=160)
    fallback_providers: list[str] = Field(default_factory=list, max_length=4)
    cloud_consent: bool = False


class GenerateDetectionRequest(AgentRequestOptions):
    source_type: AgentInputType
    source_text: str = Field(min_length=1, max_length=60_000)
    baseline_rule_id: str | None = Field(default=None, max_length=64)
    baseline_sigma: str | None = Field(default=None, max_length=64_000)


class ImproveDetectionRequest(AgentRequestOptions):
    source_type: Literal["existing_sigma"] = "existing_sigma"
    source_text: str | None = Field(default=None, min_length=1, max_length=64_000)
    rule_id: str | None = Field(default=None, min_length=1, max_length=64)
    requested_change: str = Field(min_length=3, max_length=4000)
    positive_fixtures: list[dict[str, Any]] | None = Field(default=None, max_length=20)
    negative_fixtures: list[dict[str, Any]] | None = Field(default=None, max_length=20)


class ExplainDetectionRequest(AgentRequestOptions):
    source_type: Literal["existing_sigma"] = "existing_sigma"
    source_text: str | None = Field(default=None, min_length=1, max_length=64_000)
    rule_id: str | None = Field(default=None, min_length=1, max_length=64)
