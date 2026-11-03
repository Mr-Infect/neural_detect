from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

OutputKind = Literal[
    "detection",
    "detection_candidate",
    "detection_explanation",
    "threat_intelligence",
    "investigation",
    "investigation_analysis",
    "alert_triage",
    "hunting_query",
]


class DetectionOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=4000)
    query: str = Field(min_length=1, max_length=20_000)
    query_language: Literal["sigma", "esql", "eql", "kql", "lucene"]
    attack_techniques: list[str] = Field(default_factory=list, max_length=64)
    rationale: str = Field(min_length=1, max_length=4000)


class CandidateFixture(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_.-]+$")
    events: list[dict[str, Any]] = Field(min_length=1, max_length=50)


class DetectionCandidateOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sigma_yaml: str = Field(min_length=1, max_length=64_000)
    rule_metadata: dict[str, Any] = Field(default_factory=dict)
    attack_techniques: list[str] = Field(min_length=1, max_length=64)
    required_event_sources: list[str] = Field(min_length=1, max_length=40)
    required_ecs_fields: list[str] = Field(min_length=1, max_length=100)
    positive_fixtures: list[CandidateFixture] = Field(min_length=1, max_length=20)
    negative_fixtures: list[CandidateFixture] = Field(min_length=1, max_length=20)
    explanation: str = Field(min_length=1, max_length=6000)
    behavior_summary: str = Field(min_length=1, max_length=4000)
    confidence: float = Field(ge=0, le=1)


class DetectionExplanationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    behavior_summary: str = Field(min_length=1, max_length=4000)
    attack_techniques: list[str] = Field(default_factory=list, max_length=64)
    required_event_sources: list[str] = Field(default_factory=list, max_length=40)
    required_ecs_fields: list[str] = Field(default_factory=list, max_length=100)
    logic_explanation: str = Field(min_length=1, max_length=6000)
    false_positive_scenarios: list[str] = Field(default_factory=list, max_length=50)
    limitations: list[str] = Field(default_factory=list, max_length=50)


class Indicator(BaseModel):
    type: Literal["ipv4", "ipv6", "domain", "url", "sha256", "md5", "email"]
    value: str = Field(min_length=1, max_length=2048)
    confidence: float = Field(ge=0, le=1)
    source: str = Field(min_length=1, max_length=500)


class ThreatIntelligenceOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, max_length=4000)
    indicators: list[Indicator] = Field(default_factory=list, max_length=500)
    attack_techniques: list[str] = Field(default_factory=list, max_length=64)
    source_references: list[str] = Field(default_factory=list, max_length=100)


class InvestigationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, max_length=6000)
    findings: list[str] = Field(default_factory=list, max_length=100)
    evidence_references: list[str] = Field(default_factory=list, max_length=200)
    confidence: float = Field(ge=0, le=1)
    recommended_next_steps: list[str] = Field(default_factory=list, max_length=30)


class HuntingQueryOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query_language: Literal["esql", "eql", "kql"]
    query: str = Field(min_length=1, max_length=20_000)
    explanation: str = Field(min_length=1, max_length=4000)
    time_range: str | None = Field(default=None, max_length=100)


class InferenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str = Field(
        default="default", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$"
    )
    prompt: str = Field(min_length=1, max_length=20_000)
    output_kind: OutputKind
    provider: str | None = Field(default=None, max_length=40)
    model: str | None = Field(default=None, max_length=160)
    fallback_providers: list[str] = Field(default_factory=list, max_length=4)
    cloud_consent: bool = False
    contains_raw_telemetry: bool = False
    max_response_tokens: int = Field(default=2048, ge=128, le=8192)

class EvidenceFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    statement: str = Field(min_length=1, max_length=2000)
    evidence_references: list[str] = Field(min_length=1, max_length=20)


class InvestigationAnalysisOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    observed_findings: list[EvidenceFinding] = Field(default_factory=list, max_length=50)
    analytical_inferences: list[str] = Field(default_factory=list, max_length=50)
    confidence_basis: str = Field(min_length=1, max_length=2000)
    unknowns: list[str] = Field(default_factory=list, max_length=50)
    recommended_next_steps: list[str] = Field(default_factory=list, max_length=30)


class AlertTriageOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    severity: Literal["low", "medium", "high", "critical"]
    category: str = Field(min_length=1, max_length=80)
    attack_techniques: list[str] = Field(default_factory=list, max_length=64)
    prioritization_reason: str = Field(min_length=1, max_length=2000)


