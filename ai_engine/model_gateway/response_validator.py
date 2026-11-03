import json

from pydantic import ValidationError

from ai_engine.model_gateway.schemas import (
    AlertTriageOutput,
    DetectionCandidateOutput,
    DetectionExplanationOutput,
    DetectionOutput,
    HuntingQueryOutput,
    InvestigationAnalysisOutput,
    InvestigationOutput,
    ThreatIntelligenceOutput,
)

OUTPUT_MODELS = {
    "detection": DetectionOutput,
    "detection_candidate": DetectionCandidateOutput,
    "detection_explanation": DetectionExplanationOutput,
    "threat_intelligence": ThreatIntelligenceOutput,
    "investigation": InvestigationOutput,
    "investigation_analysis": InvestigationAnalysisOutput,
    "alert_triage": AlertTriageOutput,
    "hunting_query": HuntingQueryOutput,
}


def validate_response(output_kind: str, content: str):
    model = OUTPUT_MODELS.get(output_kind)
    if model is None:
        raise ValueError("Unsupported structured output type.")
    candidate = content.strip()
    if candidate.startswith("```"):
        candidate = candidate.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
    try:
        return model.model_validate(json.loads(candidate))
    except (json.JSONDecodeError, ValidationError) as exc:
        raise ValueError("Provider response did not match the required output schema.") from exc

