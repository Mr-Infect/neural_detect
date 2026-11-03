from pydantic import BaseModel, ConfigDict, Field


class EvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str = Field(default="default", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    run_live_model: bool = False


class AgentTestRequest(EvaluationRequest):
    pass
