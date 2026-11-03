from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AgentOptions(BaseModel):
    model_config=ConfigDict(extra="forbid")
    tenant_id:str=Field(default="default",min_length=1,max_length=128,pattern=r"^[A-Za-z0-9_.:-]+$")
    provider:str|None=Field(default=None,max_length=40)
    model:str|None=Field(default=None,max_length=160)
    fallback_providers:list[str]=Field(default_factory=list,max_length=4)
    cloud_consent:bool=False

class HuntRequest(AgentOptions):
    request:str=Field(min_length=8,max_length=6000)
    time_range_hours:int=Field(default=24,ge=1,le=2160)

class InvestigationRequest(AgentOptions):
    alert_id:str=Field(min_length=1,max_length=256)
    time_range_hours:int=Field(default=72,ge=1,le=2160)

class IncidentNoteRequest(BaseModel):
    model_config=ConfigDict(extra="forbid")
    tenant_id:str=Field(default="default",min_length=1,max_length=128,pattern=r"^[A-Za-z0-9_.:-]+$")
    author:str=Field(default="analyst",min_length=1,max_length=128,pattern=r"^[A-Za-z0-9_.:@-]+$")
    note:str=Field(min_length=1,max_length=8000)

class IncidentStatusRequest(BaseModel):
    model_config=ConfigDict(extra="forbid")
    tenant_id:str=Field(default="default",min_length=1,max_length=128,pattern=r"^[A-Za-z0-9_.:-]+$")
    actor:str=Field(default="analyst",min_length=1,max_length=128,pattern=r"^[A-Za-z0-9_.:@-]+$")
    status:Literal["open","in_progress","resolved","closed"]
    note:str|None=Field(default=None,max_length=2000)

class EvidenceFinding(BaseModel):
    model_config=ConfigDict(extra="forbid")
    statement:str=Field(min_length=1,max_length=2000)
    evidence_references:list[str]=Field(min_length=1,max_length=20)

class InvestigationAnalysisOutput(BaseModel):
    model_config=ConfigDict(extra="forbid")
    observed_findings:list[EvidenceFinding]=Field(default_factory=list,max_length=50)
    analytical_inferences:list[str]=Field(default_factory=list,max_length=50)
    confidence_basis:str=Field(min_length=1,max_length=2000)
    unknowns:list[str]=Field(default_factory=list,max_length=50)
    recommended_next_steps:list[str]=Field(default_factory=list,max_length=30)

class AlertTriageOutput(BaseModel):
    model_config=ConfigDict(extra="forbid")
    severity:Literal["low","medium","high","critical"]
    category:str=Field(min_length=1,max_length=80)
    attack_techniques:list[str]=Field(default_factory=list,max_length=64)
    prioritization_reason:str=Field(min_length=1,max_length=2000)

