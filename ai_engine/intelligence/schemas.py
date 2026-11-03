from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class IntelIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str = Field(default="default", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    source_type: Literal["stix", "mitre_attack", "taxii"] = "stix"
    source_name: str = Field(default="uploaded STIX bundle", min_length=1, max_length=160)
    source_url: str = Field(default="local-upload", min_length=1, max_length=2048)
    source_version: str | None = Field(default=None, max_length=128)
    objects: list[dict] = Field(min_length=1, max_length=50000)


class IntelSyncRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str = Field(default="default", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    source: Literal["mitre_attack", "taxii"] = "mitre_attack"
    collection_id: str | None = Field(default=None, max_length=128)
    taxii_server_url: str | None = Field(default=None, max_length=2048)


class IntelSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str = Field(default="default", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    query: str = Field(min_length=2, max_length=2000)
    top_k: int = Field(default=8, ge=1, le=30)
    object_types: list[str] = Field(default_factory=list, max_length=20)


class IndicatorQuery(BaseModel):
    tenant_id: str = Field(default="default", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    indicator_type: str | None = Field(default=None, max_length=32)
    value: str | None = Field(default=None, max_length=2048)
