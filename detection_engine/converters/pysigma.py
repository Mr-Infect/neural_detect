from __future__ import annotations

from typing import Any

from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

from detection_engine.validators.sigma import validate_sigma_source

# Community (SigmaHQ/Sysmon-style) field names -> ECS. Rules already written in ECS names are untouched.
SIGMA_TO_ECS: dict[str, str] = {
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "ParentImage": "process.parent.executable",
    "ParentCommandLine": "process.parent.command_line",
    "OriginalFileName": "process.pe.original_file_name",
    "Description": "process.pe.description",
    "Product": "process.pe.product",
    "Company": "process.pe.company",
    "FileVersion": "process.pe.file_version",
    "CurrentDirectory": "process.working_directory",
    "ProcessId": "process.pid",
    "User": "user.name",
    "Computer": "host.name",
    "TargetFilename": "file.path",
    "TargetObject": "registry.path",
    "QueryName": "dns.question.name",
    "SourceIp": "source.ip",
    "SourcePort": "source.port",
    "DestinationIp": "destination.ip",
    "DestinationPort": "destination.port",
    "DestinationHostname": "destination.domain",
}


def ecs_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="neural-detect-ecs",
        priority=20,
        items=[ProcessingItem(identifier="ecs_field_mapping", transformation=FieldMappingTransformation(SIGMA_TO_ECS))],
    )


def compile_sigma(source: str) -> dict[str, Any]:
    document, stable_id = validate_sigma_source(source)
    try:
        collection = SigmaCollection.from_yaml(source)
        queries = LuceneBackend(processing_pipeline=ecs_pipeline()).convert(collection)
    except Exception as exc:
        raise ValueError(f"pySigma Elasticsearch compilation failed: {exc}") from exc
    if len(queries) != 1 or not isinstance(queries[0], str) or not queries[0].strip():
        raise ValueError("The Elasticsearch backend did not produce one usable query.")
    query = queries[0]
    deployment = {
        "type": "query",
        "language": "lucene",
        "index": ["neural-detect-*"],
        "query": query,
        "enabled": False,
        "rule_id": stable_id,
    }
    return {
        "rule_id": stable_id,
        "title": document["title"],
        "format": "sigma",
        "compiled_query": query,
        "deployment": deployment,
    }