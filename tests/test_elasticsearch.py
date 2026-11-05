import pytest

from integrations.elasticsearch.esql_service import validate_esql
from integrations.elasticsearch.search_service import validate_index


def test_validate_neural_detect_index() -> None:
    assert validate_index("neural-detect-*") == "neural-detect-*"
    assert validate_index("neural-detect-2026.11.02") == "neural-detect-2026.11.02"

@pytest.mark.parametrize("index", ["*", ".security", "logs-*", "neural-detect-../users"])
def test_reject_index_outside_platform_namespace(index: str) -> None:
    with pytest.raises(ValueError):
        validate_index(index)

@pytest.mark.parametrize("query", ["FROM neural-detect-* | LIMIT 5", "FROM neural-detect-auth, neural-detect-process | LIMIT 5"])
def test_accept_esql_only_for_platform_indices(query: str) -> None:
    assert validate_esql(query) == query

@pytest.mark.parametrize("query", ["FROM logs-* | LIMIT 5", "FROM .security | LIMIT 5", "SHOW INFO"])
def test_reject_esql_outside_platform_namespace(query: str) -> None:
    with pytest.raises(ValueError):
        validate_esql(query)

def test_recent_alerts_are_scoped_to_the_tenant_from_source() -> None:
    import asyncio
    from unittest.mock import MagicMock, patch

    from integrations.elasticsearch import alert_service

    hits = [
        {"_source": {"kibana.alert.rule.name": "a", "tenant": {"id": "default"}}},
        {"_source": {"kibana.alert.rule.name": "b", "tenant": {"id": "other"}}},
        {"_source": {"kibana.alert.rule.name": "c", "tenant.id": "default"}},
        {"_source": {"kibana.alert.rule.name": "d"}},
    ]

    class Client:
        def options(self, **_: object) -> "Client":
            return self

        async def search(self, **_: object) -> MagicMock:
            return MagicMock(body={"hits": {"hits": hits}})

    with patch.object(alert_service, "get_client", return_value=Client()):
        names = [a["kibana.alert.rule.name"] for a in asyncio.run(alert_service.recent_alerts(5, "default"))]
        limited = asyncio.run(alert_service.recent_alerts(1, "default"))
    assert names == ["a", "c"]
    assert len(limited) == 1
