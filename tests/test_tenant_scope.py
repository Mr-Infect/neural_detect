from core.authorization.middleware import _category, _request_tenant


def test_scoped_api_paths_default_to_the_default_tenant() -> None:
    assert _request_tenant("/api/v1/automation/approvals", {}, {}) == "default"
    assert _request_tenant("/api/v1/dashboard/summary", {}, {}) == "default"


def test_explicit_tenant_scope_is_preserved() -> None:
    assert _request_tenant("/api/v1/telemetry/search", {"tenant_id": "blue"}, {}) == "blue"
    assert _request_tenant("/api/v1/automation/approvals", {}, {"tenant_id": "green"}) == "green"


def test_sensitive_routes_have_explicit_policy_categories() -> None:
    assert _category("POST", "/api/v1/automation/approvals") == "approval_request"
    assert _category("POST", "/api/v1/automation/approvals/id/review") == "approval_review"
    assert _category("POST", "/api/v1/automation/approvals/id/execute") == "response_execute"
