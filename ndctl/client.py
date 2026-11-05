from __future__ import annotations

from typing import Any

import httpx


class ApiError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(f"HTTP {status}: {detail}")
        self.status = status
        self.detail = detail


class Client:
    """Thin client for the NEURAL DETECT API (/api/v1)."""

    def __init__(self, url: str, token: str | None = None, transport: httpx.BaseTransport | None = None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        self._http = httpx.Client(base_url=url.rstrip("/") + "/api/v1", headers=headers, timeout=30, transport=transport)

    def close(self) -> None:
        self._http.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        response = self._http.request(method, path, **kwargs)
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                detail = response.text
            raise ApiError(response.status_code, str(detail))
        return response.json() if response.content else None

    def login(self, email: str, password: str) -> dict[str, Any]:
        return self._request("POST", "/auth/login", json={"email": email, "password": password})

    def list_rules(self, tenant: str | None = None) -> list[dict[str, Any]]:
        return self._request("GET", "/detections", params={"tenant_id": tenant} if tenant else None)

    def create_rule(self, payload: dict[str, Any], tenant: str | None = None) -> dict[str, Any]:
        return self._request("POST", "/detections", json=payload, params={"tenant_id": tenant} if tenant else None)

    def update_rule(self, rule_uuid: str, payload: dict[str, Any], tenant: str | None = None) -> dict[str, Any]:
        return self._request("PATCH", f"/detections/{rule_uuid}", json=payload, params={"tenant_id": tenant} if tenant else None)

    def request_approval(self, rule_uuid: str, requested_by: str, tenant: str | None = None) -> dict[str, Any]:
        return self._request("POST", f"/detections/{rule_uuid}/approvals", json={"requested_by": requested_by},
                             params={"tenant_id": tenant} if tenant else None)

    def deploy(self, rule_uuid: str, approval_id: str, tenant: str | None = None) -> dict[str, Any]:
        params = {"approval_id": approval_id, **({"tenant_id": tenant} if tenant else {})}
        return self._request("POST", f"/detections/{rule_uuid}/deploy", params=params)
