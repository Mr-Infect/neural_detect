from fastapi.testclient import TestClient

from apps.api.main import app
from core.version import __version__

client = TestClient(app)

def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_versioned_health() -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["version"] == __version__

def test_system_info() -> None:
    response = client.get("/api/v1/system/info")
    assert response.status_code == 200
    assert response.json()["name"] == "NEURAL DETECT"

