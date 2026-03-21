import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_create_election(client):
    resp = client.post("/api/v1/elections", json={
        "name": "Тестови избори 2026",
        "date": "2026-04-07",
        "polls_open": "07:00",
        "polls_close": "20:00",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Тестови избори 2026"
    assert data["status"] == "draft"
    assert data["extension_policy"] == "required"


def test_add_party(client):
    # Create election
    resp = client.post("/api/v1/elections", json={
        "name": "Test", "date": "2026-04-07",
        "polls_open": "07:00", "polls_close": "20:00",
    })
    eid = resp.json()["id"]

    # Add party
    resp = client.post(f"/api/v1/elections/{eid}/parties", json={
        "name": "ГЕРБ-СДС",
        "candidates": ["Кандидат 1", "Кандидат 2"],
    })
    assert resp.status_code == 200


def test_activate_election(client):
    resp = client.post("/api/v1/elections", json={
        "name": "Test", "date": "2026-04-07",
        "polls_open": "07:00", "polls_close": "20:00",
    })
    eid = resp.json()["id"]

    # Can't activate without parties
    resp = client.post(f"/api/v1/elections/{eid}/activate")
    assert resp.status_code == 422

    # Add party then activate
    client.post(f"/api/v1/elections/{eid}/parties", json={"name": "Test Party"})
    resp = client.post(f"/api/v1/elections/{eid}/activate")
    assert resp.status_code == 200
    assert resp.json()["status"] == "active"


def test_seal_election(client):
    resp = client.post("/api/v1/elections", json={
        "name": "Test", "date": "2026-04-07",
        "polls_open": "07:00", "polls_close": "20:00",
    })
    eid = resp.json()["id"]
    client.post(f"/api/v1/elections/{eid}/parties", json={"name": "P"})
    client.post(f"/api/v1/elections/{eid}/activate")

    resp = client.post(f"/api/v1/elections/{eid}/seal")
    assert resp.status_code == 200
    assert resp.json()["status"] == "sealed"


def test_list_elections(client):
    resp = client.get("/api/v1/elections")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
