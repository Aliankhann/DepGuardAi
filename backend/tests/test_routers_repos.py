"""
Router tests for /repos endpoints.

Uses in-memory SQLite + TestClient with get_db and verify_token overridden.
Tests: create, list, get, delete, list-scans — plus auth rejection.
"""

import pytest
from app.models.repository import Repository
from app.models.scan_run import ScanRun


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_repo(db, name="test-repo", local_path="/tmp/test", ecosystem="npm"):
    repo = Repository(name=name, local_path=local_path, ecosystem=ecosystem, language="node")
    db.add(repo)
    db.commit()
    db.refresh(repo)
    return repo


# ---------------------------------------------------------------------------
# POST /repos
# ---------------------------------------------------------------------------

def test_create_repo_returns_201(client):
    resp = client.post("/repos", json={"name": "my-app", "local_path": "/code/my-app", "ecosystem": "npm"})
    assert resp.status_code == 201


def test_create_repo_response_shape(client):
    resp = client.post("/repos", json={"name": "shape-app", "local_path": "/code/shape", "ecosystem": "PyPI", "language": "python"})
    data = resp.json()
    assert "id" in data
    assert data["name"] == "shape-app"
    assert data["local_path"] == "/code/shape"
    assert data["ecosystem"] == "PyPI"
    assert data["language"] == "python"
    assert "created_at" in data
    assert data["backboard_assistant_id"] is None


def test_create_repo_defaults_ecosystem_to_npm(client):
    resp = client.post("/repos", json={"name": "default-eco"})
    assert resp.status_code == 201
    assert resp.json()["ecosystem"] == "npm"


# ---------------------------------------------------------------------------
# GET /repos
# ---------------------------------------------------------------------------

def test_list_repos_empty(client):
    resp = client.get("/repos")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_list_repos_returns_created_repos(client, db_session):
    _make_repo(db_session, name="listed-repo-1")
    _make_repo(db_session, name="listed-repo-2")
    resp = client.get("/repos")
    assert resp.status_code == 200
    names = [r["name"] for r in resp.json()]
    assert "listed-repo-1" in names
    assert "listed-repo-2" in names


def test_list_repos_ordered_by_created_at_desc(client, db_session):
    _make_repo(db_session, name="older-repo")
    _make_repo(db_session, name="newer-repo")
    resp = client.get("/repos")
    names = [r["name"] for r in resp.json()]
    # Newer should appear before older (desc order)
    assert names.index("newer-repo") < names.index("older-repo")


# ---------------------------------------------------------------------------
# GET /repos/{id}
# ---------------------------------------------------------------------------

def test_get_repo_not_found(client):
    resp = client.get("/repos/999999")
    assert resp.status_code == 404


def test_get_repo_found(client, db_session):
    repo = _make_repo(db_session, name="findable-repo")
    resp = client.get(f"/repos/{repo.id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == repo.id
    assert resp.json()["name"] == "findable-repo"


# ---------------------------------------------------------------------------
# DELETE /repos/{id}
# ---------------------------------------------------------------------------

def test_delete_repo_not_found(client):
    resp = client.delete("/repos/999999")
    assert resp.status_code == 404


def test_delete_repo_returns_204(client, db_session):
    repo = _make_repo(db_session, name="deletable-repo")
    resp = client.delete(f"/repos/{repo.id}")
    assert resp.status_code == 204


def test_delete_repo_removes_from_db(client, db_session):
    repo = _make_repo(db_session, name="gone-repo")
    repo_id = repo.id
    client.delete(f"/repos/{repo_id}")
    # Expire session cache so we re-query
    db_session.expire_all()
    assert db_session.get(Repository, repo_id) is None


def test_delete_repo_cascades_scans(client, db_session):
    """Deleting a repo also removes its ScanRun records."""
    repo = _make_repo(db_session, name="cascade-repo")
    scan = ScanRun(repo_id=repo.id, status="complete")
    db_session.add(scan)
    db_session.commit()
    scan_id = scan.id

    client.delete(f"/repos/{repo.id}")
    db_session.expire_all()
    assert db_session.get(ScanRun, scan_id) is None


# ---------------------------------------------------------------------------
# GET /repos/{id}/scans
# ---------------------------------------------------------------------------

def test_list_scans_repo_not_found(client):
    resp = client.get("/repos/999999/scans")
    assert resp.status_code == 404


def test_list_scans_empty(client, db_session):
    repo = _make_repo(db_session, name="no-scans-repo")
    resp = client.get(f"/repos/{repo.id}/scans")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_scans_returns_scans(client, db_session):
    repo = _make_repo(db_session, name="scanned-repo")
    scan = ScanRun(repo_id=repo.id, status="complete", alert_count=3)
    db_session.add(scan)
    db_session.commit()
    resp = client.get(f"/repos/{repo.id}/scans")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 1
    assert data[0]["status"] == "complete"
    assert data[0]["alert_count"] == 3


# ---------------------------------------------------------------------------
# Auth: unauthenticated requests must be rejected
# ---------------------------------------------------------------------------

def test_list_repos_requires_auth(unauth_client):
    resp = unauth_client.get("/repos")
    assert resp.status_code in (401, 403)


def test_create_repo_requires_auth(unauth_client):
    resp = unauth_client.post("/repos", json={"name": "x"})
    assert resp.status_code in (401, 403)


def test_delete_repo_requires_auth(unauth_client):
    resp = unauth_client.delete("/repos/1")
    assert resp.status_code in (401, 403)
