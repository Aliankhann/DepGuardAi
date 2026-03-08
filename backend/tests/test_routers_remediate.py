"""
Router tests for remediation endpoints:
  GET  /alerts/{id}/remediation
  POST /alerts/{id}/remediation/finalize
"""

import pytest
from unittest.mock import AsyncMock, patch

from app.models.repository import Repository
from app.models.scan_run import ScanRun
from app.models.dependency import Dependency
from app.models.alert import Alert
from app.models.remediation import Remediation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_alert(db, vuln_id="CVE-2019-10744"):
    """Create a minimal repo → scan → dep → alert chain. Returns (repo, scan, alert)."""
    repo = Repository(name=f"rem-repo-{vuln_id}", local_path="/tmp/r", ecosystem="npm", language="node")
    db.add(repo)
    db.flush()

    scan = ScanRun(repo_id=repo.id, status="complete")
    db.add(scan)
    db.flush()

    dep = Dependency(repo_id=repo.id, scan_id=scan.id, name="lodash", version="4.17.4", ecosystem="npm")
    db.add(dep)
    db.flush()

    alert = Alert(
        scan_id=scan.id, repo_id=repo.id, dependency_id=dep.id,
        vuln_id=vuln_id, severity="HIGH", summary="Prototype pollution"
    )
    db.add(alert)
    db.commit()
    db.refresh(repo)
    db.refresh(scan)
    db.refresh(alert)
    return repo, scan, alert


def _make_remediation(db, alert_id):
    rem = Remediation(
        alert_id=alert_id,
        safe_version="4.17.21",
        install_command="npm install lodash@4.17.21",
        checklist=["Upgrade lodash", "Run npm audit"],
        temporary_mitigation="Restrict merge endpoint",
        permanent_fix_summary="Upgrade lodash to 4.17.21",
        review_note="Senior review required",
        senior_review_urgency="immediate",
    )
    db.add(rem)
    db.commit()
    db.refresh(rem)
    return rem


# ---------------------------------------------------------------------------
# GET /alerts/{id}/remediation
# ---------------------------------------------------------------------------

def test_get_remediation_alert_not_found(client):
    resp = client.get("/alerts/999999/remediation")
    assert resp.status_code == 404


def test_get_remediation_not_found_when_missing(client, db_session):
    _, _, alert = _seed_alert(db_session, vuln_id="CVE-NO-REM")
    resp = client.get(f"/alerts/{alert.id}/remediation")
    assert resp.status_code == 404


def test_get_remediation_returns_remediation(client, db_session):
    _, _, alert = _seed_alert(db_session, vuln_id="CVE-HAS-REM")
    _make_remediation(db_session, alert.id)

    resp = client.get(f"/alerts/{alert.id}/remediation")
    assert resp.status_code == 200
    data = resp.json()
    assert data["safe_version"] == "4.17.21"
    assert data["install_command"] == "npm install lodash@4.17.21"
    assert data["senior_review_urgency"] == "immediate"


def test_get_remediation_response_shape(client, db_session):
    _, _, alert = _seed_alert(db_session, vuln_id="CVE-SHAPE")
    _make_remediation(db_session, alert.id)

    resp = client.get(f"/alerts/{alert.id}/remediation")
    data = resp.json()
    assert "id" in data
    assert "alert_id" in data
    assert "safe_version" in data
    assert "install_command" in data
    assert "checklist" in data
    assert isinstance(data["checklist"], list)
    assert "temporary_mitigation" in data
    assert "permanent_fix_summary" in data
    assert "review_note" in data
    assert "senior_review_urgency" in data
    assert "created_at" in data


def test_get_remediation_requires_auth(unauth_client, db_session):
    resp = unauth_client.get("/alerts/1/remediation")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# POST /alerts/{id}/remediation/finalize
# ---------------------------------------------------------------------------

def test_finalize_alert_not_found(client):
    resp = client.post(
        "/alerts/999999/remediation/finalize",
        json={"senior_approved_fix": "npm install lodash@4.17.21", "rationale": "Safe version confirmed"},
    )
    assert resp.status_code == 404


def test_finalize_remediation_not_found(client, db_session):
    _, _, alert = _seed_alert(db_session, vuln_id="CVE-FIN-MISS")
    # No remediation created
    resp = client.post(
        f"/alerts/{alert.id}/remediation/finalize",
        json={"senior_approved_fix": "upgrade", "rationale": "fine"},
    )
    assert resp.status_code == 404


def test_finalize_stores_fix_and_returns_stored_true(client, db_session):
    _, _, alert = _seed_alert(db_session, vuln_id="CVE-FIN-OK")
    _make_remediation(db_session, alert.id)

    with patch("app.routers.remediate.backboard_service.store_senior_approved_fix", new_callable=AsyncMock) as mock_store:
        resp = client.post(
            f"/alerts/{alert.id}/remediation/finalize",
            json={"senior_approved_fix": "npm install lodash@4.17.21", "rationale": "Tested and confirmed"},
        )

    assert resp.status_code == 200
    assert resp.json() == {"stored": True}
    mock_store.assert_awaited_once()


def test_finalize_passes_correct_args_to_backboard(client, db_session):
    _, _, alert = _seed_alert(db_session, vuln_id="CVE-ARGS")
    rem = _make_remediation(db_session, alert.id)

    captured_kwargs = {}

    async def capture(**kwargs):
        captured_kwargs.update(kwargs)

    with patch("app.routers.remediate.backboard_service.store_senior_approved_fix", side_effect=capture):
        client.post(
            f"/alerts/{alert.id}/remediation/finalize",
            json={"senior_approved_fix": "npm install lodash@4.17.21", "rationale": "Approved"},
        )

    assert captured_kwargs["vuln_id"] == "CVE-ARGS"
    assert captured_kwargs["senior_approved_fix"] == "npm install lodash@4.17.21"
    assert captured_kwargs["rationale"] == "Approved"
    assert captured_kwargs["dep_name"] == "lodash"
    assert captured_kwargs["safe_version"] == "4.17.21"


def test_finalize_requires_auth(unauth_client, db_session):
    resp = unauth_client.post(
        "/alerts/1/remediation/finalize",
        json={"senior_approved_fix": "x", "rationale": "y"},
    )
    assert resp.status_code in (401, 403)
