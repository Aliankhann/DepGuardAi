"""
Router tests for scan endpoints:
  POST /repos/{id}/scan
  GET  /scans/{id}/status
  GET  /scans/{id}/verify

The background pipeline (_run_pipeline_background) is patched to a no-op
so tests don't attempt real OSV/Backboard calls.
"""

import pytest
from unittest.mock import patch, MagicMock

from app.models.repository import Repository
from app.models.scan_run import ScanRun
from app.models.dependency import Dependency
from app.models.alert import Alert
from app.models.analysis import Analysis
from app.models.remediation import Remediation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_repo(db, name="scan-repo", local_path="/tmp/repo"):
    repo = Repository(name=name, local_path=local_path, ecosystem="npm", language="node")
    db.add(repo)
    db.commit()
    db.refresh(repo)
    return repo


def _make_scan(db, repo_id, status="complete", alert_count=0):
    scan = ScanRun(repo_id=repo_id, status=status, alert_count=alert_count)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


# ---------------------------------------------------------------------------
# POST /repos/{id}/scan
# ---------------------------------------------------------------------------

def test_start_scan_repo_not_found(client):
    with patch("app.routers.scan._run_pipeline_background"):
        resp = client.post("/repos/999999/scan")
    assert resp.status_code == 404


def test_start_scan_no_local_path_returns_422(client, db_session):
    repo = Repository(name="no-path-repo", ecosystem="npm", language="node")
    db_session.add(repo)
    db_session.commit()
    db_session.refresh(repo)

    with patch("app.routers.scan._run_pipeline_background"):
        resp = client.post(f"/repos/{repo.id}/scan")
    assert resp.status_code == 422


def test_start_scan_repo_url_without_local_path_returns_422(client, db_session):
    repo = Repository(name="url-only-repo", repo_url="https://github.com/foo/bar", ecosystem="npm", language="node")
    db_session.add(repo)
    db_session.commit()
    db_session.refresh(repo)

    with patch("app.routers.scan._run_pipeline_background"):
        resp = client.post(f"/repos/{repo.id}/scan")
    assert resp.status_code == 422


def test_start_scan_creates_pending_scan(client, db_session):
    repo = _make_repo(db_session, name="trigger-repo")

    with patch("app.routers.scan._run_pipeline_background"):
        resp = client.post(f"/repos/{repo.id}/scan")

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "pending"
    assert data["repo_id"] == repo.id
    assert "id" in data


def test_start_scan_response_includes_required_fields(client, db_session):
    repo = _make_repo(db_session, name="fields-check-repo")

    with patch("app.routers.scan._run_pipeline_background"):
        resp = client.post(f"/repos/{repo.id}/scan")

    data = resp.json()
    assert "id" in data
    assert "repo_id" in data
    assert "status" in data
    assert "alert_count" in data
    assert "started_at" in data


def test_start_scan_requires_auth(unauth_client, db_session):
    repo = _make_repo(db_session, name="auth-scan-repo")
    with patch("app.routers.scan._run_pipeline_background"):
        resp = unauth_client.post(f"/repos/{repo.id}/scan")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# GET /scans/{id}/status
# ---------------------------------------------------------------------------

def test_get_scan_status_not_found(client):
    resp = client.get("/scans/999999/status")
    assert resp.status_code == 404


def test_get_scan_status_returns_correct_fields(client, db_session):
    repo = _make_repo(db_session, name="status-repo")
    scan = _make_scan(db_session, repo.id, status="analyzing", alert_count=5)

    resp = client.get(f"/scans/{scan.id}/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == scan.id
    assert data["status"] == "analyzing"
    assert data["alert_count"] == 5
    assert "current_agent" in data
    assert "error_message" in data


def test_get_scan_status_failed_scan(client, db_session):
    repo = _make_repo(db_session, name="failed-repo")
    scan = ScanRun(repo_id=repo.id, status="failed", error_message="scan_agent: OSV timeout")
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    resp = client.get(f"/scans/{scan.id}/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "failed"
    assert data["error_message"] == "scan_agent: OSV timeout"


def test_get_scan_status_requires_auth(unauth_client, db_session):
    repo = _make_repo(db_session, name="auth-status-repo")
    scan = _make_scan(db_session, repo.id)
    resp = unauth_client.get(f"/scans/{scan.id}/status")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# GET /scans/{id}/verify
# ---------------------------------------------------------------------------

def test_verify_scan_not_found(client):
    resp = client.get("/scans/999999/verify")
    assert resp.status_code == 404


def test_verify_scan_zero_alerts(client, db_session):
    repo = _make_repo(db_session, name="verify-empty-repo")
    scan = _make_scan(db_session, repo.id, status="complete", alert_count=0)

    resp = client.get(f"/scans/{scan.id}/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["scan_id"] == scan.id
    assert data["total_alerts"] == 0
    assert data["alerts_with_ai_analysis"] == 0
    assert data["coverage_pct"] == 0.0


def test_verify_scan_with_ai_alert(client, db_session):
    repo = _make_repo(db_session, name="verify-ai-repo")
    scan = _make_scan(db_session, repo.id, status="complete")

    dep = Dependency(repo_id=repo.id, scan_id=scan.id, name="lodash", version="4.17.4", ecosystem="npm")
    db_session.add(dep)
    db_session.flush()

    alert = Alert(
        scan_id=scan.id, repo_id=repo.id, dependency_id=dep.id,
        vuln_id="CVE-2019-10744", severity="HIGH", summary="Prototype pollution"
    )
    db_session.add(alert)
    db_session.flush()

    analysis = Analysis(
        alert_id=alert.id, risk_level="high", confidence="high",
        reasoning="Exploitable via _.merge", business_impact="RCE possible",
        recommended_fix="Upgrade lodash", analysis_source="backboard_ai"
    )
    db_session.add(analysis)
    db_session.commit()

    resp = client.get(f"/scans/{scan.id}/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_alerts"] == 1
    assert data["alerts_with_ai_analysis"] == 1
    assert data["alerts_with_fallback"] == 0
    assert data["coverage_pct"] == 100.0


def test_verify_scan_with_fallback_alert(client, db_session):
    repo = _make_repo(db_session, name="verify-fallback-repo")
    scan = _make_scan(db_session, repo.id, status="complete")

    dep = Dependency(repo_id=repo.id, scan_id=scan.id, name="express", version="4.17.1", ecosystem="npm")
    db_session.add(dep)
    db_session.flush()

    alert = Alert(
        scan_id=scan.id, repo_id=repo.id, dependency_id=dep.id,
        vuln_id="CVE-2022-24999", severity="MEDIUM", summary="Some vuln"
    )
    db_session.add(alert)
    db_session.flush()

    analysis = Analysis(
        alert_id=alert.id, risk_level="medium", confidence="low",
        reasoning="Fallback", business_impact="Unknown",
        recommended_fix="Upgrade", analysis_source="fallback"
    )
    db_session.add(analysis)
    db_session.commit()

    resp = client.get(f"/scans/{scan.id}/verify")
    data = resp.json()
    assert data["alerts_with_fallback"] == 1
    assert data["alerts_with_ai_analysis"] == 0
    assert data["coverage_pct"] == 0.0


def test_verify_scan_missing_analysis_counted(client, db_session):
    repo = _make_repo(db_session, name="verify-missing-repo")
    scan = _make_scan(db_session, repo.id, status="complete")

    dep = Dependency(repo_id=repo.id, scan_id=scan.id, name="axios", version="0.21.1", ecosystem="npm")
    db_session.add(dep)
    db_session.flush()

    alert = Alert(
        scan_id=scan.id, repo_id=repo.id, dependency_id=dep.id,
        vuln_id="CVE-2021-3749", severity="HIGH", summary="SSRF"
    )
    db_session.add(alert)
    db_session.commit()
    # No Analysis record created — intentionally missing

    resp = client.get(f"/scans/{scan.id}/verify")
    data = resp.json()
    assert data["alerts_missing_analysis"] == 1
    assert data["total_alerts"] == 1
