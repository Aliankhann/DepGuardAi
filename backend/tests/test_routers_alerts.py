"""
Router tests for alert endpoints:
  GET /repos/{id}/alerts
  GET /alerts/{id}
"""

import pytest

from app.models.repository import Repository
from app.models.scan_run import ScanRun
from app.models.dependency import Dependency
from app.models.alert import Alert
from app.models.analysis import Analysis
from app.models.usage import UsageLocation
from app.models.remediation import Remediation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_repo(db, name="alert-repo"):
    repo = Repository(name=name, local_path="/tmp/repo", ecosystem="npm", language="node")
    db.add(repo)
    db.commit()
    db.refresh(repo)
    return repo


def _make_scan(db, repo_id, status="complete"):
    scan = ScanRun(repo_id=repo_id, status=status)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _make_dep(db, repo_id, scan_id, name="lodash", version="4.17.4"):
    dep = Dependency(repo_id=repo_id, scan_id=scan_id, name=name, version=version, ecosystem="npm")
    db.add(dep)
    db.flush()
    return dep


def _make_alert(db, scan_id, repo_id, dep_id, vuln_id="CVE-2019-10744"):
    alert = Alert(
        scan_id=scan_id, repo_id=repo_id, dependency_id=dep_id,
        vuln_id=vuln_id, severity="HIGH", summary="Prototype pollution via _.merge()",
        osv_data={"aliases": ["GHSA-jf85-cpcp-j695"], "references": [{"url": "https://osv.dev/CVE-2019-10744"}]},
    )
    db.add(alert)
    db.flush()
    return alert


# ---------------------------------------------------------------------------
# GET /repos/{id}/alerts
# ---------------------------------------------------------------------------

def test_list_alerts_no_completed_scan_returns_empty(client, db_session):
    repo = _make_repo(db_session, name="no-scan-alerts-repo")
    resp = client.get(f"/repos/{repo.id}/alerts")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_alerts_in_progress_scan_returns_empty(client, db_session):
    repo = _make_repo(db_session, name="scanning-repo")
    _make_scan(db_session, repo.id, status="scanning")
    resp = client.get(f"/repos/{repo.id}/alerts")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_alerts_returns_alerts_from_latest_scan(client, db_session):
    repo = _make_repo(db_session, name="alerts-repo")
    scan = _make_scan(db_session, repo.id)
    dep = _make_dep(db_session, repo.id, scan.id)
    _make_alert(db_session, scan.id, repo.id, dep.id)
    db_session.commit()

    resp = client.get(f"/repos/{repo.id}/alerts")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["vuln_id"] == "CVE-2019-10744"
    assert data[0]["dependency_name"] == "lodash"
    assert data[0]["dependency_version"] == "4.17.4"


def test_list_alerts_summary_shape(client, db_session):
    repo = _make_repo(db_session, name="shape-alerts-repo")
    scan = _make_scan(db_session, repo.id)
    dep = _make_dep(db_session, repo.id, scan.id)
    _make_alert(db_session, scan.id, repo.id, dep.id)
    db_session.commit()

    resp = client.get(f"/repos/{repo.id}/alerts")
    item = resp.json()[0]
    assert "id" in item
    assert "vuln_id" in item
    assert "severity" in item
    assert "summary" in item
    assert "dependency_name" in item
    assert "dependency_version" in item
    assert "usage_count" in item
    assert "risk_level" in item


def test_list_alerts_with_risk_level_from_analysis(client, db_session):
    repo = _make_repo(db_session, name="risk-alerts-repo")
    scan = _make_scan(db_session, repo.id)
    dep = _make_dep(db_session, repo.id, scan.id)
    alert = _make_alert(db_session, scan.id, repo.id, dep.id)

    analysis = Analysis(
        alert_id=alert.id, risk_level="critical", confidence="high",
        reasoning="Exploitable", business_impact="RCE", recommended_fix="Upgrade",
        analysis_source="backboard_ai"
    )
    db_session.add(analysis)
    db_session.commit()

    resp = client.get(f"/repos/{repo.id}/alerts")
    assert resp.json()[0]["risk_level"] == "critical"


def test_list_alerts_filter_by_scan_id(client, db_session):
    repo = _make_repo(db_session, name="filter-scan-repo")
    scan1 = _make_scan(db_session, repo.id)
    scan2 = _make_scan(db_session, repo.id)

    dep1 = _make_dep(db_session, repo.id, scan1.id, name="lodash")
    dep2 = _make_dep(db_session, repo.id, scan2.id, name="axios")
    _make_alert(db_session, scan1.id, repo.id, dep1.id, vuln_id="CVE-S1")
    _make_alert(db_session, scan2.id, repo.id, dep2.id, vuln_id="CVE-S2")
    db_session.commit()

    resp = client.get(f"/repos/{repo.id}/alerts?scan_id={scan1.id}")
    assert resp.status_code == 200
    assert all(a["vuln_id"] == "CVE-S1" for a in resp.json())


def test_list_alerts_invalid_scan_id_returns_404(client, db_session):
    repo = _make_repo(db_session, name="invalid-scan-repo")
    resp = client.get(f"/repos/{repo.id}/alerts?scan_id=999999")
    assert resp.status_code == 404


def test_list_alerts_scan_id_wrong_repo_returns_404(client, db_session):
    """scan_id exists but belongs to a different repo — should 404."""
    repo1 = _make_repo(db_session, name="repo-one")
    repo2 = _make_repo(db_session, name="repo-two")
    scan_of_repo2 = _make_scan(db_session, repo2.id)

    resp = client.get(f"/repos/{repo1.id}/alerts?scan_id={scan_of_repo2.id}")
    assert resp.status_code == 404


def test_list_alerts_requires_auth(unauth_client, db_session):
    repo = _make_repo(db_session, name="auth-alerts-repo")
    resp = unauth_client.get(f"/repos/{repo.id}/alerts")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# GET /alerts/{id}
# ---------------------------------------------------------------------------

def test_get_alert_not_found(client):
    resp = client.get("/alerts/999999")
    assert resp.status_code == 404


def test_get_alert_detail_shape(client, db_session):
    repo = _make_repo(db_session, name="detail-repo")
    scan = _make_scan(db_session, repo.id)
    dep = _make_dep(db_session, repo.id, scan.id)
    alert = _make_alert(db_session, scan.id, repo.id, dep.id)
    db_session.commit()

    resp = client.get(f"/alerts/{alert.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == alert.id
    assert data["vuln_id"] == "CVE-2019-10744"
    assert data["dependency_name"] == "lodash"
    assert data["dependency_version"] == "4.17.4"
    assert "usage_locations" in data
    assert "analysis" in data
    assert "remediation" in data


def test_get_alert_parses_osv_aliases_and_references(client, db_session):
    repo = _make_repo(db_session, name="osv-parse-repo")
    scan = _make_scan(db_session, repo.id)
    dep = _make_dep(db_session, repo.id, scan.id)
    alert = _make_alert(db_session, scan.id, repo.id, dep.id)
    db_session.commit()

    resp = client.get(f"/alerts/{alert.id}")
    data = resp.json()
    assert "GHSA-jf85-cpcp-j695" in data["vuln_aliases"]
    assert "https://osv.dev/CVE-2019-10744" in data["references"]


def test_get_alert_null_analysis_and_remediation_when_missing(client, db_session):
    repo = _make_repo(db_session, name="null-analysis-repo")
    scan = _make_scan(db_session, repo.id)
    dep = _make_dep(db_session, repo.id, scan.id)
    alert = _make_alert(db_session, scan.id, repo.id, dep.id)
    db_session.commit()

    resp = client.get(f"/alerts/{alert.id}")
    data = resp.json()
    assert data["analysis"] is None
    assert data["remediation"] is None


def test_get_alert_includes_analysis_when_present(client, db_session):
    repo = _make_repo(db_session, name="with-analysis-repo")
    scan = _make_scan(db_session, repo.id)
    dep = _make_dep(db_session, repo.id, scan.id)
    alert = _make_alert(db_session, scan.id, repo.id, dep.id)

    analysis = Analysis(
        alert_id=alert.id, risk_level="high", confidence="medium",
        reasoning="Used in auth path", business_impact="Data breach",
        recommended_fix="Upgrade to 4.17.21", analysis_source="backboard_ai"
    )
    db_session.add(analysis)
    db_session.commit()

    resp = client.get(f"/alerts/{alert.id}")
    data = resp.json()
    assert data["analysis"] is not None
    assert data["analysis"]["risk_level"] == "high"
    assert data["analysis"]["analysis_source"] == "backboard_ai"


def test_get_alert_includes_usage_locations(client, db_session):
    repo = _make_repo(db_session, name="usage-alert-repo")
    scan = _make_scan(db_session, repo.id)
    dep = _make_dep(db_session, repo.id, scan.id)
    alert = _make_alert(db_session, scan.id, repo.id, dep.id)

    usage = UsageLocation(
        alert_id=alert.id, file_path="src/auth/session.js", line_number=12,
        snippet="_.merge({}, req.body)", import_type="cjs", context_tags=["auth", "HIGH_SENSITIVITY"]
    )
    db_session.add(usage)
    db_session.commit()

    resp = client.get(f"/alerts/{alert.id}")
    data = resp.json()
    assert len(data["usage_locations"]) == 1
    assert data["usage_locations"][0]["file_path"] == "src/auth/session.js"
    assert data["usage_locations"][0]["snippet"] == "_.merge({}, req.body)"


def test_get_alert_requires_auth(unauth_client, db_session):
    resp = unauth_client.get("/alerts/1")
    assert resp.status_code in (401, 403)
