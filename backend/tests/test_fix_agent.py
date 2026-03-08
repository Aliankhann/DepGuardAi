"""
Unit tests for fix_agent (Remediation Memory Agent).

Tests cover:
- Phase 1 deterministic logic (safe_version, install_command, checklist)
- Phase 2 Backboard AI path (mocked)
- Fallback when Backboard unavailable
- Graceful handling of AI failure
- New fields populated on Remediation record
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.agents.fix_agent import (
    _build_checklist,
    _build_install_command,
    _extract_fixed_version,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_alert(alert_id: int, vuln_id: str = "CVE-TEST", osv_data: dict = None, dep_id: int = 1):
    return SimpleNamespace(
        id=alert_id,
        vuln_id=vuln_id,
        dependency_id=dep_id,
        scan_id=1,
        osv_data=osv_data or {},
        severity="HIGH",
        summary="Test vulnerability",
    )


def make_dep(name: str = "lodash", version: str = "4.17.4", ecosystem: str = "npm"):
    return SimpleNamespace(name=name, version=version, ecosystem=ecosystem)


def make_repo(repo_id: int = 1, backboard_assistant_id: str = None):
    return SimpleNamespace(
        id=repo_id,
        name="test-repo",
        backboard_assistant_id=backboard_assistant_id,
    )


OSV_WITH_FIX = {
    "affected": [{
        "ranges": [{
            "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]
        }]
    }]
}

OSV_NO_FIX = {
    "affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}]
}


# ---------------------------------------------------------------------------
# Phase 1 — Deterministic unit tests
# ---------------------------------------------------------------------------

def test_extract_fixed_version_found():
    assert _extract_fixed_version(OSV_WITH_FIX) == "4.17.21"


def test_extract_fixed_version_missing():
    assert _extract_fixed_version(OSV_NO_FIX) is None


def test_extract_fixed_version_empty():
    assert _extract_fixed_version({}) is None


def test_build_install_command_npm_with_version():
    assert _build_install_command("npm", "lodash", "4.17.21") == "npm install lodash@4.17.21"


def test_build_install_command_npm_no_version():
    assert _build_install_command("npm", "lodash", None) == "npm install lodash@latest"


def test_build_install_command_pypi_with_version():
    assert _build_install_command("PyPI", "pyyaml", "6.0.1") == "pip install pyyaml==6.0.1"


def test_build_install_command_pypi_no_version():
    assert _build_install_command("PyPI", "pyyaml", None) == "pip install --upgrade pyyaml"


def test_build_checklist_includes_upgrade_step():
    cl = _build_checklist("npm", "lodash", "4.17.21")
    assert any("4.17.21" in step for step in cl)


def test_build_checklist_includes_audit():
    cl = _build_checklist("npm", "lodash", "4.17.21")
    assert any("npm audit" in step for step in cl)


def test_build_checklist_prepends_prior_context():
    cl = _build_checklist("npm", "lodash", "4.17.21", prior_remediation="Previously upgraded to 4.17.20")
    assert cl[0].startswith("Prior remediation context:")


def test_build_checklist_no_prior_context():
    cl = _build_checklist("npm", "lodash", "4.17.21", prior_remediation=None)
    assert not any("Prior remediation" in s for s in cl)


# ---------------------------------------------------------------------------
# Phase 2 — run() integration (mocked DB and Backboard)
# ---------------------------------------------------------------------------

def _make_db_mock(dep, analysis=None):
    """Return a mock Session where db.get() returns dep or None."""
    db = MagicMock()
    db.get.side_effect = lambda model, pk: dep if "Dependency" in str(model) else None
    query_mock = MagicMock()
    query_mock.filter.return_value.first.return_value = analysis
    db.query.return_value = query_mock
    return db


AI_REMEDIATION = {
    "temporary_mitigation": "Restrict the merge endpoint.",
    "permanent_fix_summary": "Upgrade lodash to 4.17.21.",
    "review_note": "High-risk path — senior review required.",
    "senior_review_urgency": "immediate",
}

FALLBACK_REMEDIATION = {
    "temporary_mitigation": "Restrict or disable affected functionality until the package is upgraded.",
    "permanent_fix_summary": "Upgrade to the safe version listed in the OSV advisory and re-run DepGuard scan.",
    "review_note": "AI analysis unavailable — manual senior review required before deploying fix.",
    "senior_review_urgency": "planned",
}


@pytest.mark.asyncio
async def test_run_populates_new_fields_from_ai():
    """When Backboard returns AI remediation, all 4 new fields are set on the Remediation record."""
    alert = make_alert(1, osv_data=OSV_WITH_FIX)
    dep = make_dep()
    repo = make_repo()
    db = _make_db_mock(dep)

    added = []
    db.add.side_effect = added.append

    with patch("app.services.agents.fix_agent.backboard_service") as mock_bb:
        mock_bb.recall_remediation_context = AsyncMock(return_value=None)
        mock_bb.run_remediation_analysis = AsyncMock(return_value=AI_REMEDIATION)

        from app.services.agents import fix_agent
        await fix_agent.run([alert], repo, db)

    assert len(added) == 1
    rem = added[0]
    assert rem.temporary_mitigation == AI_REMEDIATION["temporary_mitigation"]
    assert rem.permanent_fix_summary == AI_REMEDIATION["permanent_fix_summary"]
    assert rem.review_note == AI_REMEDIATION["review_note"]
    assert rem.senior_review_urgency == AI_REMEDIATION["senior_review_urgency"]


@pytest.mark.asyncio
async def test_run_deterministic_fields_correct():
    """Phase 1 fields (safe_version, install_command, checklist) are correct regardless of AI."""
    alert = make_alert(1, osv_data=OSV_WITH_FIX)
    dep = make_dep(name="lodash", version="4.17.4", ecosystem="npm")
    repo = make_repo()
    db = _make_db_mock(dep)

    added = []
    db.add.side_effect = added.append

    with patch("app.services.agents.fix_agent.backboard_service") as mock_bb:
        mock_bb.recall_remediation_context = AsyncMock(return_value=None)
        mock_bb.run_remediation_analysis = AsyncMock(return_value=AI_REMEDIATION)

        from app.services.agents import fix_agent
        await fix_agent.run([alert], repo, db)

    rem = added[0]
    assert rem.safe_version == "4.17.21"
    assert rem.install_command == "npm install lodash@4.17.21"
    assert isinstance(rem.checklist, list)
    assert len(rem.checklist) >= 3


@pytest.mark.asyncio
async def test_run_fallback_when_ai_raises():
    """If run_remediation_analysis raises, Remediation is still created with fallback values."""
    alert = make_alert(1, osv_data=OSV_WITH_FIX)
    dep = make_dep()
    repo = make_repo()
    db = _make_db_mock(dep)

    added = []
    db.add.side_effect = added.append

    with patch("app.services.agents.fix_agent.backboard_service") as mock_bb:
        mock_bb.recall_remediation_context = AsyncMock(return_value=None)
        mock_bb.run_remediation_analysis = AsyncMock(side_effect=RuntimeError("Backboard down"))

        from app.services.agents import fix_agent
        # Should not raise
        await fix_agent.run([alert], repo, db)

    # Remediation still created — fallback values filled in by backboard_service itself
    assert len(added) == 1


@pytest.mark.asyncio
async def test_run_passes_exploitability_and_blast_radius():
    """exploitability_results and blast_radius_results are forwarded to run_remediation_analysis."""
    alert = make_alert(1, osv_data=OSV_WITH_FIX)
    dep = make_dep()
    repo = make_repo()
    db = _make_db_mock(dep)
    db.add.side_effect = lambda x: None

    expl = {1: {"exploitability": "likely", "evidence_strength": "high", "detected_functions": []}}
    blast = {1: {"blast_radius_label": "subsystem", "affected_files": 5, "scope_clarity": "high"}}

    with patch("app.services.agents.fix_agent.backboard_service") as mock_bb:
        mock_bb.recall_remediation_context = AsyncMock(return_value=None)
        mock_bb.run_remediation_analysis = AsyncMock(return_value=AI_REMEDIATION)

        from app.services.agents import fix_agent
        await fix_agent.run([alert], repo, db, exploitability_results=expl, blast_radius_results=blast)

    call_kwargs = mock_bb.run_remediation_analysis.call_args.kwargs
    assert call_kwargs["exploitability_result"] == expl[1]
    assert call_kwargs["blast_radius_result"] == blast[1]


@pytest.mark.asyncio
async def test_run_skips_alert_with_no_dep():
    """If dep lookup returns None, alert is silently skipped."""
    alert = make_alert(1)
    repo = make_repo()
    db = MagicMock()
    db.get.return_value = None  # no dep found
    db.query.return_value.filter.return_value.first.return_value = None

    added = []
    db.add.side_effect = added.append

    with patch("app.services.agents.fix_agent.backboard_service") as mock_bb:
        mock_bb.recall_remediation_context = AsyncMock(return_value=None)
        mock_bb.run_remediation_analysis = AsyncMock(return_value=AI_REMEDIATION)

        from app.services.agents import fix_agent
        await fix_agent.run([alert], repo, db)

    assert len(added) == 0
