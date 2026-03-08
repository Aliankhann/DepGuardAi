"""
Unit tests for depvuln_agent and the exploitability_agent dep_investigations integration.

Tests deterministic logic in isolation — no DB, no real Backboard calls.
Uses SimpleNamespace to mock Alert, Dependency, and UsageLocation records.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, AsyncMock

import pytest

from app.services.agents.depvuln_agent import (
    _build_fallback,
    _extract_fixed_version,
    _max_severity,
)
from app.services.agents.exploitability_agent import (
    _find_detected_functions,
    _score,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_alert(
    alert_id: int,
    vuln_id: str = "CVE-TEST",
    severity: str = "HIGH",
    summary: str = "Test summary",
    osv_data: dict | None = None,
    dependency_id: int = 1,
):
    return SimpleNamespace(
        id=alert_id,
        vuln_id=vuln_id,
        severity=severity,
        summary=summary,
        osv_data=osv_data or {},
        dependency_id=dependency_id,
        dependency_investigation=None,
    )


def make_dep(name: str = "lodash", version: str = "4.17.15", ecosystem: str = "npm"):
    return SimpleNamespace(id=1, name=name, version=version, ecosystem=ecosystem)


def make_usage(file_path: str, context_tags: list, snippet: str = "import pkg"):
    return SimpleNamespace(
        id=id(file_path),
        file_path=file_path,
        context_tags=context_tags,
        snippet=snippet,
        line_number=1,
    )


# ---------------------------------------------------------------------------
# _extract_fixed_version
# ---------------------------------------------------------------------------


def test_extracts_fixed_version_from_osv():
    osv = {
        "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]
    }
    assert _extract_fixed_version(osv) == "4.17.21"


def test_returns_none_when_no_fixed_version():
    osv = {"affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}]}
    assert _extract_fixed_version(osv) is None


def test_returns_none_on_empty_osv():
    assert _extract_fixed_version({}) is None


# ---------------------------------------------------------------------------
# _max_severity
# ---------------------------------------------------------------------------


def test_max_severity_critical_wins():
    alerts = [
        make_alert(1, severity="HIGH"),
        make_alert(2, severity="CRITICAL"),
        make_alert(3, severity="LOW"),
    ]
    assert _max_severity(alerts) == "critical"


def test_max_severity_single_high():
    alerts = [make_alert(1, severity="HIGH")]
    assert _max_severity(alerts) == "high"


def test_max_severity_defaults_to_low():
    alerts = [make_alert(1, severity="LOW")]
    assert _max_severity(alerts) == "low"


# ---------------------------------------------------------------------------
# _build_fallback
# ---------------------------------------------------------------------------


def test_fallback_has_required_keys():
    dep = make_dep("lodash", "4.17.15", "npm")
    alert = make_alert(1, vuln_id="CVE-2019-10744", severity="HIGH")
    result = _build_fallback(dep, [alert])

    required = [
        "package_name", "package_version", "ecosystem",
        "vulnerability_ids", "vulnerability_summary", "vulnerable_behaviors",
        "severity_level", "suggested_safe_version", "investigation_focus",
        "investigation_source",
    ]
    for key in required:
        assert key in result, f"Missing key: {key}"


def test_fallback_source_is_fallback():
    dep = make_dep()
    alert = make_alert(1)
    result = _build_fallback(dep, [alert])
    assert result["investigation_source"] == "fallback"


def test_fallback_lodash_investigation_focus():
    dep = make_dep("lodash")
    alert = make_alert(1)
    result = _build_fallback(dep, [alert])
    # KNOWN_DANGEROUS_PATTERNS["lodash"] should be in investigation_focus
    assert any("merge" in p for p in result["investigation_focus"])


def test_fallback_unknown_package_has_empty_focus():
    dep = make_dep("some-unknown-package")
    alert = make_alert(1)
    result = _build_fallback(dep, [alert])
    assert isinstance(result["investigation_focus"], list)


def test_fallback_suggested_safe_version_from_osv():
    dep = make_dep("lodash")
    osv = {"affected": [{"ranges": [{"events": [{"fixed": "4.17.21"}]}]}]}
    alert = make_alert(1, osv_data=osv)
    result = _build_fallback(dep, [alert])
    assert result["suggested_safe_version"] == "4.17.21"


def test_fallback_includes_all_vuln_ids():
    dep = make_dep()
    alerts = [
        make_alert(1, vuln_id="CVE-A"),
        make_alert(2, vuln_id="CVE-B"),
        make_alert(3, vuln_id="GHSA-C"),
    ]
    result = _build_fallback(dep, alerts)
    assert "CVE-A" in result["vulnerability_ids"]
    assert "CVE-B" in result["vulnerability_ids"]
    assert "GHSA-C" in result["vulnerability_ids"]


# ---------------------------------------------------------------------------
# exploitability_agent integration: dep_investigations extra_patterns
# ---------------------------------------------------------------------------


def test_extra_patterns_detected_in_snippet():
    """AI-derived investigation_focus pattern detected even if not in KNOWN_DANGEROUS_PATTERNS."""
    usages = [make_usage("src/api/client.js", ["api", "MEDIUM_SENSITIVITY"], "customMerge(obj, src)")]
    detected = _find_detected_functions(usages, "somepackage", [], extra_patterns=["customMerge("])
    assert "customMerge(" in detected


def test_extra_patterns_merged_with_known():
    """Both KNOWN_DANGEROUS_PATTERNS and extra_patterns are searched."""
    usages = [
        make_usage("src/api/client.js", ["api", "MEDIUM_SENSITIVITY"], "_.merge(a, b) and customFn(x)"),
    ]
    detected = _find_detected_functions(usages, "lodash", [], extra_patterns=["customFn("])
    assert "_.merge" in detected
    assert "customFn(" in detected


def test_extra_patterns_none_does_not_crash():
    usages = [make_usage("src/utils/helper.js", ["util", "LOW_SENSITIVITY"], "import _ from 'lodash'")]
    detected = _find_detected_functions(usages, "lodash", [], extra_patterns=None)
    assert isinstance(detected, list)


def test_score_uses_extra_patterns():
    """_score with extra_patterns from dep_investigations detects AI-derived pattern."""
    usages = [
        make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"], "customVulnFunc(req.body)")
    ]
    result = _score(usages, "unknownpkg", {}, extra_patterns=["customVulnFunc("])
    assert "customVulnFunc(" in result["detected_functions"]
    assert result["exploitability"] == "likely"   # HIGH + function → likely


def test_score_without_extra_patterns_unchanged():
    """_score without extra_patterns still works correctly (backward compat)."""
    usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"], "_.merge({}, req.body)")]
    result = _score(usages, "lodash", {})
    assert result["exploitability"] == "likely"
    assert "_.merge" in result["detected_functions"]


# ---------------------------------------------------------------------------
# depvuln_agent.run() — async integration with mock DB
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_empty_alerts_returns_empty():
    from app.services.agents.depvuln_agent import run
    db = MagicMock()
    repo = SimpleNamespace(id=1, name="test-repo", backboard_depvuln_assistant_id=None)
    result = await run([], repo, db)
    assert result == {}


@pytest.mark.asyncio
async def test_run_returns_keyed_by_dep_name(monkeypatch):
    """With BACKBOARD_API_KEY unset, run() uses fallback and returns dict keyed by dep_name."""
    from app.services.agents import depvuln_agent
    from app.services import backboard_service

    # Ensure fallback is used
    monkeypatch.setattr(backboard_service.settings, "BACKBOARD_API_KEY", "")

    dep = make_dep("lodash", "4.17.15", "npm")
    alert = make_alert(1, vuln_id="CVE-2019-10744", dependency_id=1)

    db = MagicMock()
    db.get = MagicMock(return_value=dep)

    repo = SimpleNamespace(id=1, name="test-repo", backboard_depvuln_assistant_id=None)

    # Patch alert.dependency_investigation setter
    object.__setattr__(alert, "dependency_investigation", None)

    results = await depvuln_agent.run([alert], repo, db)

    assert "lodash" in results
    inv = results["lodash"]
    assert inv["package_name"] == "lodash"
    assert inv["investigation_source"] == "fallback"
    assert isinstance(inv["investigation_focus"], list)


@pytest.mark.asyncio
async def test_run_writes_to_alert(monkeypatch):
    """run() sets alert.dependency_investigation for each alert in the package."""
    from app.services.agents import depvuln_agent
    from app.services import backboard_service

    monkeypatch.setattr(backboard_service.settings, "BACKBOARD_API_KEY", "")

    dep = make_dep("axios", "0.21.0", "npm")
    alert1 = make_alert(1, vuln_id="CVE-A", dependency_id=10)
    alert2 = make_alert(2, vuln_id="CVE-B", dependency_id=10)

    # Use a dict to track mutations since SimpleNamespace allows attribute assignment
    db = MagicMock()
    db.get = MagicMock(return_value=dep)

    repo = SimpleNamespace(id=1, name="test-repo", backboard_depvuln_assistant_id=None)

    await depvuln_agent.run([alert1, alert2], repo, db)

    # Both alerts should now have dependency_investigation set
    assert alert1.dependency_investigation is not None
    assert alert2.dependency_investigation is not None
    assert alert1.dependency_investigation["package_name"] == "axios"
    assert alert1.dependency_investigation == alert2.dependency_investigation  # same dict per package
