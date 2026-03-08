"""
Unit tests for the AI-backed context_agent.

Tests deterministic logic in isolation — no DB, no real Backboard calls.
Uses SimpleNamespace to mock UsageLocation and Alert records.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

from app.services.agents.context_agent import (
    CONTEXT_RULES,
    _classify,
    _sensitivity_label,
    _apply_fallback,
    _apply_ai_result,
)
from app.services.backboard_service import _parse_context_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_usage(
    file_path: str,
    snippet: str = "import pkg from 'pkg'",
    import_type: str = "esm",
    usage_id: int = 1,
):
    u = SimpleNamespace(
        id=usage_id,
        file_path=file_path,
        snippet=snippet,
        import_type=import_type,
        line_number=10,
        context_tags=[],
        sensitivity_level=None,
        sensitive_surface_reason=None,
        subsystem_labels=None,
        user_input_proximity=None,
    )
    return u


def make_alert(alert_id: int = 1, vuln_id: str = "CVE-TEST", summary: str = "test"):
    return SimpleNamespace(
        id=alert_id,
        vuln_id=vuln_id,
        summary=summary,
        dependency_id=1,
        osv_data={},
    )


# ---------------------------------------------------------------------------
# _classify — deterministic path-based fallback
# ---------------------------------------------------------------------------


def test_classify_auth_path_is_high():
    tags = _classify("src/auth/session.js")
    assert "HIGH_SENSITIVITY" in tags
    assert "auth" in tags


def test_classify_test_path_is_low():
    tags = _classify("tests/unit/helper.js")
    assert "LOW_SENSITIVITY" in tags
    assert "test" in tags


def test_classify_api_path_is_medium():
    tags = _classify("src/routes/handler.js")
    assert "MEDIUM_SENSITIVITY" in tags
    assert "api" in tags


def test_classify_unknown_path_is_unclassified():
    tags = _classify("src/foo/bar.js")
    assert "unclassified" in tags
    assert "LOW_SENSITIVITY" in tags


def test_classify_high_beats_low_in_same_path():
    """auth_helpers.js — HIGH wins, LOW is suppressed."""
    tags = _classify("src/auth/test_helpers.js")
    assert "HIGH_SENSITIVITY" in tags
    assert "LOW_SENSITIVITY" not in tags


def test_classify_payment_is_high():
    tags = _classify("src/billing/checkout.js")
    assert "HIGH_SENSITIVITY" in tags
    assert "payment" in tags


def test_classify_crypto_is_high():
    tags = _classify("src/utils/encrypt.js")
    assert "HIGH_SENSITIVITY" in tags


# ---------------------------------------------------------------------------
# _sensitivity_label
# ---------------------------------------------------------------------------


def test_sensitivity_label_high():
    assert _sensitivity_label(["auth", "HIGH_SENSITIVITY"]) == "HIGH"


def test_sensitivity_label_medium():
    assert _sensitivity_label(["api", "MEDIUM_SENSITIVITY"]) == "MEDIUM"


def test_sensitivity_label_low():
    assert _sensitivity_label(["test", "LOW_SENSITIVITY"]) == "LOW"


def test_sensitivity_label_defaults_to_low():
    assert _sensitivity_label(["unclassified"]) == "LOW"


# ---------------------------------------------------------------------------
# _apply_fallback
# ---------------------------------------------------------------------------


def test_apply_fallback_sets_context_tags():
    usage = make_usage("src/auth/login.js")
    _apply_fallback(usage)
    assert "HIGH_SENSITIVITY" in usage.context_tags
    assert "auth" in usage.context_tags


def test_apply_fallback_sets_sensitivity_level():
    usage = make_usage("src/auth/login.js")
    _apply_fallback(usage)
    assert usage.sensitivity_level == "HIGH"


def test_apply_fallback_enrichment_fields():
    """Fallback sets subsystem_labels from semantic tags; AI-only fields remain null."""
    usage = make_usage("src/auth/login.js")
    _apply_fallback(usage)
    assert usage.sensitive_surface_reason is None
    assert usage.user_input_proximity is None
    # subsystem_labels is derived from semantic tags in fallback mode
    assert usage.subsystem_labels == ["auth"]


def test_apply_fallback_unclassified_path_has_no_subsystem_labels():
    """Unknown paths have no semantic tags → subsystem_labels is null."""
    usage = make_usage("src/foo/bar.js")
    _apply_fallback(usage)
    assert usage.subsystem_labels is None


# ---------------------------------------------------------------------------
# _apply_ai_result
# ---------------------------------------------------------------------------


def test_apply_ai_result_sets_all_fields():
    usage = make_usage("src/auth/session.js")
    cl = {
        "index": 1,
        "context_tags": ["auth", "HIGH_SENSITIVITY"],
        "sensitivity_level": "HIGH",
        "subsystem_labels": ["auth", "session"],
        "sensitive_surface_reason": "Session middleware with secret key in auth path",
        "user_input_proximity": "indirect",
    }
    _apply_ai_result(usage, cl)
    assert "HIGH_SENSITIVITY" in usage.context_tags
    assert usage.sensitivity_level == "HIGH"
    assert usage.subsystem_labels == ["auth", "session"]
    assert usage.sensitive_surface_reason == "Session middleware with secret key in auth path"
    assert usage.user_input_proximity == "indirect"


def test_apply_ai_result_preserves_context_tags_backward_compat():
    """After AI classification, the sensitivity string must still be in context_tags."""
    usage = make_usage("src/api/handler.js")
    cl = {
        "index": 1,
        "context_tags": ["api", "MEDIUM_SENSITIVITY"],
        "sensitivity_level": "MEDIUM",
        "subsystem_labels": ["api"],
        "sensitive_surface_reason": "API route handler",
        "user_input_proximity": "direct",
    }
    _apply_ai_result(usage, cl)
    assert "MEDIUM_SENSITIVITY" in usage.context_tags


def test_apply_ai_result_missing_sensitivity_injects_fallback():
    """If AI omits sensitivity string from context_tags, deterministic fallback injected."""
    usage = make_usage("src/auth/session.js")
    cl = {
        "index": 1,
        "context_tags": ["auth"],  # Missing sensitivity string
        "sensitivity_level": "HIGH",
        "subsystem_labels": [],
        "sensitive_surface_reason": "...",
        "user_input_proximity": "none",
    }
    _apply_ai_result(usage, cl)
    # Should have injected a sensitivity string
    has_sensitivity = any(t in usage.context_tags for t in ("HIGH_SENSITIVITY", "MEDIUM_SENSITIVITY", "LOW_SENSITIVITY"))
    assert has_sensitivity


# ---------------------------------------------------------------------------
# _parse_context_json
# ---------------------------------------------------------------------------


def test_parse_valid_json_returns_list():
    content = '{"classifications": [{"index": 1, "context_tags": ["auth", "HIGH_SENSITIVITY"]}]}'
    result = _parse_context_json(content)
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["index"] == 1


def test_parse_json_with_wrapper_text():
    content = 'Here is the result:\n{"classifications": [{"index": 1, "context_tags": ["api", "MEDIUM_SENSITIVITY"]}]}\nDone.'
    result = _parse_context_json(content)
    assert len(result) == 1


def test_parse_invalid_json_returns_empty():
    result = _parse_context_json("not valid json at all {{")
    assert result == []


def test_parse_missing_classifications_key_returns_empty():
    result = _parse_context_json('{"something_else": []}')
    assert result == []


def test_parse_empty_classifications_returns_empty_list():
    result = _parse_context_json('{"classifications": []}')
    assert result == []


# ---------------------------------------------------------------------------
# run() — async integration with mock DB and fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_empty_alert_usages_returns_immediately():
    from app.services.agents.context_agent import run
    db = MagicMock()
    repo = SimpleNamespace(id=1, name="test-repo", backboard_assistant_id=None)
    await run({}, repo, db)
    db.flush.assert_not_called()


@pytest.mark.asyncio
async def test_run_fallback_sets_context_tags(monkeypatch):
    """With BACKBOARD_API_KEY unset, run() falls back to deterministic classification."""
    from app.services.agents import context_agent
    from app.services import backboard_service

    monkeypatch.setattr(backboard_service.settings, "BACKBOARD_API_KEY", "")

    usage = make_usage("src/auth/login.js")

    db = MagicMock()
    db.get = MagicMock(side_effect=lambda model, id: (
        SimpleNamespace(id=id, vuln_id="CVE-TEST", summary="test", dependency_id=1, osv_data={})
        if model.__name__ == "Alert"
        else SimpleNamespace(id=1, name="lodash", version="4.17.15")
    ))

    repo = SimpleNamespace(id=1, name="test-repo", backboard_assistant_id=None)
    await context_agent.run({1: [usage]}, repo, db)

    assert "HIGH_SENSITIVITY" in usage.context_tags
    db.flush.assert_called_once()


@pytest.mark.asyncio
async def test_run_fallback_enrichment_fields(monkeypatch):
    """In fallback mode: subsystem_labels derived from tags, AI-only fields remain null."""
    from app.services.agents import context_agent
    from app.services import backboard_service

    monkeypatch.setattr(backboard_service.settings, "BACKBOARD_API_KEY", "")

    usage = make_usage("src/api/handler.js")

    db = MagicMock()
    db.get = MagicMock(side_effect=lambda model, id: (
        SimpleNamespace(id=id, vuln_id="CVE-TEST", summary="test", dependency_id=1, osv_data={})
        if model.__name__ == "Alert"
        else SimpleNamespace(id=1, name="axios", version="0.21.0")
    ))

    repo = SimpleNamespace(id=1, name="test-repo", backboard_assistant_id=None)
    await context_agent.run({1: [usage]}, repo, db)

    assert usage.sensitive_surface_reason is None
    assert usage.user_input_proximity is None
    # subsystem_labels populated from semantic path tags in fallback mode
    assert usage.subsystem_labels == ["api"]
