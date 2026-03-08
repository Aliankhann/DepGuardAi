"""
Unit tests for blast_radius_agent.

Tests the deterministic scope estimation logic in isolation — no DB, no AI calls.
Uses SimpleNamespace to mock UsageLocation records.
"""

import asyncio
from types import SimpleNamespace

import pytest

from app.services.agents.blast_radius_agent import (
    _compute_blast_radius,
    _extract_affected_surfaces,
    _compute_scope_clarity,
    run,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_usage(file_path: str, context_tags: list, subsystem_labels=None):
    return SimpleNamespace(
        id=id(file_path + str(context_tags)),
        file_path=file_path,
        context_tags=context_tags,
        subsystem_labels=subsystem_labels,
        snippet="import pkg from 'pkg'",
        line_number=1,
    )


def make_alert(alert_id: int, vuln_id: str = "CVE-TEST"):
    return SimpleNamespace(id=alert_id, vuln_id=vuln_id)


# ---------------------------------------------------------------------------
# No usages
# ---------------------------------------------------------------------------


def test_no_usages_returns_isolated():
    result = _compute_blast_radius([])
    assert result["blast_radius_label"] == "isolated"
    assert result["affected_files"] == 0
    assert result["affected_modules"] == 0


# ---------------------------------------------------------------------------
# isolated cases
# ---------------------------------------------------------------------------


def test_single_file_low_sensitivity_is_isolated():
    usages = [make_usage("src/utils/helper.js", ["util", "LOW_SENSITIVITY"])]
    result = _compute_blast_radius(usages)
    assert result["blast_radius_label"] == "isolated"
    assert result["affected_files"] == 1


def test_two_files_same_dir_low_sensitivity_is_isolated():
    usages = [
        make_usage("src/utils/helper.js", ["util", "LOW_SENSITIVITY"]),
        make_usage("src/utils/format.js", ["util", "LOW_SENSITIVITY"]),
    ]
    result = _compute_blast_radius(usages)
    assert result["blast_radius_label"] == "isolated"
    assert result["affected_files"] == 2
    assert result["affected_modules"] == 1


# ---------------------------------------------------------------------------
# module cases
# ---------------------------------------------------------------------------


def test_multiple_dirs_no_high_sensitivity_is_module():
    usages = [
        make_usage("src/utils/helper.js", ["util", "LOW_SENSITIVITY"]),
        make_usage("src/api/client.js", ["api", "MEDIUM_SENSITIVITY"]),
    ]
    result = _compute_blast_radius(usages)
    assert result["blast_radius_label"] == "module"
    assert result["affected_modules"] == 2


def test_single_file_high_sensitivity_is_module():
    usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    result = _compute_blast_radius(usages)
    assert result["blast_radius_label"] == "module"


def test_high_sensitivity_single_module_is_module():
    usages = [
        make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"]),
        make_usage("src/auth/login.js", ["auth", "HIGH_SENSITIVITY"]),
    ]
    result = _compute_blast_radius(usages)
    assert result["blast_radius_label"] == "module"
    assert result["affected_modules"] == 1


# ---------------------------------------------------------------------------
# subsystem cases
# ---------------------------------------------------------------------------


def test_high_sensitivity_multiple_modules_is_subsystem():
    usages = [
        make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"]),
        make_usage("src/payment/checkout.js", ["payment", "HIGH_SENSITIVITY"]),
    ]
    result = _compute_blast_radius(usages)
    assert result["blast_radius_label"] == "subsystem"
    assert result["affected_modules"] >= 2


def test_high_sensitivity_three_modules_is_subsystem():
    usages = [
        make_usage("auth/session.js", ["auth", "HIGH_SENSITIVITY"]),
        make_usage("api/router.js", ["api", "MEDIUM_SENSITIVITY"]),
        make_usage("util/helper.js", ["util", "LOW_SENSITIVITY"]),
    ]
    result = _compute_blast_radius(usages)
    assert result["blast_radius_label"] == "subsystem"


# ---------------------------------------------------------------------------
# affected_files / affected_modules counting
# ---------------------------------------------------------------------------


def test_deduplicates_files():
    usages = [
        make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"]),
        make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"]),  # duplicate
    ]
    result = _compute_blast_radius(usages)
    assert result["affected_files"] == 1


def test_reason_string_is_non_empty():
    usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    result = _compute_blast_radius(usages)
    assert isinstance(result["blast_radius_reason"], str)
    assert len(result["blast_radius_reason"]) > 10


# ---------------------------------------------------------------------------
# run() — async entry point
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_returns_result_per_alert():
    alert1 = make_alert(1, "CVE-A")
    alert2 = make_alert(2, "CVE-B")

    u1 = make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])
    u2 = make_usage("src/utils/helper.js", ["util", "LOW_SENSITIVITY"])

    results = await run([alert1, alert2], {1: [u1], 2: [u2]})
    assert 1 in results
    assert 2 in results
    assert results[1]["blast_radius_label"] in ("isolated", "module", "subsystem")
    assert results[2]["blast_radius_label"] in ("isolated", "module", "subsystem")


@pytest.mark.asyncio
async def test_run_missing_usages_returns_isolated():
    alert = make_alert(99)
    results = await run([alert], {})
    assert 99 in results
    assert results[99]["blast_radius_label"] == "isolated"


@pytest.mark.asyncio
async def test_run_empty_alert_list():
    results = await run([], {})
    assert results == {}


# ---------------------------------------------------------------------------
# affected_surfaces — new field
# ---------------------------------------------------------------------------


def test_no_usages_returns_empty_surfaces():
    result = _compute_blast_radius([])
    assert result["affected_surfaces"] == []


def test_affected_surfaces_extracts_auth_from_context_tags():
    usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    result = _compute_blast_radius(usages)
    assert "auth" in result["affected_surfaces"]


def test_affected_surfaces_excludes_sensitivity_markers():
    usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    result = _compute_blast_radius(usages)
    assert "HIGH_SENSITIVITY" not in result["affected_surfaces"]
    assert "MEDIUM_SENSITIVITY" not in result["affected_surfaces"]
    assert "LOW_SENSITIVITY" not in result["affected_surfaces"]


def test_affected_surfaces_excludes_unknown_tags():
    usages = [make_usage("src/util/helper.js", ["util", "LOW_SENSITIVITY"])]
    result = _compute_blast_radius(usages)
    # "util" is not in _SURFACE_TAGS
    assert "util" not in result["affected_surfaces"]


def test_affected_surfaces_multiple_surfaces():
    usages = [
        make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"]),
        make_usage("src/payment/checkout.js", ["payment", "HIGH_SENSITIVITY"]),
    ]
    result = _compute_blast_radius(usages)
    assert "auth" in result["affected_surfaces"]
    assert "payment" in result["affected_surfaces"]


def test_affected_surfaces_deduplicates():
    usages = [
        make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"]),
        make_usage("src/auth/login.js", ["auth", "HIGH_SENSITIVITY"]),
    ]
    result = _compute_blast_radius(usages)
    assert result["affected_surfaces"].count("auth") == 1


def test_affected_surfaces_includes_subsystem_labels():
    usages = [
        make_usage(
            "src/auth/session.js",
            ["HIGH_SENSITIVITY"],
            subsystem_labels=["auth", "api"],
        )
    ]
    result = _compute_blast_radius(usages)
    assert "auth" in result["affected_surfaces"]
    assert "api" in result["affected_surfaces"]


def test_affected_surfaces_sorted():
    usages = [
        make_usage("src/payment/checkout.js", ["payment", "HIGH_SENSITIVITY"]),
        make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"]),
    ]
    result = _compute_blast_radius(usages)
    assert result["affected_surfaces"] == sorted(result["affected_surfaces"])


# ---------------------------------------------------------------------------
# scope_clarity — new field
# ---------------------------------------------------------------------------


def test_no_usages_scope_clarity_is_low():
    result = _compute_blast_radius([])
    assert result["scope_clarity"] == "low"


def test_fallback_only_context_scope_clarity_is_low():
    # No subsystem_labels → fallback context → low clarity
    usages = [make_usage("src/utils/helper.js", ["util", "LOW_SENSITIVITY"])]
    result = _compute_blast_radius(usages)
    assert result["scope_clarity"] == "low"


def test_high_sensitivity_no_subsystem_labels_is_medium():
    # has_high=True but no AI-enriched context → medium
    usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    result = _compute_blast_radius(usages)
    assert result["scope_clarity"] == "medium"


def test_ai_enriched_single_module_is_medium():
    # subsystem_labels present but only 1 module and no HIGH_SENSITIVITY or surfaces
    usages = [
        make_usage(
            "src/utils/helper.js",
            ["util", "LOW_SENSITIVITY"],
            subsystem_labels=["util"],
        )
    ]
    result = _compute_blast_radius(usages)
    # subsystem_labels present but has_high=False and M=1 → medium (ai_enriched or has_high)
    assert result["scope_clarity"] == "medium"


def test_ai_enriched_multiple_modules_is_high():
    # AI-enriched + multiple modules → high
    usages = [
        make_usage(
            "src/auth/session.js",
            ["auth", "HIGH_SENSITIVITY"],
            subsystem_labels=["auth"],
        ),
        make_usage(
            "src/payment/checkout.js",
            ["payment", "HIGH_SENSITIVITY"],
            subsystem_labels=["payment"],
        ),
    ]
    result = _compute_blast_radius(usages)
    assert result["scope_clarity"] == "high"


def test_ai_enriched_high_sensitivity_with_surfaces_is_high():
    # AI-enriched + HIGH_SENSITIVITY + surfaces present → high (even if single module)
    usages = [
        make_usage(
            "src/auth/session.js",
            ["auth", "HIGH_SENSITIVITY"],
            subsystem_labels=["auth"],
        )
    ]
    result = _compute_blast_radius(usages)
    assert result["scope_clarity"] == "high"


# ---------------------------------------------------------------------------
# run() — output shape completeness
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_output_has_all_required_keys():
    alert = make_alert(1)
    u = make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])
    results = await run([alert], {1: [u]})
    r = results[1]
    assert "blast_radius_label" in r
    assert "blast_radius_reason" in r
    assert "affected_files" in r
    assert "affected_modules" in r
    assert "affected_surfaces" in r
    assert "scope_clarity" in r


@pytest.mark.asyncio
async def test_run_without_repo_skips_phase2():
    # Passing no repo/db should still return valid Phase 1 result
    alert = make_alert(1)
    u = make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])
    results = await run([alert], {1: [u]}, repo=None, db=None)
    r = results[1]
    assert r["blast_radius_label"] == "module"
    assert "auth" in r["affected_surfaces"]
    assert r["scope_clarity"] in ("high", "medium", "low")


@pytest.mark.asyncio
async def test_run_scope_clarity_allowed_values():
    alert = make_alert(1)
    u = make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])
    results = await run([alert], {1: [u]})
    assert results[1]["scope_clarity"] in ("high", "medium", "low")


@pytest.mark.asyncio
async def test_run_blast_radius_label_allowed_values():
    alert = make_alert(1)
    u = make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])
    results = await run([alert], {1: [u]})
    assert results[1]["blast_radius_label"] in ("isolated", "module", "subsystem")


# ---------------------------------------------------------------------------
# _extract_affected_surfaces — direct unit tests
# ---------------------------------------------------------------------------


def test_extract_surfaces_empty():
    assert _extract_affected_surfaces([]) == []


def test_extract_surfaces_api_tag():
    usages = [make_usage("src/api/routes.js", ["api", "MEDIUM_SENSITIVITY"])]
    surfaces = _extract_affected_surfaces(usages)
    assert "api" in surfaces


def test_extract_surfaces_ignores_sensitivity_markers():
    usages = [make_usage("src/auth/session.js", ["HIGH_SENSITIVITY"])]
    surfaces = _extract_affected_surfaces(usages)
    assert surfaces == []  # no named surface tag, only sensitivity marker


def test_extract_surfaces_subsystem_labels_take_priority():
    usages = [
        make_usage(
            "src/gateway/index.js",
            ["api", "MEDIUM_SENSITIVITY"],
            subsystem_labels=["middleware", "api"],
        )
    ]
    surfaces = _extract_affected_surfaces(usages)
    assert "middleware" in surfaces
    assert "api" in surfaces


# ---------------------------------------------------------------------------
# _compute_scope_clarity — direct unit tests
# ---------------------------------------------------------------------------


def test_scope_clarity_zero_files_is_low():
    assert _compute_scope_clarity([], N=0, M=0, has_high=False, affected_surfaces=[]) == "low"


def test_scope_clarity_fallback_context_is_low():
    usages = [make_usage("src/utils/helper.js", ["util", "LOW_SENSITIVITY"])]
    assert _compute_scope_clarity(usages, N=1, M=1, has_high=False, affected_surfaces=[]) == "low"


def test_scope_clarity_high_sensitivity_no_ai_is_medium():
    usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    result = _compute_scope_clarity(usages, N=1, M=1, has_high=True, affected_surfaces=["auth"])
    assert result == "medium"
