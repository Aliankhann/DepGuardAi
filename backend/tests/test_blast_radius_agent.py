"""
Unit tests for blast_radius_agent.

Tests the deterministic scope estimation logic in isolation — no DB, no AI calls.
Uses SimpleNamespace to mock UsageLocation records.
"""

import asyncio
from types import SimpleNamespace

import pytest

from app.services.agents.blast_radius_agent import _compute_blast_radius, run


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_usage(file_path: str, context_tags: list):
    return SimpleNamespace(
        id=id(file_path + str(context_tags)),
        file_path=file_path,
        context_tags=context_tags,
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
