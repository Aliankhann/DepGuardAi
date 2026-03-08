"""
Unit tests for confidence_agent.

Tests the deterministic confidence scoring logic in isolation — no DB, no AI calls.
Uses SimpleNamespace to mock UsageLocation records.

Thresholds per Claude_Logic_Check.md §4:
  0–39  → "low"
  40–69 → "medium"
  70–100 → "high"
"""

from types import SimpleNamespace

from app.services.agents.confidence_agent import compute


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_usage(file_path: str, context_tags: list, snippet: str = "import pkg"):
    return SimpleNamespace(
        id=id(file_path),
        file_path=file_path,
        context_tags=context_tags,
        snippet=snippet,
    )


def make_expl(exploitability="possible", evidence_strength="low", detected_functions=None):
    return {
        "exploitability": exploitability,
        "evidence_strength": evidence_strength,
        "detected_functions": detected_functions or [],
        "exploitability_reason": "test reason",
    }


def make_br(label="isolated", affected_files=1, affected_modules=1):
    return {
        "blast_radius_label": label,
        "affected_files": affected_files,
        "affected_modules": affected_modules,
        "blast_radius_reason": "test reason",
    }


# ---------------------------------------------------------------------------
# Maximum evidence case → high
# ---------------------------------------------------------------------------


def test_maximum_evidence_is_high():
    # lodash in auth + _.merge detected + AI + subsystem
    usages = [
        make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"], "_.merge({}, req.body)"),
        make_usage("src/auth/login.js", ["auth", "HIGH_SENSITIVITY"], "_.merge({}, defaults)"),
        make_usage("src/api/handler.js", ["api", "MEDIUM_SENSITIVITY"], "const _ = require('lodash')"),
    ]
    expl = make_expl("likely", "high", ["_.merge"])
    br = make_br("subsystem", affected_files=3, affected_modules=2)

    result = compute(usages, expl, br, "backboard_ai", "lodash")

    assert result["confidence_percent"] >= 70
    assert result["confidence_label"] == "high"
    assert len(result["confidence_reasons"]) > 0


# ---------------------------------------------------------------------------
# No import + fallback → low (clamped to 0)
# ---------------------------------------------------------------------------


def test_no_import_fallback_is_low():
    result = compute(
        usages=[],
        exploitability_result=make_expl("unlikely", "low", []),
        blast_radius_result=make_br("isolated", 0, 0),
        analysis_source="fallback",
        dep_name="lodash",
    )
    assert result["confidence_percent"] == 0
    assert result["confidence_label"] == "low"
    # Negative signals should appear in reasons
    assert any("not detected" in r or "unavailable" in r for r in result["confidence_reasons"])


# ---------------------------------------------------------------------------
# Import + MEDIUM sensitivity + no function + AI → medium
# ---------------------------------------------------------------------------


def test_import_medium_no_function_ai_is_medium():
    # 10 (OSV) + 20 (import) + 10 (medium sensitivity) + 10 (AI) = 50 → medium
    usages = [make_usage("src/api/client.js", ["api", "MEDIUM_SENSITIVITY"])]
    expl = make_expl("possible", "low", [])
    br = make_br("isolated", 1, 1)

    result = compute(usages, expl, br, "backboard_ai", "axios")

    assert result["confidence_percent"] == 50
    assert result["confidence_label"] == "medium"


# ---------------------------------------------------------------------------
# LOW sensitivity only + function detected + AI → medium
# ---------------------------------------------------------------------------


def test_low_sensitivity_with_function_ai_is_medium():
    # 10 (OSV) + 20 (import) + 25 (function) - 5 (low only) + 10 (AI) = 60 → medium
    usages = [make_usage("src/utils/helper.js", ["util", "LOW_SENSITIVITY"], "_.merge({}, config)")]
    expl = make_expl("possible", "low", ["_.merge"])
    br = make_br("isolated", 1, 1)

    result = compute(usages, expl, br, "backboard_ai", "lodash")

    assert result["confidence_percent"] == 60
    assert result["confidence_label"] == "medium"


# ---------------------------------------------------------------------------
# Score clamp — never below 0, never above 100
# ---------------------------------------------------------------------------


def test_score_never_below_zero():
    # Worst case: no import + fallback
    result = compute([], make_expl(), make_br(), "fallback", "")
    assert result["confidence_percent"] >= 0


def test_score_never_above_100():
    # Best case: everything positive
    usages = [
        make_usage(f"src/auth/file{i}.js", ["auth", "HIGH_SENSITIVITY"], "_.merge({}, x)")
        for i in range(5)
    ]
    expl = make_expl("likely", "high", ["_.merge"])
    br = make_br("subsystem", 5, 3)

    result = compute(usages, expl, br, "backboard_ai", "lodash")
    assert result["confidence_percent"] <= 100


# ---------------------------------------------------------------------------
# Label threshold boundaries (Claude_Logic_Check.md §4)
# ---------------------------------------------------------------------------


def test_label_thresholds():
    """Verify boundary values produce correct labels."""
    # We test by checking scores near boundaries

    # score=39 → low
    # score=40 → medium
    # score=70 → high

    # No import + fallback: 10-20-15 = -25 → 0 → low
    result_low = compute([], make_expl(), make_br(), "fallback", "lodash")
    assert result_low["confidence_label"] == "low"
    assert result_low["confidence_percent"] <= 39

    # Import + MEDIUM + no fn + AI: 10+20+10+10 = 50 → medium
    result_med = compute(
        [make_usage("src/api/client.js", ["api", "MEDIUM_SENSITIVITY"])],
        make_expl("possible", "low", []),
        make_br("isolated"),
        "backboard_ai",
        "axios",
    )
    assert 40 <= result_med["confidence_percent"] <= 69
    assert result_med["confidence_label"] == "medium"

    # Import + HIGH + fn + AI: 10+20+25+20+10 = 85 → high
    result_high = compute(
        [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"], "_.merge(a,b)")],
        make_expl("likely", "high", ["_.merge"]),
        make_br("module"),
        "backboard_ai",
        "lodash",
    )
    assert result_high["confidence_percent"] >= 70
    assert result_high["confidence_label"] == "high"


# ---------------------------------------------------------------------------
# Reasons list content
# ---------------------------------------------------------------------------


def test_reasons_are_non_empty_strings():
    usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    expl = make_expl("likely", "high", ["_.merge"])
    br = make_br("module")

    result = compute(usages, expl, br, "backboard_ai", "lodash")

    assert isinstance(result["confidence_reasons"], list)
    assert len(result["confidence_reasons"]) > 0
    for reason in result["confidence_reasons"]:
        assert isinstance(reason, str)
        assert len(reason) > 5


def test_fallback_reason_appears_in_negative_case():
    result = compute([], make_expl(), make_br(), "fallback", "lodash")
    reason_text = " ".join(result["confidence_reasons"]).lower()
    assert "unavailable" in reason_text or "fallback" in reason_text or "static" in reason_text


def test_no_import_reason_appears():
    result = compute([], make_expl(), make_br(), "backboard_ai", "lodash")
    reason_text = " ".join(result["confidence_reasons"]).lower()
    assert "not detected" in reason_text


# ---------------------------------------------------------------------------
# Blast radius signal
# ---------------------------------------------------------------------------


def test_subsystem_adds_points():
    base_usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    expl = make_expl("likely", "high", [])

    result_isolated = compute(base_usages, expl, make_br("isolated"), "backboard_ai", "lodash")
    result_subsystem = compute(base_usages, expl, make_br("subsystem"), "backboard_ai", "lodash")

    assert result_subsystem["confidence_percent"] > result_isolated["confidence_percent"]


def test_module_adds_more_than_isolated():
    base_usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    expl = make_expl("likely", "high", [])

    result_isolated = compute(base_usages, expl, make_br("isolated"), "backboard_ai", "lodash")
    result_module = compute(base_usages, expl, make_br("module"), "backboard_ai", "lodash")

    assert result_module["confidence_percent"] > result_isolated["confidence_percent"]


# ---------------------------------------------------------------------------
# Wide usage signal (≥ 3 files)
# ---------------------------------------------------------------------------


def test_wide_usage_adds_points():
    narrow = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    wide = [
        make_usage(f"src/auth/file{i}.js", ["auth", "HIGH_SENSITIVITY"])
        for i in range(4)
    ]
    expl = make_expl("likely", "high", [])
    br = make_br("module")

    result_narrow = compute(narrow, expl, br, "backboard_ai", "lodash")
    result_wide = compute(wide, expl, br, "backboard_ai", "lodash")

    assert result_wide["confidence_percent"] > result_narrow["confidence_percent"]
