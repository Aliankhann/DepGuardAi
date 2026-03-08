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
    assert result["confidence"] == "high"
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
    assert result["confidence"] == "low"
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
    assert result["confidence"] == "medium"


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
    assert result["confidence"] == "medium"


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
    assert result_low["confidence"] == "low"
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
    assert result_med["confidence"] == "medium"

    # Import + HIGH + fn + AI: 10+20+25+20+10 = 85 → high
    result_high = compute(
        [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"], "_.merge(a,b)")],
        make_expl("likely", "high", ["_.merge"]),
        make_br("module"),
        "backboard_ai",
        "lodash",
    )
    assert result_high["confidence_percent"] >= 70
    assert result_high["confidence"] == "high"


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


# ---------------------------------------------------------------------------
# Signal 8: scope_clarity
# ---------------------------------------------------------------------------


def _base_expl():
    """Neutral exploitability result with no vulnerable_behavior_match."""
    return make_expl("possible", "low", [])


def test_scope_clarity_high_adds_10():
    usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    br_no_clarity = make_br("isolated")
    br_high = {**make_br("isolated"), "scope_clarity": "high"}

    result_base = compute(usages, _base_expl(), br_no_clarity, "backboard_ai", "lodash")
    result_high = compute(usages, _base_expl(), br_high, "backboard_ai", "lodash")

    assert result_high["confidence_percent"] - result_base["confidence_percent"] == 10
    assert any("Scope well-established" in r for r in result_high["confidence_reasons"])


def test_scope_clarity_medium_adds_5():
    usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    br_no_clarity = make_br("isolated")
    br_medium = {**make_br("isolated"), "scope_clarity": "medium"}

    result_base = compute(usages, _base_expl(), br_no_clarity, "backboard_ai", "lodash")
    result_medium = compute(usages, _base_expl(), br_medium, "backboard_ai", "lodash")

    assert result_medium["confidence_percent"] - result_base["confidence_percent"] == 5
    assert any("partially established" in r for r in result_medium["confidence_reasons"])


def test_scope_clarity_low_adds_nothing():
    usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    br_no_clarity = make_br("isolated")
    br_low = {**make_br("isolated"), "scope_clarity": "low"}

    result_base = compute(usages, _base_expl(), br_no_clarity, "backboard_ai", "lodash")
    result_low = compute(usages, _base_expl(), br_low, "backboard_ai", "lodash")

    assert result_low["confidence_percent"] == result_base["confidence_percent"]


def test_scope_clarity_missing_adds_nothing():
    usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    br = make_br("isolated")   # no scope_clarity key

    # Should not raise
    result = compute(usages, _base_expl(), br, "backboard_ai", "lodash")
    assert isinstance(result["confidence_percent"], int)


# ---------------------------------------------------------------------------
# Signal 9: vulnerable_behavior_match
# ---------------------------------------------------------------------------


def test_confirmed_match_adds_15():
    usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    br = make_br("isolated")
    expl_neutral = {**make_expl("possible", "low", []), "vulnerable_behavior_match": "insufficient_evidence"}
    expl_confirmed = {**make_expl("possible", "low", []), "vulnerable_behavior_match": "confirmed"}

    result_neutral = compute(usages, expl_neutral, br, "backboard_ai", "lodash")
    result_confirmed = compute(usages, expl_confirmed, br, "backboard_ai", "lodash")

    assert result_confirmed["confidence_percent"] - result_neutral["confidence_percent"] == 15
    assert any("confirmed" in r for r in result_confirmed["confidence_reasons"])


def test_unconfirmed_match_subtracts_10():
    usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    br = make_br("isolated")
    expl_neutral = {**make_expl("possible", "low", []), "vulnerable_behavior_match": "insufficient_evidence"}
    expl_unconfirmed = {**make_expl("possible", "low", []), "vulnerable_behavior_match": "unconfirmed"}

    result_neutral = compute(usages, expl_neutral, br, "backboard_ai", "lodash")
    result_unconfirmed = compute(usages, expl_unconfirmed, br, "backboard_ai", "lodash")

    assert result_neutral["confidence_percent"] - result_unconfirmed["confidence_percent"] == 10
    assert any("could not confirm" in r for r in result_unconfirmed["confidence_reasons"])


def test_insufficient_evidence_is_neutral():
    usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    br = make_br("isolated")
    expl_missing = make_expl("possible", "low", [])   # no key
    expl_ie = {**make_expl("possible", "low", []), "vulnerable_behavior_match": "insufficient_evidence"}

    result_missing = compute(usages, expl_missing, br, "backboard_ai", "lodash")
    result_ie = compute(usages, expl_ie, br, "backboard_ai", "lodash")

    assert result_missing["confidence_percent"] == result_ie["confidence_percent"]


def test_vulnerable_behavior_match_missing_is_neutral():
    usages = [make_usage("src/auth/session.js", ["auth", "HIGH_SENSITIVITY"])]
    br = make_br("isolated")
    expl = make_expl("possible", "low", [])   # no vulnerable_behavior_match key

    # Should not raise
    result = compute(usages, expl, br, "backboard_ai", "lodash")
    assert isinstance(result["confidence_percent"], int)


# ---------------------------------------------------------------------------
# End-to-end scenario coverage
# ---------------------------------------------------------------------------


def test_scenario_all_negative_is_low():
    # No import + fallback + unconfirmed = −20 −15 −10 = −45 → 0 → low
    expl = {**make_expl("unlikely", "low", []), "vulnerable_behavior_match": "unconfirmed"}
    result = compute([], expl, make_br("isolated"), "fallback", "lodash")
    assert result["confidence_percent"] == 0
    assert result["confidence"] == "low"


def test_scenario_all_positive_clamped_to_100():
    # Max positive: 10+20+25+20+5+10+10+10+15 = 125 → clamped 100
    usages = [
        make_usage(f"src/auth/file{i}.js", ["auth", "HIGH_SENSITIVITY"], "_.merge({}, x)")
        for i in range(4)
    ]
    expl = {**make_expl("likely", "high", ["_.merge"]), "vulnerable_behavior_match": "confirmed"}
    br = {**make_br("subsystem", 4, 2), "scope_clarity": "high"}
    result = compute(usages, expl, br, "backboard_ai", "lodash")
    assert result["confidence_percent"] == 100
    assert result["confidence"] == "high"
