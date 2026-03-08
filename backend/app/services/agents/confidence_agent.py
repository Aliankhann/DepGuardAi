"""
Confidence Agent
----------------
Input:  UsageLocations + exploitability_result + blast_radius_result + analysis_source + dep_name
Output: {confidence_percent: int, confidence_label: str, confidence_reasons: list[str]}

Deterministic evidence-based scoring — no AI, no external calls.

Answers: "How much real evidence supports the exploitability and impact assessment?"

Scoring is additive. Each observable signal contributes or detracts.
Final score is clamped to [0, 100].

Label thresholds (Claude_Logic_Check.md §4 — authoritative):
  0–39  → "low"
  40–69 → "medium"
  70–100 → "high"

This is intentionally distinct from:
  - confidence (AI-reported label — subjective)
  - confidence_score (AI-reported 0-100 — subjective)

confidence_percent + confidence_reasons are the only auditable, deterministic values.
"""

import logging

logger = logging.getLogger(__name__)


def compute(
    usages: list,
    exploitability_result: dict,
    blast_radius_result: dict,
    analysis_source: str,
    dep_name: str,
) -> dict:
    """
    Compute deterministic confidence score from observable evidence signals.

    Args:
        usages: list of UsageLocation records for this alert
        exploitability_result: output from exploitability_agent.compute()
        blast_radius_result: output from blast_radius_agent._compute_blast_radius()
        analysis_source: "backboard_ai" or "fallback"
        dep_name: package name (non-empty = OSV advisory matched)

    Returns:
        {
            "confidence_percent": int (0-100),
            "confidence_label": str ("low" | "medium" | "high"),
            "confidence_reasons": list[str]
        }
    """
    score = 0
    reasons: list[str] = []

    # ── Signal 1: OSV advisory match ──────────────────────────────────────
    if dep_name and dep_name.strip():
        score += 10
        reasons.append(f"Package '{dep_name}' confirmed in OSV advisory (+10)")

    # ── Signal 2: Import found in codebase ────────────────────────────────
    N = len(usages)
    if N > 0:
        score += 20
        reasons.append(f"Import detected in {N} file(s) (+20)")
    else:
        score -= 20
        reasons.append("Package not detected in any scanned file (-20)")

    # ── Signal 3: Dangerous function detected ─────────────────────────────
    detected_fns = exploitability_result.get("detected_functions") or []
    if detected_fns:
        fn_display = detected_fns[0]
        score += 25
        reasons.append(f"Vulnerable function pattern '{fn_display}' found in snippet (+25)")

    # ── Signal 4: Sensitivity context ─────────────────────────────────────
    has_high = any("HIGH_SENSITIVITY" in (u.context_tags or []) for u in usages)
    has_medium = any("MEDIUM_SENSITIVITY" in (u.context_tags or []) for u in usages)
    has_low_only = (
        N > 0
        and not has_high
        and not has_medium
        and all(
            "LOW_SENSITIVITY" in (u.context_tags or []) or "unclassified" in (u.context_tags or [])
            for u in usages
        )
    )

    if has_high:
        # Find the named high-sensitivity tag for the reason string
        high_tag = "security-critical"
        priority = ["auth", "payment", "admin", "crypto", "secrets", "execution"]
        for t in priority:
            if any(t in (u.context_tags or []) for u in usages):
                high_tag = t
                break
        score += 20
        reasons.append(f"Usage in security-critical path ({high_tag}) (+20)")
    elif has_medium:
        med_tag = "api"
        for t in ["api", "data"]:
            if any(t in (u.context_tags or []) for u in usages):
                med_tag = t
                break
        score += 10
        reasons.append(f"Usage in moderate-risk path ({med_tag}) (+10)")
    elif has_low_only:
        score -= 5
        reasons.append("Usage confined to low-sensitivity path (test/utility) (-5)")

    # ── Signal 5: Wide usage (≥ 3 distinct files) ─────────────────────────
    distinct_files = len({u.file_path for u in usages})
    if distinct_files >= 3:
        score += 5
        reasons.append(f"Package used across {distinct_files} files (wider attack surface) (+5)")

    # ── Signal 6: Blast radius scope ──────────────────────────────────────
    br_label = blast_radius_result.get("blast_radius_label", "isolated")
    if br_label == "subsystem":
        score += 10
        reasons.append("Blast radius extends across multiple subsystems (+10)")
    elif br_label == "module":
        score += 5
        reasons.append("Blast radius extends across a module (+5)")

    # ── Signal 7: AI analysis outcome ─────────────────────────────────────
    if analysis_source == "backboard_ai":
        score += 10
        reasons.append("AI analysis performed with full codebase context (+10)")
    else:
        score -= 15
        reasons.append("AI unavailable — assessment based on static heuristics only (-15)")

    # ── Clamp and label ───────────────────────────────────────────────────
    confidence_percent = max(0, min(100, score))

    if confidence_percent <= 39:
        label = "low"
    elif confidence_percent <= 69:
        label = "medium"
    else:
        label = "high"

    return {
        "confidence_percent": confidence_percent,
        "confidence_label": label,
        "confidence_reasons": reasons,
    }
