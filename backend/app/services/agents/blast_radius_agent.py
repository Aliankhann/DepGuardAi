"""
Blast Radius Agent
------------------
Input:  Alert records + UsageLocation records (with context_tags already set)
        Optional: exploitability_results, repo, db (for Phase 2 Backboard call)
Output: dict[alert_id, blast_radius_result] — in-memory only, no DB writes

Two-phase estimation:

Phase 1 — Deterministic (always runs):
  Estimates blast_radius_label, blast_radius_reason, affected_files, affected_modules,
  affected_surfaces, and scope_clarity from context_tags and usage distribution.

Phase 2 — Backboard (optional, graceful fallback):
  Narrow AI call that confirms scope_clarity and validates affected_surfaces.
  Uses the existing repo assistant — no new assistant created.
  No memory="Auto" — this is computation, not investigation memory.
  Falls back to Phase 1 values on any error or missing API key.

Rules (per Claude_Logic_Check.md §5):
  - isolated  : single file or directory, no HIGH_SENSITIVITY context
  - module    : multiple files in one directory OR any HIGH_SENSITIVITY context
  - subsystem : HIGH_SENSITIVITY context AND multiple distinct top-level directories

scope_clarity rules:
  - low    : no usages OR all context is fallback-only (no subsystem_labels set)
  - medium : usages found + some AI-enriched context OR single HIGH_SENSITIVITY module
  - high   : usages + AI-enriched context + multiple modules OR HIGH_SENSITIVITY + clear surfaces
"""

import logging

from app.models.alert import Alert
from app.models.usage import UsageLocation

logger = logging.getLogger(__name__)

# Tags that represent named security/functional surfaces.
# Sensitivity markers and generic tags are excluded.
_SURFACE_TAGS = frozenset({
    "auth", "payment", "admin", "crypto", "secrets",
    "execution", "api", "data", "middleware",
})


def _extract_affected_surfaces(usages: list) -> list[str]:
    """
    Union of named surface tags across all usages' context_tags and subsystem_labels.
    Only tags in _SURFACE_TAGS are included — sensitivity markers are excluded.
    """
    surfaces: set[str] = set()
    for u in usages:
        for tag in (u.context_tags or []):
            if tag in _SURFACE_TAGS:
                surfaces.add(tag)
        for label in (getattr(u, "subsystem_labels", None) or []):
            if label in _SURFACE_TAGS:
                surfaces.add(label)
    return sorted(surfaces)


def _compute_scope_clarity(
    usages: list,
    N: int,
    M: int,
    has_high: bool,
    affected_surfaces: list[str],
) -> str:
    """
    Deterministic scope clarity assessment — answers 'how confident are we in this scope?'

    high   → usages + AI-enriched context (subsystem_labels present) + (multiple modules OR HIGH_SENSITIVITY)
    medium → usages + some AI-enriched context, OR HIGH_SENSITIVITY alone
    low    → no usages OR all context is fallback-only
    """
    if N == 0:
        return "low"

    any_ai_enriched = any(getattr(u, "subsystem_labels", None) for u in usages)

    if any_ai_enriched and (M > 1 or (has_high and affected_surfaces)):
        return "high"
    elif any_ai_enriched or has_high:
        return "medium"
    else:
        return "low"


def _compute_blast_radius(usages: list) -> dict:
    """Compute blast radius for a single alert's usage set (Phase 1 — deterministic)."""
    if not usages:
        return {
            "blast_radius_label": "isolated",
            "blast_radius_reason": "Package not detected in any scanned file — impact scope is minimal.",
            "affected_files": 0,
            "affected_modules": 0,
            "affected_surfaces": [],
            "scope_clarity": "low",
        }

    # Distinct files
    distinct_files = list({u.file_path for u in usages})
    N = len(distinct_files)

    # Distinct immediate parent directories (modules).
    # Use dirname rather than top-level dir so that src/auth/ and src/payment/
    # are counted as separate modules (not both collapsed into src/).
    modules = set()
    for path in distinct_files:
        normalized = path.replace("\\", "/")
        parts = normalized.split("/")
        if len(parts) >= 2:
            # e.g. "src/auth/session.js" → "src/auth"
            modules.add("/".join(parts[:-1]))
        else:
            modules.add("root")
    M = len(modules)

    # Highest sensitivity tag across all usages
    has_high = any(
        "HIGH_SENSITIVITY" in (u.context_tags or [])
        for u in usages
    )
    has_medium = any(
        "MEDIUM_SENSITIVITY" in (u.context_tags or [])
        for u in usages
    )

    # Highest named tag for display (auth, payment, etc.)
    named_tag = "unknown"
    priority_tags = ["auth", "payment", "admin", "crypto", "secrets", "execution", "api", "data"]
    for tag in priority_tags:
        if any(tag in (u.context_tags or []) for u in usages):
            named_tag = tag
            break

    # Extract named surfaces from context_tags + subsystem_labels
    affected_surfaces = _extract_affected_surfaces(usages)

    # Decision matrix (Claude_Logic_Check.md §5)
    if has_high and M > 1:
        label = "subsystem"
        reason = (
            f"Used in {N} file(s) across {M} module(s). "
            f"HIGH_SENSITIVITY context ({named_tag}) detected across multiple subsystems — "
            f"vulnerability has broad potential impact."
        )
    elif has_high or M > 1:
        label = "module"
        if has_high:
            reason = (
                f"Used in {N} file(s) across {M} module(s). "
                f"HIGH_SENSITIVITY context ({named_tag}) detected — "
                f"vulnerability reaches a security-critical path."
            )
        else:
            reason = (
                f"Used in {N} file(s) across {M} module(s). "
                f"Multiple directories affected — vulnerability spans a module boundary."
            )
    else:
        label = "isolated"
        sensitivity = "MEDIUM" if has_medium else "LOW/unclassified"
        reason = (
            f"Used in {N} file(s) within {M} module(s). "
            f"Sensitivity: {sensitivity} — impact appears contained to a single module."
        )

    scope_clarity = _compute_scope_clarity(usages, N, M, has_high, affected_surfaces)

    return {
        "blast_radius_label": label,
        "blast_radius_reason": reason,
        "affected_files": N,
        "affected_modules": M,
        "affected_surfaces": affected_surfaces,
        "scope_clarity": scope_clarity,
    }


async def run(
    alerts: list[Alert],
    alert_usages: dict[int, list[UsageLocation]],
    exploitability_results: dict | None = None,
    repo=None,
    db=None,
) -> dict[int, dict]:
    """
    Run blast radius estimation for all alerts.
    Returns dict[alert_id -> blast_radius_result].

    Phase 1 (deterministic) always runs.
    Phase 2 (Backboard) runs when repo and db are provided, falls back gracefully.
    No DB writes.
    """
    from app.services import backboard_service

    results: dict[int, dict] = {}

    for alert in alerts:
        usages = alert_usages.get(alert.id, [])
        try:
            result = _compute_blast_radius(usages)
        except Exception as e:
            logger.warning(f"Blast radius estimation failed for alert {alert.id}: {e}")
            result = {
                "blast_radius_label": "isolated",
                "blast_radius_reason": "Blast radius estimation failed — defaulting to isolated.",
                "affected_files": 0,
                "affected_modules": 0,
                "affected_surfaces": [],
                "scope_clarity": "low",
            }

        # Phase 2: Backboard confirmation (optional — enriches scope_clarity + affected_surfaces)
        if repo is not None and db is not None:
            expl_ctx = (exploitability_results or {}).get(alert.id)
            try:
                ai_result = await backboard_service.run_blast_radius_analysis(
                    repo=repo,
                    alert=alert,
                    usages=usages,
                    phase1_result=result,
                    exploitability_context=expl_ctx,
                    db=db,
                )
                # Merge AI output — AI may refine scope_clarity and affected_surfaces.
                # blast_radius_label and blast_radius_reason remain deterministic.
                scope_clarity = ai_result.get("scope_clarity")
                if scope_clarity in ("high", "medium", "low"):
                    result["scope_clarity"] = scope_clarity

                ai_surfaces = ai_result.get("affected_surfaces")
                if isinstance(ai_surfaces, list):
                    # Only accept surface tags that are in the allowed set — AI must not invent new ones.
                    validated = [s for s in ai_surfaces if s in _SURFACE_TAGS]
                    if validated:
                        result["affected_surfaces"] = sorted(set(result["affected_surfaces"]) | set(validated))
            except Exception as e:
                logger.warning(
                    f"[blast_radius_agent] Phase 2 Backboard call failed for alert {alert.id}: {e} "
                    f"— using Phase 1 values"
                )

        results[alert.id] = result
        logger.debug(
            f"[blast_radius_agent] alert={alert.id} vuln={alert.vuln_id} "
            f"label={result['blast_radius_label']} files={result['affected_files']} "
            f"modules={result['affected_modules']} surfaces={result['affected_surfaces']} "
            f"scope_clarity={result['scope_clarity']}"
        )

    logger.info(f"[blast_radius_agent] Estimated blast radius for {len(results)} alerts")
    return results
