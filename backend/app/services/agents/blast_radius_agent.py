"""
Blast Radius Agent
------------------
Input:  Alert records + UsageLocation records (with context_tags already set)
Output: dict[alert_id, blast_radius_result] — in-memory only, no DB writes

Deterministic estimation — no AI, no external calls.

Estimates whether the vulnerability's impact is isolated to a single file,
spans a module (directory), or crosses multiple subsystems.

Outputs feed into confidence_agent scoring and the risk_agent Backboard prompt,
giving the AI concrete scope context before it reasons about business impact.

Rules (per Claude_Logic_Check.md §5):
  - isolated  : single file or directory, no HIGH_SENSITIVITY context
  - module    : multiple files in one directory OR any HIGH_SENSITIVITY context
  - subsystem : HIGH_SENSITIVITY context AND multiple distinct top-level directories
"""

import logging

from app.models.alert import Alert
from app.models.usage import UsageLocation

logger = logging.getLogger(__name__)


def _compute_blast_radius(usages: list) -> dict:
    """Compute blast radius for a single alert's usage set."""
    if not usages:
        return {
            "blast_radius_label": "isolated",
            "blast_radius_reason": "Package not detected in any scanned file — impact scope is minimal.",
            "affected_files": 0,
            "affected_modules": 0,
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

    return {
        "blast_radius_label": label,
        "blast_radius_reason": reason,
        "affected_files": N,
        "affected_modules": M,
    }


async def run(
    alerts: list[Alert],
    alert_usages: dict[int, list[UsageLocation]],
) -> dict[int, dict]:
    """
    Run blast radius estimation for all alerts.
    Returns dict[alert_id -> blast_radius_result].
    Pure computation — no DB writes, no external calls.
    """
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
            }

        results[alert.id] = result
        logger.debug(
            f"[blast_radius_agent] alert={alert.id} vuln={alert.vuln_id} "
            f"label={result['blast_radius_label']} files={result['affected_files']} "
            f"modules={result['affected_modules']}"
        )

    logger.info(f"[blast_radius_agent] Estimated blast radius for {len(results)} alerts")
    return results
