"""
Context Agent
-------------
Input:  alert_usages dict (alert_id → list[UsageLocation]) + repo + DB session
Output: context_tags, sensitivity_level, sensitive_surface_reason, subsystem_labels,
        user_input_proximity written to each UsageLocation record

Strategy: AI primary (Backboard), deterministic path-based fallback.

Fallback is always used when Backboard is unavailable — context_tags are ALWAYS
populated so downstream agents (exploitability_agent, confidence_agent) are
never blocked. New enrichment fields are null in fallback mode (except subsystem_labels,
which is derived from semantic context_tags in fallback mode).

Batching: one Backboard call per PACKAGE (not per alert).
Multiple CVEs for the same package import from the same files — we deduplicate
by file_path and make one call per unique package, then propagate results to all
matching usage records across all CVEs. This matches risk_agent's optimization.

Concurrency: all per-package calls run in parallel via asyncio.gather().

Backward compatibility: context_tags remains a flat list[str] containing
exactly the sensitivity level strings that downstream agents check:
  HIGH_SENSITIVITY | MEDIUM_SENSITIVITY | LOW_SENSITIVITY
"""

import asyncio
import logging
from collections import defaultdict

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.dependency import Dependency
from app.models.repository import Repository
from app.models.usage import UsageLocation
from app.services import backboard_service

logger = logging.getLogger(__name__)

# Rules are ordered by descending sensitivity priority.
# Each entry: (path_keywords, tag_name, sensitivity_level)
# The first matching HIGH_SENSITIVITY rule wins; LOW_SENSITIVITY tags are
# suppressed if any HIGH_SENSITIVITY match is found (conflict resolution).
CONTEXT_RULES: list[tuple[list[str], str, str]] = [
    # HIGH_SENSITIVITY — security-critical code paths
    (["auth", "login", "password", "session", "jwt", "oauth"], "auth", "HIGH_SENSITIVITY"),
    (["payment", "checkout", "billing", "stripe", "invoice"], "payment", "HIGH_SENSITIVITY"),
    (["admin", "dashboard", "internal"], "admin", "HIGH_SENSITIVITY"),
    (["crypto", "cipher", "encrypt", "decrypt", "hmac", "rsa", "aes", "sign"], "crypto", "HIGH_SENSITIVITY"),
    (["secret", "credential", "token", "apikey", "api_key", "private_key", "cert"], "secrets", "HIGH_SENSITIVITY"),
    (["exec", "spawn", "shell", "subprocess", "eval", "process"], "execution", "HIGH_SENSITIVITY"),
    # MEDIUM_SENSITIVITY — important but not directly security-critical
    (["api", "route", "middleware", "handler", "controller"], "api", "MEDIUM_SENSITIVITY"),
    (["db", "database", "query", "sql", "orm", "migration", "store", "cache"], "data", "MEDIUM_SENSITIVITY"),
    # LOW_SENSITIVITY — utility, test, or shared code
    (["util", "helper", "lib", "common", "shared"], "util", "LOW_SENSITIVITY"),
    (["test", "spec", "__tests__", "_test"], "test", "LOW_SENSITIVITY"),
]

_SENSITIVITY_ORDER = {"HIGH_SENSITIVITY": 2, "MEDIUM_SENSITIVITY": 1, "LOW_SENSITIVITY": 0}


def _classify(file_path: str) -> list[str]:
    """Deterministic path-based classification. Returns flat list of tags including sensitivity string."""
    path_lower = file_path.lower()
    matched: list[tuple[str, str]] = []  # (tag, sensitivity) pairs

    for keywords, tag, sensitivity in CONTEXT_RULES:
        if any(kw in path_lower for kw in keywords):
            matched.append((tag, sensitivity))

    if not matched:
        return ["unclassified", "LOW_SENSITIVITY"]

    max_sensitivity = max(matched, key=lambda x: _SENSITIVITY_ORDER[x[1]])[1]

    # Keep only tags at or above the highest sensitivity level found.
    filtered = [(tag, sens) for tag, sens in matched if _SENSITIVITY_ORDER[sens] >= _SENSITIVITY_ORDER[max_sensitivity]]

    tags: list[str] = []
    for tag, sensitivity in filtered:
        tags.append(tag)
        tags.append(sensitivity)
    return tags


def _sensitivity_label(tags: list[str]) -> str:
    """Convert sensitivity string in context_tags to short label ('HIGH', 'MEDIUM', 'LOW')."""
    if "HIGH_SENSITIVITY" in tags:
        return "HIGH"
    if "MEDIUM_SENSITIVITY" in tags:
        return "MEDIUM"
    return "LOW"


def _apply_fallback(usage: UsageLocation) -> None:
    """Apply deterministic classification to a single usage (fallback path)."""
    tags = _classify(usage.file_path)
    usage.context_tags = tags
    usage.sensitivity_level = _sensitivity_label(tags)
    # Derive subsystem_labels from semantic tags — filter out sensitivity strings and "unclassified"
    semantic = [t for t in tags if "SENSITIVITY" not in t and t != "unclassified"]
    usage.subsystem_labels = semantic if semantic else None
    # sensitive_surface_reason and user_input_proximity remain null in fallback mode


def _apply_ai_result(usage: UsageLocation, classification: dict) -> None:
    """Apply AI classification dict to a usage location."""
    context_tags = classification.get("context_tags") or []
    # Ensure sensitivity string is present — fall back to deterministic if AI omitted it
    has_sensitivity = any(t in context_tags for t in ("HIGH_SENSITIVITY", "MEDIUM_SENSITIVITY", "LOW_SENSITIVITY"))
    if not has_sensitivity:
        fallback_tags = _classify(usage.file_path)
        sensitivity_tag = next((t for t in fallback_tags if "SENSITIVITY" in t), "LOW_SENSITIVITY")
        context_tags = list(context_tags) + [sensitivity_tag]

    usage.context_tags = context_tags
    usage.sensitivity_level = classification.get("sensitivity_level") or _sensitivity_label(context_tags)
    usage.sensitive_surface_reason = classification.get("sensitive_surface_reason") or None
    usage.subsystem_labels = classification.get("subsystem_labels") or None
    usage.user_input_proximity = classification.get("user_input_proximity") or None


async def _classify_for_dep(
    representative_alert: Alert,
    unique_usages: list[UsageLocation],
    all_usages: list[UsageLocation],
    dep_name: str,
    dep_version: str,
    repo: Repository,
    db: Session,
) -> None:
    """
    One Backboard call per package.

    unique_usages: deduplicated by file_path — sent in the Backboard prompt (indexed 1..N).
    all_usages: all UsageLocation records for this package across all its CVEs.
                May contain multiple records per file_path (one per alert).

    Results are applied to all_usages by file_path match.
    Usages with no AI result receive deterministic fallback.
    """
    classifications = await backboard_service.run_context_analysis(
        alert=representative_alert,
        usages=unique_usages,
        dep_name=dep_name,
        dep_version=dep_version,
        repo=repo,
        db=db,
    )

    if not classifications:
        for usage in all_usages:
            _apply_fallback(usage)
        return

    # Map file_path → classification using the 1-based index into unique_usages
    file_path_to_cl: dict[str, dict] = {}
    for cl in classifications:
        idx = cl.get("index", 0)
        if 1 <= idx <= len(unique_usages):
            fp = unique_usages[idx - 1].file_path
            file_path_to_cl[fp] = cl

    # Apply to ALL usage records (including duplicates across multiple CVEs)
    for usage in all_usages:
        cl = file_path_to_cl.get(usage.file_path)
        if cl:
            _apply_ai_result(usage, cl)
        else:
            _apply_fallback(usage)
            logger.debug(
                f"[context_agent] AI missing result for {usage.file_path} "
                f"(dep={dep_name}) — fallback applied"
            )


async def run(
    alert_usages: dict[int, list[UsageLocation]],
    repo: Repository,
    db: Session,
) -> None:
    """
    Classify all usage locations grouped by package.
    One Backboard call per unique package — matching risk_agent's optimization.
    """
    if not alert_usages:
        return

    # Load alerts and group by dependency_id
    alert_objects: dict[int, Alert] = {}
    dep_cache: dict[int, Dependency] = {}
    # dep_id → list of (alert, [usages])
    by_dep: dict[int, list[tuple[Alert, list[UsageLocation]]]] = defaultdict(list)

    for alert_id, usages in alert_usages.items():
        if not usages:
            continue
        alert = db.get(Alert, alert_id)
        if not alert:
            for usage in usages:
                _apply_fallback(usage)
            continue
        alert_objects[alert_id] = alert
        dep = dep_cache.get(alert.dependency_id)
        if not dep:
            dep = db.get(Dependency, alert.dependency_id)
            if dep:
                dep_cache[alert.dependency_id] = dep
        by_dep[alert.dependency_id].append((alert, usages))

    if not by_dep:
        db.flush()
        return

    coroutines = []
    for dep_id, alert_usage_pairs in by_dep.items():
        dep = dep_cache.get(dep_id)
        dep_name = dep.name if dep else "unknown"
        dep_version = dep.version if dep else "unknown"

        # Deduplicate usages by file_path — multiple CVEs import the same files
        unique_usages: list[UsageLocation] = []
        seen_paths: set[str] = set()
        all_usages_for_dep: list[UsageLocation] = []

        for _, usages in alert_usage_pairs:
            for usage in usages:
                all_usages_for_dep.append(usage)
                if usage.file_path not in seen_paths:
                    unique_usages.append(usage)
                    seen_paths.add(usage.file_path)

        # Use the first alert as representative (vuln_id/summary for prompt context)
        representative_alert = alert_usage_pairs[0][0]

        coroutines.append(
            _classify_for_dep(
                representative_alert,
                unique_usages,
                all_usages_for_dep,
                dep_name,
                dep_version,
                repo,
                db,
            )
        )

    if coroutines:
        await asyncio.gather(*coroutines, return_exceptions=True)

    db.flush()
