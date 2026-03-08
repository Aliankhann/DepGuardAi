"""
Dependency/Vulnerability Agent
-------------------------------
Input:  Alert records (with osv_data) + DB session to load Dependency info
Output: dict[dep_name, DependencyInvestigation] — in-memory + written to alert.dependency_investigation

Position in pipeline: after scan_agent, before code_agent.

Purpose: reason over parsed OSV data to produce structured vulnerability intelligence —
what the vulnerability enables, what code patterns to look for, what safe version to target.
This normalizes raw OSV JSON into actionable fields that guide downstream agents:
  - investigation_focus → exploitability_agent uses these patterns alongside KNOWN_DANGEROUS_PATTERNS
  - vulnerability_summary → enriches the risk_agent Backboard prompt (via stored Alert field)
  - safe_version_hint → cross-checks fix_agent's version extraction

This agent does NOT replace deterministic scanning. OSV querying and dependency parsing
remain in scan_agent. This agent operates on the structured output after scanning.

One Backboard call per package (not per CVE) — matching risk_agent optimization.
Falls back gracefully to deterministic extraction if Backboard is unavailable.
"""

import asyncio
import logging
from collections import defaultdict
from typing import Optional

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.dependency import Dependency
from app.models.repository import Repository
from app.services import backboard_service
from app.services.agents.exploitability_agent import KNOWN_DANGEROUS_PATTERNS

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _extract_fixed_version(osv_data: dict) -> Optional[str]:
    """Extract earliest fixed version from osv_data (replicates fix_agent logic)."""
    for affected in osv_data.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    return fixed
    return None


def _max_severity(alerts_for_pkg: list[Alert]) -> str:
    """Return the highest severity across all CVEs for a package."""
    best = "LOW"
    for a in alerts_for_pkg:
        sev = (a.severity or "LOW").upper()
        if _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(best, 0):
            best = sev
    return best.lower()


def _build_fallback(
    dep: Dependency,
    alerts_for_pkg: list[Alert],
) -> dict:
    """Deterministic fallback when Backboard is unavailable."""
    best_osv = alerts_for_pkg[0].osv_data or {}
    safe_version = _extract_fixed_version(best_osv)

    return {
        "package_name": dep.name,
        "package_version": dep.version,
        "ecosystem": dep.ecosystem,
        "vulnerability_ids": [a.vuln_id for a in alerts_for_pkg],
        "vulnerability_summary": alerts_for_pkg[0].summary or "",
        "vulnerable_behaviors": [],
        "severity_level": _max_severity(alerts_for_pkg),
        "suggested_safe_version": safe_version,
        "investigation_focus": list(KNOWN_DANGEROUS_PATTERNS.get(dep.name.lower(), [])),
        "investigation_source": "fallback",
    }


async def _analyze_package(
    dep: Dependency,
    alerts_for_pkg: list[Alert],
    repo: Repository,
    db: Session,
) -> dict:
    """Run Backboard analysis for one package, return DependencyInvestigation dict."""
    # Build compact vuln summaries for prompt
    all_vuln_summaries = []
    seen_versions: set[str] = set()
    safe_version_hint: Optional[str] = None

    for alert in alerts_for_pkg:
        osv = alert.osv_data or {}
        aliases = osv.get("aliases", [])

        # Collect safe version hint from any CVE
        if not safe_version_hint:
            safe_version_hint = _extract_fixed_version(osv)

        all_vuln_summaries.append({
            "vuln_id": alert.vuln_id,
            "summary": alert.summary or "",
            "details": (osv.get("details") or "")[:500],
            "severity": alert.severity or "MEDIUM",
            "aliases": aliases,
        })

    try:
        result = await backboard_service.run_dependency_analysis(
            repo=repo,
            dep_name=dep.name,
            dep_version=dep.version,
            ecosystem=dep.ecosystem,
            all_vuln_summaries=all_vuln_summaries,
            db=db,
        )
    except Exception as e:
        logger.warning(f"depvuln_agent Backboard call failed for {dep.name}: {e}")
        result = _build_fallback(dep, alerts_for_pkg)

    # Merge static fields that Backboard doesn't need to compute
    result.setdefault("package_name", dep.name)
    result.setdefault("package_version", dep.version)
    result.setdefault("ecosystem", dep.ecosystem)
    result["vulnerability_ids"] = [a.vuln_id for a in alerts_for_pkg]

    # If Backboard didn't return a suggested_safe_version, fall back to deterministic extraction
    if not result.get("suggested_safe_version") and safe_version_hint:
        result["suggested_safe_version"] = safe_version_hint

    # Merge investigation_focus: AI patterns + KNOWN_DANGEROUS_PATTERNS for this package
    ai_focus = result.get("investigation_focus") or []
    static_focus = list(KNOWN_DANGEROUS_PATTERNS.get(dep.name.lower(), []))
    merged_focus = list(dict.fromkeys(ai_focus + static_focus))  # deduplicate, preserve order
    result["investigation_focus"] = merged_focus

    return result


async def run(
    alerts: list[Alert],
    repo: Repository,
    db: Session,
) -> dict[str, dict]:
    """
    Run dependency/vulnerability analysis for all alerts.
    Returns dict[dep_name (lowercase), DependencyInvestigation].
    Writes dependency_investigation JSON to each Alert in DB.
    """
    if not alerts:
        return {}

    # Group alerts by dependency_id
    by_dep: dict[int, list[Alert]] = defaultdict(list)
    for alert in alerts:
        by_dep[alert.dependency_id].append(alert)

    # Run all packages concurrently
    tasks = []
    dep_map: dict[int, Dependency] = {}
    for dep_id, dep_alerts in by_dep.items():
        dep = db.get(Dependency, dep_id)
        if not dep:
            continue
        dep_map[dep_id] = dep
        tasks.append(_analyze_package(dep, dep_alerts, repo, db))

    results_list = await asyncio.gather(*tasks, return_exceptions=True)

    investigations: dict[str, dict] = {}
    dep_ids = list(dep_map.keys())

    for i, result in enumerate(results_list):
        dep_id = dep_ids[i]
        dep = dep_map[dep_id]

        if isinstance(result, Exception):
            logger.warning(f"depvuln_agent failed for dep_id={dep_id}: {result}")
            result = _build_fallback(dep, by_dep[dep_id])

        investigations[dep.name.lower()] = result

        # Persist to each alert for this package
        for alert in by_dep[dep_id]:
            alert.dependency_investigation = result
            logger.debug(
                f"[depvuln_agent] alert={alert.id} dep={dep.name} "
                f"source={result.get('investigation_source', '?')} "
                f"focus_count={len(result.get('investigation_focus', []))}"
            )

    logger.info(f"[depvuln_agent] Analyzed {len(investigations)} packages")
    return investigations
