"""
Risk Agent
----------
Input:  Alert + UsageLocations + exploitability_results + blast_radius_results
Output: Analysis record per Alert

All AI calls go through backboard_service — never inline here.

Optimization: group alerts by dependency (package name) so we make ONE
Backboard call per unique vulnerable package, then share the result across
all CVEs for that package. This turns N-alerts calls into N-packages calls
and avoids redundant analysis of the same code locations.

The exploitability_results dict (keyed by alert_id) provides pre-computed
deterministic evidence that is injected into the Backboard prompt and also
persisted directly into each Analysis record.

The blast_radius_results dict (keyed by alert_id) provides deterministic
scope estimation that is also injected into the Backboard prompt.

After the Backboard call returns, confidence_agent.compute() is called
per-alert to produce a deterministic confidence_percent + confidence_reasons
based on all available evidence including the AI outcome (fallback vs success).
"""

import asyncio
import logging
from collections import defaultdict

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.analysis import Analysis
from app.models.dependency import Dependency
from app.models.repository import Repository
from app.models.usage import UsageLocation
from app.services import backboard_service
from app.services.agents import confidence_agent

logger = logging.getLogger(__name__)

_EVIDENCE_ORDER = {"high": 2, "medium": 1, "low": 0}
_BR_ORDER = {"subsystem": 2, "module": 1, "isolated": 0}


async def _analyze_package(
    repo: Repository,
    representative_alert: Alert,
    all_alerts_for_pkg: list[Alert],
    alert_usages: dict[int, list[UsageLocation]],
    dep_name: str,
    dep_version: str,
    exploitability_results: dict[int, dict],
    blast_radius_results: dict[int, dict],
    db: Session,
) -> list[Analysis]:
    """Run one Backboard call for a package and create Analysis for all its alerts."""
    # Collect all unique usages across all alerts for this package
    all_usages: list[UsageLocation] = []
    seen_ids: set[int] = set()
    for alert in all_alerts_for_pkg:
        for u in alert_usages.get(alert.id, []):
            if u.id not in seen_ids:
                all_usages.append(u)
                seen_ids.add(u.id)

    # Collect all CVE IDs so the AI knows the full scope of this package's vulns
    all_vuln_ids = [a.vuln_id for a in all_alerts_for_pkg]

    # Pick the highest-evidence exploitability result from this package's alerts
    pkg_exploitability = [
        exploitability_results[a.id]
        for a in all_alerts_for_pkg
        if a.id in exploitability_results
    ]
    best_exploitability = (
        max(
            pkg_exploitability,
            key=lambda x: _EVIDENCE_ORDER.get(x.get("evidence_strength", "low"), 0),
        )
        if pkg_exploitability
        else None
    )

    # Pick the widest-scope blast radius for the shared Backboard prompt context
    pkg_blast_radius = [
        blast_radius_results[a.id]
        for a in all_alerts_for_pkg
        if a.id in blast_radius_results
    ]
    best_blast_radius = (
        max(
            pkg_blast_radius,
            key=lambda x: _BR_ORDER.get(x.get("blast_radius_label", "isolated"), 0),
        )
        if pkg_blast_radius
        else None
    )

    analysis_dict, thread_id = await backboard_service.run_risk_analysis(
        repo=repo,
        alert=representative_alert,
        usage_locations=all_usages,
        dep_name=dep_name,
        dep_version=dep_version,
        all_vuln_ids=all_vuln_ids,
        exploitability_context=best_exploitability,
        blast_radius_context=best_blast_radius,
        db=db,
    )

    analyses = []
    for alert in all_alerts_for_pkg:
        expl = exploitability_results.get(alert.id, {})
        br = blast_radius_results.get(alert.id, {})
        per_alert_usages = alert_usages.get(alert.id, [])

        # Deterministic confidence scoring — runs after Backboard so analysis_source is known
        conf = confidence_agent.compute(
            usages=per_alert_usages,
            exploitability_result=expl,
            blast_radius_result=br,
            analysis_source=analysis_dict.get("analysis_source", "fallback"),
            dep_name=dep_name,
        )

        analysis = Analysis(
            alert_id=alert.id,
            risk_level=analysis_dict.get("risk_level", "medium"),
            confidence=conf["confidence"],
            reasoning=analysis_dict.get("reasoning", ""),
            business_impact=analysis_dict.get("business_impact", ""),
            recommended_fix=analysis_dict.get("recommended_fix", ""),
            urgency=analysis_dict.get("urgency"),
            analysis_source=analysis_dict.get("analysis_source", "backboard_ai"),
            backboard_thread_id=thread_id,
            exploitability_score=analysis_dict.get("exploitability_score"),
            confidence_score=analysis_dict.get("confidence_score"),
            blast_radius=analysis_dict.get("blast_radius"),
            temp_mitigation=analysis_dict.get("temp_mitigation"),
            exploitability=expl.get("exploitability"),
            evidence_strength=expl.get("evidence_strength"),
            exploitability_reason=expl.get("exploitability_reason"),
            detected_functions=expl.get("detected_functions"),
            blast_radius_label=br.get("blast_radius_label"),
            affected_surfaces=br.get("affected_surfaces"),
            scope_clarity=br.get("scope_clarity"),
            confidence_percent=conf["confidence_percent"],
            confidence_reasons=conf["confidence_reasons"],
        )
        analyses.append(analysis)
    return analyses


async def run(
    repo: Repository,
    alerts: list[Alert],
    alert_usages: dict[int, list[UsageLocation]],
    exploitability_results: dict[int, dict],
    blast_radius_results: dict[int, dict],
    db: Session,
) -> None:
    # Group alerts by dependency_id so we call Backboard once per package
    by_dep: dict[int, list[Alert]] = defaultdict(list)
    for alert in alerts:
        by_dep[alert.dependency_id].append(alert)

    # Run all packages in parallel
    tasks = []
    for dep_id, dep_alerts in by_dep.items():
        dep = db.get(Dependency, dep_id)
        dep_name = dep.name if dep else "unknown"
        dep_version = dep.version if dep else "unknown"
        tasks.append(
            _analyze_package(
                repo=repo,
                representative_alert=dep_alerts[0],
                all_alerts_for_pkg=dep_alerts,
                alert_usages=alert_usages,
                dep_name=dep_name,
                dep_version=dep_version,
                exploitability_results=exploitability_results,
                blast_radius_results=blast_radius_results,
                db=db,
            )
        )

    results = await asyncio.gather(*tasks)
    for analyses in results:
        for analysis in analyses:
            db.add(analysis)

    db.flush()
