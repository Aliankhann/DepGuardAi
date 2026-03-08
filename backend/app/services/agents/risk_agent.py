"""
Risk Agent
----------
Input:  Alert + UsageLocations
Output: Analysis record per Alert

All AI calls go through backboard_service — never inline here.

Optimization: group alerts by dependency (package name) so we make ONE
Backboard call per unique vulnerable package, then share the result across
all CVEs for that package. This turns N-alerts calls into N-packages calls
and avoids redundant analysis of the same code locations.
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

logger = logging.getLogger(__name__)


async def _analyze_package(
    repo: Repository,
    representative_alert: Alert,
    all_alerts_for_pkg: list[Alert],
    alert_usages: dict[int, list[UsageLocation]],
    dep_name: str,
    dep_version: str,
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

    analysis_dict, thread_id = await backboard_service.run_risk_analysis(
        repo=repo,
        alert=representative_alert,
        usage_locations=all_usages,
        dep_name=dep_name,
        dep_version=dep_version,
        all_vuln_ids=all_vuln_ids,
        db=db,
    )

    analyses = []
    for alert in all_alerts_for_pkg:
        analysis = Analysis(
            alert_id=alert.id,
            risk_level=analysis_dict.get("risk_level", "medium"),
            confidence=analysis_dict.get("confidence", "low"),
            reasoning=analysis_dict.get("reasoning", ""),
            business_impact=analysis_dict.get("business_impact", ""),
            recommended_fix=analysis_dict.get("recommended_fix", ""),
            urgency=analysis_dict.get("urgency"),
            analysis_source=analysis_dict.get("analysis_source", "backboard_ai"),
            backboard_thread_id=thread_id,
        )
        analyses.append(analysis)
    return analyses


async def run(
    repo: Repository,
    alerts: list[Alert],
    alert_usages: dict[int, list[UsageLocation]],
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
                db=db,
            )
        )

    results = await asyncio.gather(*tasks)
    for analyses in results:
        for analysis in analyses:
            db.add(analysis)

    db.flush()
