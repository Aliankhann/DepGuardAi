"""
Risk Agent
----------
Input:  Alert + UsageLocations
Output: Analysis record per Alert

All AI calls go through backboard_service — never inline here.
"""

import logging

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.analysis import Analysis
from app.models.dependency import Dependency
from app.models.repository import Repository
from app.models.usage import UsageLocation
from app.services import backboard_service

logger = logging.getLogger(__name__)


async def run(
    repo: Repository,
    alerts: list[Alert],
    alert_usages: dict[int, list[UsageLocation]],
    db: Session,
) -> None:
    for alert in alerts:
        usages = alert_usages.get(alert.id, [])
        dep = db.get(Dependency, alert.dependency_id)
        dep_name = dep.name if dep else "unknown"
        dep_version = dep.version if dep else "unknown"

        analysis_dict, thread_id = await backboard_service.run_risk_analysis(
            repo=repo,
            alert=alert,
            usage_locations=usages,
            dep_name=dep_name,
            dep_version=dep_version,
            db=db,
        )

        analysis = Analysis(
            alert_id=alert.id,
            risk_level=analysis_dict.get("risk_level", "medium"),
            confidence=analysis_dict.get("confidence", "low"),
            reasoning=analysis_dict.get("reasoning", ""),
            business_impact=analysis_dict.get("business_impact", ""),
            recommended_fix=analysis_dict.get("recommended_fix", ""),
            backboard_thread_id=thread_id,
        )
        db.add(analysis)

    db.flush()
