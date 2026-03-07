from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.alert import Alert
from app.models.analysis import Analysis
from app.models.dependency import Dependency
from app.models.usage import UsageLocation
from app.schemas.alert import (
    AlertDetail,
    AlertSummary,
    AnalysisResponse,
    UsageLocationResponse,
)

router = APIRouter(tags=["alerts"])


def _build_summary(alert: Alert, db: Session) -> AlertSummary:
    dep = db.get(Dependency, alert.dependency_id)
    usage_count = (
        db.query(UsageLocation).filter(UsageLocation.alert_id == alert.id).count()
    )
    analysis = db.query(Analysis).filter(Analysis.alert_id == alert.id).first()

    return AlertSummary(
        id=alert.id,
        vuln_id=alert.vuln_id,
        severity=alert.severity,
        summary=alert.summary,
        dependency_name=dep.name if dep else "unknown",
        dependency_version=dep.version if dep else "unknown",
        usage_count=usage_count,
        risk_level=analysis.risk_level if analysis else None,
    )


@router.get("/repos/{repo_id}/alerts", response_model=list[AlertSummary])
async def list_alerts(repo_id: int, db: Session = Depends(get_db)):
    alerts = db.query(Alert).filter(Alert.repo_id == repo_id).all()
    return [_build_summary(a, db) for a in alerts]


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
async def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    dep = db.get(Dependency, alert.dependency_id)
    usages = db.query(UsageLocation).filter(UsageLocation.alert_id == alert.id).all()
    analysis = db.query(Analysis).filter(Analysis.alert_id == alert.id).first()

    osv_data = alert.osv_data or {}
    vuln_aliases = osv_data.get("aliases", [])
    references = [r["url"] for r in osv_data.get("references", []) if r.get("url")]

    return AlertDetail(
        id=alert.id,
        scan_id=alert.scan_id,
        repo_id=alert.repo_id,
        vuln_id=alert.vuln_id,
        severity=alert.severity,
        summary=alert.summary,
        dependency_name=dep.name if dep else "unknown",
        dependency_version=dep.version if dep else "unknown",
        vuln_aliases=vuln_aliases,
        references=references,
        usage_locations=[UsageLocationResponse.model_validate(u) for u in usages],
        analysis=AnalysisResponse.model_validate(analysis) if analysis else None,
    )
