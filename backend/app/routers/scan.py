import asyncio
import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.auth import verify_token
from app.db import SessionLocal, get_db
from app.models.alert import Alert
from app.models.analysis import Analysis
from app.models.remediation import Remediation
from app.models.repository import Repository
from app.models.scan_run import ScanRun
from app.models.usage import UsageLocation
from app.schemas.scan import ScanRunResponse, ScanStatusResponse, ScanVerifyResponse
from app.services.agent_orchestrator import run_pipeline

logger = logging.getLogger(__name__)
router = APIRouter(tags=["scans"], dependencies=[Depends(verify_token)])


def _run_pipeline_background(scan_id: int) -> None:
    """Background task: owns its own DB session so it outlives the HTTP request."""
    db = SessionLocal()
    try:
        asyncio.run(run_pipeline(scan_id, db))
    except Exception as e:
        logger.error(f"Background pipeline error for scan {scan_id}: {e}", exc_info=True)
    finally:
        db.close()


@router.post("/repos/{repo_id}/scan", response_model=ScanRunResponse)
async def start_scan(
    repo_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    repo = db.get(Repository, repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    if repo.local_path is None:
        if repo.repo_url is not None:
            raise HTTPException(
                status_code=422,
                detail="Remote repo cloning not yet supported. Provide local_path instead.",
            )
        raise HTTPException(
            status_code=422,
            detail="Repository has no local_path. Set local_path when creating the repository.",
        )

    scan = ScanRun(repo_id=repo_id, status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(_run_pipeline_background, scan.id)

    return scan


@router.get("/scans/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(ScanRun, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/scans/{scan_id}/verify", response_model=ScanVerifyResponse)
async def verify_scan(scan_id: int, db: Session = Depends(get_db)):
    """Audit a completed scan: check coverage, AI vs fallback, missing data."""
    scan = db.get(ScanRun, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    alerts = db.query(Alert).filter(Alert.scan_id == scan_id).all()
    total = len(alerts)

    alerts_with_ai = 0
    alerts_with_fallback = 0
    alerts_missing_analysis = 0
    alerts_missing_remediation = 0
    alerts_with_usage = 0
    alerts_without_usage = 0

    if total > 0:
        alert_ids = [a.id for a in alerts]

        # Batch fetch analyses and remediations — 2 queries instead of 2×N
        analyses: dict[int, Analysis] = {
            an.alert_id: an
            for an in db.query(Analysis).filter(Analysis.alert_id.in_(alert_ids)).all()
        }
        remediation_ids: set[int] = {
            r.alert_id
            for r in db.query(Remediation.alert_id)
            .filter(Remediation.alert_id.in_(alert_ids))
            .all()
        }
        # Usage counts per alert — 1 query with GROUP BY instead of N COUNT queries
        usage_counts: dict[int, int] = {
            alert_id: count
            for alert_id, count in db.query(
                UsageLocation.alert_id, func.count(UsageLocation.id)
            )
            .filter(UsageLocation.alert_id.in_(alert_ids))
            .group_by(UsageLocation.alert_id)
            .all()
        }

        for alert in alerts:
            analysis = analyses.get(alert.id)
            if not analysis:
                alerts_missing_analysis += 1
            elif analysis.analysis_source == "backboard_ai":
                alerts_with_ai += 1
            else:
                alerts_with_fallback += 1

            if alert.id not in remediation_ids:
                alerts_missing_remediation += 1

            if usage_counts.get(alert.id, 0) > 0:
                alerts_with_usage += 1
            else:
                alerts_without_usage += 1

    duration = None
    if scan.completed_at and scan.started_at:
        duration = (scan.completed_at - scan.started_at).total_seconds()

    coverage_pct = (alerts_with_ai / total * 100) if total > 0 else 0.0

    return ScanVerifyResponse(
        scan_id=scan_id,
        status=scan.status,
        total_alerts=total,
        alerts_with_ai_analysis=alerts_with_ai,
        alerts_with_fallback=alerts_with_fallback,
        alerts_with_usage_found=alerts_with_usage,
        alerts_without_usage=alerts_without_usage,
        alerts_missing_analysis=alerts_missing_analysis,
        alerts_missing_remediation=alerts_missing_remediation,
        pipeline_duration_seconds=duration,
        coverage_pct=round(coverage_pct, 1),
    )
