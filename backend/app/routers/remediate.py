from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import verify_token
from app.db import get_db
from app.models.alert import Alert
from app.models.dependency import Dependency
from app.models.remediation import Remediation
from app.models.repository import Repository
from app.models.scan_run import ScanRun
from app.schemas.remediation import FinalizeRemediationRequest, RemediationResponse
from app.services import backboard_service

router = APIRouter(tags=["remediation"], dependencies=[Depends(verify_token)])


@router.get("/alerts/{alert_id}/remediation", response_model=RemediationResponse)
async def get_remediation(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    remediation = (
        db.query(Remediation).filter(Remediation.alert_id == alert_id).first()
    )
    if not remediation:
        raise HTTPException(status_code=404, detail="Remediation not found")

    return remediation


@router.post("/alerts/{alert_id}/remediation/finalize")
async def finalize_remediation(
    alert_id: int,
    body: FinalizeRemediationRequest,
    db: Session = Depends(get_db),
):
    """
    Mode 2 — Senior Review Writeback.

    After a senior engineer reviews and approves a final fix, call this endpoint
    to store the approved solution in Backboard memory. Future scans on this
    repository will recall the professional baseline when recommending remediations
    for similar vulnerabilities.
    """
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    remediation = (
        db.query(Remediation).filter(Remediation.alert_id == alert_id).first()
    )
    if not remediation:
        raise HTTPException(status_code=404, detail="Remediation not found")

    # Resolve Repository via Alert → ScanRun → Repository
    scan = db.get(ScanRun, alert.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    repo = db.get(Repository, scan.repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    dep = db.get(Dependency, alert.dependency_id)
    dep_name = dep.name if dep else alert.vuln_id

    await backboard_service.store_senior_approved_fix(
        repo=repo,
        dep_name=dep_name,
        vuln_id=alert.vuln_id,
        safe_version=remediation.safe_version,
        agent_temp_mitigation=remediation.temporary_mitigation or "",
        agent_permanent_fix=remediation.permanent_fix_summary or "",
        senior_approved_fix=body.senior_approved_fix,
        rationale=body.rationale,
        db=db,
    )

    return {"stored": True}
