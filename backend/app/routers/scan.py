from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.repository import Repository
from app.models.scan_run import ScanRun
from app.schemas.scan import ScanRunResponse, ScanStatusResponse
from app.services.agent_orchestrator import run_pipeline

router = APIRouter(tags=["scans"])


@router.post("/repos/{repo_id}/scan", response_model=ScanRunResponse)
async def start_scan(repo_id: int, db: Session = Depends(get_db)):
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

    # Run synchronously for MVP — simple and predictable
    await run_pipeline(scan.id, db)
    db.refresh(scan)

    return scan


@router.get("/scans/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(ScanRun, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
