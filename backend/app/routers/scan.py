import asyncio
import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import SessionLocal, get_db
from app.models.repository import Repository
from app.models.scan_run import ScanRun
from app.schemas.scan import ScanRunResponse, ScanStatusResponse
from app.services.agent_orchestrator import run_pipeline

logger = logging.getLogger(__name__)
router = APIRouter(tags=["scans"])


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
