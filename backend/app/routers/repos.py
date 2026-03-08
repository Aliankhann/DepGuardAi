from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import verify_token
from app.db import get_db
from app.models.alert import Alert
from app.models.analysis import Analysis
from app.models.dependency import Dependency
from app.models.remediation import Remediation
from app.models.repository import Repository
from app.models.scan_run import ScanRun
from app.models.usage import UsageLocation
from app.schemas.repository import RepositoryCreate, RepositoryResponse
from app.schemas.scan import ScanRunResponse

router = APIRouter(prefix="/repos", tags=["repos"], dependencies=[Depends(verify_token)])


@router.post("", response_model=RepositoryResponse, status_code=201)
async def create_repo(payload: RepositoryCreate, db: Session = Depends(get_db)):
    repo = Repository(**payload.model_dump())
    db.add(repo)
    db.commit()
    db.refresh(repo)
    return repo


@router.get("", response_model=list[RepositoryResponse])
async def list_repos(db: Session = Depends(get_db)):
    return db.query(Repository).order_by(Repository.created_at.desc()).all()


@router.get("/{repo_id}", response_model=RepositoryResponse)
async def get_repo(repo_id: int, db: Session = Depends(get_db)):
    repo = db.get(Repository, repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    return repo


@router.delete("/{repo_id}", status_code=204)
async def delete_repo(repo_id: int, db: Session = Depends(get_db)):
    repo = db.get(Repository, repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    # Cascade delete all related data manually (SQLite has no FK cascade by default)
    alerts = db.query(Alert).filter(Alert.repo_id == repo_id).all()
    for alert in alerts:
        db.query(Analysis).filter(Analysis.alert_id == alert.id).delete()
        db.query(Remediation).filter(Remediation.alert_id == alert.id).delete()
        db.query(UsageLocation).filter(UsageLocation.alert_id == alert.id).delete()
    db.query(Alert).filter(Alert.repo_id == repo_id).delete()
    db.query(Dependency).filter(Dependency.repo_id == repo_id).delete()
    db.query(ScanRun).filter(ScanRun.repo_id == repo_id).delete()
    db.delete(repo)
    db.commit()


@router.get("/{repo_id}/scans", response_model=list[ScanRunResponse])
async def list_scans(repo_id: int, db: Session = Depends(get_db)):
    repo = db.get(Repository, repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    return (
        db.query(ScanRun)
        .filter(ScanRun.repo_id == repo_id)
        .order_by(ScanRun.started_at.desc())
        .all()
    )
