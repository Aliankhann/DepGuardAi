from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.repository import Repository
from app.models.scan_run import ScanRun
from app.schemas.repository import RepositoryCreate, RepositoryResponse
from app.schemas.scan import ScanRunResponse

router = APIRouter(prefix="/repos", tags=["repos"])


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
