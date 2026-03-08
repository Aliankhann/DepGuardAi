import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from alembic import command
from alembic.config import Config

from app.config import settings
from app.db import get_db

import app.models  # noqa: F401 — ensures models register with metadata

from app.routers import alerts, remediate, repos, scan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_BACKEND_ROOT = Path(__file__).parent.parent
_ALEMBIC_CFG_PATH = _BACKEND_ROOT / "alembic.ini"


def _recover_orphaned_scans() -> None:
    """Mark any in-progress scans as failed on startup.

    If the server crashes or is killed while a scan is running, the ScanRun
    stays stuck in 'pending', 'scanning', or 'analyzing' forever. On the next
    startup we detect these and mark them failed so the frontend shows a clear
    error state instead of an endless spinner.
    """
    from datetime import datetime
    from app.db import SessionLocal
    from app.models.scan_run import ScanRun

    db = SessionLocal()
    try:
        stuck = (
            db.query(ScanRun)
            .filter(ScanRun.status.in_(["pending", "scanning", "analyzing"]))
            .all()
        )
        if stuck:
            logger.warning(
                "Found %d orphaned scan(s) from previous process — marking as failed", len(stuck)
            )
            for scan in stuck:
                scan.status = "failed"
                scan.error_message = "Server restarted during scan — re-run to retry."
                scan.completed_at = datetime.utcnow()
            db.commit()
    except Exception as e:
        logger.error("Failed to recover orphaned scans: %s", e)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    alembic_cfg = Config(str(_ALEMBIC_CFG_PATH))
    # Override script_location with absolute path so it resolves regardless of cwd
    alembic_cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    command.upgrade(alembic_cfg, "head")
    logger.info("Database schema at head")
    _recover_orphaned_scans()
    yield


app = FastAPI(
    title="DepGuard API",
    version="1.0.0",
    description=(
        "Dependency risk investigation engine. "
        "Maps vulnerable packages to actual code usage, classifies exploit context "
        "by code path sensitivity, and runs AI-backed exploitability triage per repository."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(repos.router)
app.include_router(scan.router)
app.include_router(alerts.router)
app.include_router(remediate.router)


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "version": "1.0.0"}


# ---------------------------------------------------------------------------
# Demo seed endpoint
# ---------------------------------------------------------------------------

DEMO_REPO_PATH = Path(__file__).parent.parent / "tests" / "fixtures" / "demo_repo"

DEMO_PACKAGE_JSON = {
    "name": "demo-app",
    "version": "1.0.0",
    "description": "DepGuard demo app with known-vulnerable dependencies",
    "dependencies": {
        "lodash": "4.17.4",
        "express": "4.17.1",
        "axios": "0.21.1",
    },
    "devDependencies": {
        "jest": "27.0.0",
    },
}

DEMO_JS_FILES = {
    "src/api/users.js": """\
const _ = require('lodash');
const express = require('express');

const router = express.Router();

router.get('/users', async (req, res) => {
  const users = await db.find({});
  return res.json(_.pick(users, ['id', 'name', 'email']));
});

router.post('/users/merge', async (req, res) => {
  // Merge user-supplied config into defaults — prototype pollution risk
  const merged = _.merge({}, defaultConfig, req.body);
  return res.json(merged);
});

module.exports = router;
""",
    "src/auth/session.js": """\
import _ from 'lodash';
import axios from 'axios';

export async function validateSession(token) {
  const payload = _.merge({}, defaultConfig, { token });
  const response = await axios.post('/auth/validate', payload);
  return response.data;
}

export async function fetchUserProfile(userId, redirectUrl) {
  // SSRF risk: redirectUrl is user-controlled and passed to axios
  const response = await axios.get(redirectUrl + '/profile/' + userId);
  return response.data;
}
""",
    "src/middleware/app.js": """\
const express = require('express');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Query string parsing via qs — vulnerable to prototype poisoning
app.use((req, res, next) => {
  const queryParams = req.query;
  next();
});

module.exports = app;
""",
    "src/utils/helpers.js": """\
const _ = require('lodash');

function deepMerge(target, source) {
  return _.merge(target, source);
}

module.exports = { deepMerge };
""",
}


@app.post("/demo/seed", tags=["demo"])
async def seed_demo(db: Session = Depends(get_db)):
    from app.models.repository import Repository

    # Always write fixture files so the demo repo stays in sync with DEMO_JS_FILES.
    # This ensures updated content (new files, changed snippets) takes effect on every seed.
    DEMO_REPO_PATH.mkdir(parents=True, exist_ok=True)
    (DEMO_REPO_PATH / "package.json").write_text(json.dumps(DEMO_PACKAGE_JSON, indent=2))

    for rel_path, content in DEMO_JS_FILES.items():
        full_path = DEMO_REPO_PATH / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content)

    # Idempotent: return existing demo repo if already seeded
    existing = db.query(Repository).filter(Repository.name == "demo-app").first()
    if existing:
        return {
            "message": "Demo repo already exists",
            "repo_id": existing.id,
            "local_path": existing.local_path,
        }

    repo = Repository(
        name="demo-app",
        local_path=str(DEMO_REPO_PATH),
        ecosystem="npm",
        language="node",
    )
    db.add(repo)
    db.commit()
    db.refresh(repo)

    return {
        "message": "Demo repo seeded successfully",
        "repo_id": repo.id,
        "local_path": str(DEMO_REPO_PATH),
        "next_step": f"POST /repos/{repo.id}/scan",
    }


@app.post("/demo/reset", tags=["demo"])
async def reset_demo(db: Session = Depends(get_db)):
    """
    Delete all demo data so the demo can be run fresh.
    Removes the demo-app repository and all associated scans, alerts, analyses,
    remediations, and usage locations. Does NOT delete Backboard assistant memory
    (intentional — use reset only for DB cleanup, not memory wipe).
    Safe to call multiple times.
    """
    from app.models.alert import Alert
    from app.models.analysis import Analysis
    from app.models.dependency import Dependency
    from app.models.remediation import Remediation
    from app.models.repository import Repository
    from app.models.scan_run import ScanRun
    from app.models.usage import UsageLocation

    repo = db.query(Repository).filter(Repository.name == "demo-app").first()
    if not repo:
        return {"message": "No demo data found — nothing to reset."}

    # Delete in FK-safe order: usages → remediations → analyses → alerts → deps → scans → repo
    alert_ids = [a.id for a in db.query(Alert.id).filter(Alert.repo_id == repo.id).all()]
    if alert_ids:
        db.query(UsageLocation).filter(UsageLocation.alert_id.in_(alert_ids)).delete(synchronize_session=False)
        db.query(Remediation).filter(Remediation.alert_id.in_(alert_ids)).delete(synchronize_session=False)
        db.query(Analysis).filter(Analysis.alert_id.in_(alert_ids)).delete(synchronize_session=False)

    db.query(Alert).filter(Alert.repo_id == repo.id).delete(synchronize_session=False)
    db.query(Dependency).filter(Dependency.repo_id == repo.id).delete(synchronize_session=False)
    db.query(ScanRun).filter(ScanRun.repo_id == repo.id).delete(synchronize_session=False)
    db.delete(repo)
    db.commit()

    return {
        "message": "Demo data cleared. Run POST /demo/seed to start fresh.",
        "alerts_deleted": len(alert_ids),
    }
