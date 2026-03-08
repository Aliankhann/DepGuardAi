import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.config import settings
from app.db import Base, engine, get_db

# Import all models so they register with Base.metadata before create_all
import app.models  # noqa: F401

from app.routers import alerts, remediate, repos, scan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables ready")
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

    # Create fixture directory and files
    DEMO_REPO_PATH.mkdir(parents=True, exist_ok=True)

    pkg_file = DEMO_REPO_PATH / "package.json"
    if not pkg_file.exists():
        pkg_file.write_text(json.dumps(DEMO_PACKAGE_JSON, indent=2))

    for rel_path, content in DEMO_JS_FILES.items():
        full_path = DEMO_REPO_PATH / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        if not full_path.exists():
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
