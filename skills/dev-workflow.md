# Dev Workflow

## Setup

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # fill in BACKBOARD_API_KEY
alembic upgrade head
uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend
npm install
npm run dev                 # runs on http://localhost:5173
```

---

## Commands

| Action | Command |
|--------|---------|
| Start backend | `cd backend && uvicorn app.main:app --reload --port 8000` |
| Start frontend | `cd frontend && npm run dev` |
| Run migrations | `cd backend && alembic upgrade head` |
| Reset DB | `rm -f backend/depguard.db && cd backend && alembic upgrade head` |
| Run tests | `cd backend && pytest` |
| Build frontend | `cd frontend && npm run build` |

---

## Pipeline Test Procedure

Run this after any pipeline change to verify end-to-end flow:

```bash
# 1. Seed demo repo
curl -X POST http://localhost:8000/demo/seed

# 2. Trigger scan (use repo id from step 1)
curl -X POST http://localhost:8000/repos/1/scan

# 3. Poll scan status
curl http://localhost:8000/scans/1/status

# 4. Check alerts
curl http://localhost:8000/repos/1/alerts

# 5. Check full investigation
curl http://localhost:8000/alerts/1
curl http://localhost:8000/alerts/1/remediation
```

Expected: at least 1 alert for `lodash`, with UsageLocation, Analysis, and Remediation records.

---

## Agent Isolation Test

Test each agent independently before running the full pipeline:

```bash
cd backend && python -m pytest tests/test_agents.py -v
```

Or manually:
```python
# In Python REPL / test script
from app.services.agents.scan_agent import ScanAgent
results = await ScanAgent().run(repo_path="tests/fixtures/")
assert len(results) > 0
```

---

## Demo Fixtures

Located in `backend/tests/fixtures/`:

| File | Purpose |
|------|---------|
| `sample_package.json` | Has `lodash@4.17.4` (CVE-2021-23337) |
| `osv_response_lodash.json` | Pre-captured OSV batch response |
| `sample_app.js` | Has `require('lodash')` + `_.merge()` |

Use `POST /demo/seed` to register a repo pointing at the fixtures directory.

---

## Fallback Verification

To test OSV fallback: temporarily rename `sample_package.json`, run scan, verify pipeline continues.
To test Backboard fallback: set `BACKBOARD_API_KEY=invalid`, run scan, verify Analysis has `backboard_thread_id=null`.

---

## API Docs

FastAPI auto-generates interactive docs at: `http://localhost:8000/docs`
