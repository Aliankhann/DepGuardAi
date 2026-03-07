# Person 1 — Backend Foundation

## Your Responsibility

You own everything from "project exists" to "alerts are in the database with code locations and context tags."

By the time you're done, Person 2 can plug in Backboard and Person 3 can wire the UI.

---

## What You Build

- Backend project setup (FastAPI, SQLite, Alembic, all models)
- Scan Agent — reads package.json, queries OSV, creates Alert records
- Code Agent — finds where vulnerable packages are imported in JS/TS files
- Context Agent — classifies file sensitivity by path keywords
- Demo fixtures — sample repo data for testing without a real project
- `/demo/seed` endpoint — registers the fixture repo instantly

---

## Depends On

Nothing. You go first.

---

## Blocks

- Person 2 needs your models, DB session, and Alert + UsageLocation records to exist
- Person 3 needs the backend running so they can wire up fetch calls

---

## Claude Code Prompts — Paste These In Order

### Prompt 1 — Backend Scaffolding

```
Set up the DepGuard backend project. Reference Claude.md and skills/schema.md for the full spec.

Create the following structure under backend/:

requirements.txt with:
  fastapi uvicorn[standard] sqlalchemy alembic httpx python-dotenv pydantic-settings

.env.example:
  BACKBOARD_API_KEY=
  DATABASE_URL=sqlite:///./depguard.db
  CORS_ORIGINS=http://localhost:5173

app/config.py — load settings using pydantic-settings from .env
app/db.py — SQLAlchemy engine + SessionLocal + Base + get_db dependency
app/main.py — FastAPI app with CORSMiddleware, include placeholder routers

Create all 7 SQLAlchemy models from skills/schema.md:
  app/models/__init__.py
  app/models/repository.py  (Repository)
  app/models/scan_run.py    (ScanRun)
  app/models/dependency.py  (Dependency)
  app/models/alert.py       (Alert)
  app/models/usage.py       (UsageLocation)
  app/models/analysis.py    (Analysis)
  app/models/remediation.py (Remediation)

Initialize Alembic and create the first migration that creates all tables.

Verify: uvicorn app.main:app --reload starts with no errors and GET /docs returns 200.
```

---

### Prompt 2 — Scan Agent

```
Implement the DepGuard Scan Agent. Reference skills/agents.md for the full spec.

Create backend/app/services/agents/scan_agent.py with:

async def run(scan_id: int, repo_path: str, db: Session) -> list[Alert]
  1. Read {repo_path}/package.json — extract name+version from dependencies + devDependencies
  2. POST to https://api.osv.dev/v1/querybatch with all packages (npm ecosystem)
     OSV request shape: {"queries": [{"package": {"name": "...", "ecosystem": "npm"}, "version": "..."}]}
  3. For each OSV result with vulns:
     - Create Dependency record (linked to repo + scan)
     - Create Alert record with vuln_id, severity, summary, osv_data (full JSON)
  4. Fallback: if OSV request fails or times out (5s), load backend/tests/fixtures/osv_response_lodash.json
     Log a warning when fallback is used.
  5. Return list of created Alert objects

Also create backend/tests/fixtures/ with:
  - sample_package.json: {"name": "demo-app", "dependencies": {"lodash": "4.17.4", "express": "4.17.1"}}
  - osv_response_lodash.json: a real pre-captured OSV batch response for lodash 4.17.4

Verify: running the scan agent against tests/fixtures/ creates at least 1 Alert in the DB.
```

---

### Prompt 3 — Code Agent

```
Implement the DepGuard Code Agent. Reference skills/agents.md for the spec. Keep it simple — no AST.

Create backend/app/services/agents/code_agent.py with:

async def run(scan_id: int, repo_path: str, alerts: list[Alert], db: Session) -> list[UsageLocation]
  1. Walk repo_path recursively for .js, .ts, .mjs files — skip node_modules/ and .git/
  2. For each alert, scan every file for:
     - ES module: import ... from 'package-name' or import 'package-name'
     - CommonJS: require('package-name') or require("package-name")
     - Optional symbol: for lodash specifically, also match _.merge( or _.set(
  3. For each match extract:
     - file_path (relative to repo_path)
     - line_number (1-indexed)
     - snippet: the matched line plus 1 line before and 1 line after
     - import_type: "esm" | "cjs" | "symbol"
  4. Create UsageLocation records linked to the alert
  5. Return all created UsageLocation objects

Also create backend/tests/fixtures/sample_app.js:
  A small JS file that uses lodash via require('lodash') and calls _.merge({}, userInput)
  Also include one import statement: import _ from 'lodash'
  Place this at a path like src/utils/merge.js so context agent can classify it

Verify: running code agent against fixtures finds at least 2 usage locations for lodash.
```

---

### Prompt 4 — Context Agent

```
Implement the DepGuard Context Agent. Reference skills/agents.md for the classification rules.

Create backend/app/services/agents/context_agent.py with:

async def run(usage_locations: list[UsageLocation], db: Session) -> None
  Classify each UsageLocation by file_path keywords and update context_tags (JSON array).

Classification rules (check file_path for these keywords, case-insensitive):
  - auth, login, password, session, jwt, oauth → tag: "auth", sensitivity: "HIGH_SENSITIVITY"
  - payment, checkout, billing, stripe, invoice → tag: "payment", sensitivity: "HIGH_SENSITIVITY"
  - admin, dashboard, internal → tag: "admin", sensitivity: "HIGH_SENSITIVITY"
  - api, route, middleware, handler, controller → tag: "api", sensitivity: "MEDIUM_SENSITIVITY"
  - util, helper, lib, common, shared → tag: "util", sensitivity: "LOW_SENSITIVITY"
  - test, spec, __tests__ → tag: "test", sensitivity: "LOW_SENSITIVITY"
  - If no keywords match → tag: "unknown", sensitivity: "LOW_SENSITIVITY"

context_tags should be a JSON list of all matching tags plus the sensitivity level.
Example: ["util", "LOW_SENSITIVITY"]

Update each UsageLocation.context_tags in the DB and commit.

Verify: after running context agent on sample_app.js (which is at src/utils/merge.js),
the UsageLocation should have context_tags = ["util", "LOW_SENSITIVITY"].
```

---

### Prompt 5 — Demo Seed Endpoint

```
Create the /demo/seed endpoint and wire up a basic /repos POST endpoint.

Create backend/app/routers/repos.py with:
  POST /repos — accepts {"name": str, "path": str} — creates Repository record — returns repo with id
  GET  /repos — returns list of all repositories
  GET  /repos/{id} — returns single repository or 404

Create backend/app/routers/demo.py with:
  POST /demo/seed
    - Registers a Repository pointing at the absolute path of backend/tests/fixtures/
    - If a repo with that path already exists, return the existing one
    - Returns {"repo_id": <id>, "path": "<fixtures path>", "message": "Demo repo ready"}

Register both routers in app/main.py.

Create Pydantic schemas in:
  app/schemas/repository.py — RepositoryCreate, RepositoryRead

Verify:
  POST /demo/seed returns a repo_id
  GET /repos returns that repo
  GET /repos/{id} returns the full repo object
```

---

## Done When

- [ ] `uvicorn app.main:app --reload` starts clean
- [ ] `alembic upgrade head` creates all 7 tables
- [ ] `POST /demo/seed` returns a repo_id
- [ ] Scan Agent finds lodash alert in fixture data
- [ ] Code Agent finds at least 2 usage locations in sample_app.js
- [ ] Context Agent tags usage locations with correct sensitivity
- [ ] `GET /repos` and `GET /repos/{id}` return data

Hand off to Person 2 once all checks pass.
