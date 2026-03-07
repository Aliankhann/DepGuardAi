# CLAUDE.md

## Project Overview

DepGuard is a memory-backed multi-agent AI system for dependency security analysis.
It investigates vulnerabilities and determines whether they pose real exploit risk in a codebase.
Unlike traditional scanners, DepGuard runs a full investigation pipeline powered by Backboard AI.

See `skills/` for detailed references on agents, Backboard, schema, and dev workflow.


## Pipeline

Scan Agent → Code Agent → Context Agent → Risk Agent (Backboard) → Fix Agent


## Infrastructure

| Layer    | Stack |
|----------|-------|
| Frontend | React, Vite, TypeScript, Tailwind, react-router-dom |
| Backend  | Python 3.12+, FastAPI, SQLAlchemy, SQLite, Alembic, httpx, python-dotenv |
| AI       | Backboard AI — model: `claude-sonnet-4-6` |
| Data     | OSV.dev (free, no API key) |


## Environment Variables

```
BACKBOARD_API_KEY=
DATABASE_URL=sqlite:///./depguard.db
CORS_ORIGINS=http://localhost:5173
```


## Project Structure

```
backend/app/
  main.py  config.py  db.py
  routers/   repos.py  scan.py  alerts.py  remediate.py
  services/
    agents/  scan_agent.py  code_agent.py  context_agent.py  risk_agent.py  fix_agent.py
    agent_orchestrator.py  backboard_service.py
  models/    repository.py  scan_run.py  dependency.py  alert.py  usage.py  analysis.py  remediation.py
  schemas/   repository.py  scan.py  alert.py  remediation.py

frontend/src/
  pages/     Dashboard.tsx  RepoDetail.tsx  AlertDetail.tsx
  hooks/     useRepos.ts  useAlerts.ts  useScan.ts
  components/  DependencyTable.tsx  ThreatFeed.tsx  AlertDetails.tsx  AnalysisPanel.tsx  RemediationCard.tsx
  types/     api.ts
```


## Models

`Repository` · `ScanRun` · `Dependency` · `Alert` · `UsageLocation` · `Analysis` · `Remediation`

**ScanRun status:** `pending → scanning → analyzing → complete | failed`
Fields: `id, repo_id, status, current_agent, alert_count, started_at, completed_at, error_message`


## API Endpoints

```
POST /repos          GET /repos           GET /repos/{id}
POST /repos/{id}/scan
GET  /repos/{id}/scans    GET /scans/{id}/status
GET  /repos/{id}/alerts   GET /alerts/{id}   GET /alerts/{id}/remediation
POST /demo/seed
```


## Backboard Memory Model

- One **Assistant** per repository (holds cumulative investigation memory)
- One **Thread** per scan run
- All messages use `memory="Auto"` — Backboard auto-extracts findings
- Store `backboard_assistant_id` on Repository

See `skills/backboard.md` for integration patterns and prompt structure.


## AI Output — Risk Agent JSON

```json
{
  "risk_level": "low | medium | high | critical",
  "confidence": "low | medium | high",
  "reasoning": "...",
  "business_impact": "...",
  "recommended_fix": "..."
}
```


## Coding Guidelines

- FastAPI + Pydantic + SQLAlchemy ORM + async IO
- Explicit typing, small modular services, deterministic outputs
- AI calls only in `risk_agent.py` via `backboard_service.py`
- No mixed agent responsibilities


## Design Principles

1. Evidence before AI reasoning — code snippets must come first
2. AI outputs must reference actual file paths and snippets
3. Memory accumulates — future scans on same repo get richer context
4. Agents stay modular and independently testable


## Skills Reference

| Skill file | Purpose |
|------------|---------|
| `skills/agents.md` | Agent responsibilities and I/O contracts |
| `skills/backboard.md` | Backboard API patterns, fallback handling |
| `skills/schema.md` | Full database schema with field definitions |
| `skills/dev-workflow.md` | Dev commands, pipeline test procedure |
