# Person 2 — AI Layer + API

## Your Responsibility

You own the intelligence layer — Backboard integration, risk analysis, fix generation, the agent orchestrator that chains everything together, and all the API routes that expose the results.

---

## What You Build

- Backboard service — assistant-per-repo memory model, investigation prompt, fallback
- Risk Agent — sends investigation context to Backboard, parses JSON response
- Fix Agent — extracts safe version from OSV data, generates remediation
- Agent Orchestrator — chains all 5 agents, manages ScanRun lifecycle
- All API routes — scan trigger, status polling, alerts, remediation
- ScanRun schema + scan router

---

## Depends On

**Person 1 must finish first.** You need:
- All SQLAlchemy models (`Repository`, `ScanRun`, `Alert`, `UsageLocation`, `Analysis`, `Remediation`)
- `app/db.py` with `get_db` and `SessionLocal`
- `app/config.py` with `settings.BACKBOARD_API_KEY`
- `app/services/agents/scan_agent.py`, `code_agent.py`, `context_agent.py`
- `tests/fixtures/` with sample data

---

## Blocks

Person 3 needs `GET /repos/{id}/alerts`, `GET /alerts/{id}`, `GET /scans/{id}/status` to wire their UI.

---

## Claude Code Prompts — Paste These In Order

### Prompt 1 — Backboard Service

```
Implement the Backboard service for DepGuard. Reference skills/backboard.md for the full spec.

Create backend/app/services/backboard_service.py

pip install backboard-sdk first if not in requirements.txt.

Implement:

async def get_or_create_assistant(repo: Repository, db: Session) -> str
  - If repo.backboard_assistant_id is set, return it
  - Otherwise create a Backboard assistant:
      name: f"depguard-{repo.name}"
      model: "claude-sonnet-4-6"
      system_prompt: "You are a security analyst investigating software dependency vulnerabilities.
        You reason about real-world exploitability based on how the vulnerable code is actually used.
        Always respond with valid JSON matching the required output schema."
  - Save assistant_id to repo.backboard_assistant_id, commit, return it

async def run_investigation(repo, alert, usage_locations, db) -> dict
  - Call get_or_create_assistant
  - Create a new thread: client.create_thread(assistant_id)
  - Build prompt using build_investigation_prompt(alert, usage_locations)
  - Send with memory="Auto" and a 10s timeout
  - Parse response content as JSON and return it
  - On ANY exception (timeout, parse error, API error): return FALLBACK_ANALYSIS and log warning
    Set backboard_thread_id to None when fallback is used.

FALLBACK_ANALYSIS = {
  "risk_level": "medium",
  "confidence": "low",
  "reasoning": "AI analysis unavailable. Package confirmed vulnerable per OSV. Manual review required.",
  "business_impact": "Unknown without AI analysis.",
  "recommended_fix": "Upgrade to the safe version listed in the OSV advisory."
}

def build_investigation_prompt(alert, usages) -> str
  Include: vuln_id, package name+version, severity, summary, and for each usage: file_path:line_number,
  context_tags, and code snippet. End with instruction to respond as JSON with keys:
  risk_level, confidence, reasoning, business_impact, recommended_fix.

Verify: calling run_investigation with fixture data returns a dict with all 5 required keys.
```

---

### Prompt 2 — Risk Agent

```
Implement the DepGuard Risk Agent. Reference skills/agents.md.

Create backend/app/services/agents/risk_agent.py with:

async def run(scan_id: int, alerts: list[Alert], db: Session) -> list[Analysis]
  For each alert:
    1. Load its UsageLocation records from DB (alert.id)
    2. Call backboard_service.run_investigation(repo, alert, usage_locations, db)
    3. Create Analysis record:
       - alert_id, risk_level, confidence, reasoning, business_impact, recommended_fix
       - backboard_thread_id: from response if available, else None
       - created_at: now
    4. Persist and append to results
  Return list of Analysis objects.

The repo object comes from alert.repo_id — load it from DB.
Import and use backboard_service from app/services/backboard_service.py.

Verify: running risk_agent with a fixture alert (lodash) creates 1 Analysis record in the DB.
If BACKBOARD_API_KEY is invalid, the fallback analysis should be used and the test still passes.
```

---

### Prompt 3 — Fix Agent

```
Implement the DepGuard Fix Agent. Reference skills/agents.md.

Create backend/app/services/agents/fix_agent.py with:

async def run(alerts: list[Alert], db: Session) -> list[Remediation]
  For each alert:
    1. Parse alert.osv_data to find the fixed version:
       Look in: osv_data["affected"][*]["ranges"][*]["events"] for {"fixed": "x.y.z"}
       Take the highest fixed version if multiple exist.
       If no fixed version found, set safe_version = None.
    2. Generate install_command:
       If safe_version: f"npm install {alert.dependency.name}@{safe_version}"
       Else: f"npm install {alert.dependency.name}@latest  # verify manually"
    3. Build checklist (list of strings):
       - f"Upgrade {alert.dependency.name} to {safe_version or 'latest safe version'}"
       - "Run npm audit to verify no remaining vulnerabilities"
       - "Review package changelog for breaking changes before upgrading"
       - "Re-run DepGuard scan to confirm resolution"
    4. Create Remediation record and persist
  Return list of Remediation objects.

Load the dependency from alert.dependency_id to get the package name.

Verify: running fix_agent on lodash alert creates a Remediation with:
  safe_version set (should be 4.17.21 for CVE-2021-23337)
  install_command = "npm install lodash@4.17.21"
  checklist has 4 items
```

---

### Prompt 4 — Agent Orchestrator

```
Implement the DepGuard Agent Orchestrator. Reference skills/agents.md for the pipeline flow.

Create backend/app/services/agent_orchestrator.py with:

async def run_pipeline(scan_id: int, repo_path: str, db: Session) -> None
  This is the main pipeline function. It runs all 5 agents in sequence.

  Load ScanRun and Repository from DB. If not found, log error and return.

  Wrap the entire pipeline in try/except:

  Step 1: Update ScanRun: status="scanning", current_agent="scan_agent"
          alerts = await scan_agent.run(scan_id, repo_path, db)

  Step 2: Update ScanRun: current_agent="code_agent"
          usage_locations = await code_agent.run(scan_id, repo_path, alerts, db)

  Step 3: Update ScanRun: current_agent="context_agent"
          await context_agent.run(usage_locations, db)

  Step 4: Update ScanRun: status="analyzing", current_agent="risk_agent"
          analyses = await risk_agent.run(scan_id, alerts, db)

  Step 5: Update ScanRun: current_agent="fix_agent"
          remediations = await fix_agent.run(alerts, db)

  On success: status="complete", alert_count=len(alerts), completed_at=now(), current_agent=None
  On exception: status="failed", error_message=str(e), completed_at=now()

  Commit after each status update so GET /scans/{id}/status always reflects current progress.

Verify: calling run_pipeline with scan_id pointing at fixture data completes with status="complete"
and all records (Alert, UsageLocation, Analysis, Remediation) exist in the DB.
```

---

### Prompt 5 — All API Routes

```
Implement all remaining DepGuard API routes. Reference Claude.md for the endpoint list.

Create backend/app/schemas/scan.py — ScanRunRead with all ScanRun fields
Create backend/app/schemas/alert.py — AlertRead, AlertDetailRead (includes UsageLocations + Analysis + Remediation)
Create backend/app/schemas/remediation.py — RemediationRead

Create backend/app/routers/scan.py:
  POST /repos/{repo_id}/scan
    - Create ScanRun with status="pending"
    - Add run_pipeline(scan_id, repo.path, db) as a BackgroundTask
    - Return {"scan_id": scan.id, "status": "pending"}

  GET /repos/{repo_id}/scans
    - Return list of ScanRun records for the repo, ordered by started_at desc

  GET /scans/{scan_id}/status
    - Return ScanRun fields: id, status, current_agent, alert_count, started_at, completed_at, error_message

Create backend/app/routers/alerts.py:
  GET /repos/{repo_id}/alerts
    - Return all alerts for the repo's most recent completed scan
    - Include: vuln_id, severity, summary, dependency name+version, usage_location count

  GET /alerts/{alert_id}
    - Return full alert detail: vuln_id, severity, summary, osv_data,
      usage_locations (with file_path, line_number, snippet, context_tags),
      analysis (risk_level, confidence, reasoning, business_impact, recommended_fix),
      remediation (safe_version, install_command, checklist)

Create backend/app/routers/remediate.py:
  GET /alerts/{alert_id}/remediation
    - Return Remediation record for alert or 404

Register all routers in app/main.py.

Verify all routes return expected shapes using GET http://localhost:8000/docs
```

---

## Done When

- [ ] `POST /repos/{id}/scan` creates a ScanRun and triggers background pipeline
- [ ] `GET /scans/{id}/status` shows live progress (current_agent updates)
- [ ] Full pipeline completes: all 5 agents run, ScanRun status = "complete"
- [ ] `GET /repos/{id}/alerts` returns lodash alert
- [ ] `GET /alerts/{id}` returns alert + usage locations + analysis + remediation
- [ ] `GET /alerts/{id}/remediation` returns safe version + install command
- [ ] Backboard fallback works when API key is invalid (pipeline doesn't crash)

Hand off to Person 3 once all checks pass.
