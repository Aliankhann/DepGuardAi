# Agent Responsibilities

## Scan Agent — `scan_agent.py`

**Input:** repo path
**Output:** list of Alert records + Dependency records

Steps:
1. Read `package.json` at `{repo_path}/package.json`
2. Extract `{name: version}` pairs from `dependencies` + `devDependencies`
3. POST to `https://api.osv.dev/v1/querybatch` with all packages
4. For each OSV match, create `Dependency` + `Alert` records linked to the `ScanRun`
5. Fallback: if OSV unreachable, load `tests/fixtures/osv_response_lodash.json`

OSV batch request shape:
```json
{
  "queries": [
    { "package": { "name": "lodash", "ecosystem": "npm" }, "version": "4.17.4" }
  ]
}
```

---

## Code Agent — `code_agent.py`

**Input:** repo path + list of Alert package names
**Output:** UsageLocation records per alert

Steps:
1. Walk repo for `.js`, `.ts`, `.mjs` files (skip `node_modules/`)
2. For each file, for each alert package name, regex-detect:
   - `import ... from 'package-name'`
   - `require('package-name')`
   - Optional: known vulnerable symbol (e.g. `_.merge`, `_.set`)
3. Extract: `file_path`, `line_number`, 3-line snippet (±1 line context)
4. Persist as `UsageLocation` records

Keep simple. No AST, no call graph for MVP.

---

## Context Agent — `context_agent.py`

**Input:** UsageLocation records
**Output:** `context_tags` field updated on each UsageLocation

Classify by file path keywords:

| Keywords in path | Tag | Sensitivity |
|-----------------|-----|-------------|
| auth, login, password, session, jwt, oauth | `auth` | HIGH |
| payment, checkout, billing, stripe, invoice | `payment` | HIGH |
| admin, dashboard, internal | `admin` | HIGH |
| api, route, middleware, handler, controller | `api` | MEDIUM |
| util, helper, lib, common, shared | `util` | LOW |
| test, spec, __tests__ | `test` | LOW |

No AI needed. Pure heuristic path/keyword matching.

---

## Risk Agent — `risk_agent.py`

**Input:** Alert + its UsageLocations + context_tags
**Output:** Analysis record

Steps:
1. Build investigation prompt (see `skills/backboard.md`)
2. Call `backboard_service.run_investigation(repo, alert, usage_locations)`
3. Parse response JSON into `Analysis` record
4. Fallback: if Backboard unavailable, create static fallback Analysis

Output format: see Claude.md AI Output section.

---

## Fix Agent — `fix_agent.py`

**Input:** Alert with its OSV data
**Output:** Remediation record

Steps:
1. Parse `alert.osv_data` for `affected[].ranges[].events` to find `fixed` version
2. Generate: `npm install {package}@{safe_version}`
3. Build checklist:
   - Upgrade `{package}` to `{safe_version}`
   - Run `npm audit` to verify
   - Review package changelog for breaking changes
   - Re-run DepGuard scan to confirm resolution
4. Persist as `Remediation` record

---

## Agent Orchestrator — `agent_orchestrator.py`

```
run_pipeline(scan_id):
  1. load ScanRun + Repo from DB
  2. scan_agent.run()        → update current_agent="scan_agent"
  3. code_agent.run()        → update current_agent="code_agent"
  4. context_agent.run()     → update current_agent="context_agent"
  5. risk_agent.run()        → update current_agent="risk_agent"
  6. fix_agent.run()         → update current_agent="fix_agent"
  7. set status="complete", alert_count, completed_at
  on exception: status="failed", error_message=str(e)
```

Each agent receives a DB session. Update `ScanRun.current_agent` before each step.
