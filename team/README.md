# DepGuard — Team Task Division

## Who Does What

| Person | Owns | Start When |
|--------|------|-----------|
| Person 1 | Backend scaffolding + Scan/Code/Context agents + fixtures | Immediately |
| Person 2 | Backboard + Risk/Fix agents + orchestrator + all API routes | After Person 1 is done |
| Person 3 | Frontend shell (start now) → wire to API (after Person 2) | Shell: now. Wiring: after Person 2 |

## Dependency Order

```
Person 1 ──→ Person 2 ──→ (Person 3 wiring)
                             ↑
Person 3 shell (independent, starts immediately)
```

Person 3 can build the static shell and layouts in parallel with Person 1.
Person 3 should not wire real API calls until Person 2 is done.

## How to Use These Files

Each person file contains numbered Claude Code prompts.
Paste each prompt directly into Claude Code, one at a time, in order.
Wait for each prompt to finish and verify before moving to the next.

## Handoff Checkpoints

**Person 1 → Person 2 handoff:**
- `alembic upgrade head` creates all 7 tables with no errors
- `POST /demo/seed` returns a repo_id
- Scan Agent, Code Agent, Context Agent all produce DB records from fixture data

**Person 2 → Person 3 (wiring) handoff:**
- Full pipeline runs: POST /repos/1/scan → status="complete" with all records
- `GET /repos/1/alerts` returns lodash alert
- `GET /alerts/1` returns full detail with analysis + remediation

## Reference Files

| File | When to read |
|------|-------------|
| `Claude.md` | Always — project overview and conventions |
| `skills/agents.md` | When implementing any agent |
| `skills/backboard.md` | Person 2 — Backboard SDK patterns |
| `skills/schema.md` | Exact model fields and relationships |
| `skills/dev-workflow.md` | Setup, commands, test procedures |
