"""
Agent Orchestrator
------------------
Runs the full DepGuard pipeline in order (per Claude_Logic_Check.md §2):

  scan_agent → depvuln_agent → code_agent → context_agent → exploitability_agent
  → blast_radius_agent → risk_agent (+ confidence_agent inside)
  → fix_agent → memory_agent

Updates ScanRun.current_agent before each step so the frontend can poll progress.
On any unhandled exception, marks the scan as failed with error_message.

Notes:
- depvuln_agent: Backboard call per package, writes to alert.dependency_investigation in DB
- exploitability_agent, blast_radius_agent: pure computation, no DB writes
- confidence_agent: called inside risk_agent._analyze_package() after Backboard call
- memory_agent: final writeback to Backboard — never raises, never blocks completion
"""

import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.repository import Repository
from app.models.scan_run import ScanRun
from app.services.agents import (
    blast_radius_agent,
    code_agent,
    context_agent,
    depvuln_agent,
    exploitability_agent,
    fix_agent,
    memory_agent,
    risk_agent,
    scan_agent,
)

logger = logging.getLogger(__name__)


def _set_agent(scan: ScanRun, status: str, agent: str | None, db: Session) -> None:
    scan.status = status
    scan.current_agent = agent
    db.commit()


async def run_pipeline(scan_id: int, db: Session) -> ScanRun:
    scan = db.get(ScanRun, scan_id)
    if not scan:
        raise ValueError(f"ScanRun {scan_id} not found")

    repo = db.get(Repository, scan.repo_id)
    if not repo:
        raise ValueError(f"Repository {scan.repo_id} not found")

    try:
        # ── 1. Scan Agent ──────────────────────────────────────────────────
        _set_agent(scan, "scanning", "scan_agent", db)
        alerts = await scan_agent.run(scan, repo, db)
        db.commit()
        logger.info(f"[scan_agent] {len(alerts)} vulnerabilities found")

        if not alerts:
            scan.status = "complete"
            scan.current_agent = None
            scan.alert_count = 0
            scan.completed_at = datetime.utcnow()
            db.commit()
            return scan

        # ── 2. Dependency/Vulnerability Agent ──────────────────────────────
        # AI reasoning over OSV data — normalizes vulnerability intelligence.
        # Writes dependency_investigation to each Alert in DB.
        # dep_investigations passed forward to exploitability_agent for richer pattern matching.
        _set_agent(scan, "analyzing", "depvuln_agent", db)
        dep_investigations = await depvuln_agent.run(alerts, repo, db)
        db.commit()
        logger.info(f"[depvuln_agent] Analyzed {len(dep_investigations)} packages")

        # ── 3. Code Agent ──────────────────────────────────────────────────
        _set_agent(scan, "analyzing", "code_agent", db)
        alert_usages = await code_agent.run(repo, alerts, db)
        db.commit()
        logger.info(f"[code_agent] Usages found for {len(alert_usages)} alerts")

        # ── 4. Context Agent ───────────────────────────────────────────────
        _set_agent(scan, "analyzing", "context_agent", db)
        await context_agent.run(alert_usages, repo, db)
        db.commit()
        logger.info("[context_agent] Context tags applied")

        # ── 5. Exploitability Agent ────────────────────────────────────────
        # Phase 1 (deterministic): pattern matching + sensitivity scoring.
        # Phase 2 (Backboard): confirms vulnerable_behavior_match per alert.
        # No DB writes — results passed forward.
        _set_agent(scan, "analyzing", "exploitability_agent", db)
        exploitability_results = await exploitability_agent.run(
            alerts, alert_usages, dep_investigations=dep_investigations,
            repo=repo, db=db,
        )
        logger.info(f"[exploitability_agent] Pre-assessed {len(exploitability_results)} alerts")

        # ── 6. Blast Radius Agent ──────────────────────────────────────────
        # Deterministic: estimates impact scope (isolated / module / subsystem).
        # No DB writes — results passed forward.
        _set_agent(scan, "analyzing", "blast_radius_agent", db)
        blast_radius_results = await blast_radius_agent.run(
            alerts, alert_usages,
            exploitability_results=exploitability_results,
            repo=repo,
            db=db,
        )
        logger.info(f"[blast_radius_agent] Blast radius estimated for {len(blast_radius_results)} alerts")

        # ── 7. Risk Agent (Backboard) ──────────────────────────────────────
        # AI reasoning grounded in exploitability + blast_radius evidence.
        # confidence_agent.compute() is called inside risk_agent per-alert.
        _set_agent(scan, "analyzing", "risk_agent", db)
        await risk_agent.run(repo, alerts, alert_usages, exploitability_results, blast_radius_results, db)
        db.commit()
        logger.info("[risk_agent] Risk analyses complete")

        # ── 8. Fix Agent ───────────────────────────────────────────────────
        _set_agent(scan, "analyzing", "fix_agent", db)
        await fix_agent.run(
            alerts, repo, db,
            exploitability_results=exploitability_results,
            blast_radius_results=blast_radius_results,
        )
        db.commit()
        logger.info("[fix_agent] Remediations generated")

        # ── 9. Memory Agent ────────────────────────────────────────────────
        # Writes investigation summary to Backboard for future scan recall.
        _set_agent(scan, "analyzing", "memory_agent", db)
        await memory_agent.run(
            scan_id=scan.id,
            repo=repo,
            alerts=alerts,
            alert_usages=alert_usages,
            exploitability_results=exploitability_results,
            blast_radius_results=blast_radius_results,
            db=db,
        )
        logger.info("[memory_agent] Investigation memory written")

        # ── Done ───────────────────────────────────────────────────────────
        scan.status = "complete"
        scan.current_agent = None
        scan.alert_count = len(alerts)
        scan.completed_at = datetime.utcnow()
        db.commit()

    except Exception as exc:
        logger.error(f"Pipeline failed for scan {scan_id}: {exc}", exc_info=True)
        scan.status = "failed"
        scan.error_message = str(exc)
        scan.completed_at = datetime.utcnow()
        db.commit()

    return scan
