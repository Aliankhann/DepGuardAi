"""
Agent Orchestrator
------------------
Runs the full DepGuard pipeline in order:

  scan_agent → code_agent → context_agent → risk_agent → fix_agent

Updates ScanRun.current_agent before each step so the frontend can poll progress.
On any unhandled exception, marks the scan as failed with error_message.
"""

import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.repository import Repository
from app.models.scan_run import ScanRun
from app.services.agents import (
    code_agent,
    context_agent,
    fix_agent,
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

        # ── 2. Code Agent ──────────────────────────────────────────────────
        _set_agent(scan, "analyzing", "code_agent", db)
        alert_usages = await code_agent.run(repo, alerts, db)
        db.commit()
        logger.info(f"[code_agent] Usages found for {len(alert_usages)} alerts")

        # ── 3. Context Agent ───────────────────────────────────────────────
        _set_agent(scan, "analyzing", "context_agent", db)
        await context_agent.run(alert_usages, db)
        db.commit()
        logger.info("[context_agent] Context tags applied")

        # ── 4. Risk Agent (Backboard) ──────────────────────────────────────
        _set_agent(scan, "analyzing", "risk_agent", db)
        await risk_agent.run(repo, alerts, alert_usages, db)
        db.commit()
        logger.info("[risk_agent] Risk analyses complete")

        # ── 5. Fix Agent ───────────────────────────────────────────────────
        _set_agent(scan, "analyzing", "fix_agent", db)
        await fix_agent.run(alerts, db)
        db.commit()
        logger.info("[fix_agent] Remediations generated")

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
