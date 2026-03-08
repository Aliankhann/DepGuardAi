"""
Fix Agent (Remediation Memory Agent)
-------------------------------------
Input:  Alert records + upstream agent results + Backboard memory
Output: Remediation record per Alert

Two-phase execution:

Phase 1 — Deterministic (always runs, no I/O):
  - Extract safe_version from OSV data
  - Build install_command
  - Build base checklist

Phase 2 — Backboard AI (Mode 1 — concurrent, graceful fallback):
  - All alerts run concurrently via asyncio.gather (same pattern as risk_agent)
  - Recall prior senior-reviewed fix from Backboard memory
  - Send full upstream evidence (exploitability, blast_radius, confidence) to Backboard
  - Receive structured: temporary_mitigation, permanent_fix_summary,
    review_note, senior_review_urgency
  - Falls back to conservative deterministic values on any failure

Mode 2 (Senior Review Writeback) is handled via the POST /alerts/{id}/remediation/finalize
API endpoint and backboard_service.store_senior_approved_fix() — not in this file.
"""

import asyncio
import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.analysis import Analysis
from app.models.dependency import Dependency
from app.models.remediation import Remediation
from app.models.repository import Repository
from app.services import backboard_service
from app.services.backboard_service import FALLBACK_REMEDIATION

logger = logging.getLogger(__name__)


def _extract_fixed_version(osv_data: dict) -> Optional[str]:
    for affected in osv_data.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    return fixed
    return None


def _build_install_command(ecosystem: str, name: str, safe_version: Optional[str]) -> str:
    if ecosystem == "PyPI":
        return (
            f"pip install {name}=={safe_version}"
            if safe_version
            else f"pip install --upgrade {name}"
        )
    return (
        f"npm install {name}@{safe_version}"
        if safe_version
        else f"npm install {name}@latest"
    )


def _build_checklist(
    ecosystem: str,
    name: str,
    safe_version: Optional[str],
    prior_remediation: Optional[str] = None,
) -> list[str]:
    if safe_version:
        upgrade_step = f"Upgrade `{name}` to version `{safe_version}` or later"
    else:
        upgrade_step = f"Upgrade `{name}` to the latest safe version (check OSV advisory)"

    audit_cmd = "`pip audit`" if ecosystem == "PyPI" else "`npm audit`"

    checklist = []

    if prior_remediation:
        checklist.append(f"Prior remediation context: {prior_remediation}")

    checklist += [
        upgrade_step,
        f"Run {audit_cmd} to verify no remaining vulnerabilities",
        "Review package changelog for breaking changes",
        "Re-run DepGuard scan to confirm resolution",
    ]

    return checklist


async def _remediate_alert(
    alert: Alert,
    dep: Dependency,
    repo: Repository,
    db: Session,
    exploitability_results: dict[int, dict],
    blast_radius_results: dict[int, dict],
) -> Remediation:
    """Run Phase 1 + Phase 2 for a single alert. Called concurrently across all alerts."""
    # ── Phase 1: Deterministic ──────────────────────────────────────────────
    safe_version = _extract_fixed_version(alert.osv_data or {})
    install_command = _build_install_command(dep.ecosystem, dep.name, safe_version)

    prior_remediation = await backboard_service.recall_remediation_context(
        repo=repo,
        dep_name=dep.name,
        vuln_id=alert.vuln_id,
        db=db,
    )

    checklist = _build_checklist(dep.ecosystem, dep.name, safe_version, prior_remediation)

    # ── Phase 2: Backboard AI ───────────────────────────────────────────────
    expl_result = exploitability_results.get(alert.id)
    br_result = blast_radius_results.get(alert.id)

    conf_result: Optional[dict] = None
    analysis = db.query(Analysis).filter(Analysis.alert_id == alert.id).first()
    if analysis:
        conf_result = {
            "confidence": analysis.confidence,
            "confidence_percent": analysis.confidence_percent,
            "confidence_reasons": analysis.confidence_reasons,
        }

    try:
        ai_remediation = await backboard_service.run_remediation_analysis(
            repo=repo,
            alert=alert,
            dep_name=dep.name,
            dep_version=dep.version,
            ecosystem=dep.ecosystem,
            safe_version=safe_version,
            exploitability_result=expl_result,
            blast_radius_result=br_result,
            confidence_result=conf_result,
            prior_senior_fix=prior_remediation,
            db=db,
        )
    except Exception as e:
        logger.warning(f"[fix_agent] Remediation AI call failed for alert {alert.id}: {e}")
        ai_remediation = dict(FALLBACK_REMEDIATION)

    return Remediation(
        alert_id=alert.id,
        safe_version=safe_version,
        install_command=install_command,
        checklist=checklist,
        temporary_mitigation=ai_remediation.get("temporary_mitigation"),
        permanent_fix_summary=ai_remediation.get("permanent_fix_summary"),
        review_note=ai_remediation.get("review_note"),
        senior_review_urgency=ai_remediation.get("senior_review_urgency"),
    )


async def run(
    alerts: list[Alert],
    repo: Repository,
    db: Session,
    exploitability_results: dict[int, dict] | None = None,
    blast_radius_results: dict[int, dict] | None = None,
) -> None:
    exploitability_results = exploitability_results or {}
    blast_radius_results = blast_radius_results or {}

    # Resolve deps eagerly — DB access must stay on the calling thread
    alert_dep_pairs: list[tuple[Alert, Dependency]] = []
    for alert in alerts:
        dep = db.get(Dependency, alert.dependency_id)
        if dep:
            alert_dep_pairs.append((alert, dep))

    # Run all alerts concurrently — matches risk_agent's asyncio.gather pattern
    results = await asyncio.gather(
        *[
            _remediate_alert(alert, dep, repo, db, exploitability_results, blast_radius_results)
            for alert, dep in alert_dep_pairs
        ],
        return_exceptions=True,
    )

    for i, result in enumerate(results):
        if isinstance(result, Exception):
            alert, dep = alert_dep_pairs[i]
            logger.warning(
                f"[fix_agent] _remediate_alert failed for alert {alert.id} "
                f"({dep.name}): {result} — skipping remediation record"
            )
        else:
            db.add(result)

    db.flush()
