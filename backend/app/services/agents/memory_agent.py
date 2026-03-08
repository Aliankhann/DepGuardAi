"""
Memory Agent
------------
Input:  Completed scan results (alerts, analyses from DB, exploitability/blast_radius/confidence results)
Output: Structured investigation summary written to Backboard assistant memory

Final pipeline step. No DB writes.

Purpose: Build a repository-specific investigation record in Backboard memory so future
scans can recall prior findings, approved remediations, and known hotspots. This is the
"memory writeback" that makes DepGuard improve with each scan.

Future scans on the same repo will receive this context via the Backboard assistant system,
enabling the AI to say: "This file was identified as a hotspot in the previous scan" or
"lodash was upgraded to 4.17.21 in a prior remediation."

The system is NOT autonomous — it builds memory to improve consistency and quality
of future human-reviewed recommendations.
"""

import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.analysis import Analysis
from app.models.dependency import Dependency
from app.models.remediation import Remediation
from app.models.repository import Repository
from app.services import backboard_service

logger = logging.getLogger(__name__)


async def run(
    scan_id: int,
    repo: Repository,
    alerts: list[Alert],
    alert_usages: dict,
    exploitability_results: dict[int, dict],
    blast_radius_results: dict[int, dict],
    db: Session,
) -> None:
    """
    Write investigation summary to Backboard memory for this repository.
    Graceful — never raises on failure, never blocks pipeline completion.
    """
    if not alerts:
        return

    try:
        summary = _build_summary(
            scan_id=scan_id,
            repo=repo,
            alerts=alerts,
            alert_usages=alert_usages,
            exploitability_results=exploitability_results,
            blast_radius_results=blast_radius_results,
            db=db,
        )
        await backboard_service.write_investigation_memory(repo=repo, summary=summary, db=db)
        logger.info(f"[memory_agent] Investigation summary written for scan {scan_id}")
    except Exception as e:
        logger.warning(f"[memory_agent] Failed to write memory for scan {scan_id}: {e}")


def _build_summary(
    scan_id: int,
    repo: Repository,
    alerts: list[Alert],
    alert_usages: dict,
    exploitability_results: dict[int, dict],
    blast_radius_results: dict[int, dict],
    db: Session,
) -> str:
    date_str = datetime.utcnow().strftime("%Y-%m-%d")

    lines = [
        f"INVESTIGATION COMPLETE — Scan #{scan_id} | Repo: {repo.name} | Date: {date_str}",
        f"Total vulnerabilities analyzed: {len(alerts)}",
        "",
        "PER-ALERT SUMMARY:",
    ]

    for alert in alerts:
        dep = db.get(Dependency, alert.dependency_id)
        dep_name = dep.name if dep else "unknown"
        dep_version = dep.version if dep else "unknown"

        expl = exploitability_results.get(alert.id, {})
        br = blast_radius_results.get(alert.id, {})
        usages = alert_usages.get(alert.id, [])

        # Load analysis from DB
        analysis = db.query(Analysis).filter(Analysis.alert_id == alert.id).first()
        remediation = db.query(Remediation).filter(Remediation.alert_id == alert.id).first()

        risk = analysis.risk_level if analysis else "unknown"
        confidence_pct = analysis.confidence_percent if analysis else None
        conf_str = f"{confidence_pct}%" if confidence_pct is not None else "n/a"
        source = analysis.analysis_source if analysis else "unknown"
        install_cmd = remediation.install_command if remediation else "n/a"

        lines.append(
            f"  [{alert.vuln_id}] {dep_name}@{dep_version} | severity={alert.severity}"
        )
        lines.append(
            f"    exploitability={expl.get('exploitability', 'unknown')} | "
            f"blast_radius={br.get('blast_radius_label', 'unknown')} | "
            f"confidence={conf_str} | risk={risk} | source={source}"
        )
        lines.append(f"    usage_files={len({u.file_path for u in usages})}")
        lines.append(f"    remediation_command={install_cmd}")

        detected = expl.get("detected_functions") or []
        if detected:
            lines.append(f"    detected_functions={detected[:3]}")

        high_paths = [
            u.file_path for u in usages
            if "HIGH_SENSITIVITY" in (u.context_tags or [])
        ]
        if high_paths:
            lines.append(f"    high_sensitivity_files={high_paths[:3]}")

    lines += [
        "",
        "END OF INVESTIGATION SUMMARY",
        "Note: This summary is stored in repository memory to improve future scan consistency.",
        "Remediations listed here have NOT been human-reviewed — treat as recommendations only.",
    ]

    return "\n".join(lines)
