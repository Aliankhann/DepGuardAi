"""
Fix Agent
---------
Input:  Alert records with osv_data + repo for Backboard memory recall
Output: Remediation record per Alert

Deterministic — parses OSV fixed version and generates install commands.
Enriched with Backboard memory recall: if the repository's Backboard assistant
has seen this package remediated before, that context is prepended to the checklist.
"""

import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.dependency import Dependency
from app.models.remediation import Remediation
from app.models.repository import Repository
from app.services import backboard_service

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


async def run(alerts: list[Alert], repo: Repository, db: Session) -> None:
    for alert in alerts:
        dep = db.get(Dependency, alert.dependency_id)
        if not dep:
            continue

        safe_version = _extract_fixed_version(alert.osv_data or {})
        install_command = _build_install_command(dep.ecosystem, dep.name, safe_version)

        # Query Backboard for prior remediation context on this package/vuln
        prior_remediation = await backboard_service.recall_remediation_context(
            repo=repo,
            dep_name=dep.name,
            vuln_id=alert.vuln_id,
            db=db,
        )

        checklist = _build_checklist(dep.ecosystem, dep.name, safe_version, prior_remediation)

        remediation = Remediation(
            alert_id=alert.id,
            safe_version=safe_version,
            install_command=install_command,
            checklist=checklist,
        )
        db.add(remediation)

    db.flush()
