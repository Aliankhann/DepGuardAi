"""
Fix Agent
---------
Input:  Alert records with osv_data
Output: Remediation record per Alert

Deterministic — no AI. Parses OSV fixed version and generates install commands.
"""

import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.dependency import Dependency
from app.models.remediation import Remediation

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


def _build_checklist(ecosystem: str, name: str, safe_version: Optional[str]) -> list[str]:
    if safe_version:
        upgrade_step = f"Upgrade `{name}` to version `{safe_version}` or later"
    else:
        upgrade_step = f"Upgrade `{name}` to the latest safe version (check OSV advisory)"

    if ecosystem == "PyPI":
        audit_cmd = "`pip audit`"
    else:
        audit_cmd = "`npm audit`"

    return [
        upgrade_step,
        f"Run {audit_cmd} to verify no remaining vulnerabilities",
        "Review package changelog for breaking changes",
        "Re-run DepGuard scan to confirm resolution",
    ]


async def run(alerts: list[Alert], db: Session) -> None:
    for alert in alerts:
        dep = db.get(Dependency, alert.dependency_id)
        if not dep:
            continue

        safe_version = _extract_fixed_version(alert.osv_data or {})
        install_command = _build_install_command(dep.ecosystem, dep.name, safe_version)
        checklist = _build_checklist(dep.ecosystem, dep.name, safe_version)

        remediation = Remediation(
            alert_id=alert.id,
            safe_version=safe_version,
            install_command=install_command,
            checklist=checklist,
        )
        db.add(remediation)

    db.flush()
