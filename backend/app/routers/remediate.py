import json
import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import verify_token
from app.db import get_db
from app.models.alert import Alert
from app.models.dependency import Dependency
from app.models.remediation import Remediation
from app.models.repository import Repository
from app.models.scan_run import ScanRun
from app.schemas.remediation import ApplyFixResponse, FinalizeRemediationRequest, RemediationResponse
from app.services import backboard_service

router = APIRouter(tags=["remediation"], dependencies=[Depends(verify_token)])


@router.get("/alerts/{alert_id}/remediation", response_model=RemediationResponse)
async def get_remediation(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    remediation = (
        db.query(Remediation).filter(Remediation.alert_id == alert_id).first()
    )
    if not remediation:
        raise HTTPException(status_code=404, detail="Remediation not found")

    return remediation


@router.post("/alerts/{alert_id}/remediation/finalize")
async def finalize_remediation(
    alert_id: int,
    body: FinalizeRemediationRequest,
    db: Session = Depends(get_db),
):
    """
    Mode 2 — Senior Review Writeback.

    After a senior engineer reviews and approves a final fix, call this endpoint
    to store the approved solution in Backboard memory. Future scans on this
    repository will recall the professional baseline when recommending remediations
    for similar vulnerabilities.
    """
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    remediation = (
        db.query(Remediation).filter(Remediation.alert_id == alert_id).first()
    )
    if not remediation:
        raise HTTPException(status_code=404, detail="Remediation not found")

    # Resolve Repository via Alert → ScanRun → Repository
    scan = db.get(ScanRun, alert.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    repo = db.get(Repository, scan.repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    dep = db.get(Dependency, alert.dependency_id)
    dep_name = dep.name if dep else alert.vuln_id

    await backboard_service.store_senior_approved_fix(
        repo=repo,
        dep_name=dep_name,
        vuln_id=alert.vuln_id,
        safe_version=remediation.safe_version,
        agent_temp_mitigation=remediation.temporary_mitigation or "",
        agent_permanent_fix=remediation.permanent_fix_summary or "",
        senior_approved_fix=body.senior_approved_fix,
        rationale=body.rationale,
        db=db,
    )

    return {"stored": True}


@router.post("/alerts/{alert_id}/remediation/apply", response_model=ApplyFixResponse)
async def apply_fix(alert_id: int, db: Session = Depends(get_db)):
    """
    Apply Fix — directly patch the manifest file in the repository.

    For PyPI repos: updates the version pin in requirements.txt.
    For npm repos: updates the version in package.json.
    Returns the exact line that was changed so the user can review it.
    """
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    remediation = db.query(Remediation).filter(Remediation.alert_id == alert_id).first()
    if not remediation:
        raise HTTPException(status_code=404, detail="Remediation not found")

    if not remediation.safe_version:
        raise HTTPException(status_code=422, detail="No safe version available — cannot apply fix automatically")

    scan = db.get(ScanRun, alert.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    repo = db.get(Repository, scan.repo_id)
    if not repo or not repo.local_path:
        raise HTTPException(status_code=422, detail="Repository has no local_path — cannot apply fix")

    dep = db.get(Dependency, alert.dependency_id)
    if not dep:
        raise HTTPException(status_code=404, detail="Dependency not found")

    repo_root = Path(repo.local_path)
    if not repo_root.exists():
        raise HTTPException(status_code=422, detail=f"Repository path does not exist: {repo.local_path}")

    ecosystem = (dep.ecosystem or "").lower()

    # ── PyPI ────────────────────────────────────────────────────────────────
    if ecosystem == "pypi":
        manifest = repo_root / "requirements.txt"
        if not manifest.exists():
            # Try common alternate locations
            for candidate in repo_root.rglob("requirements*.txt"):
                if "node_modules" not in str(candidate):
                    manifest = candidate
                    break

        if not manifest.exists():
            return ApplyFixResponse(
                applied=False,
                file_changed=None,
                old_line=None,
                new_line=None,
                message="requirements.txt not found in repository — run the install command manually",
            )

        lines = manifest.read_text().splitlines(keepends=True)
        pkg = re.escape(dep.name)
        # Match: pkg, pkg==x, pkg>=x, pkg~=x, pkg<=x (case-insensitive)
        pattern = re.compile(rf"^({pkg})\s*(==|>=|<=|~=|!=|>|<|)\s*[^\s#]*", re.IGNORECASE)

        new_lines = []
        old_line = new_line = None
        changed = False
        for line in lines:
            m = pattern.match(line.rstrip("\n"))
            if m and not changed:
                old_line = line.rstrip("\n")
                new_line = f"{dep.name}=={remediation.safe_version}"
                # Preserve inline comment if present
                comment_match = re.search(r"\s+#.*$", line.rstrip("\n"))
                if comment_match:
                    new_line += comment_match.group(0)
                new_lines.append(new_line + "\n")
                changed = True
            else:
                new_lines.append(line)

        if not changed:
            return ApplyFixResponse(
                applied=False,
                file_changed=str(manifest.relative_to(repo_root)),
                old_line=None,
                new_line=None,
                message=f"{dep.name} not found in {manifest.name} — run the install command manually",
            )

        manifest.write_text("".join(new_lines))
        return ApplyFixResponse(
            applied=True,
            file_changed=str(manifest.relative_to(repo_root)),
            old_line=old_line,
            new_line=new_line,
            message=f"Successfully updated {dep.name} to {remediation.safe_version} in {manifest.name}",
        )

    # ── npm ─────────────────────────────────────────────────────────────────
    elif ecosystem == "npm":
        manifest = repo_root / "package.json"
        if not manifest.exists():
            return ApplyFixResponse(
                applied=False,
                file_changed=None,
                old_line=None,
                new_line=None,
                message="package.json not found in repository — run the install command manually",
            )

        try:
            pkg_data = json.loads(manifest.read_text())
        except json.JSONDecodeError:
            raise HTTPException(status_code=500, detail="Failed to parse package.json")

        dep_key = None
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            if section in pkg_data and dep.name in pkg_data[section]:
                dep_key = section
                break

        if not dep_key:
            return ApplyFixResponse(
                applied=False,
                file_changed="package.json",
                old_line=None,
                new_line=None,
                message=f"{dep.name} not found in package.json — run the install command manually",
            )

        old_version_spec = pkg_data[dep_key][dep.name]
        new_version_spec = f"^{remediation.safe_version}"
        old_line = f'"{dep.name}": "{old_version_spec}"'
        new_line = f'"{dep.name}": "{new_version_spec}"'

        pkg_data[dep_key][dep.name] = new_version_spec
        manifest.write_text(json.dumps(pkg_data, indent=2) + "\n")

        return ApplyFixResponse(
            applied=True,
            file_changed="package.json",
            old_line=old_line,
            new_line=new_line,
            message=f"Successfully updated {dep.name} to {new_version_spec} in package.json — run 'npm install' to apply",
        )

    else:
        return ApplyFixResponse(
            applied=False,
            file_changed=None,
            old_line=None,
            new_line=None,
            message=f"Auto-fix not supported for ecosystem '{ecosystem}' — run the install command manually",
        )
