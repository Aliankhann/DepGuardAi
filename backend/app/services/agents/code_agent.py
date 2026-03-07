"""
Code Agent
----------
Input:  repo path + list of Alert records
Output: UsageLocation records per alert

Walks JS/TS files (npm) or Python files (PyPI) and regex-detects import patterns.
No AST or call graph — pure text search for MVP.
"""

import logging
import re
from pathlib import Path

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.dependency import Dependency
from app.models.repository import Repository
from app.models.usage import UsageLocation

logger = logging.getLogger(__name__)

JS_EXTENSIONS = {".js", ".ts", ".mjs", ".jsx", ".tsx"}
PY_EXTENSIONS = {".py"}
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}


def _get_snippet(lines: list[str], line_idx: int) -> str:
    start = max(0, line_idx - 1)
    end = min(len(lines), line_idx + 2)
    return "\n".join(lines[start:end])


def _scan_js_file(file_path: Path, repo_root: Path, package_name: str) -> list[dict]:
    matches = []
    escaped = re.escape(package_name)
    patterns = [
        (re.compile(rf"""import\s+.*?from\s+['"]{escaped}['"]"""), "esm"),
        (re.compile(rf"""require\s*\(\s*['"]{escaped}['"]\s*\)"""), "cjs"),
        # Subpath imports e.g. 'lodash/merge'
        (re.compile(rf"""['"]{escaped}/[^'"]+['"]"""), "esm"),
    ]

    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        for i, line in enumerate(lines):
            for pattern, import_type in patterns:
                if pattern.search(line):
                    matches.append(
                        {
                            "file_path": str(file_path.relative_to(repo_root)),
                            "line_number": i + 1,
                            "snippet": _get_snippet(lines, i),
                            "import_type": import_type,
                        }
                    )
                    break
    except Exception as e:
        logger.debug(f"Could not scan {file_path}: {e}")

    return matches


def _scan_py_file(file_path: Path, repo_root: Path, package_name: str) -> list[dict]:
    matches = []
    norm = package_name.replace("-", "_").lower()
    candidates = {norm, package_name}

    patterns = []
    for name in candidates:
        escaped = re.escape(name)
        patterns.append((re.compile(rf"^import\s+{escaped}"), "python"))
        patterns.append((re.compile(rf"^from\s+{escaped}"), "python"))

    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            for pattern, import_type in patterns:
                if pattern.search(stripped):
                    matches.append(
                        {
                            "file_path": str(file_path.relative_to(repo_root)),
                            "line_number": i + 1,
                            "snippet": _get_snippet(lines, i),
                            "import_type": import_type,
                        }
                    )
                    break
    except Exception as e:
        logger.debug(f"Could not scan {file_path}: {e}")

    return matches


def _walk_repo(repo_path: Path, extensions: set) -> list[Path]:
    files = []
    for f in repo_path.rglob("*"):
        if any(skip in f.parts for skip in SKIP_DIRS):
            continue
        if f.suffix in extensions:
            files.append(f)
    return files


async def run(
    repo: Repository,
    alerts: list[Alert],
    db: Session,
) -> dict[int, list[UsageLocation]]:
    repo_path = Path(repo.local_path) if repo.local_path else None

    if not repo_path or not repo_path.exists():
        return {}

    dep_cache: dict[int, Dependency] = {}
    file_cache: dict[str, list[Path]] = {}  # walk once per ecosystem
    alert_usages: dict[int, list[UsageLocation]] = {}

    for alert in alerts:
        dep = dep_cache.get(alert.dependency_id)
        if not dep:
            dep = db.get(Dependency, alert.dependency_id)
            if not dep:
                continue
            dep_cache[alert.dependency_id] = dep

        if dep.ecosystem == "PyPI":
            if "PyPI" not in file_cache:
                file_cache["PyPI"] = _walk_repo(repo_path, PY_EXTENSIONS)
            files = file_cache["PyPI"]
            scan_fn = _scan_py_file
        else:
            if "npm" not in file_cache:
                file_cache["npm"] = _walk_repo(repo_path, JS_EXTENSIONS)
            files = file_cache["npm"]
            scan_fn = _scan_js_file

        usages: list[UsageLocation] = []
        for file_path in files:
            for match in scan_fn(file_path, repo_path, dep.name):
                usage = UsageLocation(
                    alert_id=alert.id,
                    file_path=match["file_path"],
                    line_number=match["line_number"],
                    snippet=match["snippet"],
                    import_type=match["import_type"],
                    context_tags=[],
                )
                db.add(usage)
                usages.append(usage)

        db.flush()
        alert_usages[alert.id] = usages

    return alert_usages
