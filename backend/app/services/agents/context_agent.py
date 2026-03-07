"""
Context Agent
-------------
Input:  UsageLocation records (already persisted)
Output: context_tags field updated on each UsageLocation

Pure heuristic path/keyword matching — no AI needed.
"""

from sqlalchemy.orm import Session

from app.models.usage import UsageLocation

# (keywords_in_path, tag, sensitivity)
CONTEXT_RULES: list[tuple[list[str], str, str]] = [
    (["auth", "login", "password", "session", "jwt", "oauth"], "auth", "HIGH_SENSITIVITY"),
    (["payment", "checkout", "billing", "stripe", "invoice"], "payment", "HIGH_SENSITIVITY"),
    (["admin", "dashboard", "internal"], "admin", "HIGH_SENSITIVITY"),
    (["api", "route", "middleware", "handler", "controller"], "api", "MEDIUM_SENSITIVITY"),
    (["util", "helper", "lib", "common", "shared"], "util", "LOW_SENSITIVITY"),
    (["test", "spec", "__tests__", "_test"], "test", "LOW_SENSITIVITY"),
]


def _classify(file_path: str) -> list[str]:
    path_lower = file_path.lower()
    tags: list[str] = []
    for keywords, tag, sensitivity in CONTEXT_RULES:
        if any(kw in path_lower for kw in keywords):
            tags.append(tag)
            tags.append(sensitivity)
    return tags if tags else ["unknown", "MEDIUM_SENSITIVITY"]


async def run(
    alert_usages: dict[int, list[UsageLocation]],
    db: Session,
) -> None:
    for usages in alert_usages.values():
        for usage in usages:
            usage.context_tags = _classify(usage.file_path)
    db.flush()
