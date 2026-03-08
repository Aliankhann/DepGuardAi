"""
Context Agent
-------------
Input:  UsageLocation records (already persisted)
Output: context_tags field updated on each UsageLocation

Path-based heuristic sensitivity classification — not static analysis.
Tags are evidence for the AI risk agent, not definitive security verdicts.
Classification is based solely on file path keywords; it cannot reason about
runtime behavior, call graphs, or conditional usage.
"""

from sqlalchemy.orm import Session

from app.models.usage import UsageLocation

# Rules are ordered by descending sensitivity priority.
# Each entry: (path_keywords, tag_name, sensitivity_level)
# The first matching HIGH_SENSITIVITY rule wins; LOW_SENSITIVITY tags are
# suppressed if any HIGH_SENSITIVITY match is found (conflict resolution).
CONTEXT_RULES: list[tuple[list[str], str, str]] = [
    # HIGH_SENSITIVITY — security-critical code paths
    (["auth", "login", "password", "session", "jwt", "oauth"], "auth", "HIGH_SENSITIVITY"),
    (["payment", "checkout", "billing", "stripe", "invoice"], "payment", "HIGH_SENSITIVITY"),
    (["admin", "dashboard", "internal"], "admin", "HIGH_SENSITIVITY"),
    (["crypto", "cipher", "encrypt", "decrypt", "hmac", "rsa", "aes", "sign"], "crypto", "HIGH_SENSITIVITY"),
    (["secret", "credential", "token", "apikey", "api_key", "private_key", "cert"], "secrets", "HIGH_SENSITIVITY"),
    (["exec", "spawn", "shell", "subprocess", "eval", "process"], "execution", "HIGH_SENSITIVITY"),
    # MEDIUM_SENSITIVITY — important but not directly security-critical
    (["api", "route", "middleware", "handler", "controller"], "api", "MEDIUM_SENSITIVITY"),
    (["db", "database", "query", "sql", "orm", "migration", "store", "cache"], "data", "MEDIUM_SENSITIVITY"),
    # LOW_SENSITIVITY — utility, test, or shared code
    (["util", "helper", "lib", "common", "shared"], "util", "LOW_SENSITIVITY"),
    (["test", "spec", "__tests__", "_test"], "test", "LOW_SENSITIVITY"),
]

_SENSITIVITY_ORDER = {"HIGH_SENSITIVITY": 2, "MEDIUM_SENSITIVITY": 1, "LOW_SENSITIVITY": 0}


def _classify(file_path: str) -> list[str]:
    path_lower = file_path.lower()
    matched: list[tuple[str, str]] = []  # (tag, sensitivity) pairs

    for keywords, tag, sensitivity in CONTEXT_RULES:
        if any(kw in path_lower for kw in keywords):
            matched.append((tag, sensitivity))

    if not matched:
        # Unknown path — treat conservatively as low sensitivity
        return ["unclassified", "LOW_SENSITIVITY"]

    # Conflict resolution: determine highest sensitivity found
    max_sensitivity = max(matched, key=lambda x: _SENSITIVITY_ORDER[x[1]])[1]

    # Keep only tags at or above the highest sensitivity level found.
    # Prevents a file like auth_helpers.js from carrying both HIGH and LOW tags.
    filtered = [(tag, sens) for tag, sens in matched if _SENSITIVITY_ORDER[sens] >= _SENSITIVITY_ORDER[max_sensitivity]]

    tags: list[str] = []
    for tag, sensitivity in filtered:
        tags.append(tag)
        tags.append(sensitivity)
    return tags


async def run(
    alert_usages: dict[int, list[UsageLocation]],
    db: Session,
) -> None:
    for usages in alert_usages.values():
        for usage in usages:
            usage.context_tags = _classify(usage.file_path)
    db.flush()
