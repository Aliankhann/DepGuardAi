import asyncio
import json
import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.models.alert import Alert
from app.models.repository import Repository
from app.models.usage import UsageLocation

logger = logging.getLogger(__name__)

FALLBACK_ANALYSIS = {
    "risk_level": "medium",
    "confidence": "low",
    "urgency": "planned",
    "analysis_source": "fallback",
    "reasoning": (
        "AI analysis unavailable. Package is confirmed vulnerable per OSV. "
        "Manual review required."
    ),
    "business_impact": "Unknown without AI analysis.",
    "recommended_fix": "Upgrade to the safe version listed in OSV advisory.",
}


def _get_client():
    if not settings.BACKBOARD_API_KEY:
        return None
    try:
        from backboard import BackboardClient  # type: ignore
        return BackboardClient(api_key=settings.BACKBOARD_API_KEY)
    except ImportError:
        logger.warning("backboard-sdk not installed")
        return None


async def ensure_repository_assistant(client, repo: Repository, db: Session) -> Optional[str]:
    if repo.backboard_assistant_id:
        return repo.backboard_assistant_id

    try:
        assistant = await asyncio.wait_for(
            client.create_assistant(
                name=f"depguard-{repo.name}",
                system_prompt=(
                    "You are a dependency risk investigation engine for a software security team. "
                    "Your role is to assess whether a vulnerable dependency is actually exploitable "
                    "given how and where it is used in a specific codebase — not to give generic "
                    "vulnerability descriptions. "
                    "When analyzing usage evidence, weight risk by the sensitivity of each code path: "
                    "HIGH_SENSITIVITY locations (auth, payment, crypto, secrets, execution) significantly "
                    "increase exploitability likelihood; LOW_SENSITIVITY locations (tests, utilities) "
                    "reduce it unless the vulnerability type makes location irrelevant. "
                    "You may have prior investigation context for this repository from previous scans. "
                    "Reference it when relevant (e.g. previously identified hotspots, prior remediation history). "
                    "Always respond with valid JSON matching the required output schema."
                ),
            ),
            timeout=10.0,
        )
        repo.backboard_assistant_id = str(assistant.assistant_id)
        db.commit()
        return str(assistant.assistant_id)
    except Exception as e:
        logger.warning(f"Failed to create Backboard assistant: {e}")
        return None


def _build_investigation_prompt(
    alert: Alert,
    usages: list[UsageLocation],
    dep_name: str,
    dep_version: str,
    all_vuln_ids: Optional[list[str]] = None,
) -> str:
    usage_text = "\n".join(
        f"- {u.file_path}:{u.line_number} [{', '.join(u.context_tags or [])}]\n  {u.snippet}"
        for u in usages
    )

    # List all CVE IDs covered by this analysis — one Backboard call handles all CVEs
    # for the same package version, so the AI should reason about the full scope.
    vuln_ids_section = ""
    if all_vuln_ids and len(all_vuln_ids) > 1:
        vuln_ids_section = "\nALL VULNERABILITY IDs COVERED BY THIS ANALYSIS:\n" + "\n".join(
            f"  - {vid}" for vid in all_vuln_ids
        ) + "\n"

    return f"""You are investigating a dependency vulnerability cluster. Determine exploitability in this codebase.

PACKAGE UNDER INVESTIGATION
Package: {dep_name}@{dep_version}
Representative Vulnerability: {alert.vuln_id}
Severity: {alert.severity}
Summary: {alert.summary}{vuln_ids_section}

USAGE IN CODEBASE
{usage_text if usage_text else "No direct usage found in scanned files."}

INVESTIGATION INSTRUCTIONS
1. Assess whether this vulnerability is realistically exploitable given the actual code locations above.
2. Weight your assessment by context sensitivity:
   - HIGH_SENSITIVITY tags (auth, payment, crypto, secrets, execution) → escalate risk if usage is direct
   - LOW_SENSITIVITY tags (test, util) → reduce risk unless the vuln type makes location irrelevant
   - MEDIUM_SENSITIVITY (api, data) → assess based on exposure surface
3. Determine urgency: explain why this alert deserves immediate attention vs. lower priority,
   specifically based on where in this codebase the vulnerable code is used.
4. Do NOT restate the CVE description — reason about what can actually happen in THIS codebase.

Respond ONLY with valid JSON:

{{
  "risk_level": "low | medium | high | critical",
  "confidence": "low | medium | high",
  "urgency": "immediate | this-sprint | planned | low-priority",
  "reasoning": "explanation referencing specific file paths, sensitivity levels, and why this matters in this repo",
  "business_impact": "what could realistically go wrong if exploited in this codebase",
  "recommended_fix": "specific action to remediate, including upgrade command if known"
}}"""


def _parse_risk_json(content: str) -> dict:
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Try to extract JSON block from mixed content
    try:
        start = content.find("{")
        end = content.rfind("}") + 1
        if start != -1 and end > start:
            return json.loads(content[start:end])
    except json.JSONDecodeError:
        pass

    logger.warning("Failed to parse risk JSON from Backboard response; using fallback")
    return FALLBACK_ANALYSIS


async def run_risk_analysis(
    repo: Repository,
    alert: Alert,
    usage_locations: list[UsageLocation],
    dep_name: str,
    dep_version: str,
    db: Session,
    all_vuln_ids: Optional[list[str]] = None,
) -> tuple[dict, Optional[str]]:
    """Returns (analysis_dict, thread_id). thread_id is None when fallback is used."""
    if not settings.BACKBOARD_API_KEY:
        return FALLBACK_ANALYSIS, None

    client = _get_client()
    if not client:
        return FALLBACK_ANALYSIS, None

    assistant_id = await ensure_repository_assistant(client, repo, db)
    if not assistant_id:
        return FALLBACK_ANALYSIS, None

    prompt = _build_investigation_prompt(
        alert, usage_locations, dep_name, dep_version, all_vuln_ids
    )

    try:
        thread = await asyncio.wait_for(
            client.create_thread(assistant_id),
            timeout=5.0,
        )
        # memory="Auto": Backboard auto-extracts key findings into this repository's
        # assistant memory, so future investigations on the same repo receive prior
        # context (e.g. previously identified hotspots, past remediation history).
        response = await asyncio.wait_for(
            client.add_message(
                thread_id=thread.thread_id,
                content=prompt,
                memory="Auto",
                llm_provider="anthropic",
                model_name="claude-sonnet-4-6",
            ),
            timeout=30.0,
        )
        analysis = _parse_risk_json(response.content)
        analysis["analysis_source"] = "backboard_ai"
        return analysis, str(thread.thread_id)
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Backboard analysis failed for {dep_name}: {e}")
        return FALLBACK_ANALYSIS, None
