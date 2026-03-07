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
                model="claude-sonnet-4-6",
                system_prompt=(
                    "You are a security analyst investigating software dependency vulnerabilities. "
                    "You reason about real-world exploitability based on how vulnerable code is actually used. "
                    "Always respond with valid JSON matching the required output schema."
                ),
            ),
            timeout=10.0,
        )
        repo.backboard_assistant_id = assistant.assistant_id
        db.commit()
        return assistant.assistant_id
    except Exception as e:
        logger.warning(f"Failed to create Backboard assistant: {e}")
        return None


def _build_investigation_prompt(
    alert: Alert,
    usages: list[UsageLocation],
    dep_name: str,
    dep_version: str,
) -> str:
    usage_text = "\n".join(
        f"- {u.file_path}:{u.line_number} [{', '.join(u.context_tags or [])}]\n  {u.snippet}"
        for u in usages
    )

    return f"""You are investigating a dependency vulnerability. Determine if it is exploitable in this codebase.

VULNERABILITY
ID: {alert.vuln_id}
Package: {dep_name}@{dep_version}
Severity: {alert.severity}
Summary: {alert.summary}

USAGE IN CODEBASE
{usage_text if usage_text else "No direct usage found in scanned files."}

TASK
Analyze whether this vulnerability is exploitable given the usage context above.
Respond ONLY with valid JSON:

{{
  "risk_level": "low | medium | high | critical",
  "confidence": "low | medium | high",
  "reasoning": "explanation referencing specific file paths and usage context",
  "business_impact": "what could go wrong if exploited",
  "recommended_fix": "specific action to remediate"
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

    prompt = _build_investigation_prompt(alert, usage_locations, dep_name, dep_version)

    try:
        thread = await asyncio.wait_for(
            client.create_thread(assistant_id),
            timeout=5.0,
        )
        response = await asyncio.wait_for(
            client.add_message(
                thread_id=thread.thread_id,
                content=prompt,
                memory="Auto",
            ),
            timeout=10.0,
        )
        analysis = _parse_risk_json(response.content)
        return analysis, thread.thread_id
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Backboard analysis failed for {dep_name}: {e}")
        return FALLBACK_ANALYSIS, None
