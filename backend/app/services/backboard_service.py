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

# Fallback for depvuln_agent when Backboard is unavailable.
# depvuln_agent fills in package/vuln-specific fields at runtime.
FALLBACK_DEPENDENCY_INVESTIGATION: dict = {
    "vulnerability_summary": "",
    "vulnerable_behaviors": [],
    "severity_level": "unknown",
    "suggested_safe_version": None,
    "investigation_focus": [],
    "investigation_source": "fallback",
}

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
    "exploitability_score": 50,
    "confidence_score": 20,
    "blast_radius": "Unknown — manual review required to determine impact scope.",
    "temp_mitigation": "Restrict access to affected functionality until the package is upgraded.",
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


async def ensure_depvuln_assistant(client, repo: Repository, db: Session) -> Optional[str]:
    if repo.backboard_depvuln_assistant_id:
        return repo.backboard_depvuln_assistant_id

    try:
        assistant = await asyncio.wait_for(
            client.create_assistant(
                name=f"depguard-depvuln-{repo.name}",
                system_prompt=(
                    "You are a vulnerability intelligence analyst for this software repository. "
                    "Your role is to normalize OSV advisory data into actionable investigation intelligence — "
                    "dangerous behaviors, code patterns to search for, and attack surface context. "
                    "Prior investigations for this repository are stored in your memory. "
                    "Reference them when analyzing recurring packages or patterns. "
                    "Always respond with valid JSON matching the required output schema."
                ),
            ),
            timeout=10.0,
        )
        repo.backboard_depvuln_assistant_id = str(assistant.assistant_id)
        db.commit()
        return str(assistant.assistant_id)
    except Exception as e:
        logger.warning(f"Failed to create Backboard depvuln assistant: {e}")
        return None


def _build_investigation_prompt(
    alert: Alert,
    usages: list[UsageLocation],
    dep_name: str,
    dep_version: str,
    all_vuln_ids: Optional[list[str]] = None,
    exploitability_context: Optional[dict] = None,
    blast_radius_context: Optional[dict] = None,
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

    # Pre-computed deterministic exploitability assessment from exploitability_agent.
    # Provides concrete evidence (function patterns, sensitivity classification) to
    # calibrate the AI's risk rating rather than having it infer from raw snippets alone.
    pre_assessment_section = ""
    if exploitability_context or blast_radius_context:
        parts = ["PRE-COMPUTED DETERMINISTIC ASSESSMENT"]
        if exploitability_context:
            funcs = exploitability_context.get("detected_functions") or []
            funcs_str = str(funcs) if funcs else "none detected"
            behavior_match = exploitability_context.get("vulnerable_behavior_match", "insufficient_evidence")
            parts.append(
                f"Exploitability: {exploitability_context.get('exploitability', 'unknown')}\n"
                f"Evidence Strength: {exploitability_context.get('evidence_strength', 'unknown')}\n"
                f"Detected Dangerous Functions: {funcs_str}\n"
                f"Vulnerable Behavior Match: {behavior_match} "
                f"(confirmed=actual vulnerable behavior observed in snippets, "
                f"unconfirmed=package/function present but specific behavior not visible, "
                f"insufficient_evidence=no usage found)\n"
                f"Assessment: {exploitability_context.get('exploitability_reason', '')}"
            )
        if blast_radius_context:
            parts.append(
                f"Blast Radius: {blast_radius_context.get('blast_radius_label', 'unknown')} "
                f"({blast_radius_context.get('affected_files', 0)} file(s), "
                f"{blast_radius_context.get('affected_modules', 0)} module(s))\n"
                f"Blast Radius Detail: {blast_radius_context.get('blast_radius_reason', '')}"
            )
        parts.append(
            "Use this assessment to calibrate your risk rating and business impact. "
            "Align with it unless you have strong contrary evidence from the usage context above."
        )
        pre_assessment_section = "\n" + "\n\n".join(parts) + "\n"

    return f"""You are investigating a dependency vulnerability cluster. Determine exploitability in this codebase.

PACKAGE UNDER INVESTIGATION
Package: {dep_name}@{dep_version}
Representative Vulnerability: {alert.vuln_id}
Severity: {alert.severity}
Summary: {alert.summary}{vuln_ids_section}

USAGE IN CODEBASE
{usage_text if usage_text else "No direct usage found in scanned files."}
{pre_assessment_section}
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
  "exploitability_score": 0-100 integer (0=not exploitable in this codebase given actual usage, 100=trivially exploitable via current code paths),
  "confidence_score": 0-100 integer (your certainty in this assessment — weight by quality and quantity of usage evidence),
  "reasoning": "explanation referencing specific file paths, sensitivity levels, and why this matters in this repo",
  "business_impact": "what could realistically go wrong if exploited in this codebase",
  "blast_radius": "plain-English scope — how many users, services, or code paths are exposed if this is exploited (e.g. 'All authenticated users — session.js runs on every login')",
  "recommended_fix": "specific action to remediate, including upgrade command if known",
  "temp_mitigation": "immediate action to reduce risk while the upgrade is prepared — e.g. input validation, feature flag, WAF rule, disable endpoint, or code-level workaround"
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
    exploitability_context: Optional[dict] = None,
    blast_radius_context: Optional[dict] = None,
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
        alert, usage_locations, dep_name, dep_version,
        all_vuln_ids, exploitability_context, blast_radius_context,
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


async def recall_remediation_context(
    repo: Repository,
    dep_name: str,
    vuln_id: str,
    db: Session,
) -> Optional[str]:
    """
    Query the repository's Backboard assistant for prior remediation history.
    Used by fix_agent to enrich recommendations with memory of past approved fixes.

    Returns a plain-English recall string if found, or None on failure/fallback.
    This call does NOT store memory (no memory="Auto") — read-only recall.
    """
    if not settings.BACKBOARD_API_KEY:
        return None

    client = _get_client()
    if not client:
        return None

    assistant_id = repo.backboard_assistant_id
    if not assistant_id:
        return None

    try:
        thread = await asyncio.wait_for(
            client.create_thread(assistant_id),
            timeout=5.0,
        )
        response = await asyncio.wait_for(
            client.add_message(
                thread_id=thread.thread_id,
                content=(
                    f"Has the package '{dep_name}' (vulnerability: {vuln_id}) been remediated "
                    f"in this repository before? If so, briefly describe what approach was used "
                    f"(e.g. version upgraded, endpoint disabled, workaround applied). "
                    f"If no prior remediation is known, reply with exactly: NO_PRIOR_REMEDIATION"
                ),
                llm_provider="anthropic",
                model_name="claude-sonnet-4-6",
            ),
            timeout=15.0,
        )
        content = response.content.strip()
        if "NO_PRIOR_REMEDIATION" in content:
            return None
        return content
    except (asyncio.TimeoutError, Exception) as e:
        logger.debug(f"Recall remediation context failed for {dep_name}: {e}")
        return None


async def write_investigation_memory(
    repo: Repository,
    summary: str,
    db: Session,
) -> None:
    """
    Write a structured investigation summary to the repository's Backboard assistant memory.
    Called by memory_agent as the final pipeline step.

    Uses memory="Auto" so Backboard extracts key findings for future scans.
    """
    if not settings.BACKBOARD_API_KEY:
        return

    client = _get_client()
    if not client:
        return

    assistant_id = await ensure_repository_assistant(client, repo, db)
    if not assistant_id:
        return

    try:
        thread = await asyncio.wait_for(
            client.create_thread(assistant_id),
            timeout=5.0,
        )
        await asyncio.wait_for(
            client.add_message(
                thread_id=thread.thread_id,
                content=summary,
                memory="Auto",
                llm_provider="anthropic",
                model_name="claude-sonnet-4-6",
            ),
            timeout=20.0,
        )
        logger.info(f"[backboard_service] Investigation memory written for repo {repo.id}")
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Failed to write investigation memory for repo {repo.id}: {e}")


async def run_dependency_analysis(
    repo: Repository,
    dep_name: str,
    dep_version: str,
    ecosystem: str,
    all_vuln_summaries: list[dict],
    db: Session,
) -> dict:
    """
    Analytical call: reason over OSV vulnerability data for a package.
    Does NOT use per-repo assistant memory — this is stateless intelligence normalization.
    No memory="Auto" — results are stored on the Alert record by depvuln_agent.

    Returns a DependencyInvestigation dict or FALLBACK on failure.

    all_vuln_summaries: list of {vuln_id, summary, details, severity, aliases}
    """
    if not settings.BACKBOARD_API_KEY:
        return dict(FALLBACK_DEPENDENCY_INVESTIGATION)

    client = _get_client()
    if not client:
        return dict(FALLBACK_DEPENDENCY_INVESTIGATION)

    assistant_id = await ensure_depvuln_assistant(client, repo, db)
    if not assistant_id:
        return dict(FALLBACK_DEPENDENCY_INVESTIGATION)

    # Build compact vuln list for prompt
    vuln_lines = []
    for v in all_vuln_summaries[:5]:  # cap at 5 to keep prompt tight
        aliases_str = ", ".join(v.get("aliases", [])[:3])
        vuln_lines.append(
            f"  [{v['vuln_id']}] Severity: {v.get('severity', 'UNKNOWN')}\n"
            f"  Summary: {v.get('summary', '')[:300]}\n"
            f"  Aliases: {aliases_str or 'none'}"
        )

    prompt = f"""You are a vulnerability intelligence analyst. Normalize the following OSV vulnerability data for {dep_name}@{dep_version} ({ecosystem}).

VULNERABILITIES:
{chr(10).join(vuln_lines)}

Extract structured intelligence. Respond ONLY with valid JSON:

{{
  "vulnerability_summary": "single clear sentence describing what these vulnerabilities enable (not just CVE numbers)",
  "vulnerable_behaviors": ["list of 1-3 specific dangerous behaviors — what an attacker can DO"],
  "severity_level": "critical | high | medium | low",
  "suggested_safe_version": "earliest safe version string or null — advisory only, return null if not explicitly stated in the OSV data, do NOT guess",
  "investigation_focus": ["list of specific function call patterns, method names, or code patterns to search for in the codebase that would indicate use of the vulnerable behavior — e.g. '_.merge(', 'yaml.load(', 'pickle.loads('"]
}}

Rules:
- vulnerable_behaviors must be specific and actionable (e.g. "Prototype pollution via _.merge() when merging user-controlled objects" not "security issue")
- investigation_focus must be code-searchable strings (substrings that appear in real code)
- suggested_safe_version is advisory only — return null if not explicitly stated in the OSV data, do NOT guess"""

    try:
        thread = await asyncio.wait_for(
            client.create_thread(assistant_id),
            timeout=5.0,
        )
        # memory="Auto": Backboard extracts key findings into this repository's
        # depvuln assistant memory so future scans on the same repo recall prior
        # vulnerability intelligence (e.g. previously analyzed package behaviors).
        response = await asyncio.wait_for(
            client.add_message(
                thread_id=thread.thread_id,
                content=prompt,
                memory="Auto",
                llm_provider="anthropic",
                model_name="claude-sonnet-4-6",
            ),
            timeout=25.0,
        )
        result = _parse_dep_investigation_json(response.content)
        result["investigation_source"] = "backboard_ai"
        return result
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Dependency analysis failed for {dep_name}: {e}")
        return dict(FALLBACK_DEPENDENCY_INVESTIGATION)


def _parse_dep_investigation_json(content: str) -> dict:
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    try:
        start = content.find("{")
        end = content.rfind("}") + 1
        if start != -1 and end > start:
            return json.loads(content[start:end])
    except json.JSONDecodeError:
        pass
    logger.warning("Failed to parse dependency investigation JSON; using fallback")
    return dict(FALLBACK_DEPENDENCY_INVESTIGATION)


def _parse_context_json(content: str) -> list[dict]:
    """Parse context classification JSON from Backboard response.
    Returns list of classification dicts or [] on failure.
    """
    try:
        data = json.loads(content)
        return data.get("classifications", [])
    except json.JSONDecodeError:
        pass
    try:
        start = content.find("{")
        end = content.rfind("}") + 1
        if start != -1 and end > start:
            data = json.loads(content[start:end])
            return data.get("classifications", [])
    except json.JSONDecodeError:
        pass
    logger.warning("Failed to parse context classification JSON; using fallback")
    return []


async def run_context_analysis(
    alert: Alert,
    usages: list[UsageLocation],
    dep_name: str,
    dep_version: str,
    repo: Repository,
    db: Session,
) -> list[dict]:
    """
    Classify the security context of each usage location for an alert.
    Returns list of classification dicts (one per usage, indexed from 1).
    Returns [] on any failure — triggers deterministic fallback in context_agent.

    Uses per-repo assistant (backboard_assistant_id) — no memory="Auto" since
    classification data is stored in DB and doesn't need to persist in assistant memory.
    """
    if not settings.BACKBOARD_API_KEY:
        return []

    client = _get_client()
    if not client:
        return []

    assistant_id = await ensure_repository_assistant(client, repo, db)
    if not assistant_id:
        return []

    # Build usage location text (1-indexed for prompt clarity)
    usage_lines = []
    for i, u in enumerate(usages, start=1):
        usage_lines.append(
            f"[{i}] {u.file_path}:{u.line_number}  (import_type: {u.import_type})\n"
            f"    {u.snippet}"
        )

    vuln_summary = (alert.summary or "")[:200]

    prompt = f"""Classify the security context of each usage location for a vulnerable dependency.

PACKAGE: {dep_name}@{dep_version}
VULNERABILITY: {alert.vuln_id} — {vuln_summary}

USAGE LOCATIONS:
{chr(10).join(usage_lines)}

For EACH location, respond ONLY with valid JSON:

{{
  "classifications": [
    {{
      "index": 1,
      "context_tags": ["<semantic_tag>", "<SENSITIVITY_LEVEL>"],
      "sensitivity_level": "HIGH | MEDIUM | LOW",
      "subsystem_labels": ["<label1>", "..."],
      "sensitive_surface_reason": "one sentence referencing the actual snippet or path",
      "user_input_proximity": "direct | indirect | none"
    }}
  ]
}}

Rules:
- context_tags MUST contain exactly one of: HIGH_SENSITIVITY, MEDIUM_SENSITIVITY, LOW_SENSITIVITY
- sensitivity_level must match the tag (HIGH_SENSITIVITY → HIGH, MEDIUM_SENSITIVITY → MEDIUM, LOW_SENSITIVITY → LOW)
- Semantic tags (pick 1-2): auth, payment, crypto, secrets, execution, api, data, util, test, unclassified
- Use BOTH file path AND snippet content — snippet beats path if they conflict
- user_input_proximity: "direct" if snippet handles req/request/input/body/params/query/user data; "indirect" if one step removed from a handler; "none" otherwise
- sensitive_surface_reason: reference the actual snippet or file path, not the CVE description"""

    try:
        thread = await asyncio.wait_for(
            client.create_thread(assistant_id),
            timeout=5.0,
        )
        response = await asyncio.wait_for(
            client.add_message(
                thread_id=thread.thread_id,
                content=prompt,
                llm_provider="anthropic",
                model_name="claude-sonnet-4-6",
            ),
            timeout=30.0,
        )
        return _parse_context_json(response.content)
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Context analysis failed for alert {alert.id} ({dep_name}): {e}")
        return []


def _parse_exploitability_json(content: str) -> dict:
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    try:
        start = content.find("{")
        end = content.rfind("}") + 1
        if start != -1 and end > start:
            return json.loads(content[start:end])
    except json.JSONDecodeError:
        pass
    return {"vulnerable_behavior_match": "insufficient_evidence"}


async def run_exploitability_analysis(
    repo: Repository,
    alert: Alert,
    usages: list[UsageLocation],
    dep_inv: dict,
    deterministic_result: dict,
    db: Session,
) -> str:
    """
    Narrow AI call: determine whether the actual usage matches the known vulnerable behavior.
    Returns 'confirmed', 'unconfirmed', or 'insufficient_evidence'.

    Receives deterministic scoring as grounding evidence — AI only answers whether
    the observed code patterns match the specific vulnerable behavior from the advisory.
    Uses the repository's existing Backboard assistant (no new assistant needed).
    memory="Auto" so findings persist for future scan recall.
    """
    if not settings.BACKBOARD_API_KEY:
        return "insufficient_evidence"

    client = _get_client()
    if not client:
        return "insufficient_evidence"

    assistant_id = await ensure_repository_assistant(client, repo, db)
    if not assistant_id:
        return "insufficient_evidence"

    usage_lines = "\n".join(
        f"  - {u.file_path}:{u.line_number} [{', '.join(u.context_tags or [])}]\n    {u.snippet}"
        for u in usages[:10]
    ) or "  No usage locations found."

    vulnerable_behaviors = dep_inv.get("vulnerable_behaviors") or []
    behavior_text = "\n".join(f"  - {b}" for b in vulnerable_behaviors) or "  Not specified."

    detected = deterministic_result.get("detected_functions") or []
    detected_text = str(detected) if detected else "none"

    prompt = f"""You are reviewing whether a specific vulnerable behavior is present in this codebase.

PACKAGE: {alert.vuln_id} — {alert.summary or "No summary"}

KNOWN VULNERABLE BEHAVIORS (from advisory):
{behavior_text}

USAGE LOCATIONS IN THIS CODEBASE:
{usage_lines}

DETERMINISTIC PRE-ASSESSMENT:
- Exploitability verdict: {deterministic_result.get('exploitability', 'unknown')}
- Evidence strength: {deterministic_result.get('evidence_strength', 'unknown')}
- Detected function patterns: {detected_text}

TASK: Does the actual code usage above match one of the known vulnerable behaviors listed?

Respond ONLY with valid JSON:

{{
  "vulnerable_behavior_match": "confirmed | unconfirmed | insufficient_evidence",
  "match_reasoning": "one sentence referencing actual file paths or snippets"
}}

Rules:
- "confirmed": snippets show direct use of a vulnerable behavior (e.g. merging user-controlled input via _.merge)
- "unconfirmed": package/function is used but the specific vulnerable behavior pattern is not visible in the snippets
- "insufficient_evidence": no usage found or not enough context to determine"""

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
                llm_provider="anthropic",
                model_name="claude-sonnet-4-6",
            ),
            timeout=20.0,
        )
        data = _parse_exploitability_json(response.content)
        match = data.get("vulnerable_behavior_match", "insufficient_evidence")
        if match not in ("confirmed", "unconfirmed", "insufficient_evidence"):
            match = "insufficient_evidence"
        return match
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Exploitability analysis failed for alert {alert.id}: {e}")
        return "insufficient_evidence"
