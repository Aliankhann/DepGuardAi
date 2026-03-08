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

# Limits concurrent Backboard API calls across all agents.
# Without this, asyncio.gather across 14 alerts fires 20+ simultaneous calls
# against the same assistant, causing rate-limit fallbacks.
_BACKBOARD_SEMAPHORE = asyncio.Semaphore(5)

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

FALLBACK_BLAST_RADIUS: dict = {
    "scope_clarity": "low",
    "affected_surfaces": [],
}

FALLBACK_REMEDIATION: dict = {
    "temporary_mitigation": "Restrict or disable affected functionality until the package is upgraded.",
    "permanent_fix_summary": "Upgrade to the safe version listed in the OSV advisory and re-run DepGuard scan.",
    "review_note": "AI analysis unavailable — manual senior review required before deploying fix.",
    "senior_review_urgency": "planned",
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


def _parse_json(content: str, fallback: dict) -> dict:
    """Parse a JSON dict from a Backboard response string.

    Tries a strict parse first. On failure, attempts to extract the first
    {...} block from mixed content (e.g. prose + JSON). Returns fallback on
    any parse error. All 6 Backboard response parsers use this helper.
    """
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
    logger.warning("Failed to parse JSON from Backboard response; using fallback")
    return fallback


def _get_client():
    if not settings.BACKBOARD_API_KEY:
        return None
    try:
        from backboard import BackboardClient  # type: ignore
        return BackboardClient(api_key=settings.BACKBOARD_API_KEY)
    except ImportError:
        logger.warning("backboard-sdk not installed")
        return None


async def _add_message(client, thread_id: str, content: str, timeout: float, **kwargs) -> object:
    """Semaphore-guarded wrapper around client.add_message.
    Limits concurrent Backboard calls across all agents to prevent rate-limit fallbacks.
    """
    async with _BACKBOARD_SEMAPHORE:
        return await asyncio.wait_for(
            client.add_message(thread_id=thread_id, content=content, **kwargs),
            timeout=timeout,
        )


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
        response = await _add_message(
            client, thread.thread_id, prompt, timeout=30.0,
            memory="Auto", llm_provider="anthropic", model_name="claude-sonnet-4-6",
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
        response = await _add_message(
            client, thread.thread_id,
            f"Has the package '{dep_name}' (vulnerability: {vuln_id}) been remediated "
            f"in this repository before? If so, briefly describe what approach was used "
            f"(e.g. version upgraded, endpoint disabled, workaround applied). "
            f"If no prior remediation is known, reply with exactly: NO_PRIOR_REMEDIATION",
            timeout=15.0,
            llm_provider="anthropic", model_name="claude-sonnet-4-6",
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
        await _add_message(
            client, thread.thread_id, summary, timeout=20.0,
            memory="Auto", llm_provider="anthropic", model_name="claude-sonnet-4-6",
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
        response = await _add_message(
            client, thread.thread_id, prompt, timeout=25.0,
            memory="Auto", llm_provider="anthropic", model_name="claude-sonnet-4-6",
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
        response = await _add_message(
            client, thread.thread_id, prompt, timeout=30.0,
            llm_provider="anthropic", model_name="claude-sonnet-4-6",
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


def _parse_blast_radius_json(content: str) -> dict:
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
    return dict(FALLBACK_BLAST_RADIUS)


async def run_blast_radius_analysis(
    repo: Repository,
    alert: Alert,
    usages: list[UsageLocation],
    phase1_result: dict,
    exploitability_context: Optional[dict],
    db,
) -> dict:
    """
    Narrow AI call: confirm scope_clarity and validate affected_surfaces.

    Receives the deterministic Phase 1 blast radius result as grounding evidence.
    AI only answers whether the scope assessment is clear and which surfaces are affected.
    Uses the repository's existing Backboard assistant — no new assistant created.
    No memory="Auto" — this is a computation step, not investigation memory.

    Returns dict with scope_clarity and affected_surfaces on success,
    or FALLBACK_BLAST_RADIUS on any failure.
    """
    if not settings.BACKBOARD_API_KEY:
        return dict(FALLBACK_BLAST_RADIUS)

    client = _get_client()
    if not client:
        return dict(FALLBACK_BLAST_RADIUS)

    assistant_id = await ensure_repository_assistant(client, repo, db)
    if not assistant_id:
        return dict(FALLBACK_BLAST_RADIUS)

    # Build usage summary for prompt
    usage_lines = "\n".join(
        f"  - {u.file_path}:{u.line_number} "
        f"[{', '.join(u.context_tags or [])}]"
        f"{' subsystems=' + str(u.subsystem_labels) if u.subsystem_labels else ''}"
        for u in usages[:15]
    ) or "  No usage locations found."

    expl_summary = ""
    if exploitability_context:
        expl_summary = (
            f"\nEXPLOITABILITY PRE-ASSESSMENT:\n"
            f"  Verdict: {exploitability_context.get('exploitability', 'unknown')}\n"
            f"  Evidence strength: {exploitability_context.get('evidence_strength', 'unknown')}\n"
            f"  Detected functions: {exploitability_context.get('detected_functions') or 'none'}"
        )

    prompt = f"""You are reviewing the blast radius scope of a vulnerable dependency.

PACKAGE: {alert.vuln_id}
DETERMINISTIC PRE-ASSESSMENT:
  Blast radius label: {phase1_result.get('blast_radius_label', 'unknown')}
  Affected files: {phase1_result.get('affected_files', 0)}
  Affected modules: {phase1_result.get('affected_modules', 0)}
  Detected surfaces (from context tags): {phase1_result.get('affected_surfaces', [])}
  Reason: {phase1_result.get('blast_radius_reason', '')}
{expl_summary}

USAGE LOCATIONS:
{usage_lines}

TASK: Assess the clarity of this scope estimate and confirm which security surfaces are exposed.

Allowed surfaces: auth, payment, admin, crypto, secrets, execution, api, data, middleware
scope_clarity values: high (clear, strong evidence), medium (partial evidence), low (no usage or fallback context only)

Respond ONLY with valid JSON:

{{
  "scope_clarity": "high | medium | low",
  "affected_surfaces": ["<surface1>", "..."],
  "scope_reasoning": "one sentence referencing actual file paths or context tags"
}}

Rules:
- Only include surfaces from the allowed list above — do NOT invent new ones
- scope_clarity must align with the evidence quality above (good context tags + multiple modules = high)
- If no usages exist, scope_clarity must be "low" and affected_surfaces must be []"""

    try:
        thread = await asyncio.wait_for(
            client.create_thread(assistant_id),
            timeout=5.0,
        )
        response = await _add_message(
            client, thread.thread_id, prompt, timeout=20.0,
            llm_provider="anthropic", model_name="claude-sonnet-4-6",
        )
        result = _parse_blast_radius_json(response.content)
        # Validate scope_clarity
        if result.get("scope_clarity") not in ("high", "medium", "low"):
            result["scope_clarity"] = phase1_result.get("scope_clarity", "low")
        # Validate affected_surfaces is a list
        if not isinstance(result.get("affected_surfaces"), list):
            result["affected_surfaces"] = phase1_result.get("affected_surfaces", [])
        return result
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Blast radius AI analysis failed for alert {alert.id}: {e}")
        return dict(FALLBACK_BLAST_RADIUS)


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
        response = await _add_message(
            client, thread.thread_id, prompt, timeout=20.0,
            memory="Auto", llm_provider="anthropic", model_name="claude-sonnet-4-6",
        )
        data = _parse_exploitability_json(response.content)
        match = data.get("vulnerable_behavior_match", "insufficient_evidence")
        if match not in ("confirmed", "unconfirmed", "insufficient_evidence"):
            match = "insufficient_evidence"
        return match
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Exploitability analysis failed for alert {alert.id}: {e}")
        return "insufficient_evidence"


def _parse_remediation_json(content: str) -> dict:
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
    logger.warning("Failed to parse remediation JSON from Backboard response; using fallback")
    return dict(FALLBACK_REMEDIATION)


async def run_remediation_analysis(
    repo: Repository,
    alert: Alert,
    dep_name: str,
    dep_version: str,
    ecosystem: str,
    safe_version: Optional[str],
    exploitability_result: Optional[dict],
    blast_radius_result: Optional[dict],
    confidence_result: Optional[dict],
    prior_senior_fix: Optional[str],
    db: Session,
) -> dict:
    """
    AI-backed remediation recommendation for a single alert.

    Consumes upstream evidence (exploitability, blast radius, confidence) plus any
    prior senior-reviewed fix recalled from Backboard memory.

    Returns structured dict with temporary_mitigation, permanent_fix_summary,
    review_note, senior_review_urgency.

    Uses the repository's existing main Backboard assistant.
    memory="Auto" — findings persist so future scans recall this recommendation.
    Falls back to FALLBACK_REMEDIATION on any failure.
    """
    if not settings.BACKBOARD_API_KEY:
        return dict(FALLBACK_REMEDIATION)

    client = _get_client()
    if not client:
        return dict(FALLBACK_REMEDIATION)

    assistant_id = await ensure_repository_assistant(client, repo, db)
    if not assistant_id:
        return dict(FALLBACK_REMEDIATION)

    # Build evidence sections
    safe_ver_str = safe_version or "unknown — check OSV advisory"

    expl_section = ""
    if exploitability_result:
        expl_section = (
            f"\nEXPLOITABILITY ASSESSMENT:\n"
            f"  Verdict: {exploitability_result.get('exploitability', 'unknown')}\n"
            f"  Evidence strength: {exploitability_result.get('evidence_strength', 'unknown')}\n"
            f"  Vulnerable behavior match: {exploitability_result.get('vulnerable_behavior_match', 'insufficient_evidence')}\n"
            f"  Detected functions: {exploitability_result.get('detected_functions') or 'none'}\n"
            f"  Reason: {exploitability_result.get('exploitability_reason', '')}"
        )

    br_section = ""
    if blast_radius_result:
        br_section = (
            f"\nBLAST RADIUS:\n"
            f"  Label: {blast_radius_result.get('blast_radius_label', 'unknown')}\n"
            f"  Files: {blast_radius_result.get('affected_files', 0)}, "
            f"Modules: {blast_radius_result.get('affected_modules', 0)}\n"
            f"  Surfaces: {blast_radius_result.get('affected_surfaces', [])}\n"
            f"  Scope clarity: {blast_radius_result.get('scope_clarity', 'low')}\n"
            f"  Reason: {blast_radius_result.get('blast_radius_reason', '')}"
        )

    conf_section = ""
    if confidence_result:
        conf_section = (
            f"\nCONFIDENCE:\n"
            f"  Level: {confidence_result.get('confidence', 'unknown')} "
            f"({confidence_result.get('confidence_percent', 'n/a')}%)\n"
            f"  Reasons: {confidence_result.get('confidence_reasons', [])}"
        )

    prior_section = ""
    if prior_senior_fix:
        prior_section = (
            f"\nPRIOR SENIOR-REVIEWED FIX (from repository memory):\n"
            f"  {prior_senior_fix}\n"
            f"  Use this as a professional baseline when formulating your recommendation."
        )

    prompt = f"""You are the remediation recommendation agent for a dependency security scanner.

PACKAGE: {dep_name}@{dep_version} ({ecosystem})
VULNERABILITY: {alert.vuln_id} — {alert.summary or 'No summary'}
SEVERITY: {alert.severity}
OSV SAFE VERSION: {safe_ver_str}
{expl_section}
{br_section}
{conf_section}
{prior_section}

TASK: Recommend a conservative, review-friendly remediation for this vulnerability.

Constraints:
- temporary_mitigation must be an IMMEDIATE action a developer can take TODAY to reduce risk while preparing the upgrade
- permanent_fix_summary must be specific to this package and vulnerability (not generic)
- review_note must justify why a senior engineer should review this, referencing the evidence above
- senior_review_urgency must reflect the actual exploitability and blast radius (not just severity)
- Do NOT frame this as fully autonomous — always recommend senior review
- OSV safe version is authoritative — do not suggest a lower version

Respond ONLY with valid JSON:

{{
  "temporary_mitigation": "specific immediate action to reduce risk today (e.g. input validation, disable endpoint, feature flag, WAF rule, code-level workaround)",
  "permanent_fix_summary": "specific upgrade plan referencing the package name and safe version",
  "review_note": "one paragraph for the senior reviewer referencing exploitability evidence and blast radius",
  "senior_review_urgency": "immediate | this-sprint | planned | low-priority"
}}

Rules:
- temporary_mitigation must be actionable today, not 'upgrade the package' (that is the permanent fix)
- senior_review_urgency = immediate if exploitability=likely OR blast_radius=subsystem OR behavior_match=confirmed
- senior_review_urgency = this-sprint if exploitability=possible OR blast_radius=module
- senior_review_urgency = planned if exploitability=unlikely OR blast_radius=isolated
- senior_review_urgency = low-priority only if no usage found"""

    try:
        thread = await asyncio.wait_for(
            client.create_thread(assistant_id),
            timeout=5.0,
        )
        response = await _add_message(
            client, thread.thread_id, prompt, timeout=30.0,
            memory="Auto", llm_provider="anthropic", model_name="claude-sonnet-4-6",
        )
        result = _parse_remediation_json(response.content)

        # Validate senior_review_urgency
        valid_urgencies = {"immediate", "this-sprint", "planned", "low-priority"}
        if result.get("senior_review_urgency") not in valid_urgencies:
            result["senior_review_urgency"] = FALLBACK_REMEDIATION["senior_review_urgency"]

        return result
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Remediation analysis failed for alert {alert.id} ({dep_name}): {e}")
        return dict(FALLBACK_REMEDIATION)


async def store_senior_approved_fix(
    repo: Repository,
    dep_name: str,
    vuln_id: str,
    safe_version: Optional[str],
    agent_temp_mitigation: str,
    agent_permanent_fix: str,
    senior_approved_fix: str,
    rationale: str,
    db: Session,
) -> None:
    """
    Write a senior-reviewed final fix to Backboard memory.

    Called from the finalize endpoint after a senior SWE approves a fix.
    Stores a structured comparison so future scans on this repo can recall
    the professional baseline when recommending remediations for similar issues.

    memory="Auto" — Backboard indexes the approved pattern for future recall.
    Graceful — never raises on failure.
    """
    if not settings.BACKBOARD_API_KEY:
        return

    client = _get_client()
    if not client:
        return

    assistant_id = await ensure_repository_assistant(client, repo, db)
    if not assistant_id:
        return

    from datetime import datetime as _dt
    date_str = _dt.utcnow().strftime("%Y-%m-%d")
    safe_ver_str = safe_version or "latest safe version per OSV"

    summary = (
        f"SENIOR-REVIEWED REMEDIATION — {dep_name} ({vuln_id}) — {date_str}\n"
        f"Agent recommended (temporary): {agent_temp_mitigation}\n"
        f"Agent recommended (permanent): {agent_permanent_fix}\n"
        f"Senior approved fix: {senior_approved_fix}\n"
        f"Rationale: {rationale}\n"
        f"Accepted pattern: Upgrade {dep_name} to {safe_ver_str} with approach: {senior_approved_fix}\n"
        f"Note: This approved fix is stored as reference for future similar vulnerabilities in this repository."
    )

    try:
        thread = await asyncio.wait_for(
            client.create_thread(assistant_id),
            timeout=5.0,
        )
        await _add_message(
            client, thread.thread_id, summary, timeout=20.0,
            memory="Auto", llm_provider="anthropic", model_name="claude-sonnet-4-6",
        )
        logger.info(
            f"[backboard_service] Senior-approved fix stored for {dep_name} ({vuln_id}) "
            f"in repo {repo.id}"
        )
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(
            f"Failed to store senior-approved fix for {dep_name} ({vuln_id}): {e}"
        )
