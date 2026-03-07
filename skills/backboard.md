# Backboard AI Integration

## SDK

```
pip install backboard-sdk
```

```python
from backboard import BackboardClient

client = BackboardClient(api_key=settings.BACKBOARD_API_KEY)
```

---

## Memory Model

- One **Assistant** per repository → stores cumulative investigation memory
- One **Thread** per scan investigation → scoped to one run
- `memory="Auto"` → Backboard auto-extracts and persists key findings
- Memory is at the **assistant level** — all threads share it

---

## backboard_service.py Patterns

### Create or load repo assistant

```python
async def get_or_create_assistant(repo: Repository, db: Session) -> str:
    if repo.backboard_assistant_id:
        return repo.backboard_assistant_id

    assistant = await client.create_assistant(
        name=f"depguard-{repo.name}",
        model="claude-sonnet-4-6",
        system_prompt=(
            "You are a security analyst investigating software dependency vulnerabilities. "
            "You reason about real-world exploitability based on how vulnerable code is actually used. "
            "Always respond with valid JSON matching the required output schema."
        )
    )
    repo.backboard_assistant_id = assistant.assistant_id
    db.commit()
    return assistant.assistant_id
```

### Run an investigation

```python
async def run_investigation(
    repo: Repository,
    alert: Alert,
    usage_locations: list[UsageLocation],
    db: Session
) -> dict:
    assistant_id = await get_or_create_assistant(repo, db)
    thread = await client.create_thread(assistant_id)

    prompt = build_investigation_prompt(alert, usage_locations)

    try:
        response = await asyncio.wait_for(
            client.add_message(
                thread_id=thread.thread_id,
                content=prompt,
                memory="Auto"
            ),
            timeout=10.0
        )
        return parse_risk_json(response.content)
    except (asyncio.TimeoutError, Exception):
        return FALLBACK_ANALYSIS
```

---

## Investigation Prompt Template

```python
def build_investigation_prompt(alert: Alert, usages: list[UsageLocation]) -> str:
    usage_text = "\n".join([
        f"- {u.file_path}:{u.line_number} [{', '.join(u.context_tags)}]\n  {u.snippet}"
        for u in usages
    ])

    return f"""
You are investigating a dependency vulnerability. Determine if it is exploitable in this codebase.

VULNERABILITY
ID: {alert.vuln_id}
Package: {alert.dependency.name}@{alert.dependency.version}
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
}}
"""
```

---

## Fallback Analysis

If Backboard is unavailable (timeout, API error), return this and set `backboard_thread_id = None`:

```python
FALLBACK_ANALYSIS = {
    "risk_level": "medium",
    "confidence": "low",
    "reasoning": "AI analysis unavailable. Package is confirmed vulnerable per OSV. Manual review required.",
    "business_impact": "Unknown without AI analysis.",
    "recommended_fix": "Upgrade to the safe version listed in OSV advisory."
}
```

---

## Timeout & Error Handling

- Hard timeout: 10 seconds per Backboard call
- On timeout or any exception: use `FALLBACK_ANALYSIS`
- Log warning with package name and error message
- Pipeline continues — do not let Backboard failures block Fix Agent
