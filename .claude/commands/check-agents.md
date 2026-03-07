Verify each DepGuard agent in isolation using fixture data. Report pass/fail per agent.

Prerequisite: `cd backend && source .venv/bin/activate`

Run: `cd backend && python -m pytest tests/test_agents.py -v`

If tests don't exist yet, verify each agent manually:

1. SCAN AGENT: Parse `tests/fixtures/sample_package.json` and confirm lodash@4.17.4 is detected
2. CODE AGENT: Scan `tests/fixtures/sample_app.js` and confirm a UsageLocation is found for lodash
3. CONTEXT AGENT: Classify `tests/fixtures/sample_app.js` and confirm context_tags are assigned
4. RISK AGENT: Send fixture alert to Backboard and confirm response matches the expected JSON schema (risk_level, confidence, reasoning, business_impact, recommended_fix)
5. FIX AGENT: Generate remediation for lodash CVE-2021-23337 and confirm safe_version + install_command are set

Print PASS or FAIL for each agent with a one-line reason.
If Backboard is unavailable, confirm fallback analysis is returned instead of an error.
