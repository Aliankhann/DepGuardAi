Run a full end-to-end pipeline test using the demo fixture data. Report pass/fail for each step.

Prerequisite: backend must be running on port 8000.

Steps:
1. SEED: `curl -s -X POST http://localhost:8000/demo/seed` — expect `{"repo_id": <n>}`
2. SCAN: `curl -s -X POST http://localhost:8000/repos/1/scan` — expect `{"scan_id": <n>}`
3. POLL: `curl -s http://localhost:8000/scans/1/status` — repeat until status is "complete" or "failed" (max 30s)
4. ALERTS: `curl -s http://localhost:8000/repos/1/alerts` — expect at least 1 alert for lodash
5. INVESTIGATION: `curl -s http://localhost:8000/alerts/1` — expect UsageLocation + Analysis records present
6. REMEDIATION: `curl -s http://localhost:8000/alerts/1/remediation` — expect safe_version + install_command

For each step, print PASS or FAIL with the actual response.
If any step fails, print the error and stop — do not continue to the next step.
At the end, print a summary: X/6 steps passed.
