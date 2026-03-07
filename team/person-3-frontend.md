# Person 3 — Frontend

## Your Responsibility

You own everything the user sees. Start by building a static shell early (so you're not blocked waiting for the backend), then wire it up to the real API once Person 2 is done.

---

## What You Build

- Vite + React + TypeScript + Tailwind + react-router-dom setup
- TypeScript API types matching the backend schemas
- Static shell with layout for all 3 pages (no real data yet)
- Fetch hooks for repos, scans, and alerts
- Dashboard — register repos, trigger scans, view repo list
- RepoDetail — alert table with severity badges + live scan status polling
- AlertDetail — full investigation view: code snippet, context, AI reasoning, fix
- CORS-safe API client

---

## Depends On

**Shell (Prompt 1–2):** Nothing — start immediately, build static layout.

**Wiring (Prompt 3–5):** Person 2 must finish their routes before you wire real data:
- `GET /repos`, `POST /repos`
- `POST /repos/{id}/scan`, `GET /scans/{id}/status`
- `GET /repos/{id}/alerts`, `GET /alerts/{id}`, `GET /alerts/{id}/remediation`

---

## Claude Code Prompts — Paste These In Order

### Prompt 1 — Frontend Shell Setup

```
Set up the DepGuard frontend project shell. Reference Claude.md for the structure.

In the frontend/ directory, scaffold a Vite + React + TypeScript project.
Then install: tailwindcss @tailwindcss/vite react-router-dom

Configure Tailwind.
Set up react-router-dom with BrowserRouter in main.tsx.

Create these routes in App.tsx:
  /                  → Dashboard (placeholder)
  /repos/:repoId     → RepoDetail (placeholder)
  /alerts/:alertId   → AlertDetail (placeholder)

Create a shared Layout component with:
  - Top nav bar showing "DepGuard" brand
  - A subtle dark background (slate-900 or similar)
  - Main content area with padding

Create placeholder pages that render inside Layout:
  pages/Dashboard.tsx    → "Dashboard — repos will appear here"
  pages/RepoDetail.tsx   → "Repo Detail — alerts will appear here"
  pages/AlertDetail.tsx  → "Alert Detail — investigation will appear here"

Verify: npm run dev starts, / shows Dashboard placeholder, /repos/1 shows RepoDetail placeholder.
No real API calls yet — just static layout.
```

---

### Prompt 2 — TypeScript API Types + Static Layout

```
Define TypeScript API types for DepGuard and build static page layouts with realistic placeholder data.
Reference Claude.md and skills/schema.md for the data shapes.

Create src/types/api.ts with interfaces:
  Repository: { id, name, path, ecosystem, language, created_at }
  ScanRun: { id, repo_id, status, current_agent, alert_count, started_at, completed_at, error_message }
  Dependency: { id, name, version, ecosystem }
  Alert: { id, vuln_id, severity, summary, dependency: Dependency }
  UsageLocation: { id, file_path, line_number, snippet, import_type, context_tags: string[] }
  Analysis: { id, risk_level, confidence, reasoning, business_impact, recommended_fix, backboard_thread_id }
  Remediation: { id, safe_version, install_command, checklist: string[] }
  AlertDetail: Alert & { usage_locations: UsageLocation[], analysis: Analysis, remediation: Remediation }

Build out Dashboard.tsx with hardcoded placeholder data:
  - A "Register Repository" form with fields: Name, Local Path, [Register] button
  - A repo list showing 1-2 hardcoded repos with a "Scan" button each
  - Clean card-based layout with Tailwind

Build out RepoDetail.tsx with hardcoded placeholder data:
  - Scan status banner (show "Scanning... — Code Agent" in progress state)
  - Alert table: columns for Package, Version, Severity, CVE ID, Locations Found
  - Use color-coded severity badges (red=CRITICAL, orange=HIGH, yellow=MEDIUM, blue=LOW)
  - 2-3 hardcoded alert rows

Build out AlertDetail.tsx with hardcoded placeholder data:
  - Alert header: package name, version, CVE ID, severity badge
  - Code locations section: file path + line number + code snippet block
  - Context tags section: chips showing tags like "util", "LOW_SENSITIVITY"
  - AI Analysis section: risk level badge, confidence, reasoning text, business impact
  - Fix section: install command in a code block + checklist

Verify: all 3 pages look good with placeholder data before any real API is wired.
```

---

### Prompt 3 — API Client + Repo Hooks

```
Create the DepGuard API client and hook up Dashboard to real data.

Create src/lib/api.ts:
  Base URL from env: import.meta.env.VITE_API_URL ?? 'http://localhost:8000'
  Export typed async functions:
    fetchRepos(): Promise<Repository[]>
    createRepo(name: string, path: string): Promise<Repository>
    triggerScan(repoId: number): Promise<{ scan_id: number }>
    fetchScanStatus(scanId: number): Promise<ScanRun>
    fetchAlerts(repoId: number): Promise<Alert[]>
    fetchAlertDetail(alertId: number): Promise<AlertDetail>
    fetchRemediation(alertId: number): Promise<Remediation>

Create src/hooks/useRepos.ts:
  - Fetch repos from GET /repos on mount
  - Expose: repos, loading, error, refetch, createRepo

Create src/hooks/useScan.ts:
  - triggerScan(repoId) — calls POST /repos/{id}/scan, stores scan_id
  - pollStatus(scanId) — polls GET /scans/{id}/status every 2s until status is "complete" or "failed"
    Stop polling and return final status.
  - Expose: scanStatus, currentAgent, triggerAndPoll(repoId)

Wire up Dashboard.tsx:
  - Replace hardcoded repo list with useRepos() data
  - "Register" form calls createRepo and refetches
  - "Scan" button calls triggerAndPoll — show live current_agent text while running
    ("Scanning dependencies...", "Mapping code usage...", "Analyzing with AI...")
  - On scan complete, navigate to /repos/{id}

Create frontend/.env:
  VITE_API_URL=http://localhost:8000

Verify: Dashboard shows real repos, Register creates one, Scan triggers the pipeline with live status.
```

---

### Prompt 4 — RepoDetail + AlertDetail Pages

```
Wire up RepoDetail and AlertDetail pages to real API data.

Create src/hooks/useAlerts.ts:
  - Fetch alerts from GET /repos/{repoId}/alerts on mount
  - Expose: alerts, loading, error

Wire up RepoDetail.tsx:
  - Use useParams() to get repoId
  - Use useAlerts(repoId) to load the alerts table
  - Keep the severity badge color logic from the placeholder
  - Each alert row links to /alerts/{alertId}
  - Show alert count and last scan time at the top
  - If no alerts, show "No vulnerabilities found in last scan"

Wire up AlertDetail.tsx:
  - Use useParams() to get alertId
  - Fetch GET /alerts/{alertId} on mount — get full AlertDetail including usage_locations, analysis, remediation
  - Render all 4 sections: alert header, code locations, AI analysis, fix
  - Code snippet: render in a <pre> block with monospace font
  - Context tags: render as small colored chips
  - Risk level: use same color-coded badge system as severity
  - If analysis.backboard_thread_id is null, show a subtle "AI analysis unavailable" notice
  - Checklist: render as a checkbox list (visual only, not interactive)
  - Back button to return to /repos/{repoId}

Verify:
  - Click a repo → see its alerts
  - Click an alert → see full investigation (code location, AI reasoning, fix)
  - Navigate back and forth without errors
```

---

### Prompt 5 — Demo Polish

```
Polish the DepGuard UI for demo presentation. Keep changes minimal and focused.

1. Add a loading skeleton or spinner for each page while data is fetching
2. Add an error state banner if API calls fail ("Backend unavailable — check server")
3. Dashboard: add a "DepGuard" logo/wordmark at the top nav (text-based, no image needed)
4. RepoDetail: add a scan progress bar or step indicator showing the 5 pipeline stages
   Highlight the current_agent stage while scan is running
5. AlertDetail: make the install command copyable — add a copy button next to the code block
6. Add a small footer: "Powered by Backboard AI + OSV.dev"
7. Make sure the layout is responsive enough to not break at typical laptop screen sizes

Do NOT add animations, complex transitions, or anything that takes more than 5 minutes to implement.
Focus on making the demo path look clean: Dashboard → trigger scan → see alert → see AI reasoning → see fix.

Verify: walk through the full demo path end-to-end and confirm nothing is broken or ugly.
```

---

## Done When

- [ ] `npm run dev` starts and all 3 pages render
- [ ] Dashboard shows real repos from API
- [ ] Register form creates a repo
- [ ] Scan button triggers pipeline + shows live agent progress
- [ ] RepoDetail shows alert table with severity badges
- [ ] AlertDetail shows code snippet + AI reasoning + install command
- [ ] Copy button on install command works
- [ ] Error states show when backend is down
- [ ] Full demo path works end-to-end without console errors
