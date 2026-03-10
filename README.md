# DepGuard

**Memory-backed multi-agent AI system for dependency security analysis.**

DepGuard goes beyond traditional vulnerability scanners. Instead of just listing CVEs, it runs a full investigation pipeline — powered by Backboard AI — to determine whether a vulnerability actually poses real exploit risk in your specific codebase.

---

## How It Works

DepGuard runs a sequential 5-agent pipeline for every scan:

```
Scan Agent → Code Agent → Context Agent → Risk Agent → Fix Agent
```

| Agent | Responsibility |
|-------|---------------|
| **Scan Agent** | Reads dependencies, queries OSV.dev for known vulnerabilities |
| **Code Agent** | Finds where each vulnerable package is actually used in the codebase |
| **Context Agent** | Tags usage locations with sensitivity labels (auth, network, file I/O, etc.) |
| **Risk Agent** | Sends evidence to Backboard AI for contextual risk assessment |
| **Fix Agent** | Generates safe version upgrades and a step-by-step remediation checklist |

The **Risk Agent** uses Backboard's memory model — one persistent Assistant per repository — so every scan builds on previous findings. Investigations get richer over time.

---

## Tech Stack

| Layer | Stack |
|-------|-------|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui, React Query |
| Backend | Python 3.12, FastAPI, SQLAlchemy, SQLite, Alembic |
| AI | Backboard AI (`claude-sonnet-4-6`) |
| Vulnerability Data | OSV.dev (free, no API key required) |
| Auth | Auth0 |

---

## Getting Started

### Prerequisites

- Python 3.12+
- Node.js 18+
- A [Backboard AI](https://backboard.ai) API key

### 1. Clone the repo

```bash
git clone https://github.com/your-org/depguard.git
cd depguard
```

### 2. Set up the backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Copy the environment template and fill in your values:

```bash
cp .env.example .env
```

```env
BACKBOARD_API_KEY=your_backboard_key_here
DATABASE_URL=sqlite:///./depguard.db
CORS_ORIGINS=http://localhost:5173
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_API_AUDIENCE=your-api-audience
```

Run database migrations and start the server:

```bash
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

### 3. Set up the frontend

```bash
cd frontend
npm install
```

Create a `.env` file:

```env
VITE_API_URL=http://localhost:8000
```

Start the dev server:

```bash
npm run dev
```

The app will be available at `http://localhost:5173`.

---

## Quick Demo

Seed the database with a demo repository and fixture vulnerabilities:

```bash
curl -X POST http://localhost:8000/demo/seed
```

Then open the UI and trigger a scan on the demo repo to see the full pipeline in action.

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/repos` | Register a repository |
| `GET` | `/repos` | List all repositories |
| `GET` | `/repos/{id}` | Get repository details |
| `POST` | `/repos/{id}/scan` | Trigger a new scan |
| `GET` | `/repos/{id}/scans` | List scans for a repo |
| `GET` | `/repos/{id}/alerts` | List alerts for a repo |
| `GET` | `/scans/{id}/status` | Poll scan status |
| `GET` | `/alerts/{id}` | Get alert details |
| `GET` | `/alerts/{id}/remediation` | Get fix guidance |
| `POST` | `/demo/seed` | Seed demo data |
| `GET` | `/health` | Health check |

Interactive API docs are available at `http://localhost:8000/docs` when the backend is running.

---

## Scan Status Flow

```
pending → scanning → analyzing → complete
                               ↘ failed
```

Each scan tracks which agent is currently running via the `current_agent` field. Orphaned scans (e.g. from a crashed server) are automatically marked as `failed` on startup.

---

## Risk Output

The Risk Agent produces a structured JSON assessment for every alert:

```json
{
  "risk_level": "low | medium | high | critical",
  "confidence": "low | medium | high",
  "reasoning": "Explanation referencing actual file paths and snippets",
  "business_impact": "What could go wrong in production",
  "recommended_fix": "Specific upgrade or mitigation steps"
}
```

---

## Project Structure

```
depguard/
├── backend/
│   └── app/
│       ├── main.py                    # FastAPI app entry point
│       ├── config.py                  # Environment config
│       ├── db.py                      # Database setup
│       ├── routers/                   # API route handlers
│       ├── models/                    # SQLAlchemy ORM models
│       ├── schemas/                   # Pydantic request/response schemas
│       └── services/
│           ├── backboard_service.py   # Backboard AI integration
│           ├── agent_orchestrator.py  # Pipeline coordination
│           └── agents/                # The 5 pipeline agents
└── frontend/
    └── src/
        ├── pages/                     # Dashboard, RepoDetail, AlertDetail
        ├── components/                # UI components
        ├── hooks/                     # React Query hooks
        └── types/                     # TypeScript types
```

---

## Design Principles

1. **Evidence before reasoning** — code snippets are extracted and passed to the AI before any risk assessment is made
2. **AI outputs are grounded** — the Risk Agent must reference actual file paths and snippets in its reasoning
3. **Memory accumulates** — the Backboard Assistant persists between scans, so the AI gets smarter about your repo over time
4. **Agents are modular** — each agent can be tested in isolation with fixture data
5. **Graceful degradation** — if OSV.dev or Backboard is unreachable, the pipeline falls back to fixture data and static analysis

---

## Development

See [`skills/dev-workflow.md`](skills/dev-workflow.md) for detailed development commands, pipeline testing procedures, and agent isolation testing.

See [`skills/agents.md`](skills/agents.md) for each agent's input/output contract.

See [`skills/backboard.md`](skills/backboard.md) for the Backboard integration patterns.
