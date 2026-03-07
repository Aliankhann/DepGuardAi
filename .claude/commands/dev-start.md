Start both DepGuard dev servers.

1. Check that `backend/.venv` exists. If not, run: `cd backend && python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
2. Check that `backend/depguard.db` exists. If not, run: `cd backend && alembic upgrade head`
3. Start backend in background: `cd backend && source .venv/bin/activate && uvicorn app.main:app --reload --port 8000`
4. Check that `frontend/node_modules` exists. If not, run: `cd frontend && npm install`
5. Start frontend in background: `cd frontend && npm run dev`
6. Report both URLs: backend http://localhost:8000 and frontend http://localhost:5173
7. Confirm backend health: `curl -s http://localhost:8000/docs` should return HTML
