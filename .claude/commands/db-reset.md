Reset the DepGuard database and apply fresh migrations.

1. Stop any running uvicorn processes that may hold a lock on the DB
2. Delete `backend/depguard.db` if it exists
3. Run: `cd backend && source .venv/bin/activate && alembic upgrade head`
4. List all created tables: `cd backend && python -c "from app.db import engine; from sqlalchemy import inspect; print(inspect(engine).get_table_names())"`
5. Confirm all expected tables exist: repositories, scan_runs, dependencies, alerts, usage_locations, analyses, remediations
6. Report success or any migration errors
