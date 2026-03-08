import sys
import os

# Ensure 'app' is importable from the project root when running pytest
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

import app.models  # noqa: F401 — registers all ORM models with Base.metadata
from app.db import Base, get_db
from app.core.auth import verify_token


# ---------------------------------------------------------------------------
# Shared DB fixtures for router tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def test_engine():
    """Named shared in-memory SQLite engine for the test session.

    Uses 'file:testmemdb?mode=memory&cache=shared&uri=true' so that all
    connections within the process share the same in-memory database.
    Plain 'sqlite:///:memory:' creates a separate DB per connection, which
    means tables created in one connection are invisible to the next.
    """
    engine = create_engine(
        "sqlite:///file:testmemdb?mode=memory&cache=shared&uri=true",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def db_session(test_engine):
    """Fresh session per test — rolled back after each test for isolation."""
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def client(db_session):
    """TestClient with get_db and verify_token overridden.
    Use this for all authenticated router tests.
    """
    from app.main import app

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[verify_token] = lambda: {"sub": "test-user"}

    yield TestClient(app, raise_server_exceptions=True)

    app.dependency_overrides.clear()


@pytest.fixture
def unauth_client(db_session):
    """TestClient with get_db overridden but NO verify_token override.
    Use this to test that unauthenticated requests are rejected.
    """
    from app.main import app

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    yield TestClient(app, raise_server_exceptions=False)

    app.dependency_overrides.clear()
