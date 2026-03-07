# Database Schema

SQLite via SQLAlchemy ORM. Alembic for migrations.

---

## Repository

```python
class Repository(Base):
    __tablename__ = "repositories"
    id: int (PK)
    name: str
    path: str                        # local filesystem path
    ecosystem: str = "npm"
    language: str = "node"
    backboard_assistant_id: str | None  # set on first scan
    created_at: datetime
```

---

## ScanRun

```python
class ScanRun(Base):
    __tablename__ = "scan_runs"
    id: int (PK)
    repo_id: int (FK → repositories.id)
    status: str  # pending | scanning | analyzing | complete | failed
    current_agent: str | None  # which agent is active right now
    alert_count: int = 0       # denormalized, set on completion
    started_at: datetime
    completed_at: datetime | None
    error_message: str | None
```

---

## Dependency

```python
class Dependency(Base):
    __tablename__ = "dependencies"
    id: int (PK)
    repo_id: int (FK → repositories.id)
    scan_id: int (FK → scan_runs.id)
    name: str
    version: str
    ecosystem: str = "npm"
```

---

## Alert

```python
class Alert(Base):
    __tablename__ = "alerts"
    id: int (PK)
    scan_id: int (FK → scan_runs.id)
    repo_id: int (FK → repositories.id)
    dependency_id: int (FK → dependencies.id)
    vuln_id: str          # e.g. "GHSA-xxxx" or "CVE-xxxx"
    severity: str         # LOW | MEDIUM | HIGH | CRITICAL
    summary: str
    osv_data: dict        # full OSV response as JSON (use JSON column type)
```

---

## UsageLocation

```python
class UsageLocation(Base):
    __tablename__ = "usage_locations"
    id: int (PK)
    alert_id: int (FK → alerts.id)
    file_path: str        # relative to repo root
    line_number: int
    snippet: str          # 3-line context around the import
    import_type: str      # "esm" | "cjs" | "symbol"
    context_tags: list    # JSON array — e.g. ["auth", "HIGH_SENSITIVITY"]
```

---

## Analysis

```python
class Analysis(Base):
    __tablename__ = "analyses"
    id: int (PK)
    alert_id: int (FK → alerts.id, unique)
    risk_level: str       # low | medium | high | critical
    confidence: str       # low | medium | high
    reasoning: str
    business_impact: str
    recommended_fix: str
    backboard_thread_id: str | None  # null = fallback analysis used
    created_at: datetime
```

---

## Remediation

```python
class Remediation(Base):
    __tablename__ = "remediations"
    id: int (PK)
    alert_id: int (FK → alerts.id, unique)
    safe_version: str | None
    install_command: str  # e.g. "npm install lodash@4.17.21"
    checklist: list       # JSON array of strings
    created_at: datetime
```

---

## Relationships Summary

```
Repository ──< ScanRun
Repository ──< Dependency
Repository ──< Alert
ScanRun    ──< Dependency
ScanRun    ──< Alert
Dependency ──< Alert
Alert      ──< UsageLocation
Alert      ──1 Analysis
Alert      ──1 Remediation
```
