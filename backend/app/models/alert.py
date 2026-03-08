from sqlalchemy import Column, ForeignKey, Integer, JSON, String

from app.db import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    repo_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    dependency_id = Column(Integer, ForeignKey("dependencies.id"), nullable=False)
    vuln_id = Column(String, nullable=False)
    severity = Column(String, default="MEDIUM")
    summary = Column(String, nullable=False)
    osv_data = Column(JSON, nullable=True)
    dependency_investigation = Column(JSON, nullable=True)  # structured vuln intelligence from depvuln_agent
