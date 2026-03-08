from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String

from app.db import Base


class Remediation(Base):
    __tablename__ = "remediations"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False, unique=True)
    safe_version = Column(String, nullable=True)
    install_command = Column(String, nullable=False)
    checklist = Column(JSON, default=list)
    temporary_mitigation = Column(String, nullable=True)
    permanent_fix_summary = Column(String, nullable=True)
    review_note = Column(String, nullable=True)
    senior_review_urgency = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
