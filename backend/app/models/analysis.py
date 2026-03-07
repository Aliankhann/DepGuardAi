from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String

from app.db import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False, unique=True)
    risk_level = Column(String, nullable=False)   # low | medium | high | critical
    confidence = Column(String, nullable=False)   # low | medium | high
    reasoning = Column(String, nullable=False)
    business_impact = Column(String, nullable=False)
    recommended_fix = Column(String, nullable=False)
    backboard_thread_id = Column(String, nullable=True)  # null = fallback used
    created_at = Column(DateTime, default=datetime.utcnow)
