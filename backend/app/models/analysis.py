from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String

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
    urgency = Column(String, nullable=True)   # immediate | this-sprint | planned | low-priority
    backboard_thread_id = Column(String, nullable=True)  # null = fallback used
    analysis_source = Column(String, nullable=False, default="backboard_ai")  # "backboard_ai" | "fallback"
    exploitability_score = Column(Integer, nullable=True)   # 0-100: 0=not exploitable, 100=trivially exploitable
    confidence_score = Column(Integer, nullable=True)       # 0-100: certainty of this assessment
    blast_radius = Column(String, nullable=True)            # plain-English scope of impact if exploited
    temp_mitigation = Column(String, nullable=True)         # immediate action to reduce risk before upgrade
    exploitability = Column(String, nullable=True)           # "likely" | "possible" | "unlikely" (deterministic pre-assessment)
    evidence_strength = Column(String, nullable=True)        # "high" | "medium" | "low"
    exploitability_reason = Column(String, nullable=True)    # human-readable explanation of the verdict
    detected_functions = Column(JSON, nullable=True)         # list[str] of dangerous function patterns found in snippets
    blast_radius_label = Column(String, nullable=True)       # "isolated" | "module" | "subsystem" (deterministic)
    confidence_percent = Column(Integer, nullable=True)      # 0-100 deterministic evidence score
    confidence_reasons = Column(JSON, nullable=True)         # list[str] of contributing signals
    created_at = Column(DateTime, default=datetime.utcnow)
