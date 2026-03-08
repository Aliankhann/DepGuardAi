from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class ScanRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    repo_id: int
    status: str
    current_agent: Optional[str]
    alert_count: int
    started_at: datetime
    completed_at: Optional[datetime]
    error_message: Optional[str]


class ScanStatusResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    status: str
    current_agent: Optional[str]
    alert_count: int
    error_message: Optional[str]


class ScanVerifyResponse(BaseModel):
    scan_id: int
    status: str
    total_alerts: int
    alerts_with_ai_analysis: int
    alerts_with_fallback: int
    alerts_with_usage_found: int
    alerts_without_usage: int
    alerts_missing_analysis: int
    alerts_missing_remediation: int
    pipeline_duration_seconds: Optional[float]
    coverage_pct: float  # alerts_with_ai_analysis / total_alerts * 100
