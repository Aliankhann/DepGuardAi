from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class RemediationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: int
    safe_version: Optional[str]
    install_command: str
    checklist: list[str]
    temporary_mitigation: Optional[str]
    permanent_fix_summary: Optional[str]
    review_note: Optional[str]
    senior_review_urgency: Optional[str]
    created_at: datetime


class FinalizeRemediationRequest(BaseModel):
    senior_approved_fix: str
    rationale: str
