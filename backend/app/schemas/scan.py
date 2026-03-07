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
