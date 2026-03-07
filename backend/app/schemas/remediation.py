from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class RemediationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: int
    safe_version: Optional[str]
    install_command: str
    checklist: list
    created_at: datetime
