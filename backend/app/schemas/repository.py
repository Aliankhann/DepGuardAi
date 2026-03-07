from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class RepositoryCreate(BaseModel):
    name: str
    repo_url: Optional[str] = None
    local_path: Optional[str] = None
    ecosystem: str = "npm"
    language: str = "node"


class RepositoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    repo_url: Optional[str]
    local_path: Optional[str]
    ecosystem: str
    language: str
    backboard_assistant_id: Optional[str]
    created_at: datetime
