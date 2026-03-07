from typing import Optional

from pydantic import BaseModel, ConfigDict


class UsageLocationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    file_path: str
    line_number: int
    snippet: str
    import_type: str
    context_tags: list


class AnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    risk_level: str
    confidence: str
    reasoning: str
    business_impact: str
    recommended_fix: str
    backboard_thread_id: Optional[str]


class AlertSummary(BaseModel):
    id: int
    vuln_id: str
    severity: str
    summary: str
    dependency_name: str
    dependency_version: str
    usage_count: int
    risk_level: Optional[str]


class AlertDetail(BaseModel):
    id: int
    scan_id: int
    repo_id: int
    vuln_id: str
    severity: str
    summary: str
    dependency_name: str
    dependency_version: str
    vuln_aliases: list[str]
    references: list[str]
    usage_locations: list[UsageLocationResponse]
    analysis: Optional[AnalysisResponse]
