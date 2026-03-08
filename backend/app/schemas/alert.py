from typing import Optional

from pydantic import BaseModel, ConfigDict

from app.schemas.remediation import RemediationResponse


class UsageLocationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    file_path: str
    line_number: int
    snippet: str
    import_type: str
    context_tags: list[str]
    # AI-enriched context fields — null in fallback mode
    sensitivity_level: Optional[str] = None
    sensitive_surface_reason: Optional[str] = None
    subsystem_labels: Optional[list[str]] = None
    user_input_proximity: Optional[str] = None


class AnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    risk_level: str
    confidence: str
    reasoning: str
    business_impact: str
    recommended_fix: str
    urgency: Optional[str]  # "immediate" | "this-sprint" | "planned" | "low-priority"
    analysis_source: str    # "backboard_ai" | "fallback"
    backboard_thread_id: Optional[str]
    exploitability_score: Optional[int]   # 0-100 (AI-assigned numeric rating)
    confidence_score: Optional[int]       # 0-100 (AI certainty)
    blast_radius: Optional[str]
    temp_mitigation: Optional[str]
    exploitability: Optional[str]         # "likely" | "possible" | "unlikely" (deterministic pre-assessment)
    evidence_strength: Optional[str]      # "high" | "medium" | "low"
    exploitability_reason: Optional[str]
    detected_functions: Optional[list[str]]
    blast_radius_label: Optional[str]     # "isolated" | "module" | "subsystem" (deterministic)
    confidence_percent: Optional[int]     # 0-100 deterministic evidence score
    confidence_reasons: Optional[list[str]]  # which signals contributed


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
    remediation: Optional[RemediationResponse]
    dependency_investigation: Optional[dict] = None  # structured vuln intelligence from depvuln_agent
