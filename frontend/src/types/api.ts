export interface Repository {
  id: number;
  name: string;
  local_path?: string | null;
  repo_url?: string | null;
  ecosystem: string | null;
  language: string | null;
  created_at: string;
}

export interface ScanRun {
  id: number;
  repo_id: number;
  status: string;
  current_agent: string | null;
  alert_count: number;
  started_at: string;
  completed_at: string | null;
  error_message: string | null;
}

export interface Dependency {
  id: number;
  name: string;
  version: string;
  ecosystem: string;
}

export interface AlertSummary {
  id: number;
  vuln_id: string;
  severity: string;
  summary: string;
  dependency_name: string;
  dependency_version: string;
  usage_count: number;
  risk_level: string | null;
}

export interface UsageLocation {
  id: number;
  file_path: string;
  line_number: number;
  snippet: string;
  import_type: string;
  context_tags: string[];
}

export interface Analysis {
  id: number;
  risk_level: string;
  confidence: string;
  reasoning: string;
  business_impact: string;
  recommended_fix: string;
  backboard_thread_id?: string | null;
  urgency?: string | null;
  analysis_source?: string;
  exploitability_score?: number | null;
  confidence_score?: number | null;
  blast_radius?: string | null;
  temp_mitigation?: string | null;
  exploitability?: string | null;
  evidence_strength?: string | null;
  exploitability_reason?: string | null;
  detected_functions?: string[] | null;
  blast_radius_label?: string | null;
  affected_surfaces?: string[] | null;
  scope_clarity?: string | null;
  confidence_percent?: number | null;
  confidence_reasons?: string[] | null;
}

export interface ApplyFixResponse {
  applied: boolean;
  file_changed: string | null;
  old_line: string | null;
  new_line: string | null;
  message: string;
}

export interface Remediation {
  id: number;
  safe_version: string | null;
  install_command: string;
  checklist: string[];
  temporary_mitigation?: string | null;
  permanent_fix_summary?: string | null;
  review_note?: string | null;
  senior_review_urgency?: string | null;
}

export interface AlertDetail {
  id: number;
  vuln_id: string;
  severity: string;
  summary: string;
  dependency_name: string;
  dependency_version: string;
  vuln_aliases: string[];
  references: string[];
  usage_locations: UsageLocation[];
  analysis: Analysis | null;
  remediation: Remediation | null;
}
