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
}

export interface Remediation {
  id: number;
  safe_version: string | null;
  install_command: string;
  checklist: string[];
  temporary_mitigation?: string | null;
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
