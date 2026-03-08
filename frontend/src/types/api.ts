// TypeScript API types matching DepGuard backend schema (skills/schema.md)

export interface Repository {
  id: number;
  name: string;
  path: string;
  ecosystem: string;
  language: string;
  backboard_assistant_id?: string | null;
  created_at: string;
}

export interface ScanRun {
  id: number;
  repo_id: number;
  status: "pending" | "scanning" | "analyzing" | "complete" | "failed";
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

export interface Alert {
  id: number;
  vuln_id: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  summary: string;
  dependency: Dependency;
  usage_location_count?: number;
}

export interface UsageLocation {
  id: number;
  file_path: string;
  line_number: number;
  snippet: string;
  import_type: "esm" | "cjs" | "symbol";
  context_tags: string[];
}

export interface Analysis {
  id: number;
  risk_level: "low" | "medium" | "high" | "critical";
  confidence: "low" | "medium" | "high";
  reasoning: string;
  business_impact: string;
  recommended_fix: string;
  backboard_thread_id: string | null;
  created_at: string;
}

export interface Remediation {
  id: number;
  safe_version: string | null;
  install_command: string;
  checklist: string[];
  created_at: string;
}

export interface AlertDetail extends Alert {
  usage_locations: UsageLocation[];
  analysis: Analysis;
  remediation: Remediation;
}
