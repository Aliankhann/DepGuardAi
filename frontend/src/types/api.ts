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
  import_type: "esm" | "cjs" | "symbol" | "python";
  context_tags: string[];
  // AI-enriched context fields — null in fallback mode
  sensitivity_level: string | null;
  sensitive_surface_reason: string | null;
  subsystem_labels: string[] | null;
  user_input_proximity: string | null;
}

export interface Analysis {
  id: number;
  risk_level: "low" | "medium" | "high" | "critical";
  confidence: "low" | "medium" | "high";
  reasoning: string;
  business_impact: string;
  recommended_fix: string;
  urgency: "immediate" | "this-sprint" | "planned" | "low-priority" | null;
  analysis_source: "backboard_ai" | "fallback";
  backboard_thread_id: string | null;
  exploitability_score: number | null;   // 0-100
  confidence_score: number | null;       // 0-100
  blast_radius: string | null;
  temp_mitigation: string | null;
  exploitability: "likely" | "possible" | "unlikely" | null;
  evidence_strength: "high" | "medium" | "low" | null;
  exploitability_reason: string | null;
  detected_functions: string[] | null;
  blast_radius_label: "isolated" | "module" | "subsystem" | null;
  affected_surfaces: string[] | null;
  scope_clarity: "high" | "medium" | "low" | null;
  confidence_percent: number | null;     // 0-100
  confidence_reasons: string[] | null;
}

export interface Remediation {
  id: number;
  safe_version: string | null;
  install_command: string;
  checklist: string[];
  created_at: string;
}

export interface AlertDetail {
  id: number;
  scan_id: number;
  repo_id: number;
  vuln_id: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  summary: string;
  dependency_name: string;
  dependency_version: string;
  vuln_aliases: string[];
  references: string[];
  usage_locations: UsageLocation[];
  analysis: Analysis | null;
  remediation: Remediation | null;
  dependency_investigation: Record<string, unknown> | null;
}
