import { useParams, useNavigate } from "react-router-dom";
import { Shield, ArrowLeft, Search, GitBranch, Brain, ShieldCheck, Wrench } from "lucide-react";
import type { Alert, ScanRun } from "@/types/api";

// Pipeline stages for the scan status indicator
const PIPELINE_STAGES = [
  { key: "scan_agent", label: "Scan", icon: Search },
  { key: "code_agent", label: "Trace", icon: GitBranch },
  { key: "context_agent", label: "Context", icon: Brain },
  { key: "risk_agent", label: "Analyze", icon: Brain },
  { key: "fix_agent", label: "Fix", icon: Wrench },
];

// Hardcoded placeholder data
const PLACEHOLDER_SCAN: ScanRun = {
  id: 1,
  repo_id: 1,
  status: "complete",
  current_agent: null,
  alert_count: 3,
  started_at: "2026-03-05T09:00:00Z",
  completed_at: "2026-03-05T09:01:12Z",
  error_message: null,
};

const PLACEHOLDER_ALERTS: Alert[] = [
  {
    id: 1,
    vuln_id: "GHSA-35jh-r3h4-6jhm",
    severity: "CRITICAL",
    summary: "Prototype Pollution in lodash — _.merge and _.set allow property injection via crafted input.",
    dependency: { id: 1, name: "lodash", version: "4.17.4", ecosystem: "npm" },
    usage_location_count: 3,
  },
  {
    id: 2,
    vuln_id: "CVE-2024-29041",
    severity: "HIGH",
    summary: "Open Redirect in express — res.redirect may allow redirection to untrusted URLs.",
    dependency: { id: 2, name: "express", version: "4.17.1", ecosystem: "npm" },
    usage_location_count: 1,
  },
  {
    id: 3,
    vuln_id: "CVE-2023-26159",
    severity: "MEDIUM",
    summary: "URL parsing inconsistency in follow-redirects may allow SSRF under certain configurations.",
    dependency: { id: 3, name: "follow-redirects", version: "1.15.2", ecosystem: "npm" },
    usage_location_count: 0,
  },
];

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-400 border-red-500/30",
  HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  LOW: "bg-blue-500/15 text-blue-400 border-blue-500/30",
};

const RepoDetail = () => {
  const { repoId } = useParams();
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-background">
      {/* Top Nav */}
      <nav className="fixed top-0 left-0 right-0 z-50 border-b border-border/50 bg-background/80 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <a href="/" className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-primary" />
            <span className="font-mono font-bold text-lg text-foreground">DepGuard</span>
          </a>
          <button
            onClick={() => navigate("/dashboard")}
            className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors font-mono"
          >
            <ArrowLeft className="w-4 h-4" />
            Dashboard
          </button>
        </div>
      </nav>

      <main className="pt-24 pb-16 max-w-6xl mx-auto px-6">
        {/* Repo Header */}
        <div className="mb-8">
          <h1 className="font-mono text-3xl font-bold text-foreground mb-2">ecommerce-app</h1>
          <p className="font-mono text-sm text-muted-foreground">/home/dev/projects/ecommerce-app</p>
        </div>

        {/* Scan Status Banner */}
        <div className="mb-10 rounded-lg border border-border bg-card p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-mono font-semibold text-foreground">Last Scan</h3>
              <p className="font-mono text-xs text-muted-foreground mt-1">
                Completed {new Date(PLACEHOLDER_SCAN.completed_at!).toLocaleString()} · {PLACEHOLDER_SCAN.alert_count} alerts
              </p>
            </div>
            <span className="px-3 py-1 rounded-full text-xs font-mono font-semibold bg-primary/15 text-primary border border-primary/30">
              Complete
            </span>
          </div>

          {/* Pipeline Stage Indicator */}
          <div className="flex items-center gap-1">
            {PIPELINE_STAGES.map((stage, i) => (
              <div key={stage.key} className="flex items-center flex-1">
                <div className="flex items-center gap-2 px-3 py-2 rounded-md bg-primary/10 border border-primary/20 w-full">
                  <stage.icon className="w-4 h-4 text-primary" />
                  <span className="font-mono text-xs text-primary">{stage.label}</span>
                  <ShieldCheck className="w-3 h-3 text-primary ml-auto" />
                </div>
                {i < PIPELINE_STAGES.length - 1 && (
                  <div className="w-4 h-px bg-primary/30 shrink-0" />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Alert Table */}
        <h2 className="font-mono text-2xl font-bold mb-6">Vulnerability Alerts</h2>
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border bg-secondary/30">
                <th className="text-left px-6 py-3 font-mono text-xs text-muted-foreground font-semibold uppercase tracking-wider">Package</th>
                <th className="text-left px-6 py-3 font-mono text-xs text-muted-foreground font-semibold uppercase tracking-wider">Version</th>
                <th className="text-left px-6 py-3 font-mono text-xs text-muted-foreground font-semibold uppercase tracking-wider">Severity</th>
                <th className="text-left px-6 py-3 font-mono text-xs text-muted-foreground font-semibold uppercase tracking-wider">CVE ID</th>
                <th className="text-left px-6 py-3 font-mono text-xs text-muted-foreground font-semibold uppercase tracking-wider">Locations</th>
              </tr>
            </thead>
            <tbody>
              {PLACEHOLDER_ALERTS.map((alert) => (
                <tr
                  key={alert.id}
                  onClick={() => navigate(`/alerts/${alert.id}`)}
                  className="border-b border-border hover:bg-primary/5 cursor-pointer transition-colors"
                >
                  <td className="px-6 py-4 font-mono text-sm font-semibold text-foreground">{alert.dependency.name}</td>
                  <td className="px-6 py-4 font-mono text-sm text-muted-foreground">{alert.dependency.version}</td>
                  <td className="px-6 py-4">
                    <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold border ${SEVERITY_STYLES[alert.severity]}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4 font-mono text-sm text-muted-foreground">{alert.vuln_id}</td>
                  <td className="px-6 py-4 font-mono text-sm text-muted-foreground">{alert.usage_location_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-border py-8 px-6 text-center">
        <p className="text-sm text-muted-foreground font-mono">
          Powered by Backboard AI + OSV.dev
        </p>
      </footer>
    </div>
  );
};

export default RepoDetail;
