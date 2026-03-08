import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Shield, ArrowLeft, FileCode2, Tag, Brain, Wrench, Copy, Check, ShieldAlert, AlertTriangle } from "lucide-react";
import { useAuth0 } from "@auth0/auth0-react";
import { fetchAlertDetail } from "@/lib/api";
import type { AlertDetail as AlertDetailType } from "@/types/api";

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-400 border-red-500/30",
  HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  LOW: "bg-blue-500/15 text-blue-400 border-blue-500/30",
};

const RISK_STYLES: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
};

const CONTEXT_TAG_STYLES: Record<string, string> = {
  auth: "bg-red-500/15 text-red-400 border-red-500/30",
  HIGH_SENSITIVITY: "bg-red-500/15 text-red-400 border-red-500/30",
  payment: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  admin: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  api: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  MEDIUM_SENSITIVITY: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  util: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  test: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  LOW_SENSITIVITY: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  unknown: "bg-secondary text-secondary-foreground border-border",
};

const AlertDetail = () => {
  const { alertId } = useParams();
  const navigate = useNavigate();
  const { getAccessTokenSilently } = useAuth0();
  
  const [alert, setAlert] = useState<AlertDetailType | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const loadData = async () => {
      if (!alertId) return;
      try {
        setLoading(true);
        const token = await getAccessTokenSilently();
        const data = await fetchAlertDetail(token, parseInt(alertId, 10));
        setAlert(data);
      } catch (err: any) {
        setError(err);
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, [alertId, getAccessTokenSilently]);

  const handleCopy = () => {
    if (!alert?.remediation?.install_command) return;
    navigator.clipboard.writeText(alert.remediation.install_command);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (error || !alert) {
    return (
      <div className="min-h-screen bg-background pt-24 px-6 max-w-6xl mx-auto">
        <div className="mb-8 p-4 bg-red-500/10 border border-red-500/50 rounded-lg flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-500 mt-0.5" />
          <div>
            <h1 className="font-bold text-red-500">Failed to load alert detail</h1>
            <p className="text-sm text-red-400 mt-1">{error?.message || "Not found"}</p>
          </div>
        </div>
        <button onClick={() => navigate(-1)} className="text-primary hover:underline font-mono text-sm">
          ← Go Back
        </button>
      </div>
    );
  }

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
            onClick={() => navigate(-1)}
            className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors font-mono"
          >
            <ArrowLeft className="w-4 h-4" />
            Back
          </button>
        </div>
      </nav>

      <main className="pt-24 pb-16 max-w-6xl mx-auto px-6 space-y-8">
        {/* Alert Header */}
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="flex items-start justify-between mb-4">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <ShieldAlert className="w-6 h-6 text-red-400" />
                <h1 className="font-mono text-2xl font-bold text-foreground">
                  {alert.dependency_name}@{alert.dependency_version}
                </h1>
              </div>
              <p className="font-mono text-sm text-muted-foreground">{alert.vuln_id}</p>
            </div>
            <span
              className={`inline-flex px-3 py-1 rounded-full text-xs font-mono font-semibold border uppercase ${SEVERITY_STYLES[alert.severity] || "bg-secondary text-secondary-foreground"}`}
            >
              {alert.severity}
            </span>
          </div>
          <p className="text-sm text-muted-foreground leading-relaxed">{alert.summary}</p>
        </div>

        {/* Code Locations */}
        {alert.usage_locations.length > 0 && (
          <div className="rounded-lg border border-border bg-card p-6">
            <h2 className="font-mono text-lg font-semibold mb-4 flex items-center gap-2">
              <FileCode2 className="w-5 h-5 text-primary" />
              Code Locations ({alert.usage_locations.length})
            </h2>
            <div className="space-y-4">
              {alert.usage_locations.map((loc) => (
                <div key={loc.id} className="rounded-md border border-border bg-secondary/20 overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-secondary/30">
                    <span className="font-mono text-sm text-foreground">
                      {loc.file_path}:{loc.line_number}
                    </span>
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-xs font-mono bg-secondary text-secondary-foreground border border-border">
                        {loc.import_type}
                      </span>
                    </div>
                  </div>
                  <pre className="p-4 font-mono text-sm text-foreground overflow-x-auto leading-relaxed">
                    {loc.snippet}
                  </pre>
                  {loc.context_tags && loc.context_tags.length > 0 && (
                    <div className="px-4 py-2 border-t border-border flex items-center gap-2">
                      <Tag className="w-3 h-3 text-muted-foreground" />
                      {loc.context_tags.map((tag) => (
                        <span
                          key={tag}
                          className={`px-2 py-0.5 rounded-full text-xs font-mono border ${CONTEXT_TAG_STYLES[tag] || CONTEXT_TAG_STYLES.unknown}`}
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* AI Analysis */}
        {alert.analysis && (
          <div className="rounded-lg border border-border bg-card p-6">
            <h2 className="font-mono text-lg font-semibold mb-4 flex items-center gap-2">
              <Brain className="w-5 h-5 text-primary" />
              AI Investigation
              {alert.analysis.backboard_thread_id ? (
                <span className="ml-2 px-2 py-0.5 rounded text-xs font-mono bg-primary/10 text-primary border border-primary/20">
                  Backboard AI
                </span>
              ) : (
                <span className="ml-2 px-2 py-0.5 rounded text-xs font-mono bg-yellow-500/10 text-yellow-400 border border-yellow-500/20">
                  AI analysis unavailable — fallback used
                </span>
              )}
            </h2>

            <div className="grid md:grid-cols-2 gap-4 mb-6">
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm text-muted-foreground">Risk Level:</span>
                <span
                  className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold border uppercase ${RISK_STYLES[alert.analysis.risk_level.toLowerCase()] || "bg-secondary text-secondary-foreground"}`}
                >
                  {alert.analysis.risk_level}
                </span>
              </div>
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm text-muted-foreground">Confidence:</span>
                <span className="font-mono text-sm text-foreground font-semibold capitalize">
                  {alert.analysis.confidence}
                </span>
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <h4 className="font-mono text-sm font-semibold text-muted-foreground mb-2">Reasoning</h4>
                <p className="text-sm text-foreground leading-relaxed">{alert.analysis.reasoning}</p>
              </div>
              <div>
                <h4 className="font-mono text-sm font-semibold text-muted-foreground mb-2">Business Impact</h4>
                <p className="text-sm text-foreground leading-relaxed">{alert.analysis.business_impact}</p>
              </div>
              <div>
                <h4 className="font-mono text-sm font-semibold text-muted-foreground mb-2">Recommended Fix</h4>
                <p className="text-sm text-foreground leading-relaxed">{alert.analysis.recommended_fix}</p>
              </div>
            </div>
          </div>
        )}

        {/* Remediation */}
        {alert.remediation && (
          <div className="rounded-lg border border-border bg-card p-6">
            <h2 className="font-mono text-lg font-semibold mb-4 flex items-center gap-2">
              <Wrench className="w-5 h-5 text-primary" />
              Remediation
            </h2>

            {alert.remediation.safe_version && (
              <p className="font-mono text-sm text-muted-foreground mb-3">
                Safe version: <span className="text-primary font-semibold">{alert.remediation.safe_version}</span>
              </p>
            )}

            {/* Install command */}
            <div className="relative rounded-md border border-border bg-secondary/30 mb-6">
              <pre className="p-4 font-mono text-sm text-primary pr-16">{alert.remediation.install_command}</pre>
              <button
                onClick={handleCopy}
                className="absolute top-3 right-3 p-2 rounded-md hover:bg-secondary transition-colors"
                title="Copy to clipboard"
              >
                {copied ? (
                  <Check className="w-4 h-4 text-primary" />
                ) : (
                  <Copy className="w-4 h-4 text-muted-foreground" />
                )}
              </button>
            </div>

            {/* Checklist */}
            {alert.remediation.checklist && alert.remediation.checklist.length > 0 && (
              <>
                <h4 className="font-mono text-sm font-semibold text-muted-foreground mb-3">Verification Checklist</h4>
                <ul className="space-y-2">
                  {alert.remediation.checklist.map((item, i) => (
                    <li key={i} className="flex items-start gap-3">
                      <div className="mt-0.5 w-4 h-4 rounded border border-border bg-secondary shrink-0 flex items-center justify-center">
                        <Check className="w-3 h-3 text-muted-foreground opacity-30" />
                      </div>
                      <span className="text-sm text-foreground">{item}</span>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        )}
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

export default AlertDetail;
