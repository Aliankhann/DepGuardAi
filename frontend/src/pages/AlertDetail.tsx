import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Shield, ArrowLeft, FileCode2, Tag, Brain, Wrench, Copy, Check,
  ShieldAlert, AlertTriangle, Zap, Radio, ChevronRight, Loader2,
  CircleCheck, XCircle,
} from "lucide-react";
import { useAuth0 } from "@auth0/auth0-react";
import { fetchAlertDetail, applyFix } from "@/lib/api";
import type { AlertDetail as AlertDetailType, ApplyFixResponse } from "@/types/api";

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

const BLAST_RADIUS_CONFIG: Record<string, { label: string; color: string; bar: string; rings: number }> = {
  isolated:  { label: "Isolated",  color: "text-blue-400",   bar: "bg-blue-500",   rings: 1 },
  module:    { label: "Module",    color: "text-yellow-400", bar: "bg-yellow-500", rings: 2 },
  subsystem: { label: "Subsystem", color: "text-red-400",    bar: "bg-red-500",    rings: 3 },
};

const EXPLOITABILITY_CONFIG: Record<string, { color: string; dot: string }> = {
  likely:   { color: "text-red-400",    dot: "bg-red-500" },
  possible: { color: "text-yellow-400", dot: "bg-yellow-500" },
  unlikely: { color: "text-blue-400",   dot: "bg-blue-500" },
};

const URGENCY_STYLES: Record<string, string> = {
  immediate:     "bg-red-500/15 text-red-400 border-red-500/30",
  "this-sprint": "bg-orange-500/15 text-orange-400 border-orange-500/30",
  planned:       "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  "low-priority":"bg-blue-500/15 text-blue-400 border-blue-500/30",
};

// ── Blast Radius visual: concentric rings ─────────────────────────────────
function BlastRings({ rings }: { rings: number }) {
  const sizes = ["w-16 h-16", "w-11 h-11", "w-6 h-6"];
  const opacities = ["opacity-20", "opacity-40", "opacity-80"];
  const colors = [
    rings >= 1 ? "border-current" : "border-border",
    rings >= 2 ? "border-current" : "border-border",
    rings >= 3 ? "border-current" : "border-border",
  ];
  return (
    <div className="relative flex items-center justify-center w-16 h-16">
      {[0, 1, 2].map((i) => (
        <div
          key={i}
          className={`absolute rounded-full border-2 ${sizes[i]} ${colors[i]} ${opacities[i]}`}
        />
      ))}
      <Radio className="w-3 h-3 text-current z-10" />
    </div>
  );
}

// ── Score bar ─────────────────────────────────────────────────────────────
function ScoreBar({ value, color }: { value: number; color: string }) {
  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-1.5 bg-secondary rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${color}`}
          style={{ width: `${value}%` }}
        />
      </div>
      <span className="font-mono text-xs text-muted-foreground w-8 text-right">{value}</span>
    </div>
  );
}

const AlertDetail = () => {
  const { alertId } = useParams();
  const navigate = useNavigate();
  const { getAccessTokenSilently } = useAuth0();

  const [alert, setAlert] = useState<AlertDetailType | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [copied, setCopied] = useState(false);

  // Apply fix state
  const [applyState, setApplyState] = useState<"idle" | "loading" | "done">("idle");
  const [applyResult, setApplyResult] = useState<ApplyFixResponse | null>(null);
  const [applyError, setApplyError] = useState<string | null>(null);

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

  const handleApplyFix = async () => {
    if (!alertId) return;
    setApplyState("loading");
    setApplyError(null);
    try {
      const token = await getAccessTokenSilently();
      const result = await applyFix(token, parseInt(alertId, 10));
      setApplyResult(result);
      setApplyState("done");
    } catch (err: any) {
      setApplyError(err.message ?? "Unknown error");
      setApplyState("idle");
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
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

  const analysis = alert.analysis;
  const blastCfg = BLAST_RADIUS_CONFIG[analysis?.blast_radius_label ?? ""] ?? null;
  const exploitCfg = EXPLOITABILITY_CONFIG[analysis?.exploitability ?? ""] ?? null;

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

      <main className="pt-24 pb-16 max-w-6xl mx-auto px-6 space-y-6">

        {/* ── Alert Header ───────────────────────────────────────────────── */}
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="flex items-start justify-between mb-4">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <ShieldAlert className="w-6 h-6 text-red-400" />
                <h1 className="font-mono text-2xl font-bold text-foreground">
                  {alert.dependency_name}@{alert.dependency_version}
                </h1>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <p className="font-mono text-sm text-muted-foreground">{alert.vuln_id}</p>
                {alert.vuln_aliases.map((alias) => (
                  <span key={alias} className="font-mono text-xs text-muted-foreground/60">
                    · {alias}
                  </span>
                ))}
              </div>
            </div>
            <div className="flex items-center gap-2">
              {analysis?.urgency && (
                <span className={`hidden sm:inline-flex px-2.5 py-1 rounded-full text-xs font-mono font-semibold border ${URGENCY_STYLES[analysis.urgency] ?? ""}`}>
                  {analysis.urgency.replace("-", " ")}
                </span>
              )}
              <span className={`inline-flex px-3 py-1 rounded-full text-xs font-mono font-semibold border uppercase ${SEVERITY_STYLES[alert.severity] ?? "bg-secondary text-secondary-foreground"}`}>
                {alert.severity}
              </span>
            </div>
          </div>
          <p className="text-sm text-muted-foreground leading-relaxed">{alert.summary}</p>
        </div>

        {/* ── Two-column: Blast Radius + Exploitability ─────────────────── */}
        {analysis && (analysis.blast_radius_label || analysis.exploitability) && (
          <div className="grid md:grid-cols-2 gap-6">

            {/* Blast Radius */}
            {blastCfg && (
              <div className="rounded-lg border border-border bg-card p-6">
                <h2 className="font-mono text-sm font-semibold text-muted-foreground mb-4 flex items-center gap-2 uppercase tracking-wider">
                  <Radio className="w-4 h-4" />
                  Blast Radius
                </h2>
                <div className={`flex items-center gap-5 mb-4 ${blastCfg.color}`}>
                  <BlastRings rings={blastCfg.rings} />
                  <div>
                    <p className={`font-mono text-xl font-bold ${blastCfg.color}`}>{blastCfg.label}</p>
                    {analysis.scope_clarity && (
                      <p className="font-mono text-xs text-muted-foreground mt-0.5">
                        Scope clarity: <span className="capitalize">{analysis.scope_clarity}</span>
                      </p>
                    )}
                  </div>
                </div>
                {analysis.blast_radius && (
                  <p className="text-sm text-muted-foreground leading-relaxed mb-4">{analysis.blast_radius}</p>
                )}
                {analysis.affected_surfaces && analysis.affected_surfaces.length > 0 && (
                  <div className="flex flex-wrap gap-2">
                    {analysis.affected_surfaces.map((surface) => (
                      <span
                        key={surface}
                        className={`px-2 py-0.5 rounded-full text-xs font-mono border ${CONTEXT_TAG_STYLES[surface] ?? CONTEXT_TAG_STYLES.unknown}`}
                      >
                        {surface}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Exploitability */}
            {exploitCfg && (
              <div className="rounded-lg border border-border bg-card p-6">
                <h2 className="font-mono text-sm font-semibold text-muted-foreground mb-4 flex items-center gap-2 uppercase tracking-wider">
                  <Zap className="w-4 h-4" />
                  Exploitability
                </h2>
                <div className="flex items-center gap-3 mb-4">
                  <span className={`w-2.5 h-2.5 rounded-full ${exploitCfg.dot}`} />
                  <span className={`font-mono text-xl font-bold capitalize ${exploitCfg.color}`}>
                    {analysis.exploitability}
                  </span>
                </div>

                {analysis.exploitability_reason && (
                  <p className="text-sm text-muted-foreground leading-relaxed mb-4">{analysis.exploitability_reason}</p>
                )}

                {analysis.exploitability_score != null && (
                  <div className="mb-3">
                    <p className="font-mono text-xs text-muted-foreground mb-1.5">Exploitability score</p>
                    <ScoreBar value={analysis.exploitability_score} color={exploitCfg.dot} />
                  </div>
                )}

                {analysis.confidence_percent != null && (
                  <div className="mb-3">
                    <p className="font-mono text-xs text-muted-foreground mb-1.5">Evidence confidence</p>
                    <ScoreBar value={analysis.confidence_percent} color="bg-primary" />
                  </div>
                )}

                {analysis.detected_functions && analysis.detected_functions.length > 0 && (
                  <div className="mt-4">
                    <p className="font-mono text-xs text-muted-foreground mb-2">Detected call sites</p>
                    <div className="space-y-1">
                      {analysis.detected_functions.map((fn) => (
                        <div key={fn} className="flex items-center gap-2">
                          <ChevronRight className="w-3 h-3 text-muted-foreground shrink-0" />
                          <code className="font-mono text-xs text-foreground">{fn}</code>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* ── Code Locations ─────────────────────────────────────────────── */}
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
                    <span className="px-2 py-0.5 rounded text-xs font-mono bg-secondary text-secondary-foreground border border-border">
                      {loc.import_type}
                    </span>
                  </div>
                  <pre className="p-4 font-mono text-sm text-foreground overflow-x-auto leading-relaxed">
                    {loc.snippet}
                  </pre>
                  {loc.context_tags && loc.context_tags.length > 0 && (
                    <div className="px-4 py-2 border-t border-border flex items-center gap-2 flex-wrap">
                      <Tag className="w-3 h-3 text-muted-foreground shrink-0" />
                      {loc.context_tags.map((tag) => (
                        <span
                          key={tag}
                          className={`px-2 py-0.5 rounded-full text-xs font-mono border ${CONTEXT_TAG_STYLES[tag] ?? CONTEXT_TAG_STYLES.unknown}`}
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

        {/* ── AI Investigation ───────────────────────────────────────────── */}
        {analysis && (
          <div className="rounded-lg border border-border bg-card p-6">
            <h2 className="font-mono text-lg font-semibold mb-4 flex items-center gap-2">
              <Brain className="w-5 h-5 text-primary" />
              AI Investigation
              {analysis.backboard_thread_id ? (
                <span className="ml-2 px-2 py-0.5 rounded text-xs font-mono bg-primary/10 text-primary border border-primary/20">
                  Backboard AI
                </span>
              ) : (
                <span className="ml-2 px-2 py-0.5 rounded text-xs font-mono bg-yellow-500/10 text-yellow-400 border border-yellow-500/20">
                  fallback mode
                </span>
              )}
            </h2>

            <div className="grid md:grid-cols-2 gap-4 mb-6">
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm text-muted-foreground">Risk Level:</span>
                <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold border uppercase ${RISK_STYLES[analysis.risk_level.toLowerCase()] ?? "bg-secondary text-secondary-foreground"}`}>
                  {analysis.risk_level}
                </span>
              </div>
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm text-muted-foreground">Confidence:</span>
                <span className="font-mono text-sm text-foreground font-semibold capitalize">
                  {analysis.confidence}
                </span>
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <h4 className="font-mono text-sm font-semibold text-muted-foreground mb-2">Reasoning</h4>
                <p className="text-sm text-foreground leading-relaxed">{analysis.reasoning}</p>
              </div>
              <div>
                <h4 className="font-mono text-sm font-semibold text-muted-foreground mb-2">Business Impact</h4>
                <p className="text-sm text-foreground leading-relaxed">{analysis.business_impact}</p>
              </div>
              <div>
                <h4 className="font-mono text-sm font-semibold text-muted-foreground mb-2">Recommended Fix</h4>
                <p className="text-sm text-foreground leading-relaxed">{analysis.recommended_fix}</p>
              </div>
              {analysis.temp_mitigation && (
                <div className="rounded-md border border-yellow-500/20 bg-yellow-500/5 p-4">
                  <h4 className="font-mono text-sm font-semibold text-yellow-400 mb-2">Temporary Mitigation</h4>
                  <p className="text-sm text-foreground leading-relaxed">{analysis.temp_mitigation}</p>
                </div>
              )}
              {analysis.confidence_reasons && analysis.confidence_reasons.length > 0 && (
                <div>
                  <h4 className="font-mono text-sm font-semibold text-muted-foreground mb-2">Evidence Signals</h4>
                  <ul className="space-y-1">
                    {analysis.confidence_reasons.map((r, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                        <ChevronRight className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                        {r}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Remediation ────────────────────────────────────────────────── */}
        {alert.remediation && (
          <div className="rounded-lg border border-border bg-card p-6">
            <h2 className="font-mono text-lg font-semibold mb-4 flex items-center gap-2">
              <Wrench className="w-5 h-5 text-primary" />
              Remediation
            </h2>

            {alert.remediation.safe_version && (
              <p className="font-mono text-sm text-muted-foreground mb-4">
                Safe version:{" "}
                <span className="text-primary font-semibold">{alert.remediation.safe_version}</span>
              </p>
            )}

            {/* Install command + Apply Fix */}
            <div className="relative rounded-md border border-border bg-secondary/30 mb-2">
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

            {/* Apply Fix button */}
            <div className="mb-6">
              {applyState !== "done" && (
                <button
                  onClick={handleApplyFix}
                  disabled={applyState === "loading"}
                  className="mt-3 flex items-center gap-2 px-4 py-2 rounded-md bg-primary text-primary-foreground text-sm font-mono font-semibold hover:bg-primary/90 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
                >
                  {applyState === "loading" ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Applying fix…
                    </>
                  ) : (
                    <>
                      <Zap className="w-4 h-4" />
                      Apply Fix to Codebase
                    </>
                  )}
                </button>
              )}

              {applyError && (
                <div className="mt-3 flex items-start gap-2 p-3 rounded-md bg-red-500/10 border border-red-500/30 text-sm text-red-400 font-mono">
                  <XCircle className="w-4 h-4 mt-0.5 shrink-0" />
                  {applyError}
                </div>
              )}

              {applyState === "done" && applyResult && (
                <div className={`mt-3 rounded-md border p-4 ${applyResult.applied ? "bg-green-500/10 border-green-500/30" : "bg-yellow-500/10 border-yellow-500/30"}`}>
                  <div className="flex items-center gap-2 mb-2">
                    {applyResult.applied ? (
                      <CircleCheck className="w-4 h-4 text-green-400 shrink-0" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0" />
                    )}
                    <span className={`font-mono text-sm font-semibold ${applyResult.applied ? "text-green-400" : "text-yellow-400"}`}>
                      {applyResult.message}
                    </span>
                  </div>
                  {applyResult.file_changed && (
                    <p className="font-mono text-xs text-muted-foreground mb-2">
                      File: <span className="text-foreground">{applyResult.file_changed}</span>
                    </p>
                  )}
                  {applyResult.old_line && applyResult.new_line && (
                    <div className="rounded border border-border overflow-hidden text-xs font-mono">
                      <div className="px-3 py-1.5 bg-red-500/10 text-red-400 flex items-center gap-2">
                        <span className="select-none">−</span>
                        <span>{applyResult.old_line}</span>
                      </div>
                      <div className="px-3 py-1.5 bg-green-500/10 text-green-400 flex items-center gap-2">
                        <span className="select-none">+</span>
                        <span>{applyResult.new_line}</span>
                      </div>
                    </div>
                  )}
                  {applyResult.applied && (
                    <p className="font-mono text-xs text-muted-foreground mt-2">
                      Run the install command above to complete the update.
                    </p>
                  )}
                </div>
              )}
            </div>

            {/* AI remediation extras */}
            {alert.remediation.permanent_fix_summary && (
              <div className="mb-4 rounded-md border border-border bg-secondary/20 p-4">
                <h4 className="font-mono text-sm font-semibold text-muted-foreground mb-2">Permanent Fix</h4>
                <p className="text-sm text-foreground leading-relaxed">{alert.remediation.permanent_fix_summary}</p>
              </div>
            )}

            {alert.remediation.temporary_mitigation && (
              <div className="mb-4 rounded-md border border-yellow-500/20 bg-yellow-500/5 p-4">
                <h4 className="font-mono text-sm font-semibold text-yellow-400 mb-2">Temporary Mitigation</h4>
                <p className="text-sm text-foreground leading-relaxed">{alert.remediation.temporary_mitigation}</p>
              </div>
            )}

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

            {alert.remediation.review_note && (
              <div className="mt-4 rounded-md border border-border bg-secondary/20 p-4">
                <h4 className="font-mono text-sm font-semibold text-muted-foreground mb-1">Review Note</h4>
                <p className="text-sm text-muted-foreground">{alert.remediation.review_note}</p>
              </div>
            )}
          </div>
        )}
      </main>

      <footer className="border-t border-border py-8 px-6 text-center">
        <p className="text-sm text-muted-foreground font-mono">
          Powered by Backboard AI + OSV.dev
        </p>
      </footer>
    </div>
  );
};

export default AlertDetail;
