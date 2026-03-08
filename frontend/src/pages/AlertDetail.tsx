import { useParams, useNavigate } from "react-router-dom";
import { Shield, ArrowLeft, FileCode2, Tag, Brain, Wrench, Copy, Check, ShieldAlert } from "lucide-react";
import { useState } from "react";
import type { AlertDetail as AlertDetailType } from "@/types/api";

// Hardcoded placeholder alert detail
const PLACEHOLDER: AlertDetailType = {
  id: 1,
  scan_id: 1,
  repo_id: 1,
  vuln_id: "GHSA-35jh-r3h4-6jhm",
  severity: "CRITICAL",
  summary:
    "Prototype Pollution in lodash — The functions _.merge, _.mergeWith, _.defaultsDeep, and _.set allow modification of Object.prototype properties when processing untrusted input, enabling property injection attacks.",
  dependency_name: "lodash",
  dependency_version: "4.17.4",
  vuln_aliases: ["CVE-2019-10744"],
  references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-10744"],
  dependency_investigation: null,
  usage_locations: [
    {
      id: 1,
      file_path: "src/utils/merge.js",
      line_number: 3,
      snippet: `const _ = require('lodash');\n\nconst merged = _.merge({}, userInput);\nconsole.log(merged);`,
      import_type: "cjs",
      context_tags: ["util", "LOW_SENSITIVITY"],
      sensitivity_level: null,
      sensitive_surface_reason: null,
      subsystem_labels: null,
      user_input_proximity: null,
    },
    {
      id: 2,
      file_path: "src/utils/merge.js",
      line_number: 1,
      snippet: `import _ from 'lodash';\n\n// Deep merge utility`,
      import_type: "esm",
      context_tags: ["util", "LOW_SENSITIVITY"],
      sensitivity_level: null,
      sensitive_surface_reason: null,
      subsystem_labels: null,
      user_input_proximity: null,
    },
    {
      id: 3,
      file_path: "src/auth/session.js",
      line_number: 12,
      snippet: `const config = require('./config');\nconst _ = require('lodash');\n\n_.set(sessionData, path, value);`,
      import_type: "symbol",
      context_tags: ["auth", "HIGH_SENSITIVITY"],
      sensitivity_level: "HIGH",
      sensitive_surface_reason: "Used within authentication session handling",
      subsystem_labels: ["auth"],
      user_input_proximity: "direct",
    },
  ],
  analysis: {
    id: 1,
    risk_level: "high",
    confidence: "high",
    reasoning:
      "The lodash _.merge() call at src/utils/merge.js:3 directly passes user-controlled input (userInput) as the source object. This allows an attacker to inject or overwrite properties on Object.prototype via crafted payloads like {\"__proto__\": {\"isAdmin\": true}}. Additionally, _.set() is used in src/auth/session.js:12 within an authentication context, where the 'path' parameter could be manipulated to modify session properties. The auth context use is particularly dangerous as it could lead to privilege escalation.",
    business_impact:
      "An attacker can inject arbitrary properties into JavaScript objects, potentially enabling: 1) Privilege escalation through session manipulation (auth context), 2) Denial of service by corrupting shared prototypes, 3) Remote code execution in certain Node.js configurations.",
    recommended_fix:
      "Upgrade lodash to >=4.17.21 which patches the prototype pollution vulnerability. Additionally, validate and sanitize the 'path' parameter in _.set() calls within the auth module.",
    urgency: "immediate",
    analysis_source: "backboard_ai",
    backboard_thread_id: "thread_abc123",
    exploitability_score: 82,
    confidence_score: 88,
    blast_radius: "module",
    temp_mitigation: "Sanitize all inputs before passing to _.merge() or _.set().",
    exploitability: "likely",
    evidence_strength: "high",
    exploitability_reason: "_.merge() called with direct user input in utility and auth contexts.",
    detected_functions: ["_.merge", "_.set"],
    blast_radius_label: "module",
    affected_surfaces: ["auth"],
    scope_clarity: "high",
    confidence_percent: 78,
    confidence_reasons: ["High exploitability evidence", "Auth surface detected", "AI-enriched context available"],
  },
  remediation: {
    id: 1,
    safe_version: "4.17.21",
    install_command: "npm install lodash@4.17.21",
    checklist: [
      "Upgrade lodash to 4.17.21",
      "Run npm audit to verify no remaining vulnerabilities",
      "Review package changelog for breaking changes before upgrading",
      "Re-run DepGuard scan to confirm resolution",
    ],
    created_at: "2026-03-05T09:01:12Z",
  },
};

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
  const [copied, setCopied] = useState(false);
  const alert = PLACEHOLDER;

  const handleCopy = () => {
    navigator.clipboard.writeText(alert.remediation?.install_command ?? "");
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

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
              className={`inline-flex px-3 py-1 rounded-full text-xs font-mono font-semibold border ${SEVERITY_STYLES[alert.severity]}`}
            >
              {alert.severity}
            </span>
          </div>
          <p className="text-sm text-muted-foreground leading-relaxed">{alert.summary}</p>
        </div>

        {/* Code Locations */}
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
              </div>
            ))}
          </div>
        </div>

        {/* AI Analysis */}
        <div className="rounded-lg border border-border bg-card p-6">
          <h2 className="font-mono text-lg font-semibold mb-4 flex items-center gap-2">
            <Brain className="w-5 h-5 text-primary" />
            AI Investigation
            {alert.analysis?.backboard_thread_id ? (
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
                className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold border uppercase ${RISK_STYLES[alert.analysis?.risk_level ?? ""]}`}
              >
                {alert.analysis?.risk_level}
              </span>
            </div>
            <div className="flex items-center gap-3">
              <span className="font-mono text-sm text-muted-foreground">Confidence:</span>
              <span className="font-mono text-sm text-foreground font-semibold capitalize">
                {alert.analysis?.confidence}
              </span>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <h4 className="font-mono text-sm font-semibold text-muted-foreground mb-2">Reasoning</h4>
              <p className="text-sm text-foreground leading-relaxed">{alert.analysis?.reasoning}</p>
            </div>
            <div>
              <h4 className="font-mono text-sm font-semibold text-muted-foreground mb-2">Business Impact</h4>
              <p className="text-sm text-foreground leading-relaxed">{alert.analysis?.business_impact}</p>
            </div>
            <div>
              <h4 className="font-mono text-sm font-semibold text-muted-foreground mb-2">Recommended Fix</h4>
              <p className="text-sm text-foreground leading-relaxed">{alert.analysis?.recommended_fix}</p>
            </div>
          </div>
        </div>

        {/* Remediation */}
        <div className="rounded-lg border border-border bg-card p-6">
          <h2 className="font-mono text-lg font-semibold mb-4 flex items-center gap-2">
            <Wrench className="w-5 h-5 text-primary" />
            Remediation
          </h2>

          {alert.remediation?.safe_version && (
            <p className="font-mono text-sm text-muted-foreground mb-3">
              Safe version: <span className="text-primary font-semibold">{alert.remediation.safe_version}</span>
            </p>
          )}

          {/* Install command */}
          <div className="relative rounded-md border border-border bg-secondary/30 mb-6">
            <pre className="p-4 font-mono text-sm text-primary pr-16">{alert.remediation?.install_command}</pre>
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
          <h4 className="font-mono text-sm font-semibold text-muted-foreground mb-3">Verification Checklist</h4>
          <ul className="space-y-2">
            {(alert.remediation?.checklist ?? []).map((item, i) => (
              <li key={i} className="flex items-start gap-3">
                <div className="mt-0.5 w-4 h-4 rounded border border-border bg-secondary shrink-0" />
                <span className="text-sm text-foreground">{item}</span>
              </li>
            ))}
          </ul>
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

export default AlertDetail;
