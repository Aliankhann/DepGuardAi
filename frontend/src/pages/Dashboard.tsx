import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, Plus, ScanLine, FolderGit2, ArrowLeft } from "lucide-react";
import type { Repository, ScanRun } from "@/types/api";

// Hardcoded placeholder repos
const PLACEHOLDER_REPOS: Repository[] = [
  {
    id: 1,
    name: "ecommerce-app",
    path: "/home/dev/projects/ecommerce-app",
    ecosystem: "npm",
    language: "node",
    created_at: "2026-03-01T10:00:00Z",
  },
  {
    id: 2,
    name: "internal-dashboard",
    path: "/home/dev/projects/internal-dashboard",
    ecosystem: "npm",
    language: "node",
    created_at: "2026-03-03T14:30:00Z",
  },
];

const PLACEHOLDER_SCANS: Record<number, ScanRun> = {
  1: {
    id: 1,
    repo_id: 1,
    status: "complete",
    current_agent: null,
    alert_count: 3,
    started_at: "2026-03-05T09:00:00Z",
    completed_at: "2026-03-05T09:01:12Z",
    error_message: null,
  },
};

const AGENT_LABELS: Record<string, string> = {
  scan_agent: "Scanning dependencies…",
  code_agent: "Mapping code usage…",
  context_agent: "Classifying context…",
  risk_agent: "Analyzing with AI…",
  fix_agent: "Generating fixes…",
};

const Dashboard = () => {
  const navigate = useNavigate();
  const [repos, setRepos] = useState<Repository[]>(PLACEHOLDER_REPOS);
  const [newName, setNewName] = useState("");
  const [newPath, setNewPath] = useState("");
  const [scanningId, setScanningId] = useState<number | null>(null);
  const [scanStatus, setScanStatus] = useState<string | null>(null);

  const handleRegister = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim() || !newPath.trim()) return;
    const newRepo: Repository = {
      id: repos.length + 1,
      name: newName.trim(),
      path: newPath.trim(),
      ecosystem: "npm",
      language: "node",
      created_at: new Date().toISOString(),
    };
    setRepos([...repos, newRepo]);
    setNewName("");
    setNewPath("");
  };

  const handleScan = (repoId: number) => {
    setScanningId(repoId);
    const agents = ["scan_agent", "code_agent", "context_agent", "risk_agent", "fix_agent"];
    let step = 0;
    setScanStatus(AGENT_LABELS[agents[step]]);
    const interval = setInterval(() => {
      step++;
      if (step >= agents.length) {
        clearInterval(interval);
        setScanningId(null);
        setScanStatus(null);
        navigate(`/repos/${repoId}`);
        return;
      }
      setScanStatus(AGENT_LABELS[agents[step]]);
    }, 1200);
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
          <span className="text-sm text-muted-foreground font-mono">Dashboard</span>
        </div>
      </nav>

      <main className="pt-24 pb-16 max-w-6xl mx-auto px-6">
        {/* Register Form */}
        <div className="mb-12">
          <h2 className="font-mono text-2xl font-bold mb-6 flex items-center gap-2">
            <Plus className="w-5 h-5 text-primary" />
            Register Repository
          </h2>
          <form onSubmit={handleRegister} className="flex flex-col sm:flex-row gap-4">
            <input
              type="text"
              placeholder="Repository name"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              className="flex-1 px-4 py-3 bg-card border border-border rounded-md font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <input
              type="text"
              placeholder="Local path (e.g. /home/dev/my-app)"
              value={newPath}
              onChange={(e) => setNewPath(e.target.value)}
              className="flex-1 px-4 py-3 bg-card border border-border rounded-md font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <button
              type="submit"
              className="px-6 py-3 bg-primary text-primary-foreground font-mono font-semibold text-sm rounded-md hover:shadow-[0_0_20px_hsl(142_72%_50%/0.25)] transition-all"
            >
              Register
            </button>
          </form>
        </div>

        {/* Repo List */}
        <h2 className="font-mono text-2xl font-bold mb-6 flex items-center gap-2">
          <FolderGit2 className="w-5 h-5 text-primary" />
          Your Repositories
        </h2>
        <div className="grid gap-4">
          {repos.map((repo) => (
            <div
              key={repo.id}
              className="flex items-center justify-between p-6 rounded-lg border border-border bg-card hover:border-primary/30 transition-colors"
            >
              <div className="flex-1 min-w-0">
                <h3 className="font-mono font-semibold text-lg text-foreground">{repo.name}</h3>
                <p className="font-mono text-sm text-muted-foreground truncate mt-1">{repo.path}</p>
                <div className="flex gap-3 mt-2">
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-secondary text-secondary-foreground">
                    {repo.ecosystem}
                  </span>
                  {PLACEHOLDER_SCANS[repo.id] && (
                    <span className="text-xs font-mono text-primary">
                      {PLACEHOLDER_SCANS[repo.id].alert_count} alerts found
                    </span>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-3 ml-4">
                {scanningId === repo.id ? (
                  <div className="flex items-center gap-2 text-primary">
                    <ScanLine className="w-4 h-4 animate-pulse" />
                    <span className="font-mono text-sm">{scanStatus}</span>
                  </div>
                ) : (
                  <>
                    <button
                      onClick={() => handleScan(repo.id)}
                      className="px-5 py-2 bg-primary text-primary-foreground font-mono font-semibold text-sm rounded-md hover:shadow-[0_0_20px_hsl(142_72%_50%/0.25)] transition-all"
                    >
                      Scan
                    </button>
                    {PLACEHOLDER_SCANS[repo.id] && (
                      <button
                        onClick={() => navigate(`/repos/${repo.id}`)}
                        className="px-5 py-2 border border-border text-foreground font-mono text-sm rounded-md hover:border-primary/50 hover:bg-primary/5 transition-all"
                      >
                        View Alerts
                      </button>
                    )}
                  </>
                )}
              </div>
            </div>
          ))}
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

export default Dashboard;
