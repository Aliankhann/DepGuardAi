import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, Plus, ScanLine, FolderGit2, AlertTriangle, CheckCircle, Clock } from "lucide-react";
import { useAuth0 } from "@auth0/auth0-react";
import { useRepos } from "@/hooks/useRepos";
import { useScan } from "@/hooks/useScan";

const Dashboard = () => {
  const navigate = useNavigate();
  const { repos, loading: reposLoading, error: reposError, createRepo } = useRepos();
  const { scanStatus, currentAgent, triggerAndPoll } = useScan();
  
  const [newName, setNewName] = useState("");
  const [newPath, setNewPath] = useState("");
  const [scanningId, setScanningId] = useState<number | null>(null);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim() || !newPath.trim()) return;
    try {
      await createRepo(newName.trim(), newPath.trim());
      setNewName("");
      setNewPath("");
    } catch (err) {
      console.error("Failed to register repo", err);
    }
  };

  const { getAccessTokenSilently } = useAuth0();
  
  const handleSeed = async () => {
    try {
      const token = await getAccessTokenSilently();
      const res = await fetch(`${import.meta.env.VITE_API_URL}/demo/seed`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await res.json();
      if (data.repo_id) {
        window.location.reload(); // Refresh to show the new repo
      }
    } catch (err) {
      console.error("Failed to seed demo", err);
    }
  };

  const handleScan = async (repoId: number) => {
    try {
      setScanningId(repoId);
      const finalStatus = await triggerAndPoll(repoId);
      setScanningId(null);
      if (finalStatus.status === "complete") {
        navigate(`/repos/${repoId}`);
      }
    } catch (err) {
      console.error("Scan failed", err);
      setScanningId(null);
    }
  };

  const getAgentLabel = (agent: string | null) => {
    if (!agent) return "Starting scan...";
    const labels: Record<string, string> = {
      scan_agent: "Scanning dependencies...",
      depvuln_agent: "Analyzing vulnerability intelligence...",
      code_agent: "Mapping code usage...",
      context_agent: "Classifying context...",
      exploitability_agent: "Assessing exploitability...",
      blast_radius_agent: "Estimating blast radius...",
      risk_agent: "Analyzing with AI...",
      fix_agent: "Generating fixes...",
      memory_agent: "Saving investigation memory...",
    };
    return labels[agent] || "Processing...";
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
        {reposError && (
          <div className="mb-8 p-4 bg-red-500/10 border border-red-500/50 rounded-lg flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-red-500 shrink-0 mt-0.5" />
            <div>
              <h3 className="font-mono font-semibold text-red-500">Backend unavailable</h3>
              <p className="text-sm text-red-400 mt-1">{reposError.message}</p>
            </div>
          </div>
        )}

        <div className="mb-12">
          <div className="flex items-center justify-between mb-6">
            <h2 className="font-mono text-2xl font-bold flex items-center gap-2">
              <Plus className="w-5 h-5 text-primary" />
              Register Repository
            </h2>
            <button
              onClick={handleSeed}
              className="text-xs font-mono px-3 py-1.5 border border-primary/30 bg-primary/10 text-primary rounded-md hover:bg-primary/20 transition-all flex items-center gap-2"
            >
              <Plus className="w-3 h-3" />
              Seed Demo Repo
            </button>
          </div>
          <p className="text-sm text-muted-foreground font-mono mb-4 text-orange-400/80">
            Note: For the hackathon, please provide an <strong>absolute local path</strong> to a cloned repository.
          </p>
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
              disabled={!newName.trim() || !newPath.trim()}
              className="px-6 py-3 bg-primary text-primary-foreground font-mono font-semibold text-sm rounded-md hover:opacity-90 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
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
        
        {reposLoading ? (
          <div className="flex justify-center p-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : repos.length === 0 ? (
          <div className="text-center p-12 border border-dashed border-border rounded-lg text-muted-foreground font-mono">
            No repositories registered yet.
          </div>
        ) : (
          <div className="grid gap-4">
            {repos.map((repo) => (
              <div
                key={repo.id}
                className="flex flex-col sm:flex-row sm:items-center justify-between p-6 rounded-lg border border-border bg-card hover:border-primary/30 transition-colors gap-4"
              >
                <div className="flex-1 min-w-0">
                  <h3 className="font-mono font-semibold text-lg text-foreground">{repo.name}</h3>
                  <p className="font-mono text-sm text-muted-foreground truncate mt-1">{repo.local_path || repo.repo_url}</p>
                  <div className="flex gap-3 mt-3">
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-secondary text-secondary-foreground">
                      {repo.ecosystem || "unknown"}
                    </span>
                    <span className="text-xs font-mono flex items-center gap-1 text-muted-foreground">
                      <Clock className="w-3 h-3" />
                      {new Date(repo.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  {scanningId === repo.id ? (
                    <div className="flex items-center gap-3 text-primary bg-primary/10 px-4 py-2 rounded-md border border-primary/20">
                      <ScanLine className="w-4 h-4 animate-pulse" />
                      <span className="font-mono text-sm font-medium">{getAgentLabel(currentAgent)}</span>
                    </div>
                  ) : (
                    <>
                      <button
                        onClick={() => handleScan(repo.id)}
                        className="px-5 py-2 bg-primary text-primary-foreground font-mono font-semibold text-sm rounded-md hover:opacity-90 transition-all flex items-center gap-2"
                      >
                        <ScanLine className="w-4 h-4" />
                        Scan
                      </button>
                      <button
                        onClick={() => navigate(`/repos/${repo.id}`)}
                        className="px-5 py-2 border border-border text-foreground font-mono text-sm rounded-md hover:bg-secondary transition-all"
                      >
                        View Alerts
                      </button>
                    </>
                  )}
                </div>
              </div>
            ))}
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

export default Dashboard;
