import { Shield } from "lucide-react";
import { useAuth0 } from "@auth0/auth0-react";
import { LoginButton } from "./auth/LoginButton";
import { LogoutButton } from "./auth/LogoutButton";
import { Link } from "react-router-dom";

const Navbar = () => {
  const { isAuthenticated, user } = useAuth0();

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 border-b border-border/50 bg-background/80 backdrop-blur-xl">
      <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-6 h-6 text-primary" />
          <Link to="/" className="font-mono font-bold text-lg text-foreground">DepGuard</Link>
        </div>
        <div className="hidden md:flex items-center gap-8">
          <a href="#how" className="text-sm text-muted-foreground hover:text-foreground transition-colors font-mono">How it works</a>
          <a href="#compare" className="text-sm text-muted-foreground hover:text-foreground transition-colors font-mono">Compare</a>
          {isAuthenticated ? (
            <div className="flex items-center gap-4">
              <Link to="/dashboard" className="text-sm text-muted-foreground hover:text-foreground transition-colors font-mono">
                Dashboard
              </Link>
              <div className="flex items-center gap-2">
                {user?.picture && <img src={user.picture} alt={user.name} className="w-8 h-8 rounded-full" />}
                <span className="text-sm font-mono text-foreground hidden lg:block">{user?.name}</span>
              </div>
              <LogoutButton />
            </div>
          ) : (
            <LoginButton />
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
