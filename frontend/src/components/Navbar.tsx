import { Shield } from "lucide-react";

const Navbar = () => {
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 border-b border-border/50 bg-background/80 backdrop-blur-xl">
      <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-6 h-6 text-primary" />
          <span className="font-mono font-bold text-lg text-foreground">DepGuard</span>
        </div>
        <div className="hidden md:flex items-center gap-8">
          <a href="#how" className="text-sm text-muted-foreground hover:text-foreground transition-colors font-mono">How it works</a>
          <a href="#compare" className="text-sm text-muted-foreground hover:text-foreground transition-colors font-mono">Compare</a>
          <button className="px-5 py-2 bg-primary text-primary-foreground font-mono text-sm font-semibold rounded-md hover:shadow-[0_0_20px_hsl(142_72%_50%/0.25)] transition-all">
            Get Access
          </button>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
