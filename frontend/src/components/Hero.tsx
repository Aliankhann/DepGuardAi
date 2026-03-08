import { motion } from "framer-motion";
import { Shield, ShieldAlert, ShieldCheck, ArrowRight } from "lucide-react";
import { Link } from "react-router-dom";

const Hero = () => {
  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
      {/* Grid background */}
      <div className="absolute inset-0 bg-grid opacity-40" />
      <div className="absolute inset-0 bg-scanline pointer-events-none" />
      
      {/* Radial glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] rounded-full bg-primary/5 blur-[120px]" />

      <div className="relative z-10 max-w-5xl mx-auto px-6 text-center">
        {/* Badge */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-primary/30 bg-primary/5 mb-8"
        >
          <span className="w-2 h-2 rounded-full bg-primary animate-pulse-glow" />
          <span className="text-sm font-mono text-primary">AI-Powered Security Investigation</span>
        </motion.div>

        {/* Headline */}
        <motion.h1
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="font-mono text-5xl md:text-7xl font-bold tracking-tight mb-6"
        >
          <span className="text-foreground">Stop chasing </span>
          <span className="text-glow text-primary">false positives.</span>
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-10 leading-relaxed"
        >
          DepGuard doesn't just find vulnerabilities — it <span className="text-foreground font-medium">investigates</span> them. 
          AI agents analyze your actual code paths to determine what's truly exploitable.
        </motion.p>

        {/* CTA */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3 }}
          className="flex flex-col sm:flex-row items-center justify-center gap-4"
        >
          <Link to="/dashboard" className="group flex items-center gap-2 px-8 py-3.5 bg-primary text-primary-foreground font-mono font-semibold rounded-md hover:shadow-[0_0_30px_hsl(142_72%_50%/0.3)] transition-all duration-300">
            Start Investigating
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </Link>
          <Link to="/dashboard" className="flex items-center gap-2 px-8 py-3.5 border border-border text-foreground font-mono rounded-md hover:border-primary/50 hover:bg-primary/5 transition-all duration-300">
            View Demo
          </Link>
        </motion.div>

        {/* Terminal preview */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.5 }}
          className="mt-16 max-w-3xl mx-auto"
        >
          <div className="rounded-lg border border-border bg-card overflow-hidden border-glow">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-secondary/30">
              <div className="w-3 h-3 rounded-full bg-destructive/60" />
              <div className="w-3 h-3 rounded-full bg-glow-warning/60" />
              <div className="w-3 h-3 rounded-full bg-primary/60" />
              <span className="ml-2 text-xs font-mono text-muted-foreground">depguard scan --investigate</span>
            </div>
            <div className="p-6 font-mono text-sm space-y-2 text-left">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-glow-warning" />
                <span className="text-glow-warning">147 vulnerabilities detected</span>
                <span className="text-muted-foreground">across 23 packages</span>
              </div>
              <div className="flex items-center gap-2 text-muted-foreground">
                <span className="text-primary">▸</span>
                <span>Analyzing code paths...</span>
              </div>
              <div className="flex items-center gap-2 text-muted-foreground">
                <span className="text-primary">▸</span>
                <span>Gathering execution context...</span>
              </div>
              <div className="flex items-center gap-2 text-muted-foreground">
                <span className="text-primary">▸</span>
                <span>Cross-referencing call graphs...</span>
              </div>
              <div className="h-px bg-border my-3" />
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-primary" />
                <span className="text-primary font-semibold">3 truly exploitable</span>
                <span className="text-muted-foreground">· 144 safe to ignore</span>
              </div>
              <div className="flex items-center gap-2 mt-1">
                <Shield className="w-4 h-4 text-primary" />
                <span className="text-primary">AI-generated fixes ready</span>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
};

export default Hero;
