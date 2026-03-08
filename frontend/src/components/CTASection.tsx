import { motion } from "framer-motion";
import { ArrowRight, Shield } from "lucide-react";

const CTASection = () => {
  return (
    <section className="py-32 px-6 relative">
      <div className="absolute inset-0 bg-grid opacity-20" />
      <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-[600px] h-[400px] rounded-full bg-primary/5 blur-[100px]" />
      
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        className="relative z-10 max-w-3xl mx-auto text-center"
      >
        <Shield className="w-12 h-12 text-primary mx-auto mb-6" />
        <h2 className="font-mono text-3xl md:text-5xl font-bold mb-6">
          Security that{" "}
          <span className="text-primary text-glow">thinks.</span>
        </h2>
        <p className="text-lg text-muted-foreground mb-10 max-w-xl mx-auto">
          Stop wasting engineering hours on false positives. Let DepGuard investigate your dependencies like a security expert would.
        </p>
        <button className="group inline-flex items-center gap-2 px-10 py-4 bg-primary text-primary-foreground font-mono font-semibold rounded-md hover:shadow-[0_0_40px_hsl(142_72%_50%/0.35)] transition-all duration-300 text-lg">
          Get Early Access
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </button>
        <p className="mt-4 text-sm text-muted-foreground font-mono">Free for open source projects</p>
      </motion.div>
    </section>
  );
};

export default CTASection;
