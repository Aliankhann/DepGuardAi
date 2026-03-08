import { motion } from "framer-motion";
import { Search, GitBranch, Brain, ShieldCheck } from "lucide-react";

const steps = [
  {
    icon: Search,
    title: "Scan",
    description: "Discovers all dependencies and known CVEs across your project.",
  },
  {
    icon: GitBranch,
    title: "Trace",
    description: "Maps actual code paths that import and invoke vulnerable functions.",
  },
  {
    icon: Brain,
    title: "Investigate",
    description: "AI + rule agents score exploitability, blast radius, confidence, and urgency.",
  },
  {
    icon: ShieldCheck,
    title: "Resolve",
    description: "Delivers a prioritized list of real risks with AI-generated fixes.",
  },
];

const HowItWorks = () => {
  return (
    <section className="py-32 px-6 relative">
      <div className="absolute inset-0 bg-grid opacity-20" />
      <div className="relative z-10 max-w-5xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-20"
        >
          <span className="font-mono text-sm text-primary mb-4 block">// HOW IT WORKS</span>
          <h2 className="font-mono text-3xl md:text-5xl font-bold">
            A security engineer,{" "}
            <span className="text-primary text-glow">automated.</span>
          </h2>
        </motion.div>

        <div className="grid md:grid-cols-4 gap-6">
          {steps.map((step, i) => (
            <motion.div
              key={step.title}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.1 }}
              className="relative group"
            >
              {i < steps.length - 1 && (
                <div className="hidden md:block absolute top-10 left-full w-full h-px border-t border-dashed border-primary/20 z-0" />
              )}
              <div className="relative z-10 p-6 rounded-lg border border-border bg-card hover:border-primary/30 hover:bg-primary/5 transition-all duration-300">
                <div className="w-12 h-12 rounded-md bg-primary/10 border border-primary/20 flex items-center justify-center mb-4 group-hover:border-primary/40 transition-colors">
                  <step.icon className="w-5 h-5 text-primary" />
                </div>
                <span className="font-mono text-xs text-muted-foreground mb-2 block">0{i + 1}</span>
                <h3 className="font-mono text-lg font-semibold mb-2 text-foreground">{step.title}</h3>
                <p className="text-sm text-muted-foreground leading-relaxed">{step.description}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default HowItWorks;
