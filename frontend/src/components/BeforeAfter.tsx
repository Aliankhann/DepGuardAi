import { motion } from "framer-motion";
import { X, Check, AlertTriangle, ShieldCheck } from "lucide-react";

const BeforeAfter = () => {
  return (
    <section className="py-32 px-6">
      <div className="max-w-5xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <span className="font-mono text-sm text-primary mb-4 block">// THE DIFFERENCE</span>
          <h2 className="font-mono text-3xl md:text-5xl font-bold">
            From noise to{" "}
            <span className="text-primary text-glow">signal.</span>
          </h2>
        </motion.div>

        <div className="grid md:grid-cols-2 gap-6">
          {/* Before */}
          <motion.div
            initial={{ opacity: 0, x: -30 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            className="rounded-lg border border-destructive/20 bg-card p-8"
          >
            <div className="flex items-center gap-2 mb-6">
              <AlertTriangle className="w-5 h-5 text-destructive" />
              <span className="font-mono font-semibold text-destructive">Traditional Scanners</span>
            </div>
            <ul className="space-y-4">
              {[
                "147 vulnerability alerts",
                "No exploitability context",
                "Hours of manual triage",
                "Alert fatigue → ignored risks",
                "Generic remediation advice",
              ].map((item) => (
                <li key={item} className="flex items-start gap-3 text-sm text-muted-foreground">
                  <X className="w-4 h-4 text-destructive shrink-0 mt-0.5" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </motion.div>

          {/* After */}
          <motion.div
            initial={{ opacity: 0, x: 30 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            className="rounded-lg border border-primary/30 bg-card p-8 border-glow"
          >
            <div className="flex items-center gap-2 mb-6">
              <ShieldCheck className="w-5 h-5 text-primary" />
              <span className="font-mono font-semibold text-primary">DepGuard</span>
            </div>
            <ul className="space-y-4">
              {[
                "3 confirmed exploitable risks",
                "Full code path analysis",
                "Seconds, not hours",
                "Confidence in every finding",
                "AI-generated, context-aware fixes",
              ].map((item) => (
                <li key={item} className="flex items-start gap-3 text-sm text-foreground">
                  <Check className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </motion.div>
        </div>
      </div>
    </section>
  );
};

export default BeforeAfter;
