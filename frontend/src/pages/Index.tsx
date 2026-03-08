import Navbar from "@/components/Navbar";
import Hero from "@/components/Hero";
import HowItWorks from "@/components/HowItWorks";
import BeforeAfter from "@/components/BeforeAfter";
import CTASection from "@/components/CTASection";

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <Hero />
      <div id="how">
        <HowItWorks />
      </div>
      <div id="compare">
        <BeforeAfter />
      </div>
      <CTASection />
      <footer className="border-t border-border py-8 px-6 text-center">
        <p className="text-sm text-muted-foreground font-mono">
          © 2026 DepGuard. Security that investigates.
        </p>
      </footer>
    </div>
  );
};

export default Index;
