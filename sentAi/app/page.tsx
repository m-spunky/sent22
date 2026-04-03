import { Navbar } from "@/components/landing/Navbar";
import { LandingHero } from "@/components/landing/LandingHero";
import { ProblemSection } from "@/components/landing/ProblemSection";
import { SolutionSection } from "@/components/landing/SolutionSection";
import { FeaturesGrid } from "@/components/landing/FeaturesGrid";
import { ProcessFlow } from "@/components/landing/ProcessFlow";
import { ComparisonSection } from "@/components/landing/ComparisonSection";
import { FinalCTA } from "@/components/landing/FinalCTA";
import { LandingFooter } from "@/components/landing/LandingFooter";

export default function Home() {
  return (
    <div className="flex flex-col w-full bg-[#0a0e1a] overflow-x-hidden">
      <Navbar />
      
      <main className="flex-grow">
        <LandingHero />
        <ProblemSection />
        <SolutionSection />
        <FeaturesGrid />
        <ProcessFlow />
        <ComparisonSection />
        <FinalCTA />
      </main>
      
      <LandingFooter />
    </div>
  );
}
