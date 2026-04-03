"use client"

import React from "react"
import { ShieldCheck, Target, Radar } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

export function ComparisonSection() {
  const tableData = [
    { feature: "Detection Layer", others: "Single-model / Static", sentinel: "Multi-modal AI Fusion" },
    { feature: "Data Correlation", others: "Manual / Siloed", sentinel: "Auto-Global Intelligence" },
    { feature: "Inference Speed", others: "Hours to Days", sentinel: "Sub-second Pipeline" },
    { feature: "Transparency", others: "Black-box Results", sentinel: "AI-Powered Explanations" },
    { feature: "Interface", others: "Static Dashboards", sentinel: "Interactive Workspace" },
  ]

  return (
    <section id="compare" className="relative py-16 md:py-20 lg:py-24 px-6 bg-background overflow-hidden border-t border-border/50">
      <div className="absolute top-1/2 left-0 -translate-y-1/2 h-[600px] w-[600px] bg-blue-500/5 rounded-full blur-[140px] -z-10" />
      <div className="absolute top-[20%] right-[-10%] h-[500px] w-[500px] bg-blue-500/3 rounded-full blur-[120px] -z-1" />

      <div className="max-w-7xl mx-auto flex flex-col items-center">
        <div className="text-center max-w-4xl space-y-10 mb-16 z-10 animate-in fade-in slide-in-from-top-12 duration-1000">
           <div className="flex items-center justify-center space-x-3 text-blue-400/60 uppercase font-black tracking-[0.4em] text-[10px]">
              <Radar className="h-4 w-4" />
              <span>THE INTELLIGENCE EDGE</span>
           </div>

           <h2 className="text-4xl md:text-[5rem] font-black tracking-tighter text-foreground uppercase leading-[0.95]">
             Why Fusion <br />
             <span className="text-muted-foreground opacity-40 italic font-light decoration-4">Superiority.</span>
           </h2>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-20 items-center w-full z-10">
           {/* Left: Comparison Table */}
           <div className="w-full space-y-4 animate-in fade-in slide-in-from-left-12 duration-1000 delay-300">
              {tableData.map((row, i) => (
                <div key={i} className="group relative">
                   <div className="absolute -left-4 top-0 bottom-0 w-0.5 bg-blue-500/5 group-hover:bg-blue-500/40 group-hover:w-1 transition-all" />

                   <div className="grid grid-cols-3 gap-8 py-8 px-6 rounded-2xl bg-muted/40 border border-border/20 group-hover:bg-muted/60 group-hover:border-blue-500/10 transition-all duration-500">
                      <div className="flex flex-col space-y-1">
                         <span className="text-[10px] font-black uppercase tracking-widest text-muted-foreground opacity-60">Capability</span>
                         <span className="text-sm font-black text-foreground group-hover:text-blue-400 transition-colors">{row.feature}</span>
                      </div>
                      <div className="flex flex-col space-y-1 text-center">
                         <span className="text-[10px] font-black uppercase tracking-widest text-muted-foreground opacity-40">Others</span>
                         <span className="text-xs font-bold text-muted-foreground/60">{row.others}</span>
                      </div>
                      <div className="flex flex-col space-y-1 text-right">
                         <span className="text-[10px] font-black uppercase tracking-widest text-blue-400 opacity-60">SentinelAI</span>
                         <span className="text-sm font-black text-blue-400">{row.sentinel}</span>
                      </div>
                   </div>
                </div>
              ))}
           </div>

           {/* Right: Stats */}
           <div className="space-y-10 animate-in fade-in slide-in-from-right-12 duration-1000 delay-500">
              <div className="space-y-4 max-w-md">
                 <h3 className="text-3xl font-black tracking-tight text-foreground uppercase leading-none">Stop Guessing. <br /> Start Inferring.</h3>
                 <p className="text-lg text-muted-foreground/80 leading-relaxed font-medium">
                    Traditional security tools provide alerts. Fusion provides answers. By combining multiple AI perspectives, we reduce noise and accelerate analyst response by up to 10x.
                 </p>
              </div>

              <div className="grid grid-cols-2 gap-6">
                 {[
                   { label: "Analyst Fatigue", reduction: "-84%", icon: Target },
                   { label: "Detection Precision", reduction: "99.2%", icon: ShieldCheck },
                 ].map((kpi, i) => (
                   <div key={i} className="card-cyber p-8 space-y-4 relative group hover:scale-105 transition-all">
                      <div className="absolute top-4 right-4 h-1 w-8 bg-blue-500/5 group-hover:bg-blue-500/20 transition-all" />
                      <div className="h-10 w-10 rounded-xl bg-blue-500/10 flex items-center justify-center border border-blue-500/20 group-hover:border-blue-500/40 transition-all">
                         <kpi.icon className="h-5 w-5 text-blue-400" />
                      </div>
                      <div className="space-y-1">
                         <div className="text-3xl font-black tracking-tighter text-foreground group-hover:text-blue-400 transition-colors">{kpi.reduction}</div>
                         <div className="text-[10px] text-muted-foreground uppercase font-black tracking-widest opacity-60">{kpi.label}</div>
                      </div>
                   </div>
                 ))}
              </div>

              <div className="pt-6 border-t border-white/5">
                 <div className="flex items-center space-x-6">
                    <div className="flex -space-x-3">
                       {[1, 2, 3].map((_, i) => (
                         <div key={i} className="h-10 w-10 rounded-full bg-blue-500/20 border-2 border-[#0a0e1a] flex items-center justify-center text-[10px] font-bold text-blue-400">AI</div>
                       ))}
                    </div>
                    <p className="text-[10px] text-muted-foreground uppercase font-black tracking-[0.2em] max-w-xs">Trusted by elite SOC clusters across infrastructure-critical markets.</p>
                 </div>
              </div>
           </div>
        </div>
      </div>
    </section>
  )
}
