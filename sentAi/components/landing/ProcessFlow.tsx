"use client"

import React from "react"
import { ShieldCheck, Zap, Activity, MousePointer2, Cpu, Network } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

export function ProcessFlow() {
  const steps = [
    { title: "Input Analysis", desc: "Paste raw email headers or scan a suspicious URL.", icon: MousePointer2, badge: "Phase 1", color: "text-blue-400", bg: "group-hover:border-blue-500/40 group-hover:bg-blue-500/10" },
    { title: "Neural Logic", desc: "AI models deconstruct visuals and text in parallel.", icon: Cpu, badge: "Phase 2", color: "text-purple-400", bg: "group-hover:border-purple-500/40 group-hover:bg-purple-500/10" },
    { title: "Fusion Engine", desc: "Multiple signals converge into a singular threat score.", icon: Zap, badge: "Phase 3", color: "text-amber-400", bg: "group-hover:border-amber-500/40 group-hover:bg-amber-500/10" },
    { title: "Intel Mapping", desc: "Intelligence layers correlate data with known actors.", icon: Network, badge: "Phase 4", color: "text-orange-400", bg: "group-hover:border-orange-500/40 group-hover:bg-orange-500/10" },
    { title: "Response Node", desc: "Explainable insights and actions are generated.", icon: ShieldCheck, badge: "Phase 5", color: "text-emerald-400", bg: "group-hover:border-emerald-500/40 group-hover:bg-emerald-500/10" },
  ]

  return (
    <section id="process" className="relative py-16 md:py-20 lg:py-24 px-6 bg-muted overflow-hidden border-y border-border/50">
      <div className="absolute top-[20%] left-1/2 -translate-x-1/2 h-0.5 w-full bg-gradient-to-r from-transparent via-blue-500/20 to-transparent -z-10" />

      <div className="max-w-7xl mx-auto space-y-20 flex flex-col items-center">
        <div className="text-center max-w-4xl space-y-10 animate-in fade-in slide-in-from-top-12 duration-1000">
           <div className="flex items-center justify-center space-x-3 text-blue-400/60 uppercase font-black tracking-[0.4em] text-[10px]">
              <Activity className="h-4 w-4" />
              <span>THE FUSION PIPELINE</span>
           </div>

           <h2 className="text-4xl md:text-[5rem] font-black tracking-tighter text-foreground uppercase leading-[0.95]">
             From Detection <br />
             <span className="text-blue-400 italic font-light decoration-4 underline decoration-blue-400/10">To Inference.</span>
           </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-12 w-full animate-in fade-in slide-in-from-bottom-12 duration-1000 delay-300">
           {steps.map((step, i) => (
             <div key={i} className="group relative flex flex-col items-center text-center space-y-8">
                <div className="relative flex items-center justify-center">
                   <div className={cn(
                     "h-20 w-20 rounded-[2rem] bg-black/40 border border-white/10 flex items-center justify-center transition-all group-hover:scale-110 shadow-2xl relative z-20",
                     step.bg,
                     step.color
                   )}>
                      <step.icon className="h-8 w-8 transition-all group-hover:scale-125" />
                   </div>

                   <div className="absolute inset-0 rounded-full border-2 border-blue-500/10 animate-[spin_10s_linear_infinite] group-hover:border-blue-500/30 opacity-40" />

                   {i < steps.length - 1 && (
                      <div className="hidden md:block absolute left-20 top-1/2 -translate-y-1/2 h-px w-[calc(100%+24px)] bg-gradient-to-r from-blue-500/40 via-blue-500/10 to-transparent -z-10" />
                   )}
                </div>

                <div className="space-y-4 px-2">
                   <Badge variant="outline" className="text-[8px] h-5 rounded-full px-3 py-0 border-white/10 uppercase font-black tracking-widest text-muted-foreground transition-all group-hover:text-blue-400 group-hover:scale-110 group-hover:border-blue-500/20">{step.badge}</Badge>
                   <h4 className={cn("text-lg font-black uppercase tracking-tight text-foreground transition-colors", `group-hover:${step.color}`)}>{step.title}</h4>
                   <p className="text-[11px] md:text-[12px] text-muted-foreground/60 leading-relaxed font-black uppercase tracking-widest">
                      {step.desc}
                   </p>
                </div>

                <div className="text-4xl font-black text-white/5 absolute -top-8 left-1/2 -translate-x-1/2 -z-20 group-hover:text-white/10 transition-all uppercase tracking-tighter">0{i+1}</div>
             </div>
           ))}
        </div>

        <div className="pt-24 opacity-60 hover:opacity-100 transition-opacity">
           <Badge className="bg-blue-500/5 border-dashed border-blue-500/30 text-blue-400 font-black tracking-widest px-6 py-2 text-[10px] uppercase">
              End-to-end Inference cycle: {"<"} 1.2s
           </Badge>
        </div>
      </div>
    </section>
  )
}
