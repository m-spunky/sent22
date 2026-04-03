"use client"

import React from "react"
import { ShieldAlert, XCircle, Zap, Mail, Search, AlertTriangle } from "lucide-react"
import { cn } from "@/lib/utils"

export function ProblemSection() {
  const points = [
    {
      title: "Attack Chains are Connected",
      desc: "Phishing leads to credential theft, which enables financial fraud. Isolated tools miss the connection.",
      icon: Mail,
      accent: "text-blue-400",
      hoverBorder: "group-hover:border-blue-500/30",
    },
    {
      title: "Infrastructure Evolves Fast",
      desc: "Attackers rotate domains and payloads in seconds. Static filters and blocklists are permanently behind.",
      icon: Search,
      accent: "text-amber-400",
      hoverBorder: "group-hover:border-amber-500/30",
    },
    {
      title: "Complexity is an Exploit",
      desc: "Security analysts are overwhelmed by siloed data, leading to missed signals and catastrophic breaches.",
      icon: ShieldAlert,
      accent: "text-red-400",
      hoverBorder: "group-hover:border-red-500/30",
    }
  ]

  return (
    <section id="problem" className="relative py-16 md:py-20 lg:py-24 px-6 bg-background overflow-hidden border-t border-border/50">
      <div className="absolute top-1/2 left-0 -translate-y-1/2 h-[600px] w-[600px] bg-red-500/5 rounded-full blur-[140px] -z-10" />

      <div className="max-w-7xl mx-auto flex flex-col items-center">
        <div className="text-center max-w-4xl space-y-6 mb-24 animate-in fade-in slide-in-from-bottom-10 duration-1000">
           <div className="flex items-center justify-center space-x-3 text-blue-400/60 uppercase font-black tracking-[0.4em] text-[10px]">
              <AlertTriangle className="h-4 w-4" />
              <span>THE INTELLIGENCE GAP</span>
           </div>

           <h2 className="text-4xl md:text-7xl font-black tracking-tighter text-foreground uppercase leading-[0.9]">
             Modern Attacks Are Connected. <br />
             <span className="text-muted-foreground/40 opacity-40">Your Tools Are Not.</span>
           </h2>

           <p className="max-w-2xl mx-auto text-lg text-muted-foreground/80 font-medium italic">
             Yesterday&apos;s security stack relies on disconnected models trying to solve complex, cross-domain threats in isolation.
           </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-10 w-full animate-in fade-in slide-in-from-bottom-12 duration-1000 delay-300">
           {points.map((pt, i) => (
             <div key={i} className="group relative">
                <div className={cn(
                  "absolute -left-4 top-0 bottom-0 w-0.5 bg-gradient-to-b from-transparent via-white/5 to-transparent transition-all group-hover:w-1",
                  pt.hoverBorder.replace("group-hover:border-", "group-hover:via-").replace("/30", "/40")
                )} />

                <div className="space-y-6 pt-6 px-6">
                   <div className={cn(
                     "h-14 w-14 rounded-2xl bg-muted flex items-center justify-center border border-border/30 transition-all group-hover:scale-110 shadow-2xl",
                     pt.hoverBorder,
                     pt.accent
                   )}>
                      <pt.icon className="h-7 w-7" />
                   </div>

                   <h4 className="text-xl font-black uppercase tracking-tight text-foreground group-hover:text-slate-200 transition-colors">{pt.title}</h4>
                   <p className="text-muted-foreground/80 leading-relaxed font-medium">
                      {pt.desc}
                   </p>
                </div>
             </div>
           ))}
        </div>

        <div className="mt-32 w-full max-w-5xl h-[300px] rounded-[3rem] border border-border/20 bg-muted/80 flex flex-col items-center justify-center p-12 overflow-hidden shadow-2xl relative group">
           <div className="absolute inset-0 bg-muted/50 backdrop-blur-3xl -z-10" />
           <div className="flex flex-col items-center text-center space-y-6 relative z-10">
              <div className="flex -space-x-4 opacity-40 group-hover:opacity-100 transition-all group-hover:scale-110">
                 <div className="h-16 w-16 rounded-full bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-400">
                    <XCircle className="h-8 w-8" />
                 </div>
                 <div className="h-16 w-16 rounded-full bg-muted border border-border/20 flex items-center justify-center text-muted-foreground/40 font-black italic">VS</div>
                 <div className="h-16 w-16 rounded-full bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 shadow-[0_0_20px_rgba(59,130,246,0.3)]">
                    <Zap className="h-8 w-8" />
                 </div>
              </div>
              <p className="text-[10px] font-black uppercase tracking-[0.5em] text-blue-400 opacity-60">Bridging the detection silos</p>
           </div>

           <div className="absolute bottom-[-50px] left-[-100px] h-[300px] w-full bg-[linear-gradient(rgba(59,130,246,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(59,130,246,0.02)_1px,transparent_1px)] bg-[size:20px_20px] -z-1" />
        </div>
      </div>
    </section>
  )
}
