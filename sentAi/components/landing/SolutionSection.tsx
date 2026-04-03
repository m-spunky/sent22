"use client"

import React from "react"
import { Zap, Globe, Mail, Activity } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

export function SolutionSection() {
  return (
    <section id="solution" className="relative py-16 md:py-20 lg:py-24 px-6 bg-muted overflow-hidden">
      <div className="absolute inset-0 bg-[linear-gradient(rgba(59,130,246,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(59,130,246,0.02)_1px,transparent_1px)] bg-[size:60px_60px] opacity-10 pointer-events-none" />
      <div className="absolute top-[30%] left-[-10%] h-[800px] w-[800px] bg-blue-500/5 rounded-full blur-[180px] -z-1" />

      <div className="max-w-7xl mx-auto flex flex-col items-center">
        <div className="text-center max-w-4xl space-y-10 mb-32 z-10 animate-in fade-in slide-in-from-top-12 duration-1000">
           <div className="flex items-center justify-center space-x-3 text-blue-400/60 uppercase font-black tracking-[0.4em] text-[10px]">
              <Zap className="h-4 w-4 fill-blue-400" />
              <span>THE FUSION ARCHITECTURE</span>
           </div>

           <h2 className="text-5xl md:text-[6rem] font-black tracking-tighter text-foreground uppercase leading-[0.85]">
             One Platform. <br />
             <span className="text-blue-400 underline decoration-blue-400/20 underline-offset-8 italic font-light decoration-4">Complete</span> Threat Intel.
           </h2>

           <p className="max-w-3xl mx-auto text-xl text-muted-foreground leading-relaxed font-light">
             SentinelAI Fusion breaks tool silos by correlating signals across deep-learning models, global OSINT sources, and real-time infrastructure telemetry.
           </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-20 items-center w-full z-10">
           {/* Left: Layer Card Stack */}
           <div className="relative w-full flex items-center justify-center pt-10 group min-h-[400px]">
              <div className="absolute top-0 left-10 w-full h-[350px] card-cyber rotate-[-4deg] translate-y-0 group-hover:-translate-y-10 group-hover:rotate-0 transition-all duration-700 p-8 shadow-2xl opacity-60 group-hover:opacity-100 cursor-crosshair">
                 <div className="flex items-center justify-between mb-8 opacity-60">
                    <span className="text-[10px] font-black tracking-widest text-blue-400 uppercase">Detection Layer v1.0</span>
                    <Badge className="bg-blue-500/10 border-blue-500/20 text-blue-400 text-[8px] h-5 px-3 uppercase font-black tracking-widest">Active NLP</Badge>
                 </div>
                 <div className="space-y-4">
                    <div className="h-4 w-48 bg-white/5 rounded-full" />
                    <div className="h-4 w-64 bg-white/5 rounded-full" />
                    <div className="h-4 w-32 bg-white/5 rounded-full" />
                 </div>
                 <div className="mt-20 flex justify-end">
                    <div className="h-10 w-10 rounded-xl bg-blue-500/20 flex items-center justify-center border border-blue-500/40 shadow-xl">
                       <Mail className="h-5 w-5 text-blue-400" />
                    </div>
                 </div>
              </div>

              <div className="absolute top-20 left-4 w-full h-[350px] card-cyber rotate-[-2deg] translate-y-10 group-hover:translate-y-16 group-hover:rotate-0 transition-all duration-1000 p-8 shadow-2xl scale-[0.95] z-10 group-hover:scale-100 bg-muted/90 backdrop-blur-3xl cursor-none">
                 <div className="flex items-center justify-between mb-8 opacity-60">
                    <span className="text-[10px] font-black tracking-widest text-blue-400 uppercase">Correlation Layer v2.4</span>
                    <Badge className="bg-blue-500/10 border-blue-500/20 text-blue-400 text-[8px] h-5 px-3 uppercase font-black tracking-widest">Telemetry-Sync</Badge>
                 </div>
                 <div className="flex h-32 items-end justify-between space-x-1">
                    {Array.from({ length: 24 }).map((_, i) => (
                      <div key={i} className="flex-1 bg-blue-500/10 rounded-t-sm h-[40%] group-hover:h-[70%] group-hover:bg-blue-500/30 transition-all" style={{ transitionDelay: `${i * 20}ms` }} />
                    ))}
                 </div>
                 <div className="mt-12 flex justify-end">
                    <div className="h-10 w-10 rounded-xl bg-blue-600 text-white flex items-center justify-center shadow-[0_0_20px_rgba(59,130,246,0.4)]">
                       <Globe className="h-5 w-5" />
                    </div>
                 </div>
              </div>

              <div className="absolute bottom-40 h-[200px] w-0.5 bg-gradient-to-t from-blue-500/40 via-blue-500/20 to-transparent group-hover:h-[400px] transition-all duration-1000 z-0" />
           </div>

           {/* Right: Descriptive Blocks */}
           <div className="space-y-12 py-10 animate-in fade-in slide-in-from-right-12 duration-1000 delay-500">
              {[
                {
                  title: "Multi-modal AI Fusion",
                  desc: "Combines NLP, URL-forensics, visual identity, and metadata signatures into a singular final threat score.",
                  badge: "Nexus-4 Engine"
                },
                {
                  title: "Real-time Intelligence Correlation",
                  desc: "Connects detected signals with global threat actor campaigns and infrastructure automatically.",
                  badge: "Global OSINT-Feed"
                },
                {
                  title: "Actionable AI Explainability",
                  desc: "Every detection is accompanied by a human-readable explanation, allowing for instant analyst trust.",
                  badge: "Reasoning Layer"
                }
              ].map((feature, i) => (
                <div key={i} className="group cursor-pointer">
                   <div className="flex items-center space-x-4 mb-3">
                      <div className="h-4 w-4 rounded-full bg-blue-500/20 border border-blue-500/40 flex items-center justify-center">
                         <div className="h-1.5 w-1.5 rounded-full bg-blue-400 group-hover:animate-ping" />
                      </div>
                      <Badge variant="outline" className="text-[8px] h-5 px-3 uppercase font-black tracking-widest text-blue-400 border-blue-500/20">{feature.badge}</Badge>
                   </div>
                   <h3 className="text-2xl font-black tracking-tight text-foreground group-hover:text-blue-400 transition-colors uppercase mb-3">{feature.title}</h3>
                   <p className="text-muted-foreground/80 text-lg font-medium max-w-md leading-relaxed group-hover:text-muted-foreground transition-colors">
                      {feature.desc}
                   </p>
                </div>
              ))}
           </div>
        </div>
      </div>
    </section>
  )
}
