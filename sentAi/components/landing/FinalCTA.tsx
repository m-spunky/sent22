"use client"

import React from "react"
import Link from "next/link"
import { ArrowRight, ShieldCheck, Lock } from "lucide-react"
import { Button } from "@/components/ui/button"

export function FinalCTA() {
  return (
    <section className="relative py-16 md:py-20 lg:py-24 px-6 bg-background overflow-hidden border-t border-border/50">
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 h-[1000px] w-[1000px] bg-blue-500/5 rounded-full blur-[200px] -z-10 animate-pulse" />

      <div className="max-w-7xl mx-auto flex flex-col items-center">
        <div className="text-center max-w-4xl space-y-10 animate-in fade-in slide-in-from-top-12 duration-1000">
           <div className="flex items-center justify-center space-x-3 text-blue-400/60 uppercase font-black tracking-[0.4em] text-[10px]">
              <Lock className="h-4 w-4" />
              <span>THE FUTURE IS FUSION</span>
           </div>

           <h2 className="text-5xl md:text-[6.5rem] font-black tracking-tighter text-foreground uppercase leading-[0.85]">
             Start Seeing Threats <br />
             The Way <span className="text-blue-400 underline decoration-blue-400/10 underline-offset-8 italic font-light decoration-4 hover:decoration-blue-400/40 transition-all">Attackers</span> Do.
           </h2>

           <p className="max-w-3xl mx-auto text-xl text-muted-foreground leading-relaxed font-light">
             Stop responding to disconnected alerts. Start understanding the full narrative of your workspace security with SentinelAI.
           </p>

           <div className="flex flex-wrap items-center justify-center gap-6 pt-10">
              <Link href="/dashboard/analyze">
                <Button size="lg" className="rounded-2xl bg-blue-600 text-white hover:bg-blue-500 shadow-[0_0_30px_rgba(59,130,246,0.3)] px-12 py-8 text-xs font-black uppercase tracking-[0.2em] transition-all hover:scale-105 active:scale-95">
                   Launch Console
                   <ArrowRight className="ml-3 h-5 w-5" />
                </Button>
              </Link>
              <Link href="/dashboard">
                <Button size="lg" variant="outline" className="rounded-2xl border-blue-500/20 hover:border-blue-500/40 hover:bg-blue-500/5 px-12 py-8 text-xs font-black uppercase tracking-[0.2em] transition-all hover:scale-105 active:scale-95">
                   Explore Platform
                </Button>
              </Link>
           </div>
        </div>

        <div className="mt-16 w-full max-w-5xl rounded-[3rem] border border-blue-500/10 bg-muted/80 flex flex-col items-center justify-center p-20 overflow-hidden shadow-2xl relative group cursor-none">
           <div className="absolute inset-0 bg-muted/50 backdrop-blur-3xl -z-10" />
           <div className="flex flex-col items-center text-center space-y-10 relative z-10">
              <div className="h-24 w-24 rounded-[2rem] bg-blue-500/20 border border-blue-500/40 flex items-center justify-center shadow-[0_0_40px_rgba(59,130,246,0.3)] animate-bounce group-hover:scale-110 transition-transform">
                 <ShieldCheck className="h-12 w-12 text-blue-400" />
              </div>
              <p className="text-[12px] font-black uppercase tracking-[0.8em] text-blue-400 opacity-40">Operational Status: Peak</p>
           </div>

           <div className="absolute bottom-[-100px] left-[-150px] h-[500px] w-full bg-[linear-gradient(rgba(59,130,246,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(59,130,246,0.03)_1px,transparent_1px)] bg-[size:40px_40px] -z-1 group-hover:bg-[size:80px_80px] transition-all duration-[2000ms]" />
        </div>
      </div>
    </section>
  )
}
