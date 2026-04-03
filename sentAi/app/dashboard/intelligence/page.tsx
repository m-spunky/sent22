"use client"

import React, { useState } from "react"
import { Search, Target, Share2, Activity, Filter, PlusCircle, Download } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { GraphView } from "@/components/intelligence/GraphView"
import { DetailsPanel } from "@/components/intelligence/DetailsPanel"
import { type GraphNode } from "@/lib/api"
import { cn } from "@/lib/utils"

export default function IntelligencePage() {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)

  return (
    <div className="space-y-10 pb-10">
      {/* Page Header */}
      <header className="w-full flex flex-col md:flex-row items-start md:items-center justify-between gap-6 border-b border-white/5 pb-8 animate-in fade-in slide-in-from-top-4 duration-700">
        <div className="space-y-2">
           <div className="flex items-center space-x-3">
              <div className="h-10 w-10 rounded-xl bg-purple-500/20 text-purple-400 flex items-center justify-center shadow-xl shadow-purple-500/10 border border-purple-500/30 transition-transform hover:scale-105">
                 <Target className="h-6 w-6" />
              </div>
              <h1 className="text-4xl font-black tracking-tighter text-foreground uppercase">Threat Intelligence Explorer</h1>
           </div>
           <div className="flex items-center space-x-2 pl-12 opacity-80 transition-opacity hover:opacity-100">
              <div className="h-2 w-2 rounded-full bg-purple-500 animate-pulse" />
              <p className="text-[10px] text-muted-foreground uppercase font-black tracking-[0.3em]">Explore campaigns, actors, and infrastructure relationships <span className="text-purple-400 italic lowercase font-normal">v2.4-graph-visualizer</span></p>
           </div>
        </div>

        <div className="flex items-center space-x-4 w-full md:w-auto">
           <div className="relative group flex-1 md:flex-none">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground group-focus-within:text-purple-400 transition-colors" />
              <Input
                placeholder="Lookup Campaign ID, Actor, or IOC..."
                className="w-full md:w-80 bg-[#1B263B]/50 border-white/5 focus:border-purple-500/40 rounded-xl pl-10 text-xs font-bold transition-all focus:ring-purple-500/20"
              />
           </div>
           <Button variant="ghost" size="icon" className="h-10 w-10 text-muted-foreground hover:text-purple-400 hover:bg-purple-500/10 rounded-xl">
              <Filter className="h-5 w-5" />
           </Button>
           <Button className="rounded-xl bg-purple-500 text-white font-black uppercase tracking-widest px-6 h-10 shadow-xl shadow-purple-500/20 hover:bg-purple-600 transition-all hover:scale-105 active:scale-95">
              <PlusCircle className="h-4 w-4 mr-2" />
              New Investigation
           </Button>
        </div>
      </header>

      {/* Intelligence Grid */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch animate-in fade-in slide-in-from-bottom-8 duration-1000">

        {/* Graph Area (col-span-8) */}
        <div className="col-span-12 lg:col-span-8 min-h-[500px] lg:h-[850px]">
           <GraphView onNodeSelect={setSelectedNode} />
        </div>

        {/* Details Panel (col-span-4) */}
        <div className="col-span-12 lg:col-span-4 min-h-[500px] lg:h-[850px]">
           <DetailsPanel selectedNode={selectedNode} />
        </div>

        {/* Action Panel Footer (Operational Intel) */}
        <div className="col-span-12 pt-6">
           <Card className="card-cyber border-t-4 border-t-purple-500 overflow-hidden relative group">
              <div className="absolute top-0 right-0 p-8 opacity-20 transition-opacity group-hover:opacity-40">
                 <Target className="h-20 w-24 text-purple-500" />
              </div>
              <CardContent className="p-10 flex flex-col md:flex-row items-center justify-between gap-12 relative z-10">
                 <div className="space-y-4 text-center md:text-left">
                    <h2 className="text-3xl font-black tracking-tighter text-foreground uppercase">Synchronized Campaign Intelligence</h2>
                    <p className="text-sm text-muted-foreground uppercase font-black tracking-widest leading-none mt-1">
                       Cross-referencing global telemetry with known actor signatures
                    </p>
                 </div>

                 <div className="flex flex-wrap items-center justify-center gap-4">
                    {[
                      { label: "Sync OSINT", icon: Share2 },
                      { label: "Deep Forensic Scan", icon: Activity },
                      { label: "Export Evidence", icon: Download },
                    ].map((btn, i) => (
                      <button
                         key={i}
                         className="flex items-center gap-2 px-6 py-3 rounded-lg border border-blue-500/20 hover:border-blue-500/40 text-blue-400 hover:bg-blue-500/10 text-xs font-bold uppercase tracking-widest transition-all"
                      >
                         <btn.icon className="h-4 w-4" />
                         {btn.label}
                      </button>
                    ))}
                 </div>
              </CardContent>
           </Card>
        </div>
      </section>
    </div>
  )
}
