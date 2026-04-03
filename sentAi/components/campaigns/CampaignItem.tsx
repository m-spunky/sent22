"use client"

import React from "react"
import { Mail, Globe, Clock, ChevronRight, Zap } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

export type CampaignStatus = "Active" | "Mitigated" | "Investigating"
export type RiskLevel = "HIGH" | "MEDIUM" | "LOW"

interface CampaignItemProps {
  id: string
  type: string
  risk: RiskLevel
  status: CampaignStatus
  actor: string
  time: string
  active?: boolean
  onClick?: () => void
}

export function CampaignItem({ id, type, risk, status, actor, time, active, onClick }: CampaignItemProps) {
  const riskPulse = risk === "HIGH" ? "bg-red-400" : risk === "MEDIUM" ? "bg-amber-400" : "bg-emerald-400"
  const riskText = risk === "HIGH" ? "text-red-400" : risk === "MEDIUM" ? "text-amber-400" : "text-emerald-400"

  return (
    <div
      className={cn(
        "group relative p-4 rounded-xl border transition-all duration-300 cursor-pointer overflow-hidden flex flex-col space-y-3",
        active
          ? "bg-blue-500/10 border-blue-500/30 shadow-[0_0_20px_rgba(59,130,246,0.15)] ring-1 ring-blue-500/20"
          : "bg-[#0D1B2A]/40 border-white/5 hover:bg-white/5 hover:border-white/10"
      )}
      onClick={onClick}
    >
      {active && (
        <div className="absolute top-0 right-0 p-2 opacity-10">
           <Zap className="h-10 w-10 text-blue-400 blur-sm" />
        </div>
      )}

      <div className="flex items-center justify-between">
         <div className="flex items-center gap-2">
            <div className={cn("h-1.5 w-1.5 rounded-full animate-pulse", riskPulse)} />
            <span className="text-[10px] font-bold uppercase tracking-widest text-slate-300 font-mono">{id}</span>
         </div>
         <Badge className={cn(
           "text-[8px] h-4 rounded-full px-2 uppercase font-bold tracking-widest border-none",
           status === "Active" ? "bg-red-500/10 text-red-400" :
           status === "Investigating" ? "bg-amber-500/10 text-amber-400" :
           "bg-emerald-500/10 text-emerald-400"
         )}>
           {status}
         </Badge>
      </div>

      <div className="flex items-center gap-3">
         <div className={cn(
           "h-9 w-9 rounded-lg bg-white/5 flex items-center justify-center border border-white/5 transition-colors",
           active ? "border-blue-500/20" : "group-hover:border-white/10"
         )}>
            {type.toLowerCase().includes("email") || type.toLowerCase().includes("phish")
              ? <Mail className={cn("h-4 w-4 transition-colors", active ? "text-blue-400" : "text-slate-500 group-hover:text-slate-400")} />
              : <Globe className={cn("h-4 w-4 transition-colors", active ? "text-blue-400" : "text-slate-500")} />
            }
         </div>
         <div className="flex-1 min-w-0">
            <h4 className={cn("text-[11px] font-bold truncate transition-colors", active ? "text-blue-300" : "text-slate-300 group-hover:text-slate-200")}>{type}</h4>
            <p className="text-[8px] text-slate-600 uppercase font-bold tracking-widest mt-0.5 truncate font-mono">Actor: {actor}</p>
         </div>
         <ChevronRight className={cn(
           "h-3.5 w-3.5 transition-all",
           active ? "opacity-100 text-blue-400" : "opacity-0 -translate-x-1 group-hover:opacity-60 group-hover:translate-x-0 text-slate-500"
         )} />
      </div>

      <div className="flex items-center justify-between pt-1 border-t border-white/5 opacity-60">
         <div className="flex items-center gap-1 text-[7px] font-bold uppercase tracking-widest text-slate-600">
            <Clock className="h-2.5 w-2.5" />
            {time}
         </div>
         <span className={cn("text-[7px] font-bold uppercase tracking-widest font-mono", riskText)}>{risk} RISK</span>
      </div>
    </div>
  )
}
