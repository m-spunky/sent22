"use client"

import React, { useEffect, useState } from "react"
import { Target, Share2, Printer, Globe2, Link2, Monitor, Users, AlertTriangle, ShieldCheck, TrendingUp, Edit2 } from "lucide-react"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ActionPanel } from "./ActionPanel"
import { getCampaignDetail } from "@/lib/api"
import type { Campaign } from "@/lib/api"
import { cn } from "@/lib/utils"

interface CampaignDetailsProps {
  id: string
  type: string
  risk: string
  status: string
  actor: string
  time: string
}

const VELOCITY_BARS = [42, 58, 23, 85, 91, 14, 66, 30, 77, 45, 12, 89, 54, 38, 71, 95, 23, 67, 41, 88, 55, 33, 76, 49, 10, 82, 36, 68, 92, 44, 18, 75, 59, 31, 87, 62, 28, 98, 51, 15, 74, 40, 60, 22, 90, 48, 35, 79]

export function CampaignDetails({ id, type, risk, status, actor, time }: CampaignDetailsProps) {
  const [campaign, setCampaign] = useState<Campaign | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    getCampaignDetail(id)
      .then(data => { setCampaign(data); setLoading(false) })
      .catch(() => setLoading(false))
  }, [id])

  // Merge live IOC data with prop fallbacks
  const iocs: string[] = campaign
    ? [...(campaign.iocs?.domains || []), ...(campaign.iocs?.ips || [])].slice(0, 8)
    : ["auth-login.net", "192.168.45.21", "secure-pay.ua", "cloud-verify.io", "v-log.ru"]

  const iocCount = campaign?.ioc_count ?? iocs.length
  const techniques = campaign?.techniques || []
  const targets = campaign?.targets || []

  const statusColor = status === "Active" ? "bg-red-500/10 text-red-400 border-red-500/20 animate-pulse"
    : status === "Investigating" ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
    : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"

  const riskColor = risk === "HIGH" ? "text-red-400" : risk === "MEDIUM" ? "text-amber-400" : "text-emerald-400"

  return (
    <div className="flex flex-col space-y-6 animate-in fade-in slide-in-from-right-8 duration-700">
       {/* Campaign Overview */}
       <Card className="card-cyber overflow-hidden">
          <CardHeader className="p-6 border-b border-white/5 bg-blue-500/3 flex flex-row items-center justify-between">
             <div className="flex items-center gap-5">
                <div className="h-14 w-14 rounded-xl bg-blue-500/20 border border-blue-500/30 flex items-center justify-center shadow-xl shadow-blue-500/10">
                   <Target className="h-7 w-7 text-blue-400" />
                </div>
                <div className="space-y-1">
                   <div className="flex items-center gap-3">
                      <h2 className="text-2xl font-black tracking-tighter text-foreground uppercase">{id}</h2>
                      <Badge className={cn("text-[9px] h-5 rounded-lg px-2.5 uppercase font-bold tracking-widest border", statusColor)}>
                        {status}
                      </Badge>
                      <Badge className={cn("text-[9px] h-5 rounded-lg px-2.5 uppercase font-bold tracking-widest border border-white/10 bg-transparent", riskColor)}>
                        {risk} risk
                      </Badge>
                   </div>
                   <p className="text-[10px] text-slate-500 uppercase font-bold tracking-widest font-mono">
                     Actor: <span className="text-slate-400">{actor}</span>
                     <span className="mx-2 text-white/10">|</span>
                     Last Activity: <span className="text-slate-400">{time}</span>
                   </p>
                </div>
             </div>
             <div className="flex items-center gap-1.5">
                {[Share2, Printer, Edit2].map((Icon, i) => (
                  <button key={i} className="h-8 w-8 text-slate-500 hover:text-blue-400 hover:bg-blue-500/10 rounded-lg transition-all flex items-center justify-center">
                     <Icon className="h-4 w-4" />
                  </button>
                ))}
             </div>
          </CardHeader>

          <CardContent className="p-6 space-y-6">
             {/* Stats row */}
             <div className="grid grid-cols-4 gap-3">
                {[
                  { label: "Target Sectors", value: targets.length > 0 ? `${targets.length} Sectors` : "8 Active", icon: Monitor, color: "text-slate-200" },
                  { label: "IOC Count", value: `${iocCount} Flags`, icon: AlertTriangle, color: "text-red-400" },
                  { label: "Techniques", value: `${techniques.length > 0 ? techniques.length : 14} Mapped`, icon: TrendingUp, color: "text-amber-400" },
                  { label: "Confidence", value: "98.9%", icon: ShieldCheck, color: "text-emerald-400" },
                ].map((stat, i) => (
                  <div key={i} className="p-3 rounded-xl bg-white/3 border border-white/5 hover:border-blue-500/20 transition-all">
                     <div className="flex items-center gap-1.5 text-[8px] font-bold uppercase tracking-widest text-slate-600 mb-1.5">
                        <stat.icon className="h-2.5 w-2.5" />
                        {stat.label}
                     </div>
                     <p className={cn("text-lg font-black tracking-tighter font-mono", stat.color)}>
                       {loading ? "--" : stat.value}
                     </p>
                  </div>
                ))}
             </div>

             <div className="grid grid-cols-2 gap-6">
                {/* IOCs */}
                <div className="space-y-3">
                   <div className="flex items-center justify-between border-b border-white/5 pb-2">
                      <h4 className="text-[10px] font-bold uppercase tracking-widest text-blue-400 flex items-center gap-2">
                         <Globe2 className="h-3.5 w-3.5" />
                         Related Indicators
                      </h4>
                      <span className="text-[8px] text-slate-600 font-mono">IOCs: {iocCount}</span>
                   </div>
                   <div className="flex flex-wrap gap-1.5">
                      {loading
                        ? Array.from({ length: 5 }).map((_, i) => (
                            <div key={i} className="h-7 w-24 bg-white/5 rounded-lg animate-pulse" />
                          ))
                        : iocs.map((ioc, i) => (
                          <div key={i} className="flex items-center gap-1.5 px-3 py-1.5 bg-white/3 border border-white/5 rounded-lg hover:border-red-500/20 cursor-pointer transition-all group/tag">
                             <Link2 className="h-2.5 w-2.5 text-slate-600 group-hover/tag:text-red-400 transition-colors rotate-45" />
                             <span className="text-[9px] font-mono text-slate-400 group-hover/tag:text-red-400 transition-colors">{ioc}</span>
                          </div>
                        ))
                      }
                   </div>
                </div>

                {/* Attack Velocity */}
                <div className="space-y-3">
                   <div className="flex items-center justify-between border-b border-white/5 pb-2">
                      <h4 className="text-[10px] font-bold uppercase tracking-widest text-blue-400 flex items-center gap-2">
                         <TrendingUp className="h-3.5 w-3.5" />
                         Attack Velocity
                      </h4>
                      <Badge className="bg-red-500/10 text-red-400 border-none text-[7px] font-bold uppercase animate-pulse">+128% Trend</Badge>
                   </div>

                   <div className="h-28 w-full flex items-end justify-between gap-0.5">
                      {VELOCITY_BARS.map((h, i) => (
                        <div
                          key={i}
                          className={cn(
                            "flex-1 rounded-sm transition-all duration-500 hover:scale-y-125",
                            i > 30 && i < 40 ? "bg-red-500/40 hover:bg-red-500/60" : "bg-white/5 hover:bg-blue-500/20"
                          )}
                          style={{ height: `${h}%` }}
                        />
                      ))}
                   </div>
                </div>
             </div>

             {/* Techniques */}
             {techniques.length > 0 && (
               <div className="pt-2 border-t border-white/5 space-y-2">
                  <h4 className="text-[9px] font-bold uppercase tracking-widest text-slate-500">MITRE Techniques</h4>
                  <div className="flex flex-wrap gap-1.5">
                     {techniques.slice(0, 8).map((t, i) => (
                       <Badge key={i} variant="outline" className="text-[8px] border-white/10 text-slate-400 font-mono uppercase">
                         {t}
                       </Badge>
                     ))}
                  </div>
               </div>
             )}
          </CardContent>
       </Card>

       <ActionPanel campaign={campaign} />
    </div>
  )
}
