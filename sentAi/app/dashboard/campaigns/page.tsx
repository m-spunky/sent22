"use client"

import React, { useState, useEffect } from "react"
import { PlusCircle, Target, Filter, History } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { CampaignList } from "@/components/campaigns/CampaignList"
import { CampaignDetails } from "@/components/campaigns/CampaignDetails"
import { listCampaigns, type Campaign } from "@/lib/api"
import { cn } from "@/lib/utils"

type RiskLevel = "HIGH" | "MEDIUM" | "LOW"
type CampaignStatus = "Active" | "Mitigated" | "Investigating"

function mapCampaignToListItem(c: Campaign) {
  const riskMap: Record<string, RiskLevel> = { critical: "HIGH", high: "HIGH", medium: "MEDIUM", low: "LOW" }
  const statusMap: Record<string, CampaignStatus> = { active: "Active", monitoring: "Investigating", historical: "Mitigated" }
  return {
    id: c.id,
    type: c.name || c.description?.split(".")[0].slice(0, 40) || c.id,
    risk: riskMap[c.risk_level] || "MEDIUM" as RiskLevel,
    status: statusMap[c.status] || "Investigating" as CampaignStatus,
    actor: c.actor,
    time: c.last_activity,
  }
}

export default function CampaignsPage() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([])
  const [activeId, setActiveId] = useState<string>("")

  useEffect(() => {
    listCampaigns({ limit: 50 }).then(data => {
      setCampaigns(data.campaigns)
      if (data.campaigns.length > 0) setActiveId(data.campaigns[0].id)
    }).catch(() => {})
  }, [])

  const listItems = campaigns.map(mapCampaignToListItem)
  const activeCampaign = campaigns.find(c => c.id === activeId) || campaigns[0]
  const activeMapped = activeCampaign ? mapCampaignToListItem(activeCampaign) : listItems[0]

  return (
    <div className="space-y-10 pb-10">
      {/* Page Header */}
      <header className="w-full flex flex-col md:flex-row items-start md:items-center justify-between gap-6 border-b border-white/5 pb-8 animate-in fade-in slide-in-from-top-4 duration-700">
        <div className="space-y-2">
           <div className="flex items-center space-x-3">
              <div className="h-10 w-10 rounded-xl bg-blue-500/20 text-blue-400 flex items-center justify-center shadow-xl border border-blue-500/30 transition-transform hover:scale-105">
                 <Target className="h-6 w-6" />
              </div>
              <h1 className="text-4xl font-black tracking-tighter text-foreground uppercase">Threat Campaigns</h1>
           </div>
           <div className="flex items-center space-x-2 pl-12 opacity-80">
              <div className="h-2 w-2 rounded-full bg-blue-400 animate-pulse" />
              <p className="text-[10px] text-muted-foreground uppercase font-black tracking-[0.3em]">
                Track and manage active attack campaigns{" "}
                <span className="text-blue-400 italic lowercase font-normal">v2.4-stable</span>
              </p>
           </div>
        </div>

        <div className="flex items-center space-x-4 w-full md:w-auto">
           <div className="hidden lg:flex items-center space-x-6 mr-6 border-r border-white/10 pr-6 h-10">
              <div className="flex flex-col items-end">
                 <span className="text-[8px] font-black uppercase tracking-widest text-muted-foreground leading-none mb-1">Active Delta</span>
                 <span className="text-sm font-black text-red-400 tracking-tighter leading-none">+14 Today</span>
              </div>
              <div className="flex flex-col items-end">
                 <span className="text-[8px] font-black uppercase tracking-widest text-muted-foreground leading-none mb-1">Mitigation Rate</span>
                 <span className="text-sm font-black text-emerald-400 tracking-tighter leading-none">94.8%</span>
              </div>
           </div>

           <Button variant="ghost" size="icon" className="h-10 w-10 text-muted-foreground hover:text-blue-400 hover:bg-blue-500/10 rounded-xl">
              <Filter className="h-5 w-5" />
           </Button>
           <Button className="rounded-xl bg-blue-600 text-white font-black uppercase tracking-widest px-6 h-10 hover:bg-blue-500 transition-all hover:scale-105 active:scale-95">
              <PlusCircle className="h-4 w-4 mr-2" />
              Create Campaign
           </Button>
        </div>
      </header>

      {/* Campaigns Grid */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch animate-in fade-in slide-in-from-bottom-8 duration-1000">
        <div className="col-span-12 lg:col-span-4 min-h-[500px] lg:h-[850px]">
           <CampaignList
              items={listItems.length > 0 ? listItems : [
                { id: "CAMP-2026-1847", type: "Operation Wire Phantom", risk: "HIGH" as const, status: "Active" as const, actor: "FIN7", time: "2m ago" },
              ]}
              activeId={activeId}
              onSelect={setActiveId}
           />
        </div>

        <div className="col-span-12 lg:col-span-8 min-h-[600px] lg:min-h-[850px]">
           {activeMapped && <CampaignDetails {...activeMapped} />}
        </div>
      </section>

      {/* Historical Threat Landscape */}
      <div className="col-span-12 pt-6">
         <Card className="card-cyber p-10 relative group">
            <div className="absolute top-0 right-0 p-8 opacity-5">
               <History className="h-32 w-32 text-blue-400" />
            </div>
            <div className="space-y-8 relative z-10">
               <div className="flex items-center justify-between">
                  <div className="space-y-1">
                     <h3 className="text-xl font-black tracking-tighter text-foreground uppercase">Historical Threat Landscape</h3>
                     <p className="text-[10px] text-muted-foreground uppercase font-black tracking-widest">
                        Analyzing attack frequency across global enterprise clusters
                     </p>
                  </div>
                  <Badge variant="outline" className="border-blue-500/20 text-blue-400 text-[8px] h-5 px-3 uppercase font-bold tracking-widest">Aggregate View</Badge>
               </div>

               <div className="h-48 w-full flex items-end justify-between gap-0.5 pt-10">
                  {Array.from({ length: 72 }).map((_, i) => (
                    <div
                      key={i}
                      className={cn(
                        "flex-1 rounded-sm transition-all duration-700 hover:h-[120%] cursor-pointer group/bar relative",
                        i % 12 === 0 ? "bg-blue-500/30 hover:bg-blue-400" : "bg-white/5 hover:bg-blue-500/20"
                      )}
                      style={{ height: `${15 + Math.random() * 85}%` }}
                    />
                  ))}
               </div>

               <div className="flex justify-between text-[7px] text-muted-foreground/30 uppercase font-black tracking-[0.5em] pt-4 border-t border-white/5">
                  <span>JAN-2026</span>
                  <span>FEB-2026</span>
                  <span>MAR-2026</span>
                  <span>APR-2026</span>
                  <span>MAY-2026</span>
                  <span>CURRENT CYCLE</span>
               </div>
            </div>
         </Card>
      </div>
    </div>
  )
}
