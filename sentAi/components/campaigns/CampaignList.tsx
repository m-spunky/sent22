"use client"

import React, { useState } from "react"
import { Search, LayoutList, Target, PlusCircle } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { CampaignItem, CampaignStatus, RiskLevel } from "./CampaignItem"

interface Campaign {
  id: string
  type: string
  risk: RiskLevel
  status: CampaignStatus
  actor: string
  time: string
}

interface CampaignListProps {
  items: Campaign[]
  activeId: string
  onSelect: (id: string) => void
}

export function CampaignList({ items, activeId, onSelect }: CampaignListProps) {
  const [searchTerm, setSearchTerm] = useState("")

  const filtered = items.filter(item =>
    item.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    item.actor.toLowerCase().includes(searchTerm.toLowerCase()) ||
    item.type.toLowerCase().includes(searchTerm.toLowerCase())
  )

  return (
    <Card className="card-cyber overflow-hidden flex flex-col h-full">
       <CardHeader className="p-5 border-b border-white/5 flex flex-row items-center justify-between">
          <div className="space-y-1">
             <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
                <LayoutList className="h-3.5 w-3.5 text-blue-400" />
                Active Campaigns
             </CardTitle>
             <CardDescription className="text-[10px] text-slate-500 uppercase tracking-widest">
                Operation Intelligence Feed
             </CardDescription>
          </div>
          <Badge className="bg-red-500/10 text-red-400 border border-red-500/20 text-[8px] h-5 rounded-full px-2 uppercase font-bold tracking-widest animate-pulse">
            {items.length} Live
          </Badge>
       </CardHeader>

       <CardContent className="p-4 space-y-4 flex-1 flex flex-col overflow-hidden">
          <div className="relative">
             <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-600" />
             <Input
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                placeholder="Search campaigns..."
                className="bg-[#0D1B2A]/60 border-white/5 focus:border-blue-500/40 rounded-xl pl-9 text-xs font-bold h-9 placeholder:text-slate-700"
             />
          </div>

          <div className="flex-1 overflow-y-auto pr-1 space-y-2 scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent">
             {filtered.map((campaign) => (
               <CampaignItem
                  key={campaign.id}
                  {...campaign}
                  active={activeId === campaign.id}
                  onClick={() => onSelect(campaign.id)}
               />
             ))}

             {filtered.length === 0 && (
               <div className="h-full flex flex-col items-center justify-center space-y-4 opacity-40 py-20">
                  <div className="h-10 w-10 border-2 border-dashed border-white/20 rounded-full flex items-center justify-center">
                     <Target className="h-5 w-5 text-slate-500" />
                  </div>
                  <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500">No Campaigns Found</p>
               </div>
             )}
          </div>

          <div className="pt-3 border-t border-white/5">
             <button className="w-full h-10 bg-blue-500/5 border border-blue-500/10 rounded-xl text-[10px] font-bold uppercase tracking-widest text-blue-400 hover:bg-blue-500/10 transition-all flex items-center justify-center gap-2">
                <PlusCircle className="h-3.5 w-3.5" />
                Initialize Operation
             </button>
          </div>
       </CardContent>
    </Card>
  )
}
