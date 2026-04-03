import React from "react"
import { Globe, Target, User, Activity, MoreVertical, Link2, ExternalLink, ShieldCheck, Zap } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

interface Relationship {
  name: string
  type: "actor" | "domain" | "campaign" | "ip"
  relation: string
}

interface RelationshipListProps {
  items: Relationship[]
}

const typeIcons = {
  actor: User,
  domain: Globe,
  campaign: Target,
  ip: Activity,
}

export function RelationshipList({ items }: RelationshipListProps) {
  return (
    <div className="space-y-4">
       <div className="flex items-center justify-between">
          <h4 className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground flex items-center">
             <Zap className="h-3 w-3 mr-2" />
             Infrastructure Affiliation
          </h4>
          <Badge variant="ghost" className="text-[9px] font-bold text-accent transition-all hover:scale-105 active:scale-95 border border-accent/20 cursor-pointer">{items.length} Nodes</Badge>
       </div>
       
       <div className="space-y-2">
          {items.map((item, i) => {
            const Icon = typeIcons[item.type]
            
            return (
              <div key={i} className="flex items-center justify-between p-3 rounded-xl bg-[#0D1B2A]/60 border border-white/5 hover:border-accent/30 transition-all cursor-pointer group/item shadow-lg relative overflow-hidden">
                 <div className="flex items-center space-x-3">
                    <div className={cn(
                      "h-8 w-8 rounded-lg flex items-center justify-center transition-all group-hover/item:scale-110",
                      item.type === "actor" ? "bg-destructive/10 text-destructive" : "bg-accent/10 text-accent"
                    )}>
                       <Icon className="h-4 w-4" />
                    </div>
                    <div className="flex flex-col">
                       <span className="text-[10px] font-bold text-foreground group-hover/item:text-accent transition-colors truncate w-32">{item.name}</span>
                       <span className="text-[7px] text-muted-foreground uppercase font-black tracking-widest leading-none mt-0.5">{item.relation}</span>
                    </div>
                 </div>
                 <Badge className="bg-accent/5 text-accent border-accent/10 text-[7px] h-4 rounded-full px-2 uppercase font-black tracking-widest group-hover/item:bg-accent group-hover/item:text-accent-foreground transition-all">{item.type}</Badge>
              </div>
            )
          })}
       </div>
    </div>
  )
}
