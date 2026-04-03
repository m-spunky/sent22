import React from "react"
import { Share2, Target, User, Globe, ShieldCheck, Link2 } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

interface IntelCardProps {
  campaign: string
  actor: string
  actorConfidence?: number
  relatedDomains?: string[]
  loading?: boolean
}

export function IntelCard({ campaign, actor, actorConfidence, relatedDomains, loading }: IntelCardProps) {
  const confidenceStr = actorConfidence != null ? `${Math.round(actorConfidence * 100)}%` : "94%"
  const isKnownActor = actor !== "Unknown" && actor !== "Unattributed"

  const intelItems = [
    { label: "Campaign ID", value: campaign, icon: Target, highlight: false },
    { label: "Threat Actor", value: isKnownActor ? actor : "Unattributed", icon: User, highlight: isKnownActor },
    { label: "Confidence", value: confidenceStr, icon: ShieldCheck, highlight: false },
    { label: "Global Reach", value: "UA, PL, US", icon: Globe, highlight: false },
  ]

  const domains = relatedDomains && relatedDomains.length > 0
    ? relatedDomains
    : ["auth-login.net", "secure-pay.ua", "cloud-verify.io"]

  return (
    <Card className="card-cyber h-full flex flex-col">
      <CardHeader className="p-5 border-b border-white/5 flex flex-row items-center justify-between">
        <div className="space-y-1">
          <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
            <Share2 className="h-3.5 w-3.5 text-blue-400" />
            Threat Intelligence
          </CardTitle>
          <CardDescription className="text-[10px] text-slate-500 uppercase tracking-widest">
            OSINT & Historical Correlation
          </CardDescription>
        </div>
        {loading && (
          <div className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
        )}
      </CardHeader>

      <CardContent className="p-5 flex-1 flex flex-col justify-center space-y-5">
         <div className="grid grid-cols-2 gap-3">
            {intelItems.map((item, i) => (
              <div
                key={i}
                className={cn(
                  "space-y-1.5 px-3 py-2.5 rounded-xl border transition-all cursor-pointer",
                  item.highlight
                    ? "border-red-500/20 bg-red-500/5 hover:border-red-500/40"
                    : "border-white/5 hover:border-blue-500/20 hover:bg-blue-500/5"
                )}
              >
                 <div className="flex items-center text-[8px] font-bold uppercase tracking-widest text-slate-500 gap-1.5">
                    <item.icon className="h-3 w-3" />
                    {item.label}
                 </div>
                 <p className={cn(
                   "text-sm font-bold font-mono truncate",
                   item.highlight ? "text-red-400" : "text-slate-200"
                 )}>{loading ? "--" : item.value}</p>
              </div>
            ))}
         </div>

         <div className="pt-3 border-t border-white/5 space-y-3">
            <div className="flex items-center justify-between">
               <h4 className="text-[9px] font-bold uppercase tracking-widest text-slate-500">Related Domains</h4>
               <Badge className="bg-red-500/10 text-red-400 border-red-500/20 text-[8px] rounded-full px-2 uppercase font-bold tracking-widest">
                 Active IOCs
               </Badge>
            </div>

            <div className="flex flex-wrap gap-1.5">
               {domains.map((domain, i) => (
                 <div
                   key={i}
                   className="flex items-center gap-1.5 px-2.5 py-1 bg-white/3 border border-white/5 rounded-lg hover:border-red-500/20 transition-all cursor-pointer group/domain"
                 >
                    <Link2 className="h-2.5 w-2.5 text-slate-600 group-hover/domain:text-red-400 transition-colors rotate-45" />
                    <span className="text-[10px] font-mono text-slate-400 group-hover/domain:text-red-400 transition-colors">{domain}</span>
                 </div>
               ))}
            </div>
         </div>
      </CardContent>
    </Card>
  )
}
