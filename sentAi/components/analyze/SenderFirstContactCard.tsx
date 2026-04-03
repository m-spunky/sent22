import React from "react"
import { AlertTriangle, Clock, Globe, ShieldQuestion } from "lucide-react"
import { Card } from "@/components/ui/card"
import { cn } from "@/lib/utils"

interface SenderFirstContactCardProps {
  first_contact: {
    is_first_contact: boolean
    first_seen?: string
    domain?: string
    risk_boost?: number
    flag?: string
  }
}

export function SenderFirstContactCard({ first_contact }: SenderFirstContactCardProps) {
  if (!first_contact || !first_contact.is_first_contact) return null

  // Determine if it's a completely new domain vs recently seen
  const isBrandNew = first_contact.flag === "SENDER_FIRST_CONTACT_NEW"
  
  // Format the time since first seen
  let timeAgo = "Just now"
  if (first_contact.first_seen) {
    try {
      const firstSeenStr = first_contact.first_seen.replace("Z", "+00:00") // Ensure timezone
      const firstSeen = new Date(firstSeenStr)
      if (!isNaN(firstSeen.getTime())) {
        const diffMs = new Date().getTime() - firstSeen.getTime()
        const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
        if (diffHours < 1) {
          const diffMins = Math.floor(diffMs / (1000 * 60))
          timeAgo = `${diffMins} min${diffMins !== 1 ? 's' : ''} ago`
        } else {
          timeAgo = `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`
        }
      } else {
          // fallback if parsing fails
          timeAgo = "Recently"
      }
    } catch {
      timeAgo = "Recently"
    }
  }

  return (
    <Card className="card-cyber border-t-2 border-t-purple-500/40 p-4 relative overflow-hidden bg-purple-500/5">
      <div className="absolute top-0 right-0 p-4 opacity-10">
        <ShieldQuestion className="w-24 h-24 text-purple-400" />
      </div>

      <div className="relative z-10 flex items-start gap-4">
        <div className="h-10 w-10 rounded-xl bg-purple-500/20 border border-purple-500/30 flex items-center justify-center shrink-0">
          <AlertTriangle className="h-5 w-5 text-purple-400" />
        </div>
        
        <div className="flex-1 space-y-2">
          <div className="flex justify-between items-start">
            <div>
              <h4 className="text-[10px] font-black uppercase tracking-[0.2em] text-purple-400">Zero-Day Infrastructure Detected</h4>
              <p className="text-lg font-black text-foreground mt-0.5 tracking-tight">Sender First-Contact Alert</p>
            </div>
            {first_contact.risk_boost ? (
              <span className="text-[10px] font-mono font-bold text-red-400 bg-red-500/10 px-2 py-1 rounded-md border border-red-500/20">
                +{first_contact.risk_boost} RISK
              </span>
            ) : null}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
            <div className="bg-black/20 rounded-lg p-2.5 border border-white/5 flex items-center gap-3">
              <Globe className="h-4 w-4 text-slate-500 shrink-0" />
              <div className="min-w-0">
                <p className="text-[8px] font-black uppercase tracking-widest text-slate-500">Sender Domain</p>
                <p className="text-xs font-mono font-bold text-slate-300 truncate">{first_contact.domain || "Unknown"}</p>
              </div>
            </div>
            
            <div className="bg-black/20 rounded-lg p-2.5 border border-white/5 flex items-center gap-3">
              <Clock className="h-4 w-4 text-slate-500 shrink-0" />
              <div className="min-w-0">
                <p className="text-[8px] font-black uppercase tracking-widest text-slate-500">First Seen On Network</p>
                <p className={cn("text-xs font-mono font-bold", isBrandNew ? "text-red-400" : "text-amber-400")}>
                  {isBrandNew ? "Never (Brand New)" : timeAgo}
                </p>
              </div>
            </div>
          </div>
          
          <p className="text-[10px] text-slate-400 leading-relaxed mt-2 italic">
            This sender infrastructure has {isBrandNew ? "never been observed before" : "only recently appeared"} across our monitored networks. Burner domains are strongly correlated with zero-day phishing campaigns.
          </p>
        </div>
      </div>
    </Card>
  )
}
