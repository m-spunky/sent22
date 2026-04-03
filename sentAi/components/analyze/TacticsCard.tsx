import React from "react"
import { Flag, UserX, ShieldAlert, ShieldCheck } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { cn } from "@/lib/utils"

interface TacticsCardProps {
  tactics: string[]
  detectedTactics?: { name: string; mitre_id: string; confidence: number }[]
  loading?: boolean
}

export function TacticsCard({ tactics, detectedTactics, loading }: TacticsCardProps) {
  const getIcon = (tactic: string) => {
    switch(tactic.toLowerCase()) {
      case "urgency": return <ShieldAlert className="h-4 w-4 mr-2 text-red-400" />
      case "spoofing": return <UserX className="h-4 w-4 mr-2 text-red-400" />
      case "impersonation": return <Flag className="h-4 w-4 mr-2 text-red-400" />
      default: return <ShieldCheck className="h-4 w-4 mr-2 text-blue-400" />
    }
  }

  return (
    <Card className="card-cyber h-full flex flex-col">
      <CardHeader className="p-5 border-b border-white/5 flex flex-row items-center justify-between">
        <div className="space-y-1">
          <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
            <Flag className="h-3.5 w-3.5 text-red-400" />
            Detected Tactics
          </CardTitle>
          <CardDescription className="text-[10px] text-slate-500 uppercase tracking-widest">
            MITRE ATT&CK Mapping
          </CardDescription>
        </div>
      </CardHeader>

      <CardContent className="p-5 flex-1 flex flex-col justify-center space-y-4">
         <div className="flex flex-wrap gap-2">
            {tactics.map((tactic, i) => (
              <div
                key={i}
                className="flex items-center bg-red-500/10 border border-red-500/20 px-4 py-2.5 rounded-xl hover:bg-red-500/15 transition-all cursor-pointer group/tactic relative overflow-hidden"
              >
                 {getIcon(tactic)}
                 <span className="text-sm font-bold uppercase tracking-tight text-red-400">{tactic}</span>
              </div>
            ))}
         </div>

         {detectedTactics && detectedTactics.length > 0 && (
           <div className="pt-4 border-t border-white/5 space-y-2">
             {detectedTactics.slice(0, 4).map((t, i) => (
               <div key={i} className="flex items-center justify-between text-[9px] font-bold">
                 <div className="flex items-center gap-2">
                   <div className="h-1 w-1 rounded-full bg-red-400" />
                   <span className="text-slate-400 uppercase tracking-widest font-mono">{t.mitre_id}</span>
                 </div>
                 <div className="flex items-center gap-2">
                   <div className="h-1 bg-white/5 rounded-full overflow-hidden w-16">
                     <div className="h-full bg-red-500 rounded-full" style={{ width: `${t.confidence * 100}%` }} />
                   </div>
                   <span className="text-red-400 font-mono">{Math.round(t.confidence * 100)}%</span>
                 </div>
               </div>
             ))}
           </div>
         )}

         <div className="mt-auto pt-4 border-t border-white/5">
           <div className="flex items-center justify-between text-[9px] text-slate-500 font-mono uppercase">
             <span>Behavioral pattern match</span>
             <div className="flex items-center gap-1.5">
               <div className={cn("h-1.5 w-1.5 rounded-full", loading ? "bg-amber-400 animate-pulse" : "bg-red-400")} />
               <span className={loading ? "text-amber-400" : "text-red-400"}>{loading ? "Scanning..." : `${tactics.length} detected`}</span>
             </div>
           </div>
         </div>
      </CardContent>
    </Card>
  )
}
