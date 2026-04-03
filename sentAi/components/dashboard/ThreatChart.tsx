import React from "react"
import { ShieldCheck, Target, TrendingUp, AlertTriangle } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

export function ThreatChart() {
  const categories = [
    { name: "Phishing", value: 65, color: "bg-destructive" },
    { name: "Malware", value: 42, color: "bg-yellow-500" },
    { name: "Suspicious", value: 28, color: "bg-blue-500" },
  ]

  return (
    <Card className="card-cyber overflow-hidden group h-full">
      <CardHeader className="p-6 border-b border-white/5 bg-blue-500/3">
        <div className="space-y-1">
          <CardTitle className="text-sm font-black uppercase tracking-[0.2em] text-foreground flex items-center">
            <TrendingUp className="h-4 w-4 mr-2 text-blue-400" />
            Threat Risk Index
          </CardTitle>
          <CardDescription className="text-[10px] text-muted-foreground uppercase font-black tracking-widest leading-none mt-1">
             AI System Risk Level Assessment
          </CardDescription>
        </div>
        <div className="h-2 w-2 rounded-full bg-blue-400 animate-pulse" />
      </CardHeader>

      <CardContent className="p-8 flex flex-col items-center justify-center space-y-10">
        {/* Risk Index Visual */}
        <div className="relative h-56 w-56 flex items-center justify-center group-hover:scale-110 transition-transform duration-700">
           {/* Outer Ring */}
           <div className="absolute inset-0 rounded-full border-8 border-blue-500/10 border-t-blue-500 animate-[spin_10s_linear_infinite] shadow-[0_0_30px_rgba(59,130,246,0.15)]" />
           {/* Inner Ring */}
           <div className="absolute inset-4 rounded-full border-4 border-red-500/20 border-b-red-500 animate-[spin_6s_linear_infinite_reverse]" />
           {/* Center Content */}
           <div className="flex flex-col items-center justify-center z-10 transition-all">
             <div className="flex items-baseline space-x-1">
               <span className="text-6xl font-black tracking-tighter text-foreground group-hover:text-blue-300 transition-colors">78</span>
               <span className="text-2xl font-black text-blue-400">%</span>
             </div>
             <Badge className="bg-red-500/10 text-red-400 border-red-500/20 text-[8px] h-4 rounded-full px-3 uppercase font-black tracking-widest mt-1">
                Elevated Risk
             </Badge>
           </div>
        </div>

        {/* Dashboard Stat Bars */}
        <div className="w-full space-y-5">
           <div className="flex items-center justify-between mb-2">
             <h4 className="text-[10px] font-black uppercase tracking-[0.3em] text-muted-foreground">Category Distribution</h4>
             <div className="h-1 w-12 bg-blue-500/20 rounded-full" />
           </div>

           {categories.map((cat) => (
             <div key={cat.name} className="space-y-1.5 group/bar px-2 py-1 rounded-lg transition-colors hover:bg-white/5 cursor-pointer">
               <div className="flex items-center justify-between text-[10px] font-black uppercase tracking-widest">
                  <div className="flex items-center text-foreground group-hover/bar:text-blue-300 transition-colors">
                    {cat.name === "Phishing" ? <AlertTriangle className="h-3 w-3 mr-2 text-red-400" /> : cat.name === "Malware" ? <Target className="h-3 w-3 mr-2 text-amber-400" /> : <ShieldCheck className="h-3 w-3 mr-2 text-blue-400" />}
                    {cat.name}
                  </div>
                  <span className="text-muted-foreground">{cat.value}%</span>
               </div>
               <div className="h-2 w-full bg-black/40 rounded-full overflow-hidden border border-white/5">
                  <div 
                    className={cn("h-full transition-all duration-1000", cat.color)} 
                    style={{ width: `${cat.value}%` }} 
                  />
               </div>
             </div>
           ))}
        </div>
      </CardContent>
    </Card>
  )
}
