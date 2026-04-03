import React from "react"
import { ShieldAlert, ShieldCheck, TrendingUp, AlertTriangle } from "lucide-react"
import { Card } from "@/components/ui/card"
import { cn } from "@/lib/utils"

interface ThreatScoreCardProps {
  score: number
  classification: string
  confidence: string
  inferenceMs?: number
  loading?: boolean
}

export function ThreatScoreCard({ score, classification, confidence, inferenceMs, loading }: ThreatScoreCardProps) {
  const percentage = Math.round(score * 100)
  const isHighRisk = percentage >= 75
  const isMediumRisk = percentage >= 40 && percentage < 75

  const ringColor = isHighRisk ? "#ef4444" : isMediumRisk ? "#f59e0b" : "#3b82f6"
  const textColor = isHighRisk ? "text-red-400" : isMediumRisk ? "text-amber-400" : "text-blue-400"
  const bgColor = isHighRisk ? "bg-red-500/10 border-red-500/20 text-red-400" : isMediumRisk ? "bg-amber-500/10 border-amber-500/20 text-amber-400" : "bg-blue-500/10 border-blue-500/20 text-blue-400"
  const pulseColor = isHighRisk ? "bg-red-400" : isMediumRisk ? "bg-amber-400" : "bg-blue-400"

  return (
    <Card className="card-cyber group h-full flex flex-col items-center justify-center p-8 relative overflow-hidden">
       <div className={cn(
         "absolute inset-0 opacity-5 group-hover:opacity-10 transition-opacity blur-3xl rounded-full",
         isHighRisk ? "bg-red-500" : isMediumRisk ? "bg-amber-500" : "bg-blue-500"
       )} />

       <div className="relative z-10 w-full flex flex-col items-center text-center space-y-8">
          <div className="space-y-1">
             <h4 className="text-[10px] font-black uppercase tracking-[0.4em] text-muted-foreground">Risk Probability Index</h4>
             <div className="flex items-center justify-center space-x-2">
                <div className={cn("h-2 w-2 rounded-full animate-pulse", pulseColor)} />
                <p className="text-[10px] text-muted-foreground font-black uppercase tracking-widest italic">
                  {classification === "PHISHING" ? "Phishing Detection Confidence: " : "Classification: "}
                  <span className={textColor}>{confidence}</span>
                </p>
             </div>
          </div>

          <div className="relative h-64 w-64 flex items-center justify-center transition-transform duration-700 group-hover:scale-110">
             <svg className="absolute inset-0 h-full w-full -rotate-90 transform-gpu overflow-visible">
                <circle cx="50%" cy="50%" r="120" className="fill-none stroke-white/5 opacity-10" strokeWidth="20" />
                <circle
                  cx="50%" cy="50%" r="120"
                  fill="none"
                  stroke={ringColor}
                  strokeWidth="20"
                  strokeDasharray={`${2 * Math.PI * 120}`}
                  strokeDashoffset={`${2 * Math.PI * 120 * (1 - (loading ? 0 : score))}`}
                  strokeLinecap="round"
                  className="transition-all duration-1000 ease-in-out"
                  style={{ filter: `drop-shadow(0 0 8px ${ringColor}60)` }}
                />
             </svg>

             <div className="flex flex-col items-center justify-center space-y-2 translate-y-2">
                <span className={cn("text-8xl font-black tracking-tighter leading-none", textColor)}>
                  {loading ? "--" : percentage}
                </span>
                <span className="text-2xl font-black text-foreground/40 mt-1 uppercase tracking-tighter">%</span>
             </div>
          </div>

          <div className="space-y-4 w-full">
             <div className={cn(
               "py-4 px-10 rounded-2xl border flex items-center justify-center space-x-4 transition-all duration-300 shadow-2xl overflow-hidden",
               bgColor
             )}>
                {isHighRisk ? <ShieldAlert className="h-6 w-6" /> : isMediumRisk ? <AlertTriangle className="h-6 w-6" /> : <ShieldCheck className="h-6 w-6" />}
                <span className="text-2xl font-black uppercase tracking-[0.2em]">{classification}</span>
             </div>

             <div className="flex justify-between items-center text-[8px] font-black uppercase tracking-[0.3em] text-muted-foreground pt-4 border-t border-white/5 opacity-60">
                <div className="flex items-center">
                   <TrendingUp className="h-3 w-3 mr-1" />
                   {loading ? "Analyzing..." : score > 0.5 ? "Trend: Deteriorating" : "Trend: Stable"}
                </div>
                <span>Analysis Delta: {inferenceMs ? `${inferenceMs}ms` : "--"}</span>
             </div>
          </div>
       </div>
    </Card>
  )
}
