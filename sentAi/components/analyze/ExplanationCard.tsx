import React from "react"
import { MessageSquare, Zap, ShieldCheck } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"

interface ExplanationCardProps {
  explanation: string
  loading?: boolean
  confidence?: number
  inferenceMs?: number
}

export function ExplanationCard({ explanation, loading, confidence, inferenceMs }: ExplanationCardProps) {
  return (
    <Card className="card-cyber h-full flex flex-col overflow-hidden relative">
      <div className="absolute top-0 right-0 p-8 opacity-5">
         <MessageSquare className="h-24 w-24 text-blue-400" />
      </div>

      <CardHeader className="p-5 border-b border-white/5 flex flex-row items-center justify-between">
        <div className="space-y-1">
          <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
            <Zap className="h-3.5 w-3.5 text-amber-400" />
            AI Forensic Explanation
          </CardTitle>
          <CardDescription className="text-[10px] text-slate-500 uppercase tracking-widest">
            LLM-powered reasoning & forensic summary
          </CardDescription>
        </div>
        {loading && (
          <div className="flex items-center gap-1.5 text-[9px] text-amber-400 font-mono uppercase">
            <div className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" />
            Generating
          </div>
        )}
      </CardHeader>

      <CardContent className="p-5 flex-1 flex flex-col justify-center space-y-5 relative z-10">
         <div className="bg-[#0D1B2A]/60 border border-white/10 p-5 rounded-xl relative">
            <div className="absolute -top-3 left-4">
               <Badge className="bg-blue-600 text-white text-[8px] h-5 rounded-md px-2.5 font-bold uppercase tracking-widest border border-blue-500/30 shadow-lg">
                 Analyst Insight
               </Badge>
            </div>

            {loading ? (
              <div className="space-y-2 pt-2">
                {[100, 90, 75, 60].map((w, i) => (
                  <div key={i} className="h-3 bg-white/5 rounded animate-pulse" style={{ width: `${w}%` }} />
                ))}
              </div>
            ) : (
              <p className="text-sm text-slate-300 leading-relaxed font-medium tracking-tight pt-2
                first-letter:text-2xl first-letter:font-black first-letter:text-blue-400 first-letter:mr-1 first-letter:float-left">
                 {explanation}
              </p>
            )}
         </div>

         <div className="border-t border-white/5 pt-4">
            <div className="bg-blue-500/5 p-3.5 rounded-xl border border-blue-500/10 flex items-center justify-between">
               <div className="flex items-center gap-3">
                  <div className="h-8 w-8 rounded-lg bg-blue-500/20 border border-blue-500/30 flex items-center justify-center">
                     <ShieldCheck className="h-4 w-4 text-blue-400" />
                  </div>
                  <div>
                    <h4 className="text-[10px] font-bold uppercase tracking-widest text-blue-400">AI Forensic Narrative</h4>
                    <p className="text-[8px] text-slate-500 uppercase font-bold tracking-widest mt-0.5">
                      {confidence != null ? `${Math.round(confidence * 100)}% model confidence` : "Confidence pending"}
                    </p>
                  </div>
               </div>
               <div className="text-right">
                 <div className="text-[9px] text-slate-500 font-mono">GPT-4o-mini</div>
                 {inferenceMs != null && <div className="text-[8px] text-slate-700 font-mono">{inferenceMs}ms</div>}
               </div>
            </div>
         </div>
      </CardContent>
    </Card>
  )
}
