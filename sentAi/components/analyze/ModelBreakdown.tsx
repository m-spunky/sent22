import React from "react"
import { AlignLeft, Globe, Image as ImageIcon, Code, Zap } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { cn } from "@/lib/utils"

interface ModelBreakdownProps {
  model_scores: {
    nlp: number
    url: number
    visual: number
    metadata: number
  }
  loading?: boolean
}

const MODEL_CONFIG = [
  {
    label: "NLP Intent Engine",
    key: "nlp" as const,
    icon: AlignLeft,
    color: "#3b82f6",
    desc: "GPT-4o-mini semantic analysis",
  },
  {
    label: "URL Risk Analyzer",
    key: "url" as const,
    icon: Globe,
    color: "#ef4444",
    desc: "WHOIS/DNS/URLhaus + SHAP",
  },
  {
    label: "Visual Brand Engine",
    key: "visual" as const,
    icon: ImageIcon,
    color: "#f59e0b",
    desc: "Apify screenshot + CLIP similarity",
  },
  {
    label: "Header Anomaly",
    key: "metadata" as const,
    icon: Code,
    color: "#10b981",
    desc: "SPF/DKIM/DMARC analysis",
  },
]

export function ModelBreakdown({ model_scores, loading }: ModelBreakdownProps) {
  return (
    <Card className="card-cyber h-full flex flex-col">
      <CardHeader className="p-5 border-b border-white/5 flex flex-row items-center justify-between">
        <div className="space-y-1">
          <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
            <Zap className="h-3.5 w-3.5 text-amber-400" />
            Model Breakdown
          </CardTitle>
          <CardDescription className="text-[10px] text-slate-500 uppercase tracking-widest">
            4-layer multi-modal inference
          </CardDescription>
        </div>
      </CardHeader>

      <CardContent className="p-5 space-y-5 flex-1 flex flex-col justify-center">
        {MODEL_CONFIG.map((model) => {
          const score = model_scores[model.key]
          const pct = loading ? 0 : Math.round(score * 100)
          return (
            <div key={model.key} className="space-y-2 group cursor-pointer">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div
                    className="h-7 w-7 rounded-lg flex items-center justify-center"
                    style={{ backgroundColor: `${model.color}18`, border: `1px solid ${model.color}30` }}
                  >
                    <model.icon className="h-3.5 w-3.5" style={{ color: model.color }} />
                  </div>
                  <div>
                    <div className="text-[10px] font-bold text-slate-300 uppercase tracking-wide">{model.label}</div>
                    <div className="text-[9px] text-slate-600 font-mono">{model.desc}</div>
                  </div>
                </div>
                <span
                  className="text-sm font-bold font-mono tabular-nums"
                  style={{ color: model.color }}
                >
                  {loading ? "--" : `${pct}%`}
                </span>
              </div>

              <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-1000 ease-out"
                  style={{
                    width: loading ? "0%" : `${pct}%`,
                    backgroundColor: model.color,
                    boxShadow: pct > 60 ? `0 0 8px ${model.color}60` : "none",
                  }}
                />
              </div>
            </div>
          )
        })}

        <div className="pt-4 mt-auto border-t border-white/5">
          <div className="flex items-center justify-between text-[9px] text-slate-500 font-mono uppercase">
            <span>Attention-weighted fusion</span>
            <div className="flex items-center gap-1.5">
              <div className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
              <span className="text-blue-400">{loading ? "Inferring..." : "Complete"}</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
