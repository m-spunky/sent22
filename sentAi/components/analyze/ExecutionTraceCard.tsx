"use client"

import React, { useState } from "react"
import { Activity, ChevronDown, ChevronRight, Shield, Clock, AlertTriangle, CheckCircle2, XCircle, Zap } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

interface ExecutionStep {
  step: number
  action: string
  detail: string
  risk: "none" | "low" | "medium" | "high" | "critical"
}

interface ExecutionTrace {
  has_trace: boolean
  file_type: string
  steps: ExecutionStep[]
  kill_chain_stages: string[]
  estimated_time_to_compromise: string
  containment: string[]
}

interface ExecutionTraceCardProps {
  trace: ExecutionTrace
  filename?: string
}

const riskConfig = {
  none: { color: "text-slate-400", bg: "bg-slate-500/10 border-slate-500/20", dot: "bg-slate-500", label: "SAFE" },
  low: { color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/20", dot: "bg-blue-500", label: "LOW" },
  medium: { color: "text-amber-400", bg: "bg-amber-500/10 border-amber-500/20", dot: "bg-amber-500", label: "MEDIUM" },
  high: { color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/20", dot: "bg-orange-500", label: "HIGH" },
  critical: { color: "text-red-400", bg: "bg-red-500/10 border-red-500/20", dot: "bg-red-500", label: "CRITICAL" },
}

export function ExecutionTraceCard({ trace, filename }: ExecutionTraceCardProps) {
  const [expanded, setExpanded] = useState(true)

  if (!trace?.has_trace) return null

  const hasHighRisk = trace.steps.some(s => s.risk === "critical" || s.risk === "high")

  return (
    <div className={cn(
      "rounded-2xl border overflow-hidden transition-all",
      hasHighRisk ? "bg-red-500/5 border-red-500/15" : "bg-amber-500/5 border-amber-500/15"
    )}>
      {/* Header */}
      <button
        onClick={() => setExpanded(e => !e)}
        className="w-full flex items-center gap-3 px-5 py-4 hover:bg-white/3 transition-colors"
      >
        <div className={cn(
          "h-8 w-8 rounded-xl flex items-center justify-center flex-shrink-0 border",
          hasHighRisk ? "bg-red-500/10 border-red-500/20" : "bg-amber-500/10 border-amber-500/20"
        )}>
          <Activity className={cn("h-4 w-4", hasHighRisk ? "text-red-400" : "text-amber-400")} />
        </div>
        <div className="flex-1 text-left">
          <p className="text-[10px] font-black uppercase tracking-widest text-slate-300">
            Simulated Execution Trace
          </p>
          <p className="text-[9px] text-slate-500 mt-0.5">
            What happens when <span className="text-slate-300 font-mono">{filename || `file.${trace.file_type}`}</span> is opened
          </p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {trace.estimated_time_to_compromise !== "Unknown" && (
            <div className="flex items-center gap-1.5">
              <Clock className="h-3 w-3 text-red-400" />
              <span className="text-[9px] font-mono font-bold text-red-400">{trace.estimated_time_to_compromise}</span>
            </div>
          )}
          <Badge className={cn(
            "text-[7px] uppercase font-black",
            hasHighRisk ? "bg-red-500/10 text-red-400 border-red-500/20" : "bg-amber-500/10 text-amber-400 border-amber-500/20"
          )}>
            {trace.steps.length} Steps
          </Badge>
          {expanded
            ? <ChevronDown className="h-4 w-4 text-slate-600" />
            : <ChevronRight className="h-4 w-4 text-slate-600" />
          }
        </div>
      </button>

      {/* Expanded content */}
      {expanded && (
        <div className="border-t border-white/5 px-5 py-4 space-y-4">
          {/* Execution steps — vertical stepper */}
          <div className="relative">
            {trace.steps.map((step, i) => {
              const rc = riskConfig[step.risk] || riskConfig.none
              const isLast = i === trace.steps.length - 1
              return (
                <div key={step.step} className="flex gap-3 relative">
                  {/* Vertical line connector */}
                  {!isLast && (
                    <div className="absolute left-[11px] top-[24px] bottom-0 w-px bg-white/10" />
                  )}

                  {/* Step indicator */}
                  <div className="flex flex-col items-center flex-shrink-0 z-10">
                    <div className={cn(
                      "h-6 w-6 rounded-full flex items-center justify-center border text-[8px] font-black",
                      rc.bg
                    )}>
                      {step.risk === "critical" ? (
                        <XCircle className={cn("h-3.5 w-3.5", rc.color)} />
                      ) : step.risk === "high" ? (
                        <AlertTriangle className={cn("h-3 w-3", rc.color)} />
                      ) : step.risk === "none" ? (
                        <CheckCircle2 className="h-3 w-3 text-slate-500" />
                      ) : (
                        <span className={rc.color}>{step.step}</span>
                      )}
                    </div>
                  </div>

                  {/* Step content */}
                  <div className={cn("flex-1 pb-4 min-w-0", isLast && "pb-0")}>
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className={cn("text-[10px] font-black uppercase tracking-widest", rc.color)}>
                        {step.action}
                      </span>
                      <Badge className={cn("text-[6px] uppercase font-black", rc.bg)}>
                        {rc.label}
                      </Badge>
                    </div>
                    <p className="text-[9px] text-slate-400 leading-relaxed">
                      {step.detail}
                    </p>
                  </div>
                </div>
              )
            })}
          </div>

          {/* Kill Chain Stages */}
          {trace.kill_chain_stages.length > 0 && (
            <div className="space-y-2">
              <p className="text-[8px] font-bold uppercase tracking-widest text-slate-500">
                MITRE ATT&CK Kill Chain Coverage
              </p>
              <div className="flex flex-wrap gap-1.5">
                {trace.kill_chain_stages.map((stage, i) => (
                  <Badge key={i} className={cn(
                    "text-[7px] font-black uppercase",
                    stage.includes("Execution") || stage.includes("Initial Access")
                      ? "bg-red-500/10 text-red-400 border-red-500/20"
                      : stage.includes("Command") || stage.includes("Exfiltration")
                      ? "bg-orange-500/10 text-orange-400 border-orange-500/20"
                      : "bg-amber-500/10 text-amber-400 border-amber-500/20"
                  )}>
                    {stage}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Time to compromise banner */}
          {trace.estimated_time_to_compromise !== "Unknown" && trace.estimated_time_to_compromise !== "N/A" && (
            <div className="flex items-center gap-3 px-3 py-2 bg-red-500/8 border border-red-500/15 rounded-xl">
              <Zap className="h-4 w-4 text-red-400 flex-shrink-0" />
              <div className="flex-1">
                <p className="text-[9px] font-black text-red-300 uppercase tracking-widest">
                  Estimated Time to Compromise
                </p>
                <p className="text-sm font-black font-mono text-red-400">
                  {trace.estimated_time_to_compromise}
                </p>
              </div>
            </div>
          )}

          {/* Containment Recommendations */}
          {trace.containment.length > 0 && (
            <div className="space-y-2">
              <p className="text-[8px] font-bold uppercase tracking-widest text-slate-500">
                Containment Recommendations
              </p>
              <div className="space-y-1">
                {trace.containment.map((rec, i) => (
                  <div key={i} className="flex items-start gap-2 text-[9px] text-slate-400">
                    <Shield className="h-3 w-3 text-blue-400 flex-shrink-0 mt-0.5" />
                    <span className="leading-relaxed">{rec}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
