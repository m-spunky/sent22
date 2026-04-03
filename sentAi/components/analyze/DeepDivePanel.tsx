"use client"

import React, { useState } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { 
  Network, ArrowRight, ArrowDown, Globe, Download, Play, 
  ShieldAlert, ScanFace, Loader2, Link, FileKey, CheckCircle2 
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { runDeepDive, type DeepDiveResult } from "@/lib/api"
import { ExecutionTraceCard } from "./ExecutionTraceCard"

interface DeepDivePanelProps {
  url: string
  eventId?: string
}

export function DeepDivePanel({ url, eventId }: DeepDivePanelProps) {
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<DeepDiveResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleRun = async () => {
    setRunning(true)
    setError(null)
    try {
      const data = await runDeepDive(url, eventId)
      setResult(data)
    } catch (err: any) {
      setError(err.message || "Failed to run deep dive analysis")
    } finally {
      setRunning(false)
    }
  }

  if (!result && !running && !error) {
    return (
      <div className="rounded-2xl border border-blue-500/20 bg-blue-500/5 p-6 flex flex-col sm:flex-row items-center gap-6 justify-between">
        <div className="flex items-center gap-4">
          <div className="h-12 w-12 rounded-xl bg-blue-500/20 flex items-center justify-center border border-blue-500/30">
            <Network className="h-6 w-6 text-blue-400" />
          </div>
          <div>
            <h4 className="text-sm font-black uppercase tracking-widest text-blue-100 flex items-center gap-2">
              Auto-Chain Deep Dive
              <Badge className="bg-blue-500/20 text-blue-300 border-blue-500/30 text-[8px]">ADVANCED</Badge>
            </h4>
            <p className="text-[10px] text-blue-300/70 mt-1 max-w-sm">
              Automatically follows redirects, downloads payloads, and traces execution paths to reveal the full attack chain.
            </p>
          </div>
        </div>
        <Button 
          onClick={handleRun}
          className="bg-blue-600 hover:bg-blue-500 text-white shadow-[0_0_20px_rgba(37,99,235,0.3)] transition-all uppercase tracking-widest text-[10px] font-black w-full sm:w-auto"
        >
          <Play className="h-3 w-3 mr-2" />
          Run Deep Dive
        </Button>
      </div>
    )
  }

  if (running) {
    return (
      <div className="rounded-2xl border border-blue-500/20 bg-blue-500/5 p-8 flex flex-col items-center justify-center space-y-4">
        <div className="relative">
          <div className="absolute inset-0 bg-blue-500/20 blur-xl rounded-full" />
          <Loader2 className="h-10 w-10 text-blue-400 animate-spin relative z-10" />
        </div>
        <div className="text-center">
          <p className="text-[11px] font-black uppercase tracking-widest text-blue-300">
            Running Deep Dive Analysis
          </p>
          <p className="text-[9px] text-blue-400/60 font-mono mt-1">
            Following redirects • Inspecting DOM • Downloading payloads
          </p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="rounded-2xl border border-red-500/20 bg-red-500/5 p-6 flex items-center gap-4">
        <ShieldAlert className="h-6 w-6 text-red-400" />
        <div className="flex-1">
          <p className="text-[10px] font-black uppercase tracking-widest text-red-300">Analysis Failed</p>
          <p className="text-[9px] text-red-400/70 mt-1">{error}</p>
        </div>
        <Button variant="outline" size="sm" onClick={handleRun} className="border-red-500/30 text-red-400 hover:bg-red-500/10">
          Retry
        </Button>
      </div>
    )
  }

  if (!result) return null

  const isCritical = result.overall_risk >= 0.85
  const isSuspicious = result.overall_risk >= 0.35

  return (
    <div className={cn(
      "rounded-2xl border overflow-hidden",
      isCritical ? "border-red-500/30 bg-red-500/5" :
      isSuspicious ? "border-amber-500/30 bg-amber-500/5" :
      "border-emerald-500/30 bg-emerald-500/5"
    )}>
      {/* Header */}
      <div className="px-6 py-5 border-b border-white/5 flex flex-wrap items-center justify-between gap-4 bg-black/20">
        <div className="flex items-center gap-4">
          <div className={cn(
            "h-10 w-10 rounded-xl flex items-center justify-center border shadow-lg",
            isCritical ? "bg-red-500/20 border-red-500/40 text-red-400" :
            isSuspicious ? "bg-amber-500/20 border-amber-500/40 text-amber-400" :
            "bg-emerald-500/20 border-emerald-500/40 text-emerald-400"
          )}>
            <Network className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-black uppercase tracking-widest text-slate-200">
                Attack Chain Analysis
              </h3>
              <Badge className={cn(
                "text-[8px] font-black uppercase tracking-wider",
                isCritical ? "bg-red-500/20 text-red-400 border-red-500/30" :
                isSuspicious ? "bg-amber-500/20 text-amber-400 border-amber-500/30" :
                "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
              )}>
                {result.overall_verdict}
              </Badge>
            </div>
            <p className="text-[10px] text-slate-400 mt-1 max-w-xl leading-relaxed">
              {result.chain_narrative}
            </p>
          </div>
        </div>
      </div>

      {/* Stages Pipeline */}
      <div className="p-6 relative">
        <div className="absolute left-10 top-10 bottom-10 w-0.5 bg-white/5" />
        
        <div className="space-y-8">
          {result.chain_stages.map((stage, i) => (
            <motion.div 
              key={i}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.15 }}
              className="relative pl-12"
            >
              <div className="absolute left-1 top-1.5 h-6 w-6 rounded-full bg-slate-900 border-2 border-slate-700 flex items-center justify-center z-10">
                {stage.stage === "url_sandbox" ? <Globe className="h-3 w-3 text-blue-400" /> :
                 stage.stage === "download_check" ? <Download className="h-3 w-3 text-purple-400" /> :
                 <ScanFace className="h-3 w-3 text-red-400" />}
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-[9px] font-black uppercase tracking-widest text-slate-400">
                    Stage {i + 1}
                  </span>
                  <span className="text-[10px] font-bold text-slate-200">
                    {stage.label}
                  </span>
                </div>

                {/* Stage-specific renders */}
                {stage.stage === "url_sandbox" && (
                  <div className="space-y-2">
                    <p className="text-[10px] font-mono text-slate-400 break-all">{url}</p>
                    {stage.redirect_count > 0 && (
                      <div className="flex items-center gap-2 text-[9px] text-amber-400/80 my-1">
                        <ArrowDown className="h-3 w-3" />
                        <span>Redirected {stage.redirect_count} times</span>
                      </div>
                    )}
                    {(stage.redirect_count > 0 || stage.final_url !== url) && (
                      <p className="text-[10px] font-mono text-slate-300 break-all bg-black/20 p-2 rounded border border-white/5">
                        {stage.final_url}
                      </p>
                    )}
                    
                    <div className="flex flex-wrap gap-2 mt-3">
                      {stage.has_credential_form && (
                        <Badge className="bg-red-500/10 text-red-400 border-red-500/20 text-[8px]">
                          Credential Form
                        </Badge>
                      )}
                      {!stage.ssl_valid && (
                        <Badge className="bg-orange-500/10 text-orange-400 border-orange-500/20 text-[8px]">
                          Invalid SSL
                        </Badge>
                      )}
                      {stage.flags?.slice(0, 3).map((f: string, j: number) => (
                        <Badge key={j} variant="outline" className="text-[8px] text-slate-400 border-slate-600">
                          {f}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {stage.stage === "download_check" && (
                  <div className="space-y-2 text-[10px] text-slate-300">
                    {stage.is_download ? (
                      <div className="flex items-start gap-3">
                        <div className="h-8 w-8 rounded bg-purple-500/10 border border-purple-500/20 flex items-center justify-center flex-shrink-0">
                          <FileKey className="h-4 w-4 text-purple-400" />
                        </div>
                        <div>
                          <p className="font-bold text-slate-200">Payload Download Discovered</p>
                          <p className="font-mono text-slate-400 mt-0.5">{stage.filename}</p>
                          <div className="flex gap-3 mt-1.5 text-[9px] text-slate-500">
                            <span>{stage.content_type}</span>
                            <span>{Math.round(stage.content_length / 1024)} KB</span>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2 text-slate-500">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500/50" />
                        <span>No executable payload downloads detected.</span>
                      </div>
                    )}
                  </div>
                )}

                {stage.stage === "attachment_analysis" && (
                  <div className="space-y-3">
                    <div className="flex items-baseline gap-2">
                      <span className={cn(
                        "text-[10px] font-black uppercase tracking-widest",
                        stage.risk_level === "CRITICAL" ? "text-red-400" :
                        stage.risk_level === "HIGH" ? "text-amber-400" : "text-emerald-400"
                      )}>
                        {stage.risk_level} RISK
                      </span>
                      <span className="text-[9px] text-slate-500">
                        ({stage.findings?.length || 0} findings)
                      </span>
                    </div>
                    
                    {stage.findings?.length > 0 && (
                      <div className="bg-black/20 rounded border border-white/5 p-3 space-y-1.5">
                        {stage.findings.map((finding: string, j: number) => (
                          <div key={j} className="flex gap-2 text-[9px] text-slate-300">
                            <span className="text-red-400/50 mt-0.5">▪</span>
                            <span className="leading-relaxed">{finding}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </motion.div>
          ))}
        </div>

        {/* Execution Trace Append */}
        {result.execution_trace?.has_trace && (
          <motion.div 
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: result.chain_stages.length * 0.15 }}
            className="mt-6 pl-12"
          >
            <div className="relative">
              <div className="absolute -left-11 -top-3 h-6 w-0.5 bg-gradient-to-b from-white/5 to-transparent" />
              <ExecutionTraceCard trace={result.execution_trace} filename={result.attachment_result?.filename} />
            </div>
          </motion.div>
        )}
      </div>
    </div>
  )
}
