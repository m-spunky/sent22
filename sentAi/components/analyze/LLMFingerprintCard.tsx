"use client"

import React, { useState } from "react"
import { Bot, ChevronDown, ChevronRight, AlertTriangle, CheckCircle, XCircle, Brain, Sparkles, Info } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import type { LLMFingerprint } from "@/lib/api"

interface LLMFingerprintCardProps {
  fingerprint: LLMFingerprint
}

function GaugeRing({ value, size = 80 }: { value: number; size?: number }) {
  const radius = (size - 8) / 2
  const circumference = 2 * Math.PI * radius
  const progress = circumference * (1 - value)

  const color = value >= 0.7 ? "#ef4444" : value >= 0.45 ? "#f59e0b" : "#10b981"
  const bgColor = value >= 0.7 ? "rgba(239,68,68,0.1)" : value >= 0.45 ? "rgba(245,158,11,0.1)" : "rgba(16,185,129,0.1)"

  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="4" />
        <circle
          cx={size / 2} cy={size / 2} r={radius} fill="none"
          stroke={color} strokeWidth="4" strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={progress}
          className="transition-all duration-700"
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-lg font-black font-mono" style={{ color }}>{Math.round(value * 100)}%</span>
        <span className="text-[7px] uppercase tracking-widest text-slate-600 font-bold">AI Prob</span>
      </div>
    </div>
  )
}

function SignalBar({ label, value, threshold }: { label: string; value: number; threshold: number }) {
  const isAI = value <= threshold
  return (
    <div className="flex items-center gap-2">
      <span className="text-[8px] font-mono text-slate-500 w-32 truncate uppercase tracking-wider">{label}</span>
      <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
        <div
          className={cn("h-full rounded-full transition-all", isAI ? "bg-red-500" : "bg-emerald-500")}
          style={{ width: `${Math.min(Math.max(value * 100, 5), 100)}%` }}
        />
      </div>
      <span className={cn("text-[8px] font-mono font-bold", isAI ? "text-red-400" : "text-emerald-400")}>
        {typeof value === "number" ? value.toFixed(2) : "—"}
      </span>
    </div>
  )
}

export function LLMFingerprintCard({ fingerprint }: LLMFingerprintCardProps) {
  const [expanded, setExpanded] = useState(false)

  const prob = fingerprint.ai_generated_probability
  const verdict = fingerprint.verdict
  const method = fingerprint.detection_method

  const verdictConfig = {
    LIKELY_AI: { label: "LIKELY AI-GENERATED", color: "text-red-400", bg: "bg-red-500/10 border-red-500/20", icon: <Bot className="h-4 w-4 text-red-400" /> },
    POSSIBLY_AI: { label: "POSSIBLY AI-GENERATED", color: "text-amber-400", bg: "bg-amber-500/10 border-amber-500/20", icon: <AlertTriangle className="h-4 w-4 text-amber-400" /> },
    LIKELY_HUMAN: { label: "LIKELY HUMAN-WRITTEN", color: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/20", icon: <CheckCircle className="h-4 w-4 text-emerald-400" /> },
    UNKNOWN: { label: "UNKNOWN", color: "text-slate-400", bg: "bg-white/5 border-white/10", icon: <Info className="h-4 w-4 text-slate-400" /> },
  }

  const vc = verdictConfig[verdict] || verdictConfig.UNKNOWN
  const stylo = fingerprint.stylometric_scores || {}

  return (
    <div className={cn("rounded-2xl border overflow-hidden transition-all", vc.bg)}>
      {/* Header */}
      <button
        onClick={() => setExpanded(e => !e)}
        className="w-full flex items-center gap-3 px-5 py-4 hover:bg-white/3 transition-colors"
      >
        <div className="h-8 w-8 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center flex-shrink-0">
          <Sparkles className="h-4 w-4 text-purple-400" />
        </div>
        <div className="flex-1 text-left">
          <p className="text-[10px] font-black uppercase tracking-widest text-slate-300">
            AI-Generated Content Detection
          </p>
          <div className="flex items-center gap-2 mt-0.5">
            {vc.icon}
            <span className={cn("text-[10px] font-black uppercase tracking-widest", vc.color)}>
              {vc.label}
            </span>
            <span className="text-[8px] font-mono text-slate-600">
              ({Math.round(prob * 100)}% probability)
            </span>
          </div>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <Badge className="text-[7px] bg-purple-500/10 border-purple-500/20 text-purple-400 uppercase font-black">
            LLM Fingerprint
          </Badge>
          {expanded
            ? <ChevronDown className="h-4 w-4 text-slate-600" />
            : <ChevronRight className="h-4 w-4 text-slate-600" />
          }
        </div>
      </button>

      {/* Expanded content */}
      {expanded && (
        <div className="border-t border-white/5 p-5 space-y-5">
          {/* Top row: Gauge + Signals */}
          <div className="flex gap-6">
            <GaugeRing value={prob} size={90} />
            <div className="flex-1 space-y-3">
              <div className="flex items-center gap-2">
                <span className="text-[8px] font-bold uppercase tracking-widest text-slate-500">Detection Method</span>
                <Badge variant="outline" className="text-[7px] border-white/10 text-slate-400 font-mono">
                  {method.replace(/_/g, " ")}
                </Badge>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[8px] font-bold uppercase tracking-widest text-slate-500">Confidence</span>
                <span className="text-[9px] font-mono text-slate-300">{Math.round(fingerprint.ai_confidence * 100)}%</span>
              </div>
            </div>
          </div>

          {/* Stylometric Scores */}
          <div className="space-y-2">
            <p className="text-[8px] font-bold uppercase tracking-widest text-slate-500">Stylometric Analysis</p>
            <div className="space-y-1.5">
              {stylo.sentence_length_std !== undefined && (
                <SignalBar
                  label="Sentence Length StdDev"
                  value={(stylo.sentence_length_std || 0) / 15}
                  threshold={0.27}
                />
              )}
              {stylo.type_token_ratio !== undefined && (
                <SignalBar
                  label="Type-Token Ratio"
                  value={stylo.type_token_ratio || 0}
                  threshold={0.5}
                />
              )}
              {stylo.template_phrase_density !== undefined && (
                <div className="flex items-center gap-2">
                  <span className="text-[8px] font-mono text-slate-500 w-32 truncate uppercase tracking-wider">Template Phrases</span>
                  <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
                    <div
                      className={cn("h-full rounded-full transition-all", (stylo.template_phrase_density || 0) > 0.025 ? "bg-red-500" : "bg-emerald-500")}
                      style={{ width: `${Math.min((stylo.template_phrase_density || 0) * 2000, 100)}%` }}
                    />
                  </div>
                  <span className={cn("text-[8px] font-mono font-bold", (stylo.template_phrase_density || 0) > 0.025 ? "text-red-400" : "text-emerald-400")}>
                    {(stylo.template_phrase_density || 0).toFixed(4)}
                  </span>
                </div>
              )}
              {stylo.punctuation_regularity !== undefined && (
                <SignalBar
                  label="Punct. Regularity"
                  value={stylo.punctuation_regularity || 0}
                  threshold={0.995}
                />
              )}
              {stylo.coherence_overlap !== undefined && (
                <SignalBar
                  label="Coherence Overlap"
                  value={stylo.coherence_overlap || 0}
                  threshold={0.3}
                />
              )}
            </div>
          </div>

          {/* Perplexity */}
          {fingerprint.perplexity?.variance >= 0 && (
            <div className="space-y-2">
              <p className="text-[8px] font-bold uppercase tracking-widest text-slate-500">BERT Perplexity Analysis</p>
              <div className="flex items-center gap-3 px-3 py-2 bg-white/3 border border-white/5 rounded-lg">
                <Brain className="h-4 w-4 text-purple-400 flex-shrink-0" />
                <div className="flex-1">
                  <p className="text-[9px] text-slate-300">
                    Prediction entropy: <span className="font-mono font-bold">{fingerprint.perplexity.variance.toFixed(4)}</span>
                  </p>
                  <p className="text-[8px] text-slate-600">
                    AI text typically has entropy &lt; 0.3 (very predictable). Human text &gt; 0.5.
                  </p>
                </div>
                <Badge className={cn("text-[7px] font-black uppercase",
                  fingerprint.perplexity.score >= 0.5 ? "bg-red-500/10 text-red-400 border-red-500/20" : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                )}>
                  {fingerprint.perplexity.score >= 0.5 ? "AI PATTERN" : "HUMAN PATTERN"}
                </Badge>
              </div>
            </div>
          )}

          {/* LLM Assessment */}
          {fingerprint.llm_assessment?.source && fingerprint.llm_assessment.source !== "unavailable" && fingerprint.llm_assessment.source !== "gemma_error" && (
            <div className="space-y-2">
              <p className="text-[8px] font-bold uppercase tracking-widest text-slate-500">Gemma-3 12B Meta-Analysis</p>
              <div className="px-3 py-2.5 bg-white/3 border border-white/5 rounded-lg space-y-1.5">
                <div className="flex items-center gap-2">
                  <Bot className="h-3.5 w-3.5 text-purple-400 flex-shrink-0" />
                  <span className={cn("text-[9px] font-black uppercase tracking-widest",
                    fingerprint.llm_assessment.is_ai ? "text-red-400" : "text-emerald-400"
                  )}>
                    {fingerprint.llm_assessment.is_ai ? "AI-Generated" : "Human-Written"}
                  </span>
                  <span className="text-[8px] font-mono text-slate-600 ml-auto">
                    {Math.round(fingerprint.llm_assessment.probability * 100)}% probability
                  </span>
                </div>
                {fingerprint.llm_assessment.reasoning && (
                  <p className="text-[9px] text-slate-400 leading-relaxed">
                    {fingerprint.llm_assessment.reasoning}
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Signals */}
          {fingerprint.signals?.length > 0 && (
            <div className="space-y-2">
              <p className="text-[8px] font-bold uppercase tracking-widest text-slate-500">Detection Signals</p>
              <div className="space-y-1">
                {fingerprint.signals.map((sig, i) => (
                  <div key={i} className="flex items-start gap-2 text-[9px] text-slate-400">
                    <XCircle className="h-3 w-3 text-red-400/60 flex-shrink-0 mt-0.5" />
                    <span className="leading-relaxed">{sig}</span>
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
