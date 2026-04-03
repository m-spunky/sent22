"use client"

import React, { useState } from "react"
import {
  ChevronDown, ChevronRight, TreeDeciduous, Brain, Globe, Eye, FileText,
  Database, Crosshair, Shield, AlertTriangle, CheckCircle
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import type { AnalysisResult } from "@/lib/api"

interface EvidenceChainCardProps {
  result: AnalysisResult
}

interface TreeNode {
  id: string
  label: string
  score: number
  weight?: number
  icon: React.ReactNode
  color: string
  children: TreeLeaf[]
}

interface TreeLeaf {
  label: string
  value: string
  isAlert?: boolean
}

function scoreColor(score: number) {
  if (score >= 0.65) return "text-red-400"
  if (score >= 0.35) return "text-amber-400"
  return "text-emerald-400"
}

function ScoreBadge({ score }: { score: number }) {
  return (
    <span className={cn("text-[9px] font-mono font-black", scoreColor(score))}>
      {Math.round(score * 100)}%
    </span>
  )
}

function TreeBranch({ node, isLast }: { node: TreeNode; isLast: boolean }) {
  const [expanded, setExpanded] = useState(node.score >= 0.35)

  return (
    <div className="relative">
      {/* Branch connector lines */}
      <div className="flex items-stretch">
        {/* Vertical line from parent */}
        <div className="w-6 flex-shrink-0 relative">
          <div className={cn(
            "absolute left-3 top-0 w-px bg-white/10",
            isLast ? "h-4" : "h-full"
          )} />
          <div className="absolute left-3 top-4 w-3 h-px bg-white/10" />
        </div>

        {/* Node content */}
        <div className="flex-1 min-w-0 pb-1">
          <button
            onClick={() => setExpanded(e => !e)}
            className={cn(
              "w-full flex items-center gap-2 px-3 py-2 rounded-xl transition-all hover:bg-white/3",
              node.score >= 0.65 ? "bg-red-500/5 border border-red-500/10" :
              node.score >= 0.35 ? "bg-amber-500/5 border border-amber-500/10" :
              "bg-white/3 border border-white/5"
            )}
          >
            <div className={cn(
              "h-6 w-6 rounded-lg flex items-center justify-center flex-shrink-0 border",
              node.score >= 0.65 ? "bg-red-500/10 border-red-500/20" :
              node.score >= 0.35 ? "bg-amber-500/10 border-amber-500/20" :
              "bg-emerald-500/10 border-emerald-500/20"
            )}>
              {node.icon}
            </div>
            <span className="text-[9px] font-bold uppercase tracking-widest text-slate-300 flex-1 text-left">
              {node.label}
            </span>
            {node.weight !== undefined && (
              <span className="text-[7px] font-mono text-slate-600 uppercase">
                w:{Math.round(node.weight * 100)}%
              </span>
            )}
            <ScoreBadge score={node.score} />
            {node.children.length > 0 && (
              expanded
                ? <ChevronDown className="h-3 w-3 text-slate-600" />
                : <ChevronRight className="h-3 w-3 text-slate-600" />
            )}
          </button>

          {/* Expanded children */}
          {expanded && node.children.length > 0 && (
            <div className="ml-3 mt-1 space-y-0.5 border-l border-white/5 pl-3">
              {node.children.map((leaf, i) => (
                <div key={i} className="flex items-start gap-2 py-1">
                  {leaf.isAlert ? (
                    <AlertTriangle className="h-3 w-3 text-amber-400 flex-shrink-0 mt-0.5" />
                  ) : (
                    <div className="h-1.5 w-1.5 rounded-full bg-white/20 flex-shrink-0 mt-1.5" />
                  )}
                  <div className="min-w-0">
                    <span className="text-[8px] text-slate-500 uppercase tracking-wider">{leaf.label}: </span>
                    <span className="text-[9px] text-slate-300 font-mono break-all">{leaf.value}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export function EvidenceChainCard({ result }: EvidenceChainCardProps) {
  const bd = result.model_breakdown
  const intel = result.threat_intelligence
  const tactics = result.detected_tactics || []
  const llm = (result as any).llm_fingerprint

  // Build tree nodes from the analysis result
  const nodes: TreeNode[] = []

  // NLP Layer
  const nlpLeaves: TreeLeaf[] = []
  if (bd.nlp.explanation) nlpLeaves.push({ label: "Reasoning", value: bd.nlp.explanation })
  if (tactics.length > 0) {
    nlpLeaves.push({ label: "Tactics", value: tactics.map(t => `${t.name} [${t.mitre_id}]`).join(", "), isAlert: true })
  }
  if (bd.nlp.top_phrases?.length) {
    nlpLeaves.push({ label: "Key Phrases", value: bd.nlp.top_phrases.join(" · ") })
  }
  if (bd.nlp.phishing_intent) nlpLeaves.push({ label: "Intent", value: bd.nlp.phishing_intent, isAlert: true })
  nodes.push({
    id: "nlp", label: "NLP Intent Engine", score: bd.nlp.score, weight: bd.nlp.weight,
    icon: <Brain className={cn("h-3.5 w-3.5", scoreColor(bd.nlp.score))} />,
    color: "blue", children: nlpLeaves
  })

  // URL Layer
  const urlLeaves: TreeLeaf[] = []
  if (bd.url.top_features?.length) {
    urlLeaves.push({ label: "Risk Indicators", value: bd.url.top_features.join(", "), isAlert: bd.url.score >= 0.5 })
  }
  if (result.urls_analyzed?.length) {
    urlLeaves.push({ label: "URLs Analyzed", value: result.urls_analyzed.slice(0, 3).join(", ") })
  }
  const shap = bd.url.shap_values || {}
  const topShap = Object.entries(shap).sort(([,a], [,b]) => (b as number) - (a as number)).slice(0, 3)
  if (topShap.length > 0) {
    for (const [feature, val] of topShap) {
      urlLeaves.push({ label: feature.replace(/_/g, " "), value: `SHAP: ${(val as number).toFixed(3)}` })
    }
  }
  nodes.push({
    id: "url", label: "URL Risk Analyzer", score: bd.url.score, weight: bd.url.weight,
    icon: <Globe className={cn("h-3.5 w-3.5", scoreColor(bd.url.score))} />,
    color: "purple", children: urlLeaves
  })

  // Visual Layer
  const visualLeaves: TreeLeaf[] = []
  if (bd.visual.matched_brand && bd.visual.matched_brand !== "Unknown") {
    visualLeaves.push({ label: "Brand Match", value: `${bd.visual.matched_brand} (${Math.round(bd.visual.similarity * 100)}% similarity)`, isAlert: true })
  }
  if (bd.visual.screenshot_path) {
    visualLeaves.push({ label: "Screenshot", value: "Captured via Apify sandbox" })
  }
  nodes.push({
    id: "visual", label: "Visual Brand Engine", score: bd.visual.score, weight: bd.visual.weight,
    icon: <Eye className={cn("h-3.5 w-3.5", scoreColor(bd.visual.score))} />,
    color: "pink", children: visualLeaves
  })

  // Header Layer
  const headerLeaves: TreeLeaf[] = []
  headerLeaves.push({ label: "SPF", value: bd.header.spf_result || "unknown", isAlert: bd.header.spf_result === "fail" })
  headerLeaves.push({ label: "DKIM", value: bd.header.dkim_result || "unknown", isAlert: bd.header.dkim_result === "fail" || bd.header.dkim_result === "missing" })
  headerLeaves.push({ label: "DMARC", value: bd.header.dmarc_result || "none" })
  if (bd.header.flags?.length) {
    headerLeaves.push({ label: "Flags", value: bd.header.flags.join(", "), isAlert: true })
  }
  nodes.push({
    id: "header", label: "Header Authentication", score: bd.header.score, weight: bd.header.weight,
    icon: <FileText className={cn("h-3.5 w-3.5", scoreColor(bd.header.score))} />,
    color: "cyan", children: headerLeaves
  })

  // Intel Layer
  const intelLeaves: TreeLeaf[] = []
  if (intel?.campaign_id && intel.campaign_id !== "Unknown") {
    intelLeaves.push({ label: "Campaign", value: intel.campaign_id, isAlert: true })
  }
  if (intel?.threat_actor && intel.threat_actor !== "Unknown") {
    intelLeaves.push({ label: "Threat Actor", value: `${intel.threat_actor} (${Math.round((intel.actor_confidence || 0) * 100)}% confidence)`, isAlert: true })
  }
  if (intel?.related_domains?.length) {
    intelLeaves.push({ label: "IOC Domains", value: intel.related_domains.slice(0, 3).join(", ") })
  }
  const intelScore = intel?.actor_confidence || 0
  if (intelLeaves.length > 0) {
    nodes.push({
      id: "intel", label: "Threat Intelligence", score: intelScore,
      icon: <Database className={cn("h-3.5 w-3.5", scoreColor(intelScore))} />,
      color: "orange", children: intelLeaves
    })
  }

  // LLM Fingerprint (if present)
  if (llm && llm.verdict !== "UNKNOWN") {
    const llmLeaves: TreeLeaf[] = []
    llmLeaves.push({ label: "Method", value: llm.detection_method?.replace(/_/g, " ") || "unknown" })
    if (llm.llm_assessment?.reasoning) {
      llmLeaves.push({ label: "AI Assessment", value: llm.llm_assessment.reasoning })
    }
    if (llm.signals?.length) {
      llmLeaves.push({ label: "Signals", value: llm.signals.slice(0, 3).join(" · "), isAlert: llm.is_likely_ai })
    }
    nodes.push({
      id: "llm", label: "AI-Generated Detection", score: llm.ai_generated_probability,
      icon: <Crosshair className={cn("h-3.5 w-3.5", scoreColor(llm.ai_generated_probability))} />,
      color: "purple", children: llmLeaves
    })
  }

  const verdict = result.verdict
  const score = result.threat_score

  return (
    <div className={cn(
      "rounded-2xl border overflow-hidden",
      score >= 0.65 ? "bg-red-500/5 border-red-500/15" :
      score >= 0.35 ? "bg-amber-500/5 border-amber-500/15" :
      "bg-emerald-500/5 border-emerald-500/15"
    )}>
      {/* Root node */}
      <div className="px-5 py-4 border-b border-white/5">
        <div className="flex items-center gap-3">
          <div className={cn(
            "h-9 w-9 rounded-xl flex items-center justify-center border",
            score >= 0.65 ? "bg-red-500/10 border-red-500/20" :
            score >= 0.35 ? "bg-amber-500/10 border-amber-500/20" :
            "bg-emerald-500/10 border-emerald-500/20"
          )}>
            <Shield className={cn("h-5 w-5", scoreColor(score))} />
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <p className="text-[10px] font-black uppercase tracking-widest text-slate-300">
                Evidence Chain
              </p>
              <Badge className="text-[7px] bg-blue-500/10 border-blue-500/20 text-blue-400 uppercase font-black">
                Glass Box
              </Badge>
            </div>
            <p className="text-[9px] text-slate-500 mt-0.5">
              Why <span className={cn("font-black uppercase", scoreColor(score))}>{verdict}</span> at{" "}
              <span className={cn("font-mono font-black", scoreColor(score))}>{Math.round(score * 100)}%</span>? 
              Drill into each layer below.
            </p>
          </div>
          <div className="text-right shrink-0">
            <p className={cn("text-2xl font-black font-mono", scoreColor(score))}>
              {Math.round(score * 100)}%
            </p>
            <p className="text-[7px] uppercase tracking-widest text-slate-600 font-bold">Fused Score</p>
          </div>
        </div>
      </div>

      {/* Tree branches */}
      <div className="px-2 py-3">
        {nodes.map((node, i) => (
          <TreeBranch key={node.id} node={node} isLast={i === nodes.length - 1} />
        ))}
      </div>

      {/* XGBoost calibration footer */}
      <div className="px-5 py-3 border-t border-white/5 flex items-center gap-3">
        <div className="h-1 flex-1 bg-white/5 rounded-full overflow-hidden">
          <div
            className={cn("h-full rounded-full transition-all",
              score >= 0.65 ? "bg-red-500" : score >= 0.35 ? "bg-amber-500" : "bg-emerald-500"
            )}
            style={{ width: `${score * 100}%` }}
          />
        </div>
        <span className="text-[8px] font-mono text-slate-500">
          XGBoost calibration · {Math.round(result.confidence * 100)}% confidence
        </span>
      </div>
    </div>
  )
}
