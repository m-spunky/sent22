"use client"

import React, { useState, useEffect, useCallback, useRef } from "react"
import { useSearchParams } from "next/navigation"
import {
  Search, Mail, Globe, FileText, QrCode, Upload,
  ShieldAlert, ShieldCheck, AlertTriangle, Zap, CheckCircle,
  X, Minus, ChevronRight, Eye, Skull, TrendingUp, Lock, WifiOff, Paperclip, File
} from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Textarea } from "@/components/ui/textarea"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"
import { motion, AnimatePresence } from "framer-motion"
import { ThreatScoreCard } from "@/components/analyze/ThreatScoreCard"
import { TacticsCard } from "@/components/analyze/TacticsCard"
import { IntelCard } from "@/components/analyze/IntelCard"
import { ExplanationCard } from "@/components/analyze/ExplanationCard"
import { EvidencePanel } from "@/components/analyze/EvidencePanel"
import { TransparencyPanel } from "@/components/analyze/TransparencyPanel"
import type { AnalysisResult } from "@/lib/api"
import { generateReport, submitFeedback } from "@/lib/api"
import { WS_BASE } from "@/lib/api"
import { useGlobalStore } from "@/lib/global-store"

type InputTab = "email" | "url" | "headers" | "qr" | "attachment"
type AnalysisState = "idle" | "analyzing" | "done" | "error"

interface PipelineLayer {
  key: string
  label: string
  step: number
  score?: number
  flags?: string[]
  data?: Record<string, unknown>
}

const INPUT_TABS: { id: InputTab; label: string; icon: React.ReactNode; placeholder: string }[] = [
  { id: "email", label: "Email Body", icon: <Mail className="h-3.5 w-3.5" />, placeholder: "Paste the full email body or headers here...\n\nFrom: suspicious@paypal-verify.net\nSubject: Your account has been limited\n\nDear customer, we noticed unusual activity..." },
  { id: "url", label: "URL", icon: <Globe className="h-3.5 w-3.5" />, placeholder: "Enter a suspicious URL, e.g.:\nhttps://paypal-secure-login.xyz/verify" },
  { id: "headers", label: "Email Headers", icon: <FileText className="h-3.5 w-3.5" />, placeholder: "Paste raw email headers:\n\nReceived: from mail.attacker.com ...\nFrom: PayPal Support <support@paypaI.com>\nReply-To: attacker@gmail.com\nX-Originating-IP: 185.220.101.45" },
  { id: "qr", label: "QR Code", icon: <QrCode className="h-3.5 w-3.5" />, placeholder: "" },
  { id: "attachment", label: "Attachment", icon: <Paperclip className="h-3.5 w-3.5" />, placeholder: "" },
]

function LivePipelineCard({ layers, state }: { layers: PipelineLayer[]; state: AnalysisState }) {
  const stageOrder = ["pipeline_start", "nlp", "header", "url", "visual", "intel"]
  const stageLabels: Record<string, string> = {
    pipeline_start: "Pre-Process",
    nlp: "NLP Engine",
    header: "Header Analysis",
    url: "URL Intelligence",
    visual: "Visual Sandbox",
    intel: "Threat Intel",
  }
  const completedKeys = new Set(layers.map(l => l.key))

  return (
    <Card className="card-cyber p-5 space-y-4">
      <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
        <Zap className="h-3.5 w-3.5 text-amber-400" />
        Detection Pipeline
        {state === "analyzing" && <div className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse ml-auto" />}
        {state === "done" && <Badge className="ml-auto bg-emerald-500/10 text-emerald-400 border-emerald-500/20 text-[7px] uppercase font-black">Complete</Badge>}
      </CardTitle>
      <div className="space-y-2">
        {stageOrder.map((key, i) => {
          const layer = layers.find(l => l.key === key)
          const isDone = completedKeys.has(key)
          const isRunning = state === "analyzing" && !isDone && i === completedKeys.size
          return (
            <div key={key} className={cn("flex items-center gap-3 px-3 py-2 rounded-lg transition-all",
              isDone ? "bg-blue-500/5 border border-blue-500/10" : isRunning ? "bg-white/5 border border-white/10" : "opacity-30"
            )}>
              <div className={cn("h-5 w-5 rounded-full flex items-center justify-center flex-shrink-0",
                isDone ? "bg-emerald-500/20 text-emerald-400" : isRunning ? "bg-blue-500/20" : "bg-white/5"
              )}>
                {isDone ? <CheckCircle className="h-3 w-3" /> : isRunning ? <div className="h-2 w-2 rounded-full bg-blue-400 animate-pulse" /> : <div className="h-2 w-2 rounded-full bg-white/20" />}
              </div>
              <span className="text-[10px] font-bold uppercase tracking-widest flex-1 text-slate-400">{stageLabels[key]}</span>
              {layer?.score != null && (
                <div className="flex items-center gap-2">
                  <div className="w-12 h-1 bg-white/5 rounded-full overflow-hidden">
                    <div className={cn("h-full rounded-full", layer.score >= 0.65 ? "bg-red-500" : layer.score >= 0.35 ? "bg-amber-500" : "bg-emerald-500")} style={{ width: `${layer.score * 100}%` }} />
                  </div>
                  <span className={cn("text-[9px] font-mono font-black",
                    layer.score >= 0.65 ? "text-red-400" : layer.score >= 0.35 ? "text-amber-400" : "text-emerald-400"
                  )}>{Math.round(layer.score * 100)}%</span>
                </div>
              )}
              {layer?.flags && layer.flags.length > 0 && (
                <span className="text-[8px] text-red-400 font-mono">{layer.flags[0]}</span>
              )}
            </div>
          )
        })}
      </div>
    </Card>
  )
}

function KillChainCard({ killChain }: { killChain: AnalysisResult["kill_chain"] }) {
  if (!killChain?.kill_chain_stages?.length) return null
  return (
    <Card className="card-cyber border-t-2 border-t-red-500/40 p-5 space-y-4">
      <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
        <Skull className="h-3.5 w-3.5 text-red-400" />
        Kill Chain Analysis
        <Badge className="ml-auto bg-red-500/10 text-red-400 border-red-500/20 text-[7px] uppercase font-black">PS-02 / PS-03</Badge>
      </CardTitle>
      <div className="space-y-3">
        {killChain.kill_chain_stages.map((stage, i) => (
          <div key={i} className={cn("flex items-start gap-3 p-3 rounded-xl border transition-all",
            stage.active
              ? stage.color === "red" ? "bg-red-500/8 border-red-500/15" : "bg-amber-500/8 border-amber-500/15"
              : "bg-white/3 border-white/5 opacity-50"
          )}>
            <div className={cn("h-7 w-7 rounded-lg flex items-center justify-center text-[10px] font-black flex-shrink-0 border",
              stage.active
                ? stage.color === "red" ? "bg-red-500/20 border-red-500/30 text-red-400" : "bg-amber-500/20 border-amber-500/30 text-amber-400"
                : "bg-white/5 border-white/10 text-slate-600"
            )}>
              {i + 1}
            </div>
            <div className="flex-1 min-w-0 space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-black uppercase tracking-widest text-slate-300">{stage.phase}</span>
                <Badge variant="outline" className="text-[7px] border-white/10 text-slate-500 font-mono">{stage.technique}</Badge>
                <Badge className="text-[7px] bg-blue-500/10 text-blue-400 border-blue-500/20 ml-auto">{stage.ps}</Badge>
              </div>
              <p className="text-[10px] text-slate-500 leading-relaxed">{stage.description}</p>
            </div>
          </div>
        ))}
      </div>
      {killChain.estimated_impact && (
        <div className={cn("p-3 rounded-xl border",
          killChain.estimated_impact.level === "CRITICAL" ? "bg-red-500/8 border-red-500/15"
          : killChain.estimated_impact.level === "HIGH" ? "bg-orange-500/8 border-orange-500/15"
          : "bg-white/3 border-white/5"
        )}>
          <div className="flex items-center justify-between">
            <span className="text-[9px] font-black uppercase tracking-widest text-slate-500">Estimated Financial Impact</span>
            <span className={cn("text-xs font-black font-mono",
              killChain.estimated_impact.level === "CRITICAL" ? "text-red-400" : killChain.estimated_impact.level === "HIGH" ? "text-orange-400" : "text-slate-400"
            )}>{killChain.estimated_impact.financial_risk_usd}</span>
          </div>
        </div>
      )}
    </Card>
  )
}

function DarkWebCard({ darkWeb }: { darkWeb: AnalysisResult["dark_web_exposure"] }) {
  if (!darkWeb || darkWeb.dark_web_risk === "UNKNOWN") return null
  const isExposed = (darkWeb.breach_count || 0) > 0 || (darkWeb.paste_count || 0) > 0
  const riskColor = darkWeb.dark_web_risk === "HIGH" ? "red" : darkWeb.dark_web_risk === "MEDIUM" ? "amber" : "emerald"
  return (
    <Card className={cn("card-cyber border-t-2 p-5 space-y-4",
      riskColor === "red" ? "border-t-red-500/40" : riskColor === "amber" ? "border-t-amber-500/40" : "border-t-emerald-500/30"
    )}>
      <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
        <Eye className="h-3.5 w-3.5 text-purple-400" />
        Dark Web Exposure
        <div className="ml-auto flex items-center gap-2">
          {darkWeb.sources && darkWeb.sources.map(s => (
            <span key={s} className="text-[7px] font-mono text-slate-600 uppercase">{s}</span>
          ))}
          <Badge className="bg-purple-500/10 text-purple-400 border-purple-500/20 text-[7px] uppercase font-black">PS-05</Badge>
        </div>
      </CardTitle>
      <div className={cn("flex items-center gap-4 p-3 rounded-xl border",
        riskColor === "red" ? "bg-red-500/8 border-red-500/15"
        : riskColor === "amber" ? "bg-amber-500/8 border-amber-500/15"
        : "bg-emerald-500/8 border-emerald-500/15"
      )}>
        {isExposed
          ? <ShieldAlert className={cn("h-5 w-5 flex-shrink-0", riskColor === "red" ? "text-red-400" : "text-amber-400")} />
          : <ShieldCheck className="h-5 w-5 text-emerald-400 flex-shrink-0" />
        }
        <div className="flex-1">
          {isExposed ? (
            <>
              <p className={cn("text-sm font-black", riskColor === "red" ? "text-red-300" : "text-amber-300")}>
                {darkWeb.breach_count} Known Breach{darkWeb.breach_count !== 1 ? "es" : ""}
                {(darkWeb.paste_count || 0) > 0 && <span className="text-[10px] ml-2 text-red-400">+{darkWeb.paste_count} paste{darkWeb.paste_count !== 1 ? "s" : ""}</span>}
              </p>
              <p className="text-[9px] text-slate-500 mt-0.5">
                {darkWeb.total_exposed > 0 ? `~${darkWeb.total_exposed.toLocaleString()} records exposed` : "Domain found in dark web databases"}
              </p>
            </>
          ) : (
            <>
              <p className="text-sm font-black text-emerald-300">No Exposures Found</p>
              <p className="text-[9px] text-slate-500">Domain not in XposedOrNot or HIBP databases</p>
            </>
          )}
        </div>
        <Badge className={cn("text-[8px] font-black uppercase shrink-0",
          riskColor === "red" ? "bg-red-500/10 text-red-400 border-red-500/20"
          : riskColor === "amber" ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
          : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
        )}>{darkWeb.dark_web_risk}</Badge>
      </div>
      {isExposed && darkWeb.breaches && darkWeb.breaches.slice(0, 4).map((b, i) => (
        <div key={i} className="flex items-center justify-between px-3 py-2 bg-white/3 border border-white/5 rounded-lg">
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-[9px] font-bold text-slate-400 truncate">{b.name}</span>
            {b.source && <span className="text-[7px] font-mono text-slate-700 uppercase shrink-0">{b.source}</span>}
          </div>
          <div className="flex items-center gap-3 shrink-0">
            {b.pwn_count ? <span className="text-[8px] font-mono text-slate-600">{b.pwn_count.toLocaleString()} records</span> : null}
            {b.date && <span className="text-[8px] text-purple-400 font-mono">{b.date}</span>}
          </div>
        </div>
      ))}
    </Card>
  )
}

interface AttachmentResult {
  filename: string
  extension: string
  mime_type: string
  size_bytes: number
  risk_score: number
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "CLEAN"
  findings: string[]
}
interface AttachmentAnalysis {
  count: number
  max_risk: number
  results: AttachmentResult[]
  verdict: string
}

function AttachmentRiskPanel({ analysis }: { analysis: AttachmentAnalysis }) {
  if (!analysis || analysis.count === 0) return null
  const isHigh = analysis.verdict === "CRITICAL" || analysis.verdict === "HIGH_RISK"
  const isMed = analysis.verdict === "SUSPICIOUS"
  const borderCls = isHigh ? "border-t-red-500/40" : isMed ? "border-t-amber-500/40" : "border-t-emerald-500/30"
  const badgeCls = isHigh
    ? "bg-red-500/10 text-red-400 border-red-500/20"
    : isMed ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
    : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
  const riskColor = (level: string) =>
    level === "CRITICAL" || level === "HIGH" ? "text-red-400" : level === "MEDIUM" ? "text-amber-400" : level === "LOW" ? "text-yellow-400" : "text-emerald-400"

  return (
    <Card className={cn("card-cyber border-t-2 p-5 space-y-4", borderCls)}>
      <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
        <Paperclip className="h-3.5 w-3.5 text-slate-400" />
        Attachment Analysis
        <span className="text-slate-600 font-normal normal-case tracking-normal text-[10px]">{analysis.count} file{analysis.count !== 1 ? "s" : ""}</span>
        <Badge className={cn("ml-auto text-[7px] uppercase font-black", badgeCls)}>{analysis.verdict}</Badge>
      </CardTitle>
      <div className="space-y-2">
        {analysis.results.map((att, i) => (
          <div key={i} className="p-3 bg-white/3 border border-white/5 rounded-xl space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono font-bold text-slate-300 truncate flex-1">{att.filename}</span>
              <span className={cn("text-[9px] font-black uppercase shrink-0", riskColor(att.risk_level))}>{att.risk_level}</span>
              <span className="text-[8px] font-mono text-slate-600 shrink-0">{Math.round(att.risk_score * 100)}%</span>
            </div>
            {att.findings.map((f, j) => (
              <p key={j} className="text-[9px] text-slate-500 leading-relaxed">{f}</p>
            ))}
            {att.size_bytes > 0 && (
              <p className="text-[8px] text-slate-700 font-mono">{att.mime_type} · {(att.size_bytes / 1024).toFixed(1)} KB</p>
            )}
          </div>
        ))}
      </div>
    </Card>
  )
}

function FeedbackBar({ eventId }: { eventId: string }) {
  const [feedback, setFeedback] = useState<string | null>(null)
  const handleFeedback = async (type: "correct" | "false_positive" | "missed") => {
    await submitFeedback(eventId, type)
    setFeedback(type)
  }
  if (feedback) return (
    <div className="flex items-center gap-2 text-[10px] font-bold text-slate-500 uppercase tracking-widest">
      <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />
      Feedback recorded: {feedback.replace("_", " ")}
    </div>
  )
  return (
    <div className="flex items-center gap-3">
      <span className="text-[9px] font-bold uppercase tracking-widest text-slate-600">Was this correct?</span>
      {[
        { type: "correct" as const, icon: <CheckCircle className="h-3.5 w-3.5" />, label: "Yes", cls: "text-emerald-400 border-emerald-500/20 hover:bg-emerald-500/10" },
        { type: "false_positive" as const, icon: <Minus className="h-3.5 w-3.5" />, label: "False Positive", cls: "text-amber-400 border-amber-500/20 hover:bg-amber-500/10" },
        { type: "missed" as const, icon: <X className="h-3.5 w-3.5" />, label: "Missed", cls: "text-red-400 border-red-500/20 hover:bg-red-500/10" },
      ].map(btn => (
        <button key={btn.type} onClick={() => handleFeedback(btn.type)}
          className={cn("flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-[9px] font-black uppercase tracking-widest transition-all hover:scale-105", btn.cls)}>
          {btn.icon}{btn.label}
        </button>
      ))}
    </div>
  )
}

export default function AnalyzePage() {
  const searchParams = useSearchParams()
  const [tab, setTab] = useState<InputTab>("email")
  const [inputText, setInputText] = useState("")
  const [urlInput, setUrlInput] = useState("")
  const [qrFile, setQrFile] = useState<File | null>(null)
  const [attachmentFile, setAttachmentFile] = useState<File | null>(null)
  const [state, setState] = useState<AnalysisState>("idle")
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState("")
  const [pipelineLayers, setPipelineLayers] = useState<PipelineLayer[]>([])
  const [gmailAttachments, setGmailAttachments] = useState<AttachmentAnalysis | null>(null)
  const [gmailBanner, setGmailBanner] = useState<string | null>(null)
  const [piiRedacted, setPiiRedacted] = useState<string[] | undefined>(undefined)
  const { visualSandboxEnabled: visualEnabled } = useGlobalStore()
  const wsRef = useRef<WebSocket | null>(null)
  const qrInputRef = useRef<HTMLInputElement>(null)
  const attachmentInputRef = useRef<HTMLInputElement>(null)
  const pendingAnalyzeRef = useRef(false)

  // WebSocket for per-layer streaming
  useEffect(() => {
    const ws = new WebSocket(`${WS_BASE}/api/v1/stream`)
    ws.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data)
        if (data.type === "pipeline_progress") {
          setPipelineLayers(prev => {
            const exists = prev.find(l => l.key === data.layer)
            if (exists) return prev
            return [...prev, { key: data.layer, label: data.layer, step: data.step, score: data.data?.score, flags: data.data?.flags }]
          })
        }
      } catch { }
    }
    wsRef.current = ws
    return () => { ws.close() }
  }, [])

  // Load Gmail message if ?gmail=<id> is in the URL
  useEffect(() => {
    const gmailId = searchParams.get("gmail")
    if (!gmailId) return
    fetch(`/api/v1/gmail/message/${gmailId}`)
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json() })
      .then(data => {
        const headerLines = [
          `From: ${data.from_name || ""} <${data.from || ""}>`,
          `Subject: ${data.subject || ""}`,
          `Date: ${data.date || ""}`,
        ]
        // Include key security headers
        if (data.raw_headers) {
          const securityHeaders = ["received-spf", "dkim-signature", "authentication-results", "reply-to", "return-path", "x-originating-ip", "x-spam-status"]
          for (const h of securityHeaders) {
            if (data.raw_headers[h]) headerLines.push(`${h}: ${data.raw_headers[h]}`)
          }
        }
        const fullContent = headerLines.join("\n") + "\n\n" + (data.body || data.snippet || "")
        setTab("email")
        setInputText(fullContent)
        setGmailBanner(`Gmail: ${data.from || ""} — ${data.subject || ""}`)

        // Always surface attachment analysis from cache (covers all file types)
        if (data.attachment_analysis && data.attachment_analysis.count > 0) {
          setGmailAttachments(data.attachment_analysis)
        }
        setPiiRedacted(data.pii_redacted ?? [])

        // ── Use cached full_analysis if available — avoids wasting API credits ──
        // The inbox scan already ran the 5-layer pipeline; reuse that result.
        // Cached result is augmented with attachment_analysis so all layers show.
        if (data.full_analysis) {
          const cached = {
            ...data.full_analysis,
            // Inject attachment analysis into the result so TransparencyPanel can show it
            _attachment_analysis: data.attachment_analysis ?? null,
            _gmail_cached: true,
          }
          setResult(cached as any)
          setState("done")
          // Mark all pipeline stages as complete
          setPipelineLayers([
            { key: "pipeline_start", label: "Pre-Process", step: 0, score: 0 },
            { key: "nlp", label: "NLP", step: 1, score: data.full_analysis.model_breakdown?.nlp?.score ?? 0 },
            { key: "header", label: "Header", step: 2, score: data.full_analysis.model_breakdown?.header?.score ?? 0 },
            { key: "url", label: "URL", step: 3, score: data.full_analysis.model_breakdown?.url?.score ?? 0 },
            { key: "visual", label: "Visual", step: 4, score: data.full_analysis.model_breakdown?.visual?.score ?? 0 },
            { key: "intel", label: "Intel", step: 5, score: 0 },
          ])
        } else {
          // No cache — run fresh analysis
          pendingAnalyzeRef.current = true
        }
      })
      .catch(e => setError(`Failed to load Gmail message: ${e.message}`))
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const handleAnalyze = useCallback(async () => {
    const content = tab === "url" ? urlInput.trim() : inputText.trim()
    if (!content && tab !== "qr" && tab !== "attachment") { setError("Please enter content to analyze."); return }
    if (tab === "qr" && !qrFile) { setError("Please select a QR code image."); return }
    if (tab === "attachment" && !attachmentFile) { setError("Please select a file to analyze."); return }

    setState("analyzing")
    setError("")
    setResult(null)
    setPipelineLayers([])

    // Safe error extractor — handles non-JSON responses (plain text 500s, Nginx errors, etc.)
    const getErrMsg = async (r: Response, fallback: string): Promise<string> => {
      try { const j = await r.json(); return j.detail || j.message || fallback } catch { return fallback }
    }

    try {
      let res: AnalysisResult

      if (tab === "attachment" && attachmentFile) {
        const form = new FormData()
        form.append("file", attachmentFile)
        const resp = await fetch("/api/v1/analyze/attachment", { method: "POST", body: form })
        if (!resp.ok) throw new Error(await getErrMsg(resp, "Attachment analysis failed"))
        const data = await resp.json()
        // Use full_analysis if available, otherwise build a minimal result from attachment data
        if (data.full_analysis) {
          res = { ...data.full_analysis, _attachment_analysis: data.attachment_analysis, _filename: data.filename }
        } else {
          // Attachment-only result (no extractable text) — synthesize a minimal AnalysisResult shape
          res = {
            event_id: `ATT-${Date.now()}`,
            status: "complete",
            threat_score: data.threat_score,
            verdict: data.verdict,
            confidence: data.attachment_analysis.max_risk,
            model_breakdown: { nlp: { score: 0, weight: 0.3, tactics: [], explanation: "No text extracted" }, url: { score: 0, weight: 0.25, top_features: [], shap_values: {} }, visual: { score: 0, weight: 0.2, matched_brand: "Unknown", similarity: 0 }, header: { score: 0, weight: 0.25, flags: [], spf_result: "n/a", dkim_result: "n/a", dmarc_result: "n/a" } },
            detected_tactics: [],
            threat_intelligence: { campaign_id: "Unknown", threat_actor: "Unknown", actor_confidence: 0, related_domains: [], global_reach: [] },
            explanation_narrative: `Attachment analysis of "${data.filename}": ${data.findings?.join("; ") || "No threats detected."}`,
            recommended_action: data.risk_level === "CRITICAL" ? "Do not open. Quarantine immediately." : data.risk_level === "HIGH" ? "Exercise extreme caution. Verify sender before opening." : "Treat with caution.",
            inference_time_ms: 0,
            timestamp: new Date().toISOString(),
            urls_analyzed: [],
            _attachment_analysis: data.attachment_analysis,
            _filename: data.filename,
          } as any
        }
      } else if (tab === "qr" && qrFile) {
        const form = new FormData()
        form.append("file", qrFile)
        const resp = await fetch("/api/v1/quishing/decode", { method: "POST", body: form })
        if (!resp.ok) throw new Error(await getErrMsg(resp, "QR analysis failed"))
        const data = await resp.json()
        res = data.analysis
      } else {
        const endpoint = tab === "url" ? "/api/v1/analyze/url" : tab === "headers" ? "/api/v1/analyze/headers" : "/api/v1/analyze/email"
        const body = tab === "url"
          ? { url: content, options: { run_visual: visualEnabled } }
          : tab === "headers"
          ? { headers: content, options: { run_visual: false } }
          : { content, options: { run_visual: visualEnabled } }
        const resp = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        })
        if (!resp.ok) throw new Error(await getErrMsg(resp, `Analysis failed (HTTP ${resp.status})`))
        res = await resp.json()
      }

      setResult(res)
      setState("done")
    } catch (e) {
      setError(e instanceof Error ? e.message : "Analysis failed. Is the backend running on port 8001?")
      setState("error")
    }
  }, [tab, inputText, urlInput, qrFile, attachmentFile, visualEnabled])

  // Auto-trigger analysis once Gmail email content is populated
  useEffect(() => {
    if (pendingAnalyzeRef.current && inputText && tab === "email" && state === "idle") {
      pendingAnalyzeRef.current = false
      handleAnalyze()
    }
  }, [inputText, tab, state, handleAnalyze])

  const handleReset = () => { setState("idle"); setResult(null); setError(""); setPipelineLayers([]); setInputText(""); setUrlInput(""); setGmailAttachments(null); setGmailBanner(null); setPiiRedacted(undefined); setAttachmentFile(null) }

  const handleDownloadReport = async () => {
    if (!result) return
    try {
      const resp = await generateReport(result.event_id)
      const blob = await resp.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a"); a.href = url; a.download = `phishguard-${result.event_id}.pdf`; a.click()
      URL.revokeObjectURL(url)
    } catch { }
  }

  const currentTab = INPUT_TABS.find(t => t.id === tab)!
  const verdictColor = result ? result.verdict === "CONFIRMED_THREAT" || result.verdict === "PHISHING" ? "text-red-400"
    : result.verdict === "SUSPICIOUS" ? "text-amber-400" : "text-emerald-400" : ""
  const verdictBorderTop = result ? result.verdict === "CONFIRMED_THREAT" || result.verdict === "PHISHING" ? "border-t-red-500"
    : result.verdict === "SUSPICIOUS" ? "border-t-amber-500" : "border-t-emerald-500" : ""

  return (
    <div className="space-y-8 pb-10">
      {/* Header */}
      <header className="flex items-center justify-between border-b border-white/5 pb-6">
        <div className="flex items-center gap-4">
          <div className="h-10 w-10 rounded-xl bg-blue-500/20 border border-blue-500/30 flex items-center justify-center shadow-xl">
            <Search className="h-5 w-5 text-blue-400" />
          </div>
          <div>
            <h1 className="text-3xl font-black tracking-tighter text-foreground uppercase">Phishing Analyzer</h1>
            <p className="text-[10px] text-muted-foreground uppercase font-black tracking-[0.3em]">
              5-layer AI detection · NLP + URL + Visual + Header + Intel
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {state === "done" && (
            <>
              <FeedbackBar eventId={result!.event_id} />
              <Button onClick={handleReset} variant="ghost" className="h-9 px-4 rounded-xl text-[10px] font-black uppercase tracking-widest text-slate-500 hover:text-slate-300">
                <X className="h-3.5 w-3.5 mr-2" />
                New Scan
              </Button>
            </>
          )}
        </div>
      </header>

      {/* Gmail source banner */}
      {gmailBanner && (
        <div className="flex items-center gap-3 px-4 py-2.5 bg-blue-500/8 border border-blue-500/15 rounded-xl text-[10px] text-blue-300 font-mono">
          <Mail className="h-3.5 w-3.5 text-blue-400 flex-shrink-0" />
          <span className="truncate">{gmailBanner}</span>
          <div className="ml-auto flex items-center gap-2 shrink-0">
            {gmailAttachments && gmailAttachments.count > 0 && (
              <span className="text-amber-400 uppercase font-black tracking-widest">
                + {gmailAttachments.count} Attachment{gmailAttachments.count !== 1 ? "s" : ""}
              </span>
            )}
            <span className="text-blue-500 uppercase font-black tracking-widest">
              {(result as any)?._gmail_cached ? "Cached Analysis" : "Full Analysis"}
            </span>
          </div>
        </div>
      )}

      <div className="grid grid-cols-12 gap-8">
        {/* LEFT: Input + Pipeline */}
        <div className="col-span-12 lg:col-span-5 space-y-6">
          {/* Input Card */}
          <Card className="card-cyber overflow-hidden">
            {/* Tabs */}
            <div className="flex border-b border-white/5">
              {INPUT_TABS.map(t => (
                <button key={t.id} onClick={() => setTab(t.id)}
                  className={cn(
                    "flex-1 flex items-center justify-center gap-1.5 py-3.5 text-[9px] font-black uppercase tracking-widest transition-all",
                    tab === t.id ? "bg-blue-500/10 text-blue-400 border-b-2 border-blue-500" : "text-slate-600 hover:text-slate-400 hover:bg-white/3"
                  )}>
                  {t.icon}{t.label}
                </button>
              ))}
            </div>

            <div className="p-5 space-y-4">
              {tab === "url" ? (
                <div className="relative">
                  <Globe className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-600" />
                  <Input
                    value={urlInput}
                    onChange={e => setUrlInput(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && handleAnalyze()}
                    placeholder="https://suspicious-site.xyz/login"
                    className="pl-11 bg-[#0D1B2A] border-white/10 focus:border-blue-500/40 rounded-xl h-12 font-mono text-sm"
                  />
                </div>
              ) : tab === "qr" ? (
                <div
                  onClick={() => qrInputRef.current?.click()}
                  className="border-2 border-dashed border-white/10 hover:border-blue-500/30 rounded-2xl p-10 flex flex-col items-center gap-4 cursor-pointer transition-all hover:bg-white/3"
                >
                  <input ref={qrInputRef} type="file" accept="image/*" className="hidden" onChange={e => setQrFile(e.target.files?.[0] || null)} />
                  <QrCode className="h-10 w-10 text-slate-600" />
                  <div className="text-center">
                    <p className="text-sm font-black uppercase text-slate-400">{qrFile ? qrFile.name : "Upload QR Code Image"}</p>
                    <p className="text-[9px] text-slate-600 uppercase tracking-widest mt-1">Detects quishing (QR phishing) attacks · PNG, JPG, WEBP</p>
                  </div>
                </div>
              ) : tab === "attachment" ? (
                <div className="space-y-3">
                  <div
                    onClick={() => attachmentInputRef.current?.click()}
                    className={cn(
                      "border-2 border-dashed rounded-2xl p-10 flex flex-col items-center gap-4 cursor-pointer transition-all",
                      attachmentFile
                        ? "border-blue-500/40 bg-blue-500/5 hover:bg-blue-500/8"
                        : "border-white/10 hover:border-blue-500/30 hover:bg-white/3"
                    )}
                  >
                    <input
                      ref={attachmentInputRef}
                      type="file"
                      className="hidden"
                      accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.rtf,.zip,.rar,.7z,.exe,.bat,.ps1,.vbs,.js,.lnk,.svg,.jpg,.jpeg,.png,.gif,.mp4,.avi,.mov,.txt,.eml"
                      onChange={e => setAttachmentFile(e.target.files?.[0] || null)}
                    />
                    {attachmentFile ? (
                      <>
                        <File className="h-10 w-10 text-blue-400" />
                        <div className="text-center">
                          <p className="text-sm font-black uppercase text-slate-200">{attachmentFile.name}</p>
                          <p className="text-[9px] text-slate-500 uppercase tracking-widest mt-1">
                            {(attachmentFile.size / 1024).toFixed(1)} KB · {attachmentFile.type || "unknown type"}
                          </p>
                          <p className="text-[8px] text-blue-400 mt-2 uppercase tracking-widest font-bold">Click to change file</p>
                        </div>
                      </>
                    ) : (
                      <>
                        <Paperclip className="h-10 w-10 text-slate-600" />
                        <div className="text-center">
                          <p className="text-sm font-black uppercase text-slate-400">Upload Suspicious Attachment</p>
                          <p className="text-[9px] text-slate-600 uppercase tracking-widest mt-1">
                            PDF · Office · ZIP · EXE · Script · Image · Video · SVG
                          </p>
                        </div>
                      </>
                    )}
                  </div>
                  <div className="px-3 py-2 bg-amber-500/5 border border-amber-500/15 rounded-xl">
                    <p className="text-[9px] text-amber-400/80 leading-relaxed">
                      Files are analyzed locally — content inspection, macro detection, steganography, and PDF script scanning. Text is extracted and sent to AI for NLP analysis. Max 20 MB.
                    </p>
                  </div>
                </div>
              ) : (
                <Textarea
                  value={inputText}
                  onChange={e => setInputText(e.target.value)}
                  placeholder={currentTab.placeholder}
                  rows={10}
                  className="bg-[#0D1B2A] border-white/10 focus:border-blue-500/40 rounded-xl font-mono text-sm resize-none placeholder:text-slate-700"
                />
              )}

              {error && (
                <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/20 rounded-xl">
                  <WifiOff className="h-4 w-4 text-red-400 flex-shrink-0 mt-0.5" />
                  <p className="text-xs text-red-300">{error}</p>
                </div>
              )}

              <Button
                onClick={handleAnalyze}
                disabled={state === "analyzing"}
                className="w-full bg-blue-600 hover:bg-blue-500 text-white h-12 rounded-xl font-black uppercase tracking-widest text-xs shadow-[0_0_20px_rgba(59,130,246,0.3)] transition-all hover:scale-[1.02] disabled:opacity-50"
              >
                {state === "analyzing" ? (
                  <><div className="h-4 w-4 border-2 border-white/20 border-t-white rounded-full animate-spin mr-3" />Analyzing...</>
                ) : (
                  <><Zap className="h-4 w-4 mr-2" />Run AI Analysis</>
                )}
              </Button>
            </div>
          </Card>

          {/* Live Pipeline */}
          <AnimatePresence>
            {(state === "analyzing" || state === "done") && (
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                <LivePipelineCard layers={pipelineLayers} state={state} />
              </motion.div>
            )}
          </AnimatePresence>

          {/* Kill Chain */}
          <AnimatePresence>
            {result?.kill_chain && state === "done" && (
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
                <KillChainCard killChain={result.kill_chain} />
              </motion.div>
            )}
          </AnimatePresence>

          {/* Dark Web */}
          <AnimatePresence>
            {result?.dark_web_exposure && state === "done" && (
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }}>
                <DarkWebCard darkWeb={result.dark_web_exposure} />
              </motion.div>
            )}
          </AnimatePresence>

          {/* Attachment Risk — Gmail cache OR uploaded file result */}
          <AnimatePresence>
            {state === "done" && (gmailAttachments || (result as any)?._attachment_analysis) && (
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6 }}>
                <AttachmentRiskPanel analysis={gmailAttachments ?? (result as any)._attachment_analysis} />
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* RIGHT: Results */}
        <div className="col-span-12 lg:col-span-7 space-y-6">
          {state === "idle" && (
            <div className="h-full min-h-[400px] flex flex-col items-center justify-center space-y-6 opacity-30">
              <ShieldCheck className="h-20 w-20 text-slate-600" />
              <div className="text-center space-y-2">
                <p className="text-lg font-black uppercase tracking-tight text-slate-500">Ready to Analyze</p>
                <p className="text-[10px] text-slate-600 uppercase font-bold tracking-widest">Paste an email, URL, or headers — results appear here</p>
              </div>
            </div>
          )}

          <AnimatePresence>
            {(state === "analyzing" || state === "done") && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
                {/* Threat Score */}
                <ThreatScoreCard
                  score={result?.threat_score ?? 0}
                  classification={result?.verdict ?? "Analyzing..."}
                  confidence={result ? `${Math.round(result.confidence * 100)}% confidence` : "Running..."}
                  inferenceMs={result?.inference_time_ms}
                  loading={state === "analyzing"}
                />

                {/* Evidence Panel — per-analysis forensics (NLP phrases, URL SHAP, Screenshot, Headers) */}
                {result && (
                  <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
                    <EvidencePanel
                      model_breakdown={result.model_breakdown}
                      urls_analyzed={result.urls_analyzed ?? []}
                      verdict={result.verdict}
                    />
                  </motion.div>
                )}

                {/* Tactics + Intel row */}
                {result && (
                  <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
                    className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                    <TacticsCard tactics={result.detected_tactics.map(t => t.name)} detectedTactics={result.detected_tactics} />
                    <IntelCard
                      campaign={result.threat_intelligence?.campaign_id ?? "Unknown"}
                      actor={result.threat_intelligence?.threat_actor ?? "Unknown"}
                      actorConfidence={result.threat_intelligence?.actor_confidence}
                      relatedDomains={result.threat_intelligence?.related_domains}
                    />
                  </motion.div>
                )}

                {/* AI Narrative Explanation */}
                {result && (
                  <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
                    <ExplanationCard
                      explanation={result.explanation_narrative ?? ""}
                      confidence={result.confidence}
                      inferenceMs={result.inference_time_ms}
                    />
                  </motion.div>
                )}

                {/* Audit Trail — full explainability panel */}
                {result && state === "done" && (
                  <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }}>
                    <TransparencyPanel
                      result={result}
                      inputType={tab}
                      inputLength={(tab === "url" ? urlInput : inputText).length}
                      attachmentAnalysis={gmailAttachments}
                      piiRedacted={piiRedacted}
                    />
                  </motion.div>
                )}

                {/* Response Actions */}
                {result && state === "done" && (
                  <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}>
                    <Card className="card-cyber border-t-2 border-t-blue-500/30 p-5">
                      <div className="flex flex-wrap items-center justify-between gap-4">
                        <div>
                          <h4 className="text-xs font-black uppercase tracking-widest text-slate-300 mb-1">Rapid Response</h4>
                          <p className="text-[9px] text-slate-600 font-mono">{result.recommended_action}</p>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {[
                            { label: "Quarantine", cls: "border-red-500/20 hover:border-red-500/40 text-red-400 hover:bg-red-500/8" },
                            { label: "Block IOCs", cls: "border-orange-500/20 hover:border-orange-500/40 text-orange-400 hover:bg-orange-500/8" },
                            { label: "Alert Team", cls: "border-blue-500/20 hover:border-blue-500/40 text-blue-400 hover:bg-blue-500/8" },
                            { label: "PDF Report", cls: "border-amber-500/20 hover:border-amber-500/40 text-amber-400 hover:bg-amber-500/8" },
                          ].map((btn, i) => (
                            <button key={i}
                              onClick={btn.label === "PDF Report" ? handleDownloadReport : undefined}
                              className={cn("px-4 h-9 rounded-xl border font-black uppercase tracking-wider text-[9px] transition-all hover:scale-105 active:scale-95 font-mono", btn.cls)}>
                              {btn.label}
                            </button>
                          ))}
                        </div>
                      </div>
                    </Card>
                  </motion.div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  )
}
