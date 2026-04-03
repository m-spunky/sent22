"use client"

import React, { useState } from "react"
import { ChevronDown, ChevronRight, CheckCircle, AlertTriangle, XCircle,
  Shield, Globe, Eye, FileText, Cpu, Paperclip, Lock, Info,
  Brain, Hash, BarChart2, Zap } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import type { AnalysisResult } from "@/lib/api"

// ── Types ──────────────────────────────────────────────────────────────────────

interface AttachmentResult {
  filename: string
  extension: string
  mime_type: string
  size_bytes: number
  risk_score: number
  risk_level: string
  findings: string[]
  content_scanned?: boolean
}

interface AttachmentAnalysis {
  count: number
  max_risk: number
  results: AttachmentResult[]
  verdict: string
  content_scanned_count?: number
}

interface TransparencyPanelProps {
  result: AnalysisResult
  inputType: string
  inputLength: number
  attachmentAnalysis?: AttachmentAnalysis | null
  piiRedacted?: string[]
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function statusIcon(score: number, size = "h-3.5 w-3.5") {
  if (score >= 0.65) return <XCircle className={cn(size, "text-red-400 flex-shrink-0")} />
  if (score >= 0.35) return <AlertTriangle className={cn(size, "text-amber-400 flex-shrink-0")} />
  return <CheckCircle className={cn(size, "text-emerald-400 flex-shrink-0")} />
}

function scoreColor(score: number) {
  if (score >= 0.65) return "text-red-400"
  if (score >= 0.35) return "text-amber-400"
  return "text-emerald-400"
}

function scoreBg(score: number) {
  if (score >= 0.65) return "bg-red-500/10 border-red-500/20"
  if (score >= 0.35) return "bg-amber-500/10 border-amber-500/20"
  return "bg-emerald-500/10 border-emerald-500/20"
}

function ScoreBar({ score }: { score: number }) {
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-white/5 rounded-full overflow-hidden">
        <div
          className={cn("h-full rounded-full transition-all", score >= 0.65 ? "bg-red-500" : score >= 0.35 ? "bg-amber-500" : "bg-emerald-500")}
          style={{ width: `${score * 100}%` }}
        />
      </div>
      <span className={cn("text-[9px] font-black font-mono", scoreColor(score))}>
        {Math.round(score * 100)}%
      </span>
    </div>
  )
}

function authColor(val: string) {
  const v = (val || "").toUpperCase()
  if (v === "PASS" || v === "DMARC_PASS") return "text-emerald-400"
  if (v === "FAIL" || v === "DMARC_FAIL") return "text-red-400"
  if (v === "SOFTFAIL") return "text-amber-400"
  return "text-slate-500"
}

// ── Sub-sections ──────────────────────────────────────────────────────────────

function SectionHeader({
  icon, label, score, weight, open, onToggle,
}: {
  icon: React.ReactNode
  label: string
  score?: number
  weight?: number
  open: boolean
  onToggle: () => void
}) {
  return (
    <button
      onClick={onToggle}
      className="w-full flex items-center gap-3 px-4 py-3 hover:bg-white/3 transition-colors rounded-lg text-left"
    >
      <div className="h-6 w-6 rounded-md bg-white/5 border border-white/8 flex items-center justify-center flex-shrink-0">
        {icon}
      </div>
      <span className="text-[10px] font-black uppercase tracking-widest text-slate-300 flex-1">{label}</span>
      {score !== undefined && (
        <div className="flex items-center gap-3 mr-2">
          {weight !== undefined && (
            <span className="text-[8px] font-mono text-slate-600">weight {Math.round(weight * 100)}%</span>
          )}
          <ScoreBar score={score} />
          {statusIcon(score)}
        </div>
      )}
      {open
        ? <ChevronDown className="h-3 w-3 text-slate-600 flex-shrink-0" />
        : <ChevronRight className="h-3 w-3 text-slate-600 flex-shrink-0" />
      }
    </button>
  )
}

function CheckRow({ label, value, status = "info" }: { label: string; value: React.ReactNode; status?: "pass" | "warn" | "fail" | "info" }) {
  const icon = status === "pass" ? <CheckCircle className="h-3 w-3 text-emerald-400 flex-shrink-0 mt-0.5" />
    : status === "warn" ? <AlertTriangle className="h-3 w-3 text-amber-400 flex-shrink-0 mt-0.5" />
    : status === "fail" ? <XCircle className="h-3 w-3 text-red-400 flex-shrink-0 mt-0.5" />
    : <Info className="h-3 w-3 text-blue-400 flex-shrink-0 mt-0.5" />
  return (
    <div className="flex items-start gap-2 py-1">
      {icon}
      <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest w-32 flex-shrink-0">{label}</span>
      <span className="text-[9px] text-slate-300 leading-relaxed">{value}</span>
    </div>
  )
}

// ── Individual layer sections ─────────────────────────────────────────────────

function NLPSection({ breakdown }: { breakdown: AnalysisResult["model_breakdown"] }) {
  const [open, setOpen] = useState(true)
  const nlp = breakdown.nlp

  return (
    <div className="border-b border-white/5">
      <SectionHeader
        icon={<Brain className="h-3 w-3 text-purple-400" />}
        label="Layer 1 — NLP Intent Engine"
        score={nlp.score}
        weight={nlp.weight}
        open={open}
        onToggle={() => setOpen(o => !o)}
      />
      {open && (
        <div className="px-4 pb-4 space-y-1 ml-9">
          <CheckRow
            label="Purpose"
            value="Detects psychological manipulation tactics in text — urgency, fear, impersonation, credential requests"
            status="info"
          />
          <CheckRow
            label="Score"
            value={<ScoreBar score={nlp.score} />}
            status={nlp.score >= 0.65 ? "fail" : nlp.score >= 0.35 ? "warn" : "pass"}
          />
          {nlp.tactics?.length > 0 && (
            <CheckRow
              label="Tactics"
              value={
                <div className="flex flex-wrap gap-1">
                  {nlp.tactics.map((t, i) => (
                    <span key={i} className="px-1.5 py-0.5 bg-purple-500/10 border border-purple-500/20 rounded text-[8px] text-purple-300 font-mono">{t}</span>
                  ))}
                </div>
              }
              status={nlp.tactics.length > 0 ? "fail" : "pass"}
            />
          )}
          {nlp.top_phrases && nlp.top_phrases.length > 0 && (
            <CheckRow
              label="Key phrases"
              value={
                <div className="flex flex-col gap-0.5">
                  {nlp.top_phrases.slice(0, 5).map((p, i) => (
                    <span key={i} className="text-[9px] text-slate-400 font-mono">"{p}"</span>
                  ))}
                </div>
              }
              status="warn"
            />
          )}
          {nlp.explanation && (
            <CheckRow label="Reasoning" value={nlp.explanation} status="info" />
          )}
          <CheckRow
            label="Verdict basis"
            value={`NLP contributes ${Math.round((nlp.weight || 0) * 100)}% of the final threat score`}
            status="info"
          />
        </div>
      )}
    </div>
  )
}

function URLSection({ breakdown, urlsAnalyzed }: { breakdown: AnalysisResult["model_breakdown"]; urlsAnalyzed: string[] }) {
  const [open, setOpen] = useState(true)
  const url = breakdown.url

  const shapEntries = Object.entries(url.shap_values || {})
    .filter(([, v]) => Math.abs(v as number) > 0.01)
    .sort(([, a], [, b]) => Math.abs(b as number) - Math.abs(a as number))
    .slice(0, 6)

  return (
    <div className="border-b border-white/5">
      <SectionHeader
        icon={<Globe className="h-3 w-3 text-blue-400" />}
        label="Layer 2 — URL Intelligence"
        score={url.score}
        weight={url.weight}
        open={open}
        onToggle={() => setOpen(o => !o)}
      />
      {open && (
        <div className="px-4 pb-4 space-y-1 ml-9">
          <CheckRow
            label="Purpose"
            value="Extracts and scores all URLs using a gradient-boosted ML model trained on domain age, TLD, entropy, homoglyphs, and 40+ features"
            status="info"
          />
          <CheckRow
            label="URLs found"
            value={urlsAnalyzed?.length > 0
              ? <div className="flex flex-col gap-0.5">{urlsAnalyzed.slice(0, 5).map((u, i) => <span key={i} className="text-[9px] font-mono text-blue-300 break-all">{u}</span>)}</div>
              : "No URLs detected in input"
            }
            status={urlsAnalyzed?.length > 0 ? (url.score >= 0.65 ? "fail" : "warn") : "pass"}
          />
          {url.top_features?.length > 0 && (
            <CheckRow
              label="Risk features"
              value={
                <div className="flex flex-wrap gap-1">
                  {url.top_features.slice(0, 6).map((f, i) => (
                    <span key={i} className="px-1.5 py-0.5 bg-blue-500/10 border border-blue-500/20 rounded text-[8px] text-blue-300 font-mono">{f.replace(/_/g, " ")}</span>
                  ))}
                </div>
              }
              status="warn"
            />
          )}
          {shapEntries.length > 0 && (
            <CheckRow
              label="SHAP drivers"
              value={
                <div className="space-y-0.5">
                  {shapEntries.map(([feat, val], i) => (
                    <div key={i} className="flex items-center gap-2">
                      <span className="text-[8px] font-mono text-slate-400 w-36 truncate">{feat.replace(/_/g, " ")}</span>
                      <div className="flex-1 h-1 bg-white/5 rounded-full overflow-hidden">
                        <div className={cn("h-full rounded-full", (val as number) > 0 ? "bg-red-500" : "bg-emerald-500")}
                          style={{ width: `${Math.min(Math.abs(val as number) * 200, 100)}%` }} />
                      </div>
                      <span className={cn("text-[8px] font-mono", (val as number) > 0 ? "text-red-400" : "text-emerald-400")}>
                        {(val as number) > 0 ? "+" : ""}{((val as number) * 100).toFixed(0)}%
                      </span>
                    </div>
                  ))}
                </div>
              }
              status="info"
            />
          )}
        </div>
      )}
    </div>
  )
}

function VisualSection({ breakdown }: { breakdown: AnalysisResult["model_breakdown"] }) {
  const [open, setOpen] = useState(false)
  const vis = breakdown.visual

  return (
    <div className="border-b border-white/5">
      <SectionHeader
        icon={<Eye className="h-3 w-3 text-cyan-400" />}
        label="Layer 3 — Visual Sandbox"
        score={vis.score}
        weight={vis.weight}
        open={open}
        onToggle={() => setOpen(o => !o)}
      />
      {open && (
        <div className="px-4 pb-4 space-y-1 ml-9">
          <CheckRow
            label="Purpose"
            value="Takes a live screenshot of any URL and runs perceptual hashing + CNN brand classifier against 500+ brand logos"
            status="info"
          />
          <CheckRow
            label="Brand detected"
            value={vis.matched_brand && vis.matched_brand !== "Unknown"
              ? `${vis.matched_brand} (${Math.round((vis.similarity || 0) * 100)}% visual similarity)`
              : "No brand impersonation detected"}
            status={vis.matched_brand && vis.matched_brand !== "Unknown" ? "fail" : "pass"}
          />
          <CheckRow
            label="Similarity score"
            value={<ScoreBar score={vis.similarity || 0} />}
            status={vis.similarity >= 0.6 ? "fail" : "pass"}
          />
          {vis.screenshot_url && (
            <CheckRow
              label="Screenshot"
              value={
                <img
                  src={vis.screenshot_url}
                  alt="Page screenshot"
                  className="mt-1 rounded-lg border border-white/10 max-w-[260px] max-h-[140px] object-cover"
                />
              }
              status="info"
            />
          )}
          {!vis.screenshot_url && (
            <CheckRow label="Screenshot" value="Not captured (URL not present or sandbox timeout)" status="info" />
          )}
        </div>
      )}
    </div>
  )
}

function HeaderSection({ breakdown }: { breakdown: AnalysisResult["model_breakdown"] }) {
  const [open, setOpen] = useState(true)
  const hdr = breakdown.header

  const authStatus = (val: string): "pass" | "warn" | "fail" => {
    const v = (val || "").toUpperCase()
    if (v === "PASS" || v === "DMARC_PASS") return "pass"
    if (v === "SOFTFAIL") return "warn"
    return "fail"
  }

  return (
    <div className="border-b border-white/5">
      <SectionHeader
        icon={<FileText className="h-3 w-3 text-orange-400" />}
        label="Layer 4 — Header & Auth Analysis"
        score={hdr.score}
        weight={hdr.weight}
        open={open}
        onToggle={() => setOpen(o => !o)}
      />
      {open && (
        <div className="px-4 pb-4 space-y-1 ml-9">
          <CheckRow
            label="Purpose"
            value="Validates email sender authentication (SPF/DKIM/DMARC), checks for Reply-To mismatches, X-Originating-IP, and routing anomalies"
            status="info"
          />
          <CheckRow
            label="SPF"
            value={<span className={authColor(hdr.spf_result)}>{hdr.spf_result || "not checked"} — {hdr.spf_result === "pass" ? "sender IP is authorized" : "sender IP not authorized by domain"}</span>}
            status={authStatus(hdr.spf_result)}
          />
          <CheckRow
            label="DKIM"
            value={<span className={authColor(hdr.dkim_result)}>{hdr.dkim_result || "not checked"} — {hdr.dkim_result === "pass" ? "cryptographic signature valid" : "signature missing or invalid"}</span>}
            status={authStatus(hdr.dkim_result)}
          />
          <CheckRow
            label="DMARC"
            value={<span className={authColor(hdr.dmarc_result)}>{hdr.dmarc_result || "not checked"} — {hdr.dmarc_result?.toLowerCase().includes("pass") ? "policy aligned" : "policy alignment failed"}</span>}
            status={authStatus(hdr.dmarc_result)}
          />
          {hdr.flags?.length > 0 && (
            <CheckRow
              label="Anomaly flags"
              value={
                <div className="flex flex-col gap-0.5">
                  {hdr.flags.map((f, i) => (
                    <span key={i} className="text-[9px] font-mono text-orange-300">{f.replace(/_/g, " ")}</span>
                  ))}
                </div>
              }
              status="fail"
            />
          )}
        </div>
      )}
    </div>
  )
}

function IntelSection({ intel }: { intel: AnalysisResult["threat_intelligence"] }) {
  const [open, setOpen] = useState(false)
  const hasMatch = intel?.campaign_id && intel.campaign_id !== "Unknown"

  return (
    <div className="border-b border-white/5">
      <SectionHeader
        icon={<Shield className="h-3 w-3 text-red-400" />}
        label="Layer 5 — Threat Intelligence"
        open={open}
        onToggle={() => setOpen(o => !o)}
      />
      {open && (
        <div className="px-4 pb-4 space-y-1 ml-9">
          <CheckRow
            label="Purpose"
            value="Cross-references IOCs against the SentinelAI knowledge graph of 14+ active campaigns, 5 tracked APT groups, and OSINT feeds"
            status="info"
          />
          <CheckRow
            label="Campaign match"
            value={hasMatch ? intel.campaign_id : "No matching campaign in knowledge graph"}
            status={hasMatch ? "fail" : "pass"}
          />
          {intel?.threat_actor && intel.threat_actor !== "Unknown" && (
            <CheckRow
              label="Threat actor"
              value={`${intel.threat_actor} (${Math.round((intel.actor_confidence || 0) * 100)}% attribution confidence)`}
              status="fail"
            />
          )}
          {intel?.related_domains?.length > 0 && (
            <CheckRow
              label="Related domains"
              value={
                <div className="flex flex-col gap-0.5">
                  {intel.related_domains.slice(0, 4).map((d, i) => (
                    <span key={i} className="text-[9px] font-mono text-red-300">{d}</span>
                  ))}
                </div>
              }
              status="warn"
            />
          )}
          {(!hasMatch) && (
            <CheckRow label="Result" value="No known campaign or actor infrastructure matched — novel or untracked threat" status="info" />
          )}
        </div>
      )}
    </div>
  )
}

function AttachmentSection({ analysis }: { analysis: AttachmentAnalysis }) {
  const [open, setOpen] = useState(true)

  return (
    <div className="border-b border-white/5">
      <SectionHeader
        icon={<Paperclip className="h-3 w-3 text-slate-400" />}
        label={`Attachment Deep Scan — ${analysis.count} file${analysis.count !== 1 ? "s" : ""}`}
        open={open}
        onToggle={() => setOpen(o => !o)}
      />
      {open && (
        <div className="px-4 pb-4 space-y-3 ml-9">
          {analysis.content_scanned_count !== undefined && (
            <div className="flex items-center gap-2 text-[9px] text-slate-500">
              <Cpu className="h-3 w-3" />
              {analysis.content_scanned_count} of {analysis.count} file{analysis.count !== 1 ? "s" : ""} content-scanned (bytes downloaded + binary inspection)
              {" · "}{analysis.count - (analysis.content_scanned_count || 0)} metadata-only (images/unsupported)
            </div>
          )}
          {analysis.results.map((att, i) => {
            const riskScore = att.risk_score
            return (
              <div key={i} className={cn("p-3 rounded-xl border space-y-2",
                riskScore >= 0.85 ? "bg-red-500/5 border-red-500/15" :
                riskScore >= 0.65 ? "bg-orange-500/5 border-orange-500/15" :
                riskScore >= 0.35 ? "bg-amber-500/5 border-amber-500/15" : "bg-white/3 border-white/5"
              )}>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono font-bold text-slate-200 flex-1 truncate">{att.filename}</span>
                  <span className={cn("text-[8px] font-black uppercase shrink-0",
                    att.risk_level === "CRITICAL" ? "text-red-400" :
                    att.risk_level === "HIGH" ? "text-orange-400" :
                    att.risk_level === "MEDIUM" ? "text-amber-400" :
                    att.risk_level === "LOW" ? "text-yellow-400" : "text-emerald-400"
                  )}>{att.risk_level}</span>
                  <ScoreBar score={riskScore} />
                  {att.content_scanned
                    ? <span className="text-[7px] font-mono text-blue-400 uppercase border border-blue-500/20 px-1 py-0.5 rounded shrink-0">Content Scanned</span>
                    : <span className="text-[7px] font-mono text-slate-600 uppercase border border-white/10 px-1 py-0.5 rounded shrink-0">Metadata Only</span>
                  }
                </div>
                <div className="text-[8px] font-mono text-slate-600">{att.mime_type} · {att.extension.toUpperCase()} · {att.size_bytes > 0 ? `${(att.size_bytes / 1024).toFixed(1)} KB` : "size unknown"}</div>
                <div className="space-y-0.5">
                  {att.findings.map((f, j) => (
                    <div key={j} className="flex items-start gap-1.5">
                      {att.risk_level === "CLEAN" || att.risk_level === "LOW"
                        ? <CheckCircle className="h-2.5 w-2.5 text-emerald-500 flex-shrink-0 mt-0.5" />
                        : <XCircle className="h-2.5 w-2.5 text-red-400 flex-shrink-0 mt-0.5" />
                      }
                      <span className="text-[9px] text-slate-400 leading-relaxed">{f}</span>
                    </div>
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

function PIISection({ types }: { types: string[] }) {
  const [open, setOpen] = useState(false)
  const typeLabels: Record<string, string> = {
    EMAIL: "Email addresses → [EMAIL]",
    PHONE: "Phone numbers → [PHONE]",
    CARD: "Credit card numbers → [CARD]",
    SSN: "Social Security numbers → [SSN]",
    NAME: "Personal names in headers → [NAME]",
  }
  return (
    <div className="border-b border-white/5">
      <SectionHeader
        icon={<Lock className="h-3 w-3 text-emerald-400" />}
        label="Privacy — PII Redaction Before AI"
        open={open}
        onToggle={() => setOpen(o => !o)}
      />
      {open && (
        <div className="px-4 pb-4 space-y-1 ml-9">
          <CheckRow
            label="When"
            value="Applied before any email content is sent to the LLM API — original is stored locally in cache only"
            status="info"
          />
          <CheckRow
            label="What was found"
            value={types.length > 0
              ? <div className="flex flex-col gap-0.5">{types.map((t, i) => <span key={i} className="text-[9px] font-mono text-emerald-300">{typeLabels[t] || t}</span>)}</div>
              : "No PII patterns detected in this email"
            }
            status={types.length > 0 ? "warn" : "pass"}
          />
          <CheckRow
            label="What was sent"
            value="Redacted copy with placeholder tokens — the AI never sees real personal data"
            status="pass"
          />
          <CheckRow
            label="Analysis impact"
            value="Redaction preserves threat signals (domain names, suspicious patterns) while removing personal identifiers"
            status="info"
          />
        </div>
      )}
    </div>
  )
}

function VerdictSection({ result }: { result: AnalysisResult }) {
  const [open, setOpen] = useState(true)
  const bd = result.model_breakdown
  const layers = [
    { name: "NLP", score: bd.nlp.score, weight: bd.nlp.weight },
    { name: "URL", score: bd.url.score, weight: bd.url.weight },
    { name: "Visual", score: bd.visual.score, weight: bd.visual.weight },
    { name: "Header", score: bd.header.score, weight: bd.header.weight },
  ]
  const weighted = layers.reduce((sum, l) => sum + (l.score || 0) * (l.weight || 0), 0)

  const verdictThresholds = [
    { label: "CONFIRMED_THREAT / PHISHING", range: "≥ 0.75", color: "text-red-400" },
    { label: "SUSPICIOUS", range: "0.45 – 0.74", color: "text-amber-400" },
    { label: "CLEAN", range: "< 0.25", color: "text-emerald-400" },
  ]

  return (
    <div>
      <SectionHeader
        icon={<BarChart2 className="h-3 w-3 text-blue-400" />}
        label="Verdict Derivation"
        open={open}
        onToggle={() => setOpen(o => !o)}
      />
      {open && (
        <div className="px-4 pb-4 space-y-3 ml-9">
          {/* Weighted formula */}
          <div>
            <p className="text-[8px] text-slate-600 uppercase tracking-widest font-bold mb-2">Weighted Score Formula</p>
            <div className="flex flex-wrap gap-2">
              {layers.map((l, i) => (
                <div key={i} className="flex items-center gap-1.5 px-2 py-1.5 bg-white/3 border border-white/5 rounded-lg">
                  <span className="text-[8px] font-black uppercase text-slate-500">{l.name}</span>
                  <span className="text-[8px] font-mono text-slate-400">{Math.round(l.score * 100)}%</span>
                  <span className="text-[7px] text-slate-700">×</span>
                  <span className="text-[8px] font-mono text-slate-600">{Math.round((l.weight || 0) * 100)}%</span>
                  <span className="text-[7px] text-slate-700">=</span>
                  <span className={cn("text-[8px] font-black font-mono", scoreColor(l.score))}>
                    {((l.score * (l.weight || 0)) * 100).toFixed(1)}
                  </span>
                </div>
              ))}
              <div className="flex items-center gap-1.5 px-2 py-1.5 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                <span className="text-[8px] font-black uppercase text-blue-400">Total</span>
                <span className={cn("text-[9px] font-black font-mono", scoreColor(result.threat_score))}>
                  {Math.round(result.threat_score * 100)}%
                </span>
              </div>
            </div>
          </div>

          {/* Thresholds */}
          <div>
            <p className="text-[8px] text-slate-600 uppercase tracking-widest font-bold mb-2">Classification Thresholds</p>
            <div className="space-y-1">
              {verdictThresholds.map((t, i) => (
                <div key={i} className={cn("flex items-center gap-2 px-2 py-1.5 rounded-lg border",
                  result.verdict === t.label.split(" ")[0] ? "bg-white/5 border-white/10" : "border-transparent"
                )}>
                  {result.verdict.includes(t.label.split(" ")[0]) || result.verdict === t.label.split("/")[0].trim()
                    ? <Zap className="h-3 w-3 text-blue-400 flex-shrink-0" />
                    : <div className="h-3 w-3 flex-shrink-0" />
                  }
                  <span className={cn("text-[9px] font-black uppercase tracking-widest", t.color)}>{t.label.split(" /")[0]}</span>
                  <span className="text-[8px] font-mono text-slate-600 ml-auto">{t.range}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Confidence */}
          <CheckRow
            label="Confidence"
            value={`${Math.round(result.confidence * 100)}% — based on signal agreement across all detection layers`}
            status={result.confidence >= 0.7 ? "pass" : "warn"}
          />
          <CheckRow
            label="Inference time"
            value={`${result.inference_time_ms}ms total across all engines`}
            status="info"
          />
        </div>
      )}
    </div>
  )
}

// ── Main panel ────────────────────────────────────────────────────────────────

export function TransparencyPanel({
  result,
  inputType,
  inputLength,
  attachmentAnalysis,
  piiRedacted,
}: TransparencyPanelProps) {
  const [expanded, setExpanded] = useState(false)

  const isGmail = (piiRedacted !== undefined)
  const hasAttachments = attachmentAnalysis && attachmentAnalysis.count > 0

  return (
    <div className="rounded-2xl border border-white/8 bg-[#070D14]/60 overflow-hidden">
      {/* Toggle header */}
      <button
        onClick={() => setExpanded(e => !e)}
        className="w-full flex items-center gap-3 px-5 py-4 hover:bg-white/3 transition-colors"
      >
        <div className="h-7 w-7 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center flex-shrink-0">
          <Cpu className="h-3.5 w-3.5 text-blue-400" />
        </div>
        <div className="flex-1 text-left">
          <p className="text-[10px] font-black uppercase tracking-widest text-slate-300">
            Audit Trail — How this verdict was reached
          </p>
          <p className="text-[9px] text-slate-600 mt-0.5">
            5 detection layers · {isGmail ? "PII redacted" : "direct input"} · {inputType} · {inputLength.toLocaleString()} chars
            {hasAttachments ? ` · ${attachmentAnalysis.count} attachment${attachmentAnalysis.count !== 1 ? "s" : ""} scanned` : ""}
          </p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <Badge className="text-[7px] bg-white/5 border-white/10 text-slate-500 uppercase font-black">
            {expanded ? "Hide Details" : "Show Details"}
          </Badge>
          {expanded
            ? <ChevronDown className="h-4 w-4 text-slate-600" />
            : <ChevronRight className="h-4 w-4 text-slate-600" />
          }
        </div>
      </button>

      {/* Expanded content */}
      {expanded && (
        <div className="border-t border-white/5">
          {/* Input summary row */}
          <div className="px-5 py-3 bg-white/2 border-b border-white/5 flex flex-wrap gap-4 text-[9px] font-mono text-slate-500">
            <span><span className="text-slate-400 font-bold">Input type:</span> {inputType}</span>
            <span><span className="text-slate-400 font-bold">Length:</span> {inputLength.toLocaleString()} chars</span>
            <span><span className="text-slate-400 font-bold">Event ID:</span> {result.event_id}</span>
            <span><span className="text-slate-400 font-bold">Inference:</span> {result.inference_time_ms}ms</span>
            {isGmail && <span className="text-emerald-400"><span className="font-bold">PII redacted:</span> {piiRedacted!.length > 0 ? piiRedacted!.join(", ") : "none detected"}</span>}
          </div>

          <NLPSection breakdown={result.model_breakdown} />
          <URLSection breakdown={result.model_breakdown} urlsAnalyzed={result.urls_analyzed ?? []} />
          <VisualSection breakdown={result.model_breakdown} />
          <HeaderSection breakdown={result.model_breakdown} />
          <IntelSection intel={result.threat_intelligence} />
          {hasAttachments && <AttachmentSection analysis={attachmentAnalysis!} />}
          {isGmail && <PIISection types={piiRedacted!} />}
          <VerdictSection result={result} />
        </div>
      )}
    </div>
  )
}
