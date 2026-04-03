"use client"

import React, { useState } from "react"
import {
  AlignLeft, Globe, Image as ImageIcon, Mail, ExternalLink,
  CheckCircle, XCircle, AlertTriangle, Shield, Clock, Hash,
  TrendingUp, Eye, Fingerprint
} from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import type { ModelBreakdown } from "@/lib/api"
import { ShapChart } from "@/components/analyze/ShapChart"

type Tab = "nlp" | "url" | "visual" | "header"

interface EvidencePanelProps {
  model_breakdown: ModelBreakdown
  urls_analyzed: string[]
  verdict: string
}

function AuthBadge({ label, result }: { label: string; result: string }) {
  const pass = result === "pass" || result === "PASS"
  const fail = result === "fail" || result === "FAIL" || result === "none" || result === "NONE"
  return (
    <div className={cn(
      "flex items-center gap-2 px-3 py-2 rounded-xl border text-[10px] font-black uppercase tracking-widest",
      pass ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
      : fail ? "bg-red-500/10 border-red-500/20 text-red-400"
      : "bg-amber-500/10 border-amber-500/20 text-amber-400"
    )}>
      {pass ? <CheckCircle className="h-3.5 w-3.5" /> : fail ? <XCircle className="h-3.5 w-3.5" /> : <AlertTriangle className="h-3.5 w-3.5" />}
      <span>{label}</span>
      <span className="ml-auto font-mono opacity-70">{result || "unknown"}</span>
    </div>
  )
}

function ShapBar({ feature, value, max }: { feature: string; value: number; max: number }) {
  const pct = Math.abs(value) / (max || 1) * 100
  const isRisk = value > 0
  const label = feature.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())
  return (
    <div className="flex items-center gap-3">
      <span className="text-[9px] font-mono text-slate-500 w-40 truncate shrink-0">{label}</span>
      <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
        <div
          className={cn("h-full rounded-full transition-all duration-700", isRisk ? "bg-red-500" : "bg-emerald-500")}
          style={{ width: `${Math.min(pct, 100)}%` }}
        />
      </div>
      <span className={cn("text-[9px] font-mono font-black w-10 text-right shrink-0", isRisk ? "text-red-400" : "text-emerald-400")}>
        {isRisk ? "+" : ""}{value.toFixed(2)}
      </span>
    </div>
  )
}

export function EvidencePanel({ model_breakdown, urls_analyzed, verdict }: EvidencePanelProps) {
  const [tab, setTab] = useState<Tab>("nlp")
  const { nlp, url, visual, header } = model_breakdown

  const tabs: { id: Tab; label: string; icon: React.ReactNode; score: number }[] = [
    { id: "nlp",    label: "NLP",     icon: <AlignLeft className="h-3 w-3" />,   score: nlp.score },
    { id: "url",    label: "URL",     icon: <Globe className="h-3 w-3" />,        score: url.score },
    { id: "visual", label: "Visual",  icon: <ImageIcon className="h-3 w-3" />,    score: visual.score },
    { id: "header", label: "Headers", icon: <Mail className="h-3 w-3" />,         score: header.score },
  ]

  const shapEntries = Object.entries(url.shap_values || {}).sort((a, b) => Math.abs(b[1]) - Math.abs(a[1])).slice(0, 8)
  const maxShap = shapEntries.length > 0 ? Math.max(...shapEntries.map(([, v]) => Math.abs(v))) : 1

  return (
    <Card className="card-cyber overflow-hidden">
      <CardHeader className="p-5 border-b border-white/5">
        <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
          <Fingerprint className="h-3.5 w-3.5 text-blue-400" />
          Evidence Breakdown
          <span className="ml-auto text-[8px] text-slate-600 font-mono uppercase tracking-widest">Per-analysis forensics</span>
        </CardTitle>
      </CardHeader>

      {/* Layer tabs */}
      <div className="flex border-b border-white/5">
        {tabs.map(t => {
          const pct = Math.round(t.score * 100)
          const isHigh = t.score >= 0.65
          const isMed = t.score >= 0.35
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={cn(
                "flex-1 flex flex-col items-center gap-1 py-3 text-[8px] font-black uppercase tracking-widest transition-all",
                tab === t.id
                  ? "bg-blue-500/8 text-blue-400 border-b-2 border-blue-500"
                  : "text-slate-600 hover:text-slate-400 hover:bg-white/3"
              )}
            >
              <div className="flex items-center gap-1">{t.icon}{t.label}</div>
              <span className={cn("font-mono text-[9px] font-black",
                isHigh ? "text-red-400" : isMed ? "text-amber-400" : "text-emerald-400"
              )}>{pct}%</span>
            </button>
          )
        })}
      </div>

      <CardContent className="p-5 space-y-4 min-h-[280px]">

        {/* ── NLP TAB ───────────────────────────────────────────────────────── */}
        {tab === "nlp" && (
          <div className="space-y-4">
            {/* Intent classification */}
            {nlp.phishing_intent && (
              <div className="flex items-start gap-3 p-3 bg-white/3 border border-white/5 rounded-xl">
                <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <p className="text-[9px] font-black uppercase tracking-widest text-slate-500 mb-1">Detected Intent</p>
                  <p className="text-xs font-mono text-amber-300">{nlp.phishing_intent}</p>
                </div>
              </div>
            )}

            {/* Specific phrases found IN THIS EMAIL */}
            {nlp.top_phrases && nlp.top_phrases.length > 0 && (
              <div className="space-y-2">
                <p className="text-[9px] font-black uppercase tracking-widest text-slate-500">Flagged Phrases in This Email</p>
                <div className="flex flex-wrap gap-2">
                  {nlp.top_phrases.map((phrase, i) => (
                    <span key={i} className="px-2.5 py-1 bg-red-500/10 border border-red-500/20 rounded-lg text-[10px] font-mono text-red-300">
                      &ldquo;{phrase}&rdquo;
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* MITRE tactics triggered */}
            {nlp.tactics && nlp.tactics.length > 0 && (
              <div className="space-y-2">
                <p className="text-[9px] font-black uppercase tracking-widest text-slate-500">MITRE Tactics Matched</p>
                <div className="flex flex-wrap gap-2">
                  {nlp.tactics.map((t, i) => (
                    <Badge key={i} className="bg-blue-500/10 text-blue-400 border-blue-500/20 text-[8px] font-black uppercase">
                      {t}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {/* NLP explanation */}
            {nlp.explanation && (
              <div className="p-3 bg-[#0D1B2A] border border-white/5 rounded-xl">
                <p className="text-[9px] font-black uppercase tracking-widest text-slate-500 mb-2">Model Reasoning</p>
                <p className="text-xs text-slate-400 leading-relaxed font-mono">{nlp.explanation}</p>
              </div>
            )}

            {(!nlp.top_phrases?.length && !nlp.phishing_intent && !nlp.explanation) && (
              <p className="text-[10px] text-slate-600 italic">NLP layer returned no specific phrase data for this input.</p>
            )}
          </div>
        )}

        {/* ── URL TAB ───────────────────────────────────────────────────────── */}
        {tab === "url" && (
          <div className="space-y-4">
            {/* Analyzed URL */}
            {urls_analyzed.length > 0 && (
              <div className="p-3 bg-[#0D1B2A] border border-white/5 rounded-xl space-y-2">
                <p className="text-[9px] font-black uppercase tracking-widest text-slate-500">URL Analyzed</p>
                {urls_analyzed.map((u, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <Globe className="h-3 w-3 text-slate-600 shrink-0" />
                    <span className="text-[10px] font-mono text-slate-400 truncate flex-1">{u}</span>
                    <a href={u} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}>
                      <ExternalLink className="h-3 w-3 text-slate-600 hover:text-blue-400 transition-colors shrink-0" />
                    </a>
                  </div>
                ))}
              </div>
            )}

            {/* Domain metadata */}
            {url.features && (
              <div className="grid grid-cols-2 gap-2">
                {url.features.domain_age_days != null && (
                  <div className="p-2.5 bg-white/3 border border-white/5 rounded-xl flex items-center gap-2">
                    <Clock className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                    <div>
                      <p className="text-[8px] text-slate-500 uppercase font-bold tracking-widest">Domain Age</p>
                      <p className={cn("text-xs font-black font-mono",
                        (url.features.domain_age_days as number) < 30 ? "text-red-400"
                        : (url.features.domain_age_days as number) < 180 ? "text-amber-400"
                        : "text-emerald-400"
                      )}>
                        {url.features.domain_age_days === -1 ? "Unknown" : `${url.features.domain_age_days} days`}
                      </p>
                    </div>
                  </div>
                )}
                {url.features.urlhaus_hit != null && (
                  <div className={cn("p-2.5 rounded-xl border flex items-center gap-2",
                    url.features.urlhaus_hit ? "bg-red-500/10 border-red-500/20" : "bg-emerald-500/10 border-emerald-500/20"
                  )}>
                    <Shield className={cn("h-3.5 w-3.5 shrink-0", url.features.urlhaus_hit ? "text-red-400" : "text-emerald-400")} />
                    <div>
                      <p className="text-[8px] text-slate-500 uppercase font-bold tracking-widest">URLhaus</p>
                      <p className={cn("text-xs font-black", url.features.urlhaus_hit ? "text-red-400" : "text-emerald-400")}>
                        {url.features.urlhaus_hit ? "BLACKLISTED" : "Clean"}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Top risk features */}
            {url.top_features && url.top_features.length > 0 && (
              <div className="space-y-2">
                <p className="text-[9px] font-black uppercase tracking-widest text-slate-500">Risk Signals Detected</p>
                <div className="flex flex-wrap gap-2">
                  {url.top_features.map((f, i) => (
                    <span key={i} className="px-2.5 py-1 bg-red-500/10 border border-red-500/15 rounded-lg text-[9px] font-mono text-red-300">
                      {f.replace(/_/g, " ")}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* SHAP values — Interactive Chart */}
            {shapEntries.length > 0 && (
              <div className="space-y-2">
                <ShapChart shapValues={url.shap_values} title="Feature Attribution (SHAP)" />
              </div>
            )}
          </div>
        )}

        {/* ── VISUAL TAB ────────────────────────────────────────────────────── */}
        {tab === "visual" && (
          <div className="space-y-4">
            {/* Brand match */}
            <div className={cn("flex items-center gap-4 p-3 rounded-xl border",
              visual.score >= 0.65 ? "bg-red-500/8 border-red-500/15"
              : visual.score >= 0.35 ? "bg-amber-500/8 border-amber-500/15"
              : "bg-emerald-500/8 border-emerald-500/15"
            )}>
              <ImageIcon className={cn("h-8 w-8 shrink-0",
                visual.score >= 0.65 ? "text-red-400" : visual.score >= 0.35 ? "text-amber-400" : "text-emerald-400"
              )} />
              <div className="flex-1">
                <p className="text-[9px] font-black uppercase tracking-widest text-slate-500 mb-1">Brand Impersonation Check</p>
                <p className="text-sm font-black text-foreground">{visual.matched_brand}</p>
                <div className="flex items-center gap-2 mt-1">
                  <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
                    <div
                      className={cn("h-full rounded-full", visual.similarity >= 0.65 ? "bg-red-500" : visual.similarity >= 0.35 ? "bg-amber-500" : "bg-emerald-500")}
                      style={{ width: `${visual.similarity * 100}%` }}
                    />
                  </div>
                  <span className={cn("text-[10px] font-black font-mono",
                    visual.similarity >= 0.65 ? "text-red-400" : visual.similarity >= 0.35 ? "text-amber-400" : "text-emerald-400"
                  )}>{Math.round(visual.similarity * 100)}% match</span>
                </div>
              </div>
            </div>

            {/* Apify screenshot */}
            {(() => {
              // Support both new screenshot_path (static file) and legacy screenshot_url (base64)
              const BACKEND = (typeof window !== "undefined" && process.env.NEXT_PUBLIC_API_URL) || "http://localhost:8001"
              const imgSrc = visual.screenshot_path
                ? `${BACKEND}${visual.screenshot_path}`
                : visual.screenshot_url || null
              return imgSrc ? (
                <div className="space-y-2">
                  <p className="text-[9px] font-black uppercase tracking-widest text-slate-500 flex items-center gap-2">
                    <Eye className="h-3 w-3 text-blue-400" />
                    Live Screenshot — Apify Sandbox
                  </p>
                  <div className="relative rounded-xl overflow-hidden border border-white/10 group cursor-pointer">
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                      src={imgSrc}
                      alt="Phishing page screenshot"
                      className="w-full object-cover max-h-64 group-hover:scale-[1.02] transition-transform duration-300"
                      onError={e => { (e.target as HTMLImageElement).style.display = "none" }}
                    />
                    {visual.score >= 0.65 && (
                      <div className="absolute inset-0 bg-red-500/10 border-2 border-red-500/40 rounded-xl flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">
                        <Badge className="bg-red-500/90 text-white border-0 font-black uppercase text-[10px]">
                          ⚠ Credential Harvesting Page
                        </Badge>
                      </div>
                    )}
                    <a
                      href={imgSrc}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="absolute top-2 right-2 p-1.5 bg-black/50 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity"
                      onClick={e => e.stopPropagation()}
                    >
                      <ExternalLink className="h-3.5 w-3.5 text-white" />
                    </a>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-8 space-y-2 border border-white/5 rounded-xl bg-white/2">
                  <ImageIcon className="h-8 w-8 text-slate-700" />
                  <p className="text-[10px] text-slate-600 uppercase font-bold tracking-widest">
                    {visual.score < 0.1 ? "Screenshot not captured (Visual Sandbox is OFF)" : "Screenshot unavailable — enable Visual Sandbox toggle"}
                  </p>
                </div>
              )
            })()}
          </div>
        )}

        {/* ── HEADER TAB ────────────────────────────────────────────────────── */}
        {tab === "header" && (
          <div className="space-y-4">
            {/* Authentication results */}
            <div className="space-y-2">
              <p className="text-[9px] font-black uppercase tracking-widest text-slate-500">Email Authentication Results</p>
              <AuthBadge label="SPF"  result={header.spf_result} />
              <AuthBadge label="DKIM" result={header.dkim_result} />
              <AuthBadge label="DMARC" result={header.dmarc_result} />
            </div>

            {/* Flags specific to this email */}
            {header.flags && header.flags.length > 0 && (
              <div className="space-y-2">
                <p className="text-[9px] font-black uppercase tracking-widest text-slate-500">Header Anomalies Detected</p>
                <div className="space-y-1.5">
                  {header.flags.map((flag, i) => (
                    <div key={i} className="flex items-start gap-2.5 p-2.5 bg-red-500/5 border border-red-500/10 rounded-lg">
                      <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0 mt-0.5" />
                      <span className="text-[10px] font-mono text-red-300">{flag}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* What these mean */}
            <div className="p-3 bg-[#0D1B2A] border border-white/5 rounded-xl space-y-2">
              <p className="text-[9px] font-black uppercase tracking-widest text-slate-500">What This Means</p>
              <div className="space-y-1.5 text-[10px] text-slate-500 font-mono leading-relaxed">
                <p><span className="text-slate-400 font-bold">SPF</span> — Verifies if the sending server is authorized by the domain</p>
                <p><span className="text-slate-400 font-bold">DKIM</span> — Cryptographic signature proving email wasn&apos;t tampered with</p>
                <p><span className="text-slate-400 font-bold">DMARC</span> — Policy that ties SPF and DKIM together; defines what to do on failure</p>
              </div>
            </div>

            {header.score < 0.05 && header.flags.length === 0 && (
              <div className="flex items-center gap-2 text-emerald-400 text-[10px] font-bold uppercase tracking-widest">
                <CheckCircle className="h-4 w-4" />
                No header anomalies — email authentication passed
              </div>
            )}
          </div>
        )}

      </CardContent>
    </Card>
  )
}
