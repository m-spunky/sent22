"use client"

import React, { useState } from "react"
import {
  Globe, Search, Shield, ShieldAlert, Link2, Lock, LockOpen,
  AlertTriangle, CheckCircle, ChevronRight, Eye, Code2,
  ExternalLink, Loader2, ArrowRight
} from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"
import { motion, AnimatePresence } from "framer-motion"

interface SandboxResult {
  url: string
  hostname: string
  analyzed_at: string
  redirect_chain: string[]
  redirect_count: number
  ssl_info: { valid: boolean; issuer?: { organizationName?: string }; expires?: string; error?: string }
  page_info: {
    title?: string
    status_code?: number
    has_password_field?: boolean
    has_email_field?: boolean
    form_input_count?: number
    external_scripts?: string[]
    iframe_count?: number
    suspicious_keywords?: string[]
    credential_harvesting_detected?: boolean
    error?: string
  }
  screenshot_url?: string
  sandbox_risk_score: number
  sandbox_verdict: string
  sandbox_flags: string[]
}

export default function SandboxPage() {
  const [url, setUrl] = useState("")
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<SandboxResult | null>(null)
  const [error, setError] = useState("")

  const handleAnalyze = async () => {
    if (!url.trim()) return
    setLoading(true)
    setError("")
    setResult(null)
    try {
      const resp = await fetch("/api/v1/sandbox/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim(), depth: "standard" }),
      })
      if (!resp.ok) throw new Error(`Error ${resp.status}`)
      const data = await resp.json()
      setResult(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Sandbox analysis failed")
    }
    setLoading(false)
  }

  const riskColor = result
    ? result.sandbox_verdict === "PHISHING" ? "text-red-400"
      : result.sandbox_verdict === "SUSPICIOUS" ? "text-amber-400" : "text-emerald-400"
    : ""

  const riskBg = result
    ? result.sandbox_verdict === "PHISHING" ? "border-t-red-500"
      : result.sandbox_verdict === "SUSPICIOUS" ? "border-t-amber-500" : "border-t-emerald-500"
    : ""

  return (
    <div className="space-y-8 pb-10">
      <header className="flex items-center gap-4 border-b border-white/5 pb-6">
        <div className="h-10 w-10 rounded-xl bg-blue-500/20 border border-blue-500/30 flex items-center justify-center shadow-xl">
          <Globe className="h-5 w-5 text-blue-400" />
        </div>
        <div>
          <h1 className="text-3xl font-black tracking-tighter text-foreground uppercase">URL Sandbox</h1>
          <p className="text-[10px] text-muted-foreground uppercase font-black tracking-[0.3em]">
            Deep isolation analysis — redirect chain, DOM, SSL, credential detection
          </p>
        </div>
      </header>

      {/* Input */}
      <Card className="card-cyber p-6">
        <div className="flex gap-4">
          <div className="relative flex-1">
            <Globe className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-600" />
            <Input
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleAnalyze()}
              placeholder="Enter URL to sandbox (e.g. http://suspicious-site.xyz/login)"
              className="pl-11 bg-[#0D1B2A] border-white/10 focus:border-blue-500/40 rounded-xl h-12 text-sm font-mono"
            />
          </div>
          <Button
            onClick={handleAnalyze}
            disabled={loading || !url.trim()}
            className="bg-blue-600 hover:bg-blue-500 text-white px-8 h-12 rounded-xl font-black uppercase tracking-widest text-xs shadow-[0_0_20px_rgba(59,130,246,0.3)] transition-all hover:scale-105 disabled:opacity-40"
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <><Search className="h-4 w-4 mr-2" />Analyze</>}
          </Button>
        </div>
        {error && <p className="mt-3 text-sm text-red-400 font-mono">{error}</p>}
      </Card>

      {loading && (
        <div className="grid grid-cols-3 gap-4">
          {["Unwinding redirect chain...", "Validating SSL certificate...", "Scanning DOM for credential forms..."].map((msg, i) => (
            <Card key={i} className="card-cyber p-5 flex items-center gap-3">
              <Loader2 className="h-4 w-4 text-blue-400 animate-spin flex-shrink-0" />
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{msg}</span>
            </Card>
          ))}
        </div>
      )}

      <AnimatePresence>
        {result && (
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
            {/* Verdict Banner */}
            <Card className={cn("card-cyber border-t-2 p-6 overflow-hidden relative", riskBg)}>
              <div className="absolute top-0 right-0 p-8 opacity-5">
                {result.sandbox_verdict === "PHISHING" ? <ShieldAlert className="h-32 w-32 text-red-400" /> : <Shield className="h-32 w-32 text-blue-400" />}
              </div>
              <div className="flex items-center justify-between relative z-10">
                <div className="space-y-2">
                  <div className="flex items-center gap-3">
                    <span className={cn("text-4xl font-black tracking-tighter", riskColor)}>{Math.round(result.sandbox_risk_score * 100)}%</span>
                    <span className={cn("text-xl font-black uppercase tracking-tight", riskColor)}>{result.sandbox_verdict}</span>
                  </div>
                  <p className="text-[10px] text-slate-500 font-mono truncate max-w-xl">{result.url}</p>
                </div>
                <div className="flex flex-col items-end gap-2">
                  <Badge className="text-[9px] uppercase font-black tracking-widest bg-white/5 border-white/10">
                    {result.redirect_count} Redirects
                  </Badge>
                  <Badge className={cn("text-[9px] uppercase font-black tracking-widest", result.ssl_info?.valid ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-red-500/10 text-red-400 border-red-500/20")}>
                    {result.ssl_info?.valid ? "SSL Valid" : "SSL Invalid"}
                  </Badge>
                </div>
              </div>
              {result.sandbox_flags.length > 0 && (
                <div className="mt-4 flex flex-wrap gap-2">
                  {result.sandbox_flags.map((flag, i) => (
                    <div key={i} className="flex items-center gap-1.5 px-3 py-1 bg-red-500/10 border border-red-500/15 rounded-lg">
                      <AlertTriangle className="h-3 w-3 text-red-400 flex-shrink-0" />
                      <span className="text-[10px] text-red-300 font-medium">{flag}</span>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            <div className="grid grid-cols-12 gap-6">
              {/* Left Column */}
              <div className="col-span-12 lg:col-span-7 space-y-6">
                {/* Redirect Chain */}
                <Card className="card-cyber p-6 space-y-4">
                  <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
                    <Link2 className="h-3.5 w-3.5 text-blue-400" />
                    Redirect Chain ({result.redirect_count} hops)
                  </CardTitle>
                  <div className="space-y-2">
                    {result.redirect_chain.map((hop, i) => (
                      <div key={i} className="flex items-start gap-3">
                        <div className="flex flex-col items-center">
                          <div className={cn("h-6 w-6 rounded-full flex items-center justify-center text-[9px] font-black border flex-shrink-0",
                            i === 0 ? "bg-blue-500/20 border-blue-500/30 text-blue-400"
                              : i === result.redirect_chain.length - 1 ? "bg-red-500/20 border-red-500/30 text-red-400"
                              : "bg-white/5 border-white/10 text-slate-500"
                          )}>
                            {i + 1}
                          </div>
                          {i < result.redirect_chain.length - 1 && <div className="w-px h-4 bg-white/10 my-1" />}
                        </div>
                        <div className="flex-1 min-w-0 pb-2">
                          <p className={cn("text-[11px] font-mono break-all",
                            i === 0 ? "text-slate-300" : i === result.redirect_chain.length - 1 ? "text-red-300" : "text-slate-500"
                          )}>{hop}</p>
                          {i === result.redirect_chain.length - 1 && result.redirect_count > 0 && (
                            <Badge className="mt-1 bg-red-500/10 text-red-400 border-red-500/20 text-[7px] uppercase font-bold">Final Destination</Badge>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>

                {/* DOM Analysis */}
                <Card className="card-cyber p-6 space-y-4">
                  <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
                    <Code2 className="h-3.5 w-3.5 text-blue-400" />
                    DOM Analysis
                  </CardTitle>
                  {result.page_info.error ? (
                    <p className="text-sm text-slate-500 italic">Could not access page: {result.page_info.error}</p>
                  ) : (
                    <div className="space-y-3">
                      <p className="text-sm font-bold text-slate-300 bg-white/3 border border-white/5 rounded-lg px-3 py-2">
                        "{result.page_info.title || "No title"}"
                      </p>
                      <div className="grid grid-cols-2 gap-3">
                        {[
                          { label: "Password Field", val: result.page_info.has_password_field, risky: true },
                          { label: "Email/Login Field", val: result.page_info.has_email_field, risky: true },
                          { label: "Credential Harvesting", val: result.page_info.credential_harvesting_detected, risky: true },
                          { label: "Iframes Detected", val: (result.page_info.iframe_count ?? 0) > 0, risky: false },
                        ].map((item, i) => (
                          <div key={i} className={cn("flex items-center justify-between p-2.5 rounded-lg border", item.val && item.risky ? "bg-red-500/8 border-red-500/15" : "bg-white/3 border-white/5")}>
                            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{item.label}</span>
                            {item.val
                              ? <ShieldAlert className="h-3.5 w-3.5 text-red-400" />
                              : <CheckCircle className="h-3.5 w-3.5 text-emerald-400/40" />
                            }
                          </div>
                        ))}
                      </div>
                      {result.page_info.suspicious_keywords && result.page_info.suspicious_keywords.length > 0 && (
                        <div className="space-y-1.5">
                          <p className="text-[9px] font-bold uppercase tracking-widest text-slate-600">Suspicious Keywords Found</p>
                          <div className="flex flex-wrap gap-1.5">
                            {result.page_info.suspicious_keywords.map((kw, i) => (
                              <Badge key={i} className="bg-amber-500/10 text-amber-400 border-amber-500/20 text-[8px] uppercase font-bold">{kw}</Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </Card>
              </div>

              {/* Right Column */}
              <div className="col-span-12 lg:col-span-5 space-y-6">
                {/* SSL Certificate */}
                <Card className={cn("card-cyber p-6 space-y-4 border-t-2", result.ssl_info?.valid ? "border-t-emerald-500/50" : "border-t-red-500/50")}>
                  <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
                    {result.ssl_info?.valid ? <Lock className="h-3.5 w-3.5 text-emerald-400" /> : <LockOpen className="h-3.5 w-3.5 text-red-400" />}
                    SSL Certificate
                  </CardTitle>
                  {result.ssl_info?.valid ? (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 p-3 bg-emerald-500/5 border border-emerald-500/10 rounded-xl">
                        <CheckCircle className="h-4 w-4 text-emerald-400 flex-shrink-0" />
                        <span className="text-xs text-emerald-400 font-bold">Certificate Valid</span>
                      </div>
                      {result.ssl_info.issuer?.organizationName && (
                        <div className="text-[10px] text-slate-400 font-mono px-1">Issuer: {result.ssl_info.issuer.organizationName}</div>
                      )}
                      {result.ssl_info.expires && (
                        <div className="text-[10px] text-slate-400 font-mono px-1">Expires: {result.ssl_info.expires}</div>
                      )}
                    </div>
                  ) : (
                    <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/20 rounded-xl">
                      <ShieldAlert className="h-4 w-4 text-red-400 flex-shrink-0 mt-0.5" />
                      <div className="text-xs text-red-300 font-medium">{result.ssl_info?.error || "Certificate validation failed"}</div>
                    </div>
                  )}
                </Card>

                {/* Screenshot */}
                <Card className="card-cyber overflow-hidden">
                  <CardHeader className="p-4 border-b border-white/5">
                    <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
                      <Eye className="h-3.5 w-3.5 text-blue-400" />
                      Sandbox Screenshot
                    </CardTitle>
                  </CardHeader>
                  <div className="relative bg-[#070D14] aspect-video flex items-center justify-center">
                    {result.screenshot_url ? (
                      <img src={result.screenshot_url} alt="Sandbox screenshot" className="w-full h-full object-cover object-top" />
                    ) : (
                      <div className="flex flex-col items-center gap-3 opacity-30 p-8">
                        <Eye className="h-12 w-12 text-slate-600" />
                        <p className="text-[9px] font-black uppercase tracking-widest text-slate-600 text-center">Screenshot available with deep mode<br />or when Apify is configured</p>
                      </div>
                    )}
                    {result.page_info.credential_harvesting_detected && (
                      <div className="absolute inset-0 border-4 border-red-500/40 pointer-events-none">
                        <div className="absolute top-2 left-2 bg-red-500/80 text-white text-[8px] font-black uppercase tracking-widest px-2 py-1 rounded">Credential Harvesting Detected</div>
                      </div>
                    )}
                  </div>
                </Card>

                {/* Actions */}
                <Card className="card-cyber p-5 space-y-3">
                  <p className="text-[9px] font-black uppercase tracking-widest text-slate-500">Response Actions</p>
                  <div className="grid grid-cols-2 gap-2">
                    {[
                      { label: "Full Analysis", icon: Search, cls: "bg-blue-500/10 text-blue-400 hover:border-blue-500/30 hover:bg-blue-500/15" },
                      { label: "Block Domain", icon: ShieldAlert, cls: "bg-red-500/10 text-red-400 hover:border-red-500/30 hover:bg-red-500/15" },
                      { label: "Open Safely", icon: ExternalLink, cls: "bg-slate-500/10 text-slate-400 hover:border-slate-500/30" },
                      { label: "Copy Report", icon: Code2, cls: "bg-amber-500/10 text-amber-400 hover:border-amber-500/30" },
                    ].map((btn, i) => (
                      <button key={i} className={cn("flex flex-col items-center gap-1.5 h-14 rounded-xl border border-white/5 transition-all hover:scale-105 p-3", btn.cls)}>
                        <btn.icon className="h-4 w-4" />
                        <span className="text-[8px] font-black uppercase tracking-widest">{btn.label}</span>
                      </button>
                    ))}
                  </div>
                </Card>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
