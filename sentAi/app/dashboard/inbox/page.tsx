"use client"

import React, { useState, useEffect, useCallback } from "react"
import {
  Inbox, ShieldCheck, ShieldAlert, AlertTriangle, Mail, Paperclip,
  Clock, RefreshCw, Filter, ChevronRight, Zap, X, CheckCircle,
  WifiOff, ExternalLink
} from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { motion, AnimatePresence } from "framer-motion"

const API = "/api/v1/gmail"

interface EmailItem {
  id: string
  from: string
  from_name: string
  subject: string
  snippet: string
  date: string
  is_read: boolean
  has_attachments: boolean
  risk_score: number
  verdict: string
  risk_flags: string[]
}

interface InboxData {
  total: number
  phishing_count: number
  suspicious_count: number
  clean_count: number
  items: EmailItem[]
}

function RiskBadge({ verdict, score }: { verdict: string; score: number }) {
  const pct = Math.round(score * 100)
  if (verdict === "CONFIRMED_THREAT" || verdict === "PHISHING")
    return <div className="flex items-center gap-1.5 px-2 py-1 bg-red-500/10 border border-red-500/20 rounded-lg"><ShieldAlert className="h-3 w-3 text-red-400" /><span className="text-[9px] font-black text-red-400 uppercase tracking-widest">{pct}%</span></div>
  if (verdict === "SUSPICIOUS")
    return <div className="flex items-center gap-1.5 px-2 py-1 bg-amber-500/10 border border-amber-500/20 rounded-lg"><AlertTriangle className="h-3 w-3 text-amber-400" /><span className="text-[9px] font-black text-amber-400 uppercase tracking-widest">{pct}%</span></div>
  return <div className="flex items-center gap-1.5 px-2 py-1 bg-emerald-500/10 border border-emerald-500/20 rounded-lg"><ShieldCheck className="h-3 w-3 text-emerald-400" /><span className="text-[9px] font-black text-emerald-400 uppercase tracking-widest">Safe</span></div>
}

function EmailRow({ email, selected, onClick }: { email: EmailItem; selected: boolean; onClick: () => void }) {
  const isRisky = email.verdict !== "CLEAN"
  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      onClick={onClick}
      className={cn(
        "flex items-center gap-4 px-5 py-4 border-b border-white/5 cursor-pointer transition-all hover:bg-white/3 relative group",
        selected && "bg-blue-500/5 border-l-2 border-l-blue-500",
        isRisky && !selected && "border-l-2 border-l-red-500/30"
      )}
    >
      <div className={cn("h-2 w-2 rounded-full flex-shrink-0", !email.is_read ? "bg-blue-400" : "bg-transparent")} />
      <div className="flex-1 min-w-0 space-y-1">
        <div className="flex items-center gap-2">
          <span className={cn("text-xs font-bold truncate", !email.is_read ? "text-slate-200" : "text-slate-400")}>{email.from_name}</span>
          {email.has_attachments && <Paperclip className="h-3 w-3 text-slate-600 flex-shrink-0" />}
        </div>
        <p className={cn("text-[11px] font-medium truncate", !email.is_read ? "text-slate-300" : "text-slate-500")}>{email.subject}</p>
        <p className="text-[10px] text-slate-600 truncate">{email.snippet}</p>
      </div>
      <div className="flex flex-col items-end gap-2 flex-shrink-0">
        <RiskBadge verdict={email.verdict} score={email.risk_score} />
        <div className="flex items-center gap-1 text-[8px] text-slate-600 font-mono">
          <Clock className="h-2.5 w-2.5" />
          {new Date(email.date).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
        </div>
      </div>
      <ChevronRight className="h-3.5 w-3.5 text-slate-700 opacity-0 group-hover:opacity-100 transition-opacity" />
    </motion.div>
  )
}

function EmailDetailPanel({ email, onClose, onAnalyze }: { email: EmailItem | null; onClose: () => void; onAnalyze: (id: string) => void }) {
  if (!email) return null
  const isRisky = email.verdict !== "CLEAN"
  const borderColor = email.verdict === "CONFIRMED_THREAT" || email.verdict === "PHISHING" ? "border-t-red-500"
    : email.verdict === "SUSPICIOUS" ? "border-t-amber-500" : "border-t-emerald-500"

  return (
    <motion.div
      initial={{ opacity: 0, x: 40 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 40 }}
      className={cn("h-full flex flex-col border-t-2 card-cyber rounded-none rounded-r-3xl overflow-hidden", borderColor)}
    >
      <div className="flex items-center justify-between p-5 border-b border-white/5">
        <div className="space-y-0.5">
          <h3 className="text-sm font-black text-foreground uppercase tracking-tight line-clamp-1">{email.subject}</h3>
          <p className="text-[10px] text-slate-500 font-mono">{email.from_name} &lt;{email.from}&gt;</p>
        </div>
        <button onClick={onClose} className="h-7 w-7 rounded-lg bg-white/5 hover:bg-white/10 flex items-center justify-center text-slate-500 hover:text-slate-300 transition-colors">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {/* Risk Score */}
        <div className={cn(
          "p-4 rounded-2xl border",
          email.verdict === "CONFIRMED_THREAT" ? "bg-red-500/10 border-red-500/20"
            : email.verdict === "PHISHING" ? "bg-red-500/8 border-red-500/15"
            : email.verdict === "SUSPICIOUS" ? "bg-amber-500/8 border-amber-500/15"
            : "bg-emerald-500/8 border-emerald-500/15"
        )}>
          <div className="flex items-center justify-between mb-3">
            <span className="text-[9px] font-black uppercase tracking-widest text-slate-500">AI Verdict</span>
            <span className={cn(
              "text-xs font-black uppercase tracking-widest",
              isRisky ? (email.verdict === "SUSPICIOUS" ? "text-amber-400" : "text-red-400") : "text-emerald-400"
            )}>{email.verdict.replace("_", " ")}</span>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-4xl font-black tracking-tighter text-foreground">{Math.round(email.risk_score * 100)}<span className="text-xl text-slate-500">%</span></div>
            <div className="flex-1 space-y-1">
              <div className="h-2 bg-white/5 rounded-full overflow-hidden">
                <div className={cn("h-full rounded-full transition-all", isRisky ? "bg-red-500" : "bg-emerald-500")} style={{ width: `${email.risk_score * 100}%` }} />
              </div>
              <p className="text-[8px] text-slate-500 uppercase font-bold tracking-widest">Phishing Probability</p>
            </div>
          </div>
        </div>

        {/* Risk Flags */}
        {email.risk_flags.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-[9px] font-bold uppercase tracking-widest text-slate-500">Detection Flags</h4>
            <div className="space-y-1.5">
              {email.risk_flags.map((flag, i) => (
                <div key={i} className="flex items-start gap-2 p-2.5 bg-red-500/5 border border-red-500/10 rounded-lg">
                  <ShieldAlert className="h-3 w-3 text-red-400 mt-0.5 flex-shrink-0" />
                  <span className="text-[10px] text-red-300 font-medium">{flag}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Email Preview */}
        <div className="space-y-2">
          <h4 className="text-[9px] font-bold uppercase tracking-widest text-slate-500">Email Preview</h4>
          <div className="bg-[#0D1B2A] border border-white/5 rounded-xl p-4">
            <p className="text-sm text-slate-300 leading-relaxed">{email.snippet}</p>
          </div>
        </div>

        {/* Actions */}
        <div className="grid grid-cols-2 gap-2 pt-2">
          <Button onClick={() => onAnalyze(email.id)} className="bg-blue-600 hover:bg-blue-500 text-white text-[10px] font-black uppercase tracking-widest rounded-xl h-10">
            <Zap className="h-3.5 w-3.5 mr-2" />
            Full Analysis
          </Button>
          {isRisky ? (
            <Button variant="outline" className="border-red-500/20 text-red-400 hover:bg-red-500/10 text-[10px] font-black uppercase tracking-widest rounded-xl h-10">
              <ShieldAlert className="h-3.5 w-3.5 mr-2" />
              Quarantine
            </Button>
          ) : (
            <Button variant="outline" className="border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/10 text-[10px] font-black uppercase tracking-widest rounded-xl h-10">
              <CheckCircle className="h-3.5 w-3.5 mr-2" />
              Mark Safe
            </Button>
          )}
        </div>
      </div>
    </motion.div>
  )
}

export default function InboxPage() {
  const [connected, setConnected] = useState(false)
  const [isDemo, setIsDemo] = useState(false)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [data, setData] = useState<InboxData | null>(null)
  const [selected, setSelected] = useState<EmailItem | null>(null)
  const [filter, setFilter] = useState("ALL")
  const [connecting, setConnecting] = useState(false)
  const [connectedEmail, setConnectedEmail] = useState<string | null>(null)

  const checkStatus = useCallback(async () => {
    try {
      const r = await fetch(`${API}/status`)
      const d = await r.json()
      setConnected(d.connected)
      setIsDemo(d.demo_mode ?? true)
      setConnectedEmail(d.email ?? null)
    } catch { setConnected(false) }
  }, [])

  const loadInbox = useCallback(async () => {
    setLoading(true)
    setLoadError(null)
    try {
      const r = await fetch(`${API}/inbox?risk_filter=${filter}`, { signal: AbortSignal.timeout(120_000) })
      const d = await r.json()
      if (!r.ok) {
        setLoadError(d.detail ?? `Server error ${r.status}`)
      } else if (Array.isArray(d.items)) {
        setData(d)
      } else {
        setLoadError("Unexpected response from server")
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to load inbox"
      setLoadError(msg.includes("timed out") ? "Analysis timed out — AI is processing 3 emails. Try refreshing." : msg)
    }
    setLoading(false)
  }, [filter])

  useEffect(() => {
    // Handle OAuth callback redirect (?connected=true)
    const params = new URLSearchParams(window.location.search)
    if (params.get("connected") === "true") {
      window.history.replaceState({}, "", window.location.pathname)
    }
    checkStatus()
  }, [checkStatus])

  useEffect(() => { if (connected) loadInbox() }, [connected, loadInbox, filter])

  const handleConnect = async () => {
    setConnecting(true)
    try {
      // Check if real OAuth credentials are available
      const authRes = await fetch(`${API}/auth-url?session_id=default`)
      const authData = await authRes.json()

      if (authData.auth_url && !authData.demo_mode) {
        // Real OAuth — redirect to Google
        window.location.href = authData.auth_url
        return
      }

      // Demo mode fallback (no Google credentials configured)
      await fetch(`${API}/demo-connect`)
      setConnected(true)
      setIsDemo(true)
      await loadInbox()
    } catch {
      // Fallback to demo
      await fetch(`${API}/demo-connect`)
      setConnected(true)
      setIsDemo(true)
      await loadInbox()
    } finally {
      setConnecting(false)
    }
  }

  const handleAnalyze = async (messageId: string) => {
    window.location.href = `/dashboard/analyze?gmail=${messageId}`
  }

  const filterCounts = data ? {
    ALL: data.total ?? 0,
    FLAGGED: (data.phishing_count ?? 0) + (data.suspicious_count ?? 0),
    PHISHING: data.phishing_count ?? 0,
    SUSPICIOUS: data.suspicious_count ?? 0,
    CLEAN: data.clean_count ?? 0,
  } : {}

  return (
    <div className="space-y-8 pb-10">
      <header className="flex items-center justify-between border-b border-white/5 pb-6">
        <div className="flex items-center gap-4">
          <div className="h-10 w-10 rounded-xl bg-blue-500/20 border border-blue-500/30 flex items-center justify-center shadow-xl">
            <Inbox className="h-5 w-5 text-blue-400" />
          </div>
          <div>
            <h1 className="text-3xl font-black tracking-tighter text-foreground uppercase">Gmail Inbox</h1>
            <p className="text-[10px] text-muted-foreground uppercase font-black tracking-[0.3em]">
              {connected
                ? isDemo
                  ? "Demo mode — 8 sample emails"
                  : `${connectedEmail ?? "Gmail"} — live AI phishing detection`
                : "Connect Gmail to analyze your inbox in real-time"}
            </p>
          </div>
        </div>
        {connected && (
          <div className="flex items-center gap-2">
            <Button onClick={loadInbox} variant="ghost" size="icon" className="h-9 w-9 text-muted-foreground hover:text-blue-400 hover:bg-blue-500/10 rounded-xl">
              <RefreshCw className="h-4 w-4" />
            </Button>
            <Button
              onClick={async () => {
                await fetch(`${API}/disconnect`, { method: "DELETE" })
                setConnected(false)
                setData(null)
                setSelected(null)
                setLoadError(null)
                setConnectedEmail(null)
              }}
              variant="ghost"
              className="h-9 px-3 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded-xl text-[10px] font-black uppercase tracking-widest gap-1.5"
            >
              <X className="h-3.5 w-3.5" />
              Disconnect
            </Button>
          </div>
        )}
      </header>

      {!connected ? (
        <div className="flex flex-col items-center justify-center py-32 space-y-8">
          <div className="h-24 w-24 rounded-[2rem] bg-blue-500/10 border border-blue-500/20 flex items-center justify-center shadow-[0_0_40px_rgba(59,130,246,0.15)]">
            <Inbox className="h-12 w-12 text-blue-400" />
          </div>
          <div className="text-center space-y-3 max-w-md">
            <h2 className="text-2xl font-black tracking-tight uppercase">Connect Your Gmail</h2>
            <p className="text-slate-500 text-sm leading-relaxed">Get AI-powered phishing scores on every email in your inbox, in real time. Uses Google OAuth2 — your emails never leave your device in production.</p>
          </div>
          <div className="flex flex-col items-center gap-3">
            <Button onClick={handleConnect} disabled={connecting} className="bg-blue-600 hover:bg-blue-500 text-white px-10 py-6 text-xs font-black uppercase tracking-widest rounded-2xl shadow-[0_0_20px_rgba(59,130,246,0.3)] transition-all hover:scale-105">
              {connecting ? "Redirecting to Google..." : "Connect Gmail with Google"}
            </Button>
            <p className="text-[9px] text-slate-600 uppercase tracking-widest">Authorizes read-only inbox access via Google OAuth2</p>
          </div>
        </div>
      ) : (
        <>
          {/* Error / loading state */}
          {loadError && (
            <div className="flex items-center gap-3 p-4 rounded-2xl bg-red-500/8 border border-red-500/20 text-red-300 text-xs font-mono">
              <WifiOff className="h-4 w-4 shrink-0 text-red-400" />
              {loadError}
            </div>
          )}
          {loading && !loadError && (
            <div className="flex items-center gap-3 p-4 rounded-2xl bg-blue-500/5 border border-blue-500/10 text-blue-300 text-xs font-mono">
              <RefreshCw className="h-4 w-4 shrink-0 text-blue-400 animate-spin" />
              Running AI analysis on your inbox — this takes 30–60 seconds for real emails...
            </div>
          )}

          {/* Stats Bar */}
          <div className="grid grid-cols-4 gap-4">
            {[
              { label: "Total Emails", value: data?.total ?? "--", color: "text-slate-200", bg: "bg-white/3" },
              { label: "Phishing Detected", value: data?.phishing_count ?? "--", color: "text-red-400", bg: "bg-red-500/5 border border-red-500/10" },
              { label: "Suspicious", value: data?.suspicious_count ?? "--", color: "text-amber-400", bg: "bg-amber-500/5 border border-amber-500/10" },
              { label: "Clean", value: data?.clean_count ?? "--", color: "text-emerald-400", bg: "bg-emerald-500/5 border border-emerald-500/10" },
            ].map((s, i) => (
              <div key={i} className={cn("p-4 rounded-2xl space-y-1", s.bg)}>
                <p className="text-[8px] font-black uppercase tracking-widest text-slate-600">{s.label}</p>
                <p className={cn("text-3xl font-black tracking-tighter", s.color)}>{s.value}</p>
              </div>
            ))}
          </div>

          {/* Main Inbox */}
          <div className="grid grid-cols-12 gap-6 h-[600px]">
            {/* Email List */}
            <Card className="col-span-12 lg:col-span-5 card-cyber overflow-hidden flex flex-col">
              {/* Filter Tabs */}
              <div className="flex items-center gap-1 p-3 border-b border-white/5 overflow-x-auto">
                {["ALL", "FLAGGED", "PHISHING", "SUSPICIOUS", "CLEAN"].map(f => (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    className={cn(
                      "px-3 py-1.5 rounded-lg text-[9px] font-black uppercase tracking-widest whitespace-nowrap transition-all flex items-center gap-1.5",
                      filter === f ? "bg-blue-500/20 text-blue-400 border border-blue-500/20"
                        : "text-slate-600 hover:text-slate-400 hover:bg-white/5"
                    )}
                  >
                    {f}
                    {filterCounts[f as keyof typeof filterCounts] !== undefined && (
                      <span className={cn("text-[7px] px-1 rounded", filter === f ? "bg-blue-500/30" : "bg-white/10")}>
                        {filterCounts[f as keyof typeof filterCounts]}
                      </span>
                    )}
                  </button>
                ))}
              </div>

              <div className="flex-1 overflow-y-auto">
                {loading ? (
                  Array.from({ length: 5 }).map((_, i) => (
                    <div key={i} className="flex items-center gap-4 px-5 py-4 border-b border-white/5">
                      <div className="h-2 w-2 rounded-full bg-white/10 animate-pulse" />
                      <div className="flex-1 space-y-2">
                        <div className="h-3 w-32 bg-white/10 rounded animate-pulse" />
                        <div className="h-2 w-48 bg-white/5 rounded animate-pulse" />
                      </div>
                    </div>
                  ))
                ) : data?.items?.map(email => (
                  <EmailRow key={email.id} email={email} selected={selected?.id === email.id} onClick={() => setSelected(email)} />
                ))}
              </div>
            </Card>

            {/* Detail Panel */}
            <div className="col-span-12 lg:col-span-7 h-full">
              <AnimatePresence mode="wait">
                {selected ? (
                  <EmailDetailPanel key={selected.id} email={selected} onClose={() => setSelected(null)} onAnalyze={handleAnalyze} />
                ) : (
                  <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="h-full card-cyber rounded-3xl flex flex-col items-center justify-center space-y-4 opacity-30">
                    <Mail className="h-16 w-16 text-slate-600" />
                    <p className="text-[10px] font-black uppercase tracking-widest text-slate-600">Select an email to view details</p>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
