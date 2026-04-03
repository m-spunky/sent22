"use client"

import React, { useEffect, useState } from "react"
import {
  ShieldAlert, Globe, Activity, Zap, Target, Link2, ExternalLink,
  AlertTriangle, Clock, CheckCircle, XCircle, Loader2, TrendingUp, Shield
} from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import { executeResponse, verdictBg } from "@/lib/api"

type BtnState = "idle" | "loading" | "success" | "error"

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001"

interface HistoryItem {
  event_id: string
  verdict: string
  threat_score: number
  timestamp: string
  urls_analyzed?: string[]
  input_type?: string
  explanation_narrative?: string
}

interface HistoryStats {
  total_scans: number
  phishing_detected: number
  safe_count: number
  avg_threat_score: number
  most_targeted_brand?: string
}

export function ContextPanel() {
  const [recentThreats, setRecentThreats] = useState<HistoryItem[]>([])
  const [stats, setStats] = useState<HistoryStats | null>(null)
  const [loadingData, setLoadingData] = useState(true)
  const [btnStates, setBtnStates] = useState<Record<string, BtnState>>({})

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [histRes, statsRes] = await Promise.all([
          fetch(`${API_BASE}/api/v1/history?page=1&limit=4`),
          fetch(`${API_BASE}/api/v1/history/stats`),
        ])
        if (histRes.ok) {
          const data = await histRes.json()
          setRecentThreats(data.items || data.results || [])
        }
        if (statsRes.ok) {
          const s = await statsRes.json()
          setStats(s)
        }
      } catch {
        // Backend offline — show minimal UI
      } finally {
        setLoadingData(false)
      }
    }
    fetchData()
  }, [])

  const run = async (key: string, action: string, target: Record<string, unknown>) => {
    setBtnStates(s => ({ ...s, [key]: "loading" }))
    try {
      await executeResponse(action, target)
      setBtnStates(s => ({ ...s, [key]: "success" }))
      setTimeout(() => setBtnStates(s => ({ ...s, [key]: "idle" })), 2500)
    } catch {
      setBtnStates(s => ({ ...s, [key]: "error" }))
      setTimeout(() => setBtnStates(s => ({ ...s, [key]: "idle" })), 2500)
    }
  }

  const getBtnContent = (key: string, Icon: React.ElementType, label: string) => {
    const st = btnStates[key] ?? "idle"
    return {
      st,
      icon: st === "loading" ? <Loader2 className="h-4 w-4 animate-spin" />
        : st === "success" ? <CheckCircle className="h-4 w-4 text-emerald-400" />
        : st === "error" ? <XCircle className="h-4 w-4 text-red-400" />
        : <Icon className="h-4 w-4" />,
      text: st === "success" ? "Done" : st === "error" ? "Failed" : label,
    }
  }

  const quarantine = getBtnContent("quarantine", ShieldAlert, "Quarantine")
  const block = getBtnContent("block", Globe, "Block IOC")
  const escalate = getBtnContent("escalate", Activity, "Escalate L3")
  const mfa = getBtnContent("mfa", Shield, "Enforce MFA")

  // Grab latest high-risk event for action context
  const latestThreat = recentThreats.find(t => t.verdict === "PHISHING" || t.verdict === "CRITICAL") || recentThreats[0]

  return (
    <div className="h-full flex flex-col space-y-5 animate-in fade-in slide-in-from-right-8 duration-700">

      {/* Platform Stats */}
      <Card className="card-cyber group relative overflow-hidden">
        <CardHeader className="p-5 border-b border-white/5 bg-blue-500/3">
          <div className="flex items-center justify-between">
            <Badge className="bg-blue-500/10 text-blue-400 border border-blue-500/20 text-[8px] h-5 rounded-full px-3 uppercase font-bold tracking-widest">
              Live Platform Stats
            </Badge>
            <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
          </div>
        </CardHeader>
        <CardContent className="p-5">
          {loadingData ? (
            <div className="flex items-center justify-center py-4">
              <Loader2 className="h-5 w-5 animate-spin text-blue-400" />
            </div>
          ) : stats ? (
            <div className="grid grid-cols-2 gap-2">
              <div className="p-3 rounded-xl bg-white/3 border border-white/5">
                <span className="text-[8px] text-slate-600 uppercase font-bold tracking-widest mb-1 block">Total Scans</span>
                <span className="text-lg font-black text-blue-400 tracking-tighter font-mono">{stats.total_scans}</span>
              </div>
              <div className="p-3 rounded-xl bg-white/3 border border-white/5">
                <span className="text-[8px] text-slate-600 uppercase font-bold tracking-widest mb-1 block">Phishing Found</span>
                <span className="text-lg font-black text-red-400 tracking-tighter font-mono">{stats.phishing_detected}</span>
              </div>
              <div className="p-3 rounded-xl bg-white/3 border border-white/5">
                <span className="text-[8px] text-slate-600 uppercase font-bold tracking-widest mb-1 block">Safe</span>
                <span className="text-lg font-black text-emerald-400 tracking-tighter font-mono">{stats.safe_count}</span>
              </div>
              <div className="p-3 rounded-xl bg-white/3 border border-white/5">
                <span className="text-[8px] text-slate-600 uppercase font-bold tracking-widest mb-1 block">Avg Risk</span>
                <span className="text-lg font-black text-amber-400 tracking-tighter font-mono">
                  {Math.round((stats.avg_threat_score ?? 0) * 100)}%
                </span>
              </div>
            </div>
          ) : (
            <p className="text-[10px] text-slate-500 text-center py-4 italic">Start scanning to see stats</p>
          )}
        </CardContent>
      </Card>

      {/* Recent Detections */}
      <Card className="card-cyber relative overflow-hidden">
        <CardHeader className="p-5 border-b border-white/5">
          <CardTitle className="text-[10px] font-bold uppercase tracking-widest text-slate-400 flex items-center gap-2">
            <Clock className="h-3.5 w-3.5 text-blue-400" />
            Recent Detections
          </CardTitle>
        </CardHeader>
        <CardContent className="p-3 space-y-1.5">
          {loadingData ? (
            <div className="flex items-center justify-center py-4">
              <Loader2 className="h-5 w-5 animate-spin text-blue-400" />
            </div>
          ) : recentThreats.length === 0 ? (
            <p className="text-[10px] text-slate-500 text-center py-4 italic">No scans yet — analyze an email or URL to get started.</p>
          ) : (
            recentThreats.map((item, i) => {
              const domain = item.urls_analyzed?.[0]
                ? (() => { try { return new URL(item.urls_analyzed[0]).hostname } catch { return item.urls_analyzed[0].slice(0, 28) } })()
                : item.input_type === "email" ? "Email scan" : `Scan ${item.event_id?.slice(-6) || i}`
              const timeAgo = (() => {
                const diff = Date.now() - new Date(item.timestamp).getTime()
                const m = Math.floor(diff / 60000)
                if (m < 1) return "just now"
                if (m < 60) return `${m}m ago`
                const h = Math.floor(m / 60)
                if (h < 24) return `${h}h ago`
                return `${Math.floor(h / 24)}d ago`
              })()
              return (
                <div key={item.event_id || i} className="flex items-center justify-between p-2 px-3 rounded-lg bg-[#0D1B2A]/40 border border-white/5 hover:border-blue-500/20 transition-all">
                  <div className="flex items-center gap-2">
                    <div className={cn(
                      "p-1.5 rounded-md shrink-0",
                      item.verdict === "PHISHING" || item.verdict === "CRITICAL" ? "bg-red-500/10 text-red-400"
                      : item.verdict === "SUSPICIOUS" ? "bg-amber-500/10 text-amber-400"
                      : "bg-emerald-500/10 text-emerald-400"
                    )}>
                      <AlertTriangle className="h-3 w-3" />
                    </div>
                    <div className="flex flex-col min-w-0">
                      <span className="text-[10px] font-bold text-slate-300 truncate w-36 font-mono">{domain}</span>
                      <span className="text-[7px] text-slate-600 uppercase font-bold tracking-widest">{timeAgo}</span>
                    </div>
                  </div>
                  <Badge className={cn("text-[7px] h-4 rounded-full px-2 border shrink-0", verdictBg(item.verdict))}>
                    {item.verdict}
                  </Badge>
                </div>
              )
            })
          )}
        </CardContent>
      </Card>

      {/* Operations Center */}
      <Card className="card-cyber p-5">
        <div className="flex flex-col space-y-4">
          <h4 className="text-[9px] font-bold uppercase tracking-widest text-blue-400 flex items-center gap-2">
            <Zap className="h-3.5 w-3.5" />
            Operations Center
          </h4>

          <div className="grid grid-cols-2 gap-2">
            {[
              {
                key: "quarantine", info: quarantine,
                cls: "bg-red-500/10 text-red-400 hover:border-red-500/30 hover:bg-red-500/15",
                fn: () => run("quarantine", "quarantine", { event_id: latestThreat?.event_id, domains: latestThreat?.urls_analyzed || [] }),
              },
              {
                key: "block", info: block,
                cls: "bg-red-500/10 text-red-400 hover:border-red-500/30 hover:bg-red-500/15",
                fn: () => run("block", "block_ioc", { event_id: latestThreat?.event_id, domains: latestThreat?.urls_analyzed || [] }),
              },
              {
                key: "escalate", info: escalate,
                cls: "bg-blue-500/10 text-blue-400 hover:border-blue-500/30 hover:bg-blue-500/15",
                fn: () => run("escalate", "alert_team", { event_id: latestThreat?.event_id, escalation_level: "L3" }),
              },
              {
                key: "mfa", info: mfa,
                cls: "bg-amber-500/10 text-amber-400 hover:border-amber-500/30 hover:bg-amber-500/15",
                fn: () => run("mfa", "enforce_mfa", { event_id: latestThreat?.event_id }),
              },
            ].map(({ key, info, cls, fn }) => (
              <button
                key={key}
                onClick={fn}
                disabled={info.st === "loading"}
                className={cn(
                  "flex flex-col items-center justify-center h-16 rounded-xl border border-white/5 p-3 transition-all hover:scale-105 active:scale-95 gap-1.5 disabled:opacity-60 disabled:cursor-not-allowed disabled:hover:scale-100",
                  info.st === "success" ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                  : info.st === "error" ? "bg-red-500/10 border-red-500/40 text-red-300"
                  : cls
                )}
              >
                {info.icon}
                <span className="text-[8px] font-bold uppercase tracking-widest leading-none">{info.text}</span>
              </button>
            ))}
          </div>
        </div>
      </Card>
    </div>
  )
}
