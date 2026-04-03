"use client"

import React, { useState, useEffect } from "react"
import {
  History, ShieldAlert, ShieldCheck, AlertTriangle, Download,
  Filter, CheckCircle, X, Minus, Globe, Mail, FileText, QrCode, BarChart2
} from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, AreaChart, Area, XAxis, CartesianGrid } from "recharts"

interface HistoryEntry {
  event_id: string
  timestamp: string
  input_type: string
  input_preview: string
  verdict: string
  threat_score: number
  confidence: number
  inference_time_ms: number
  brand_impersonated: string
  threat_actor: string
  feedback: string | null
}

interface Stats {
  total_analyses: number
  accuracy_percent: number | null
  false_positives: number
  missed: number
  verdict_breakdown: Record<string, number>
  top_impersonated_brands: [string, number][]
  avg_inference_ms: number
}

const VERDICT_COLORS: Record<string, string> = {
  CONFIRMED_THREAT: "#ef4444",
  PHISHING: "#f97316",
  SUSPICIOUS: "#f59e0b",
  CLEAN: "#10b981",
}

const INPUT_ICONS: Record<string, React.ReactNode> = {
  url: <Globe className="h-3.5 w-3.5" />,
  email: <Mail className="h-3.5 w-3.5" />,
  headers: <FileText className="h-3.5 w-3.5" />,
  qr: <QrCode className="h-3.5 w-3.5" />,
}

async function submitFeedback(event_id: string, type: string) {
  await fetch("/api/v1/feedback", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ event_id, feedback_type: type }),
  })
}

function VerdictChip({ verdict }: { verdict: string }) {
  const map: Record<string, { cls: string; icon: React.ReactNode }> = {
    CONFIRMED_THREAT: { cls: "bg-red-500/10 text-red-400 border-red-500/20", icon: <ShieldAlert className="h-3 w-3" /> },
    PHISHING: { cls: "bg-orange-500/10 text-orange-400 border-orange-500/20", icon: <ShieldAlert className="h-3 w-3" /> },
    SUSPICIOUS: { cls: "bg-amber-500/10 text-amber-400 border-amber-500/20", icon: <AlertTriangle className="h-3 w-3" /> },
    CLEAN: { cls: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20", icon: <ShieldCheck className="h-3 w-3" /> },
  }
  const config = map[verdict] || map.CLEAN
  return (
    <Badge className={cn("text-[8px] h-5 rounded-full px-2.5 uppercase font-bold tracking-widest border flex items-center gap-1", config.cls)}>
      {config.icon}{verdict.replace("_", " ")}
    </Badge>
  )
}

export default function HistoryPage() {
  const [entries, setEntries] = useState<HistoryEntry[]>([])
  const [stats, setStats] = useState<Stats | null>(null)
  const [verdictFilter, setVerdictFilter] = useState("ALL")
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [feedbackMap, setFeedbackMap] = useState<Record<string, string>>({})

  const loadData = async () => {
    try {
      const [hResp, sResp] = await Promise.all([
        fetch(`/api/v1/history?page=${page}&limit=15${verdictFilter !== "ALL" ? `&verdict=${verdictFilter}` : ""}`),
        fetch("/api/v1/history/stats"),
      ])
      const hData = await hResp.json()
      const sData = await sResp.json()
      setEntries(hData.items || [])
      setTotal(hData.total || 0)
      setStats(sData)
      const fm: Record<string, string> = {}
      for (const e of hData.items || []) {
        if (e.feedback) fm[e.event_id] = e.feedback
      }
      setFeedbackMap(prev => ({ ...prev, ...fm }))
    } catch { }
  }

  useEffect(() => { loadData() }, [page, verdictFilter])

  const handleFeedback = async (event_id: string, type: string) => {
    await submitFeedback(event_id, type)
    setFeedbackMap(prev => ({ ...prev, [event_id]: type }))
  }

  const pieData = stats ? Object.entries(stats.verdict_breakdown).map(([name, value]) => ({
    name, value, color: VERDICT_COLORS[name] || "#64748b"
  })) : []

  const exportCSV = () => {
    const header = "event_id,timestamp,input_type,verdict,score,inference_ms,feedback\n"
    const rows = entries.map(e => `${e.event_id},${e.timestamp},${e.input_type},${e.verdict},${e.threat_score},${e.inference_time_ms},${e.feedback || ""}`).join("\n")
    const blob = new Blob([header + rows], { type: "text/csv" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url; a.download = "sentinelai-history.csv"; a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-8 pb-10">
      <header className="flex items-center justify-between border-b border-white/5 pb-6">
        <div className="flex items-center gap-4">
          <div className="h-10 w-10 rounded-xl bg-blue-500/20 border border-blue-500/30 flex items-center justify-center">
            <History className="h-5 w-5 text-blue-400" />
          </div>
          <div>
            <h1 className="text-3xl font-black tracking-tighter text-foreground uppercase">Analysis History</h1>
            <p className="text-[10px] text-muted-foreground uppercase font-black tracking-[0.3em]">
              {total} total analyses · Feedback loop active
            </p>
          </div>
        </div>
        <Button onClick={exportCSV} variant="outline" className="border-blue-500/20 text-blue-400 hover:bg-blue-500/10 rounded-xl text-[10px] font-black uppercase tracking-widest h-9 px-4">
          <Download className="h-3.5 w-3.5 mr-2" />
          Export CSV
        </Button>
      </header>

      {/* Stats Row */}
      {stats && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: "Total Analyses", value: stats.total_analyses, color: "text-slate-200" },
            { label: "Model Accuracy", value: stats.accuracy_percent != null ? `${stats.accuracy_percent}%` : "Pending feedback", color: "text-emerald-400" },
            { label: "Avg Speed", value: `${stats.avg_inference_ms}ms`, color: "text-blue-400" },
            { label: "False Positive Rate", value: stats.accuracy_percent != null ? `${(100 - stats.accuracy_percent).toFixed(1)}%` : "--", color: "text-amber-400" },
          ].map((s, i) => (
            <Card key={i} className="card-cyber p-5 space-y-1">
              <p className="text-[8px] font-black uppercase tracking-widest text-slate-600">{s.label}</p>
              <p className={cn("text-3xl font-black tracking-tighter", s.color)}>{s.value}</p>
            </Card>
          ))}
        </div>
      )}

      <div className="grid grid-cols-12 gap-6">
        {/* History Table */}
        <div className="col-span-12 lg:col-span-8 space-y-4">
          {/* Filters */}
          <div className="flex items-center gap-2">
            {["ALL", "PHISHING", "SUSPICIOUS", "CLEAN", "CONFIRMED_THREAT"].map(v => (
              <button key={v} onClick={() => { setVerdictFilter(v); setPage(1) }}
                className={cn("px-3 py-1.5 rounded-lg text-[9px] font-black uppercase tracking-widest transition-all",
                  verdictFilter === v ? "bg-blue-500/20 text-blue-400 border border-blue-500/20" : "text-slate-600 hover:text-slate-400 hover:bg-white/5"
                )}>{v.replace("_", " ")}</button>
            ))}
          </div>

          <Card className="card-cyber overflow-hidden">
            <table className="w-full text-[11px]">
              <thead>
                <tr className="border-b border-white/5">
                  {["Type", "Input", "Verdict", "Score", "Speed", "Feedback"].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-[8px] font-black uppercase tracking-widest text-slate-600">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {entries.length === 0 ? (
                  <tr><td colSpan={6} className="text-center py-16 text-slate-600 text-[10px] uppercase tracking-widest font-black">No analyses yet. Run your first detection to see history.</td></tr>
                ) : entries.map(entry => (
                  <tr key={entry.event_id} className="border-b border-white/5 hover:bg-white/3 transition-colors group">
                    <td className="px-4 py-3">
                      <div className={cn("flex items-center gap-1.5 text-slate-500", entry.input_type === "url" ? "text-blue-400" : entry.input_type === "email" ? "text-emerald-400" : "text-slate-400")}>
                        {INPUT_ICONS[entry.input_type] || <FileText className="h-3.5 w-3.5" />}
                        <span className="font-bold uppercase">{entry.input_type}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 max-w-[200px]">
                      <p className="font-mono text-slate-400 truncate">{entry.input_preview || "—"}</p>
                    </td>
                    <td className="px-4 py-3"><VerdictChip verdict={entry.verdict} /></td>
                    <td className="px-4 py-3">
                      <span className={cn("font-black font-mono",
                        entry.threat_score >= 0.65 ? "text-red-400" : entry.threat_score >= 0.35 ? "text-amber-400" : "text-emerald-400"
                      )}>{Math.round(entry.threat_score * 100)}%</span>
                    </td>
                    <td className="px-4 py-3 text-slate-500 font-mono">{entry.inference_time_ms}ms</td>
                    <td className="px-4 py-3">
                      {feedbackMap[entry.event_id] ? (
                        <Badge className={cn("text-[7px] uppercase font-black border",
                          feedbackMap[entry.event_id] === "correct" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" :
                          feedbackMap[entry.event_id] === "false_positive" ? "bg-amber-500/10 text-amber-400 border-amber-500/20" :
                          "bg-red-500/10 text-red-400 border-red-500/20"
                        )}>{feedbackMap[entry.event_id].replace("_", " ")}</Badge>
                      ) : (
                        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                          <button onClick={() => handleFeedback(entry.event_id, "correct")} className="h-6 w-6 rounded bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 flex items-center justify-center transition-colors" title="Correct">
                            <CheckCircle className="h-3 w-3" />
                          </button>
                          <button onClick={() => handleFeedback(entry.event_id, "false_positive")} className="h-6 w-6 rounded bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 flex items-center justify-center transition-colors" title="False Positive">
                            <Minus className="h-3 w-3" />
                          </button>
                          <button onClick={() => handleFeedback(entry.event_id, "missed")} className="h-6 w-6 rounded bg-red-500/10 text-red-400 hover:bg-red-500/20 flex items-center justify-center transition-colors" title="Missed">
                            <X className="h-3 w-3" />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {total > 15 && (
              <div className="flex items-center justify-between px-4 py-3 border-t border-white/5">
                <span className="text-[9px] text-slate-600 font-bold uppercase tracking-widest">Page {page} of {Math.ceil(total / 15)}</span>
                <div className="flex gap-2">
                  <Button variant="ghost" size="sm" disabled={page === 1} onClick={() => setPage(p => p - 1)} className="h-7 text-[9px] font-black uppercase tracking-widest text-slate-500">Prev</Button>
                  <Button variant="ghost" size="sm" disabled={page * 15 >= total} onClick={() => setPage(p => p + 1)} className="h-7 text-[9px] font-black uppercase tracking-widest text-slate-500">Next</Button>
                </div>
              </div>
            )}
          </Card>
        </div>

        {/* Right Column: Charts */}
        <div className="col-span-12 lg:col-span-4 space-y-6">
          {/* Verdict Distribution */}
          {pieData.length > 0 && (
            <Card className="card-cyber p-5 space-y-4">
              <p className="text-[9px] font-black uppercase tracking-widest text-slate-500 flex items-center gap-2">
                <BarChart2 className="h-3.5 w-3.5 text-blue-400" />
                Verdict Distribution
              </p>
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={40} outerRadius={65} paddingAngle={3} dataKey="value">
                    {pieData.map((entry, i) => <Cell key={i} fill={entry.color} fillOpacity={0.8} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#0D1B2A", border: "1px solid rgba(255,255,255,0.05)", borderRadius: "12px", fontSize: "10px", color: "#94a3b8", fontFamily: "JetBrains Mono, monospace" }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-1.5">
                {pieData.map((d, i) => (
                  <div key={i} className="flex items-center justify-between text-[9px]">
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-2 rounded-full" style={{ backgroundColor: d.color }} />
                      <span className="text-slate-400 uppercase font-bold">{d.name.replace("_", " ")}</span>
                    </div>
                    <span className="text-slate-300 font-mono font-black">{d.value}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Top Impersonated Brands */}
          {stats && stats.top_impersonated_brands.length > 0 && (
            <Card className="card-cyber p-5 space-y-4">
              <p className="text-[9px] font-black uppercase tracking-widest text-slate-500">Top Impersonated Brands</p>
              <div className="space-y-3">
                {stats.top_impersonated_brands.map(([brand, count], i) => (
                  <div key={i} className="space-y-1">
                    <div className="flex items-center justify-between text-[9px]">
                      <span className="text-slate-300 font-bold">{brand}</span>
                      <span className="text-slate-500 font-mono">{count}x</span>
                    </div>
                    <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                      <div className="h-full bg-blue-500/60 rounded-full" style={{ width: `${(count / (stats.top_impersonated_brands[0]?.[1] || 1)) * 100}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Feedback Legend */}
          <Card className="card-cyber p-5 space-y-3">
            <p className="text-[9px] font-black uppercase tracking-widest text-slate-500">Feedback Controls</p>
            {[
              { icon: CheckCircle, color: "text-emerald-400", label: "Correct", desc: "Detection was accurate" },
              { icon: Minus, color: "text-amber-400", label: "False Positive", desc: "Flagged incorrectly" },
              { icon: X, color: "text-red-400", label: "Missed", desc: "Should have been flagged" },
            ].map((item, i) => (
              <div key={i} className="flex items-center gap-3">
                <item.icon className={cn("h-4 w-4 flex-shrink-0", item.color)} />
                <div>
                  <p className="text-[10px] font-bold text-slate-300">{item.label}</p>
                  <p className="text-[8px] text-slate-600 uppercase font-bold tracking-widest">{item.desc}</p>
                </div>
              </div>
            ))}
          </Card>
        </div>
      </div>
    </div>
  )
}
