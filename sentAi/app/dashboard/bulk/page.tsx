"use client"

import React, { useState, useRef, useCallback } from "react"
import {
  Upload, FileText, Loader2, CheckCircle, ShieldAlert,
  AlertTriangle, ShieldCheck, Download, X, BarChart2, Lightbulb, Users, Clock, Globe
} from "lucide-react"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import { motion, AnimatePresence } from "framer-motion"

interface BulkResult {
  row: number
  input: string
  verdict: string
  threat_score: number
  confidence: number
  inference_ms: number
  event_id?: string
  error?: string
}

interface JobStatus {
  job_id: string
  status: string
  total: number
  completed: number
  progress_percent: number
  summary: { total: number; phishing: number; suspicious: number; clean: number; errors: number; avg_score: number }
}

interface JobResult extends JobStatus {
  results: BulkResult[]
}

export default function BulkPage() {
  const [dragging, setDragging] = useState(false)
  const [jobId, setJobId] = useState<string | null>(null)
  const [jobStatus, setJobStatus] = useState<JobStatus | null>(null)
  const [results, setResults] = useState<BulkResult[]>([])
  const [clusters, setClusters] = useState<any[]>([])
  const [clustering, setClustering] = useState(false)
  const [error, setError] = useState("")
  const [uploading, setUploading] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const SAMPLE_CSV = `url
http://paypal-secure-update.xyz/verify
https://github.com
http://amazon-payment-verify.net/account
https://google.com
http://microsoft-helpdesk.ru/login
https://stackoverflow.com
http://bank-of-america-verify.click
https://youtube.com`

  const uploadFile = async (file: File) => {
    if (!file.name.endsWith(".csv")) { setError("Please upload a CSV file."); return }
    setError(""); setUploading(true); setJobId(null); setJobStatus(null); setResults([]); setClusters([])

    const form = new FormData()
    form.append("file", file)

    try {
      const resp = await fetch("/api/v1/bulk/upload", { method: "POST", body: form })
      if (!resp.ok) { const d = await resp.json(); throw new Error(d.detail || "Upload failed") }
      const data = await resp.json()
      setJobId(data.job_id)
      startPolling(data.job_id)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed")
    }
    setUploading(false)
  }

  const startPolling = useCallback((id: string) => {
    if (pollRef.current) clearInterval(pollRef.current)
    pollRef.current = setInterval(async () => {
      try {
        const resp = await fetch(`/api/v1/bulk/${id}/status`)
        const data: JobStatus = await resp.json()
        setJobStatus(data)
        if (data.status === "completed") {
          clearInterval(pollRef.current!)
          const rResp = await fetch(`/api/v1/bulk/${id}/results`)
          const rData: JobResult = await rResp.json()
          setResults(rData.results || [])
        }
      } catch { clearInterval(pollRef.current!) }
    }, 1500)
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); setDragging(false)
    const file = e.dataTransfer.files?.[0]
    if (file) uploadFile(file)
  }, [])

  const downloadSample = () => {
    const blob = new Blob([SAMPLE_CSV], { type: "text/csv" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a"); a.href = url; a.download = "sample-urls.csv"; a.click()
    URL.revokeObjectURL(url)
  }

  const exportResults = () => {
    if (!results.length) return
    const header = "row,input,verdict,threat_score,inference_ms\n"
    const rows = results.map(r => `${r.row},"${r.input}",${r.verdict},${r.threat_score},${r.inference_ms}`).join("\n")
    const blob = new Blob([header + rows], { type: "text/csv" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a"); a.href = url; a.download = "bulk-results.csv"; a.click()
    URL.revokeObjectURL(url)
  }

  const runClustering = async () => {
    if (!jobId) return
    setClustering(true)
    try {
      const resp = await fetch(`/api/v1/bulk/${jobId}/cluster`)
      const data = await resp.json()
      setClusters(data.clusters || [])
    } catch (e) {
      console.error("Clustering failed:", e)
    }
    setClustering(false)
  }

  const isRunning = jobStatus && jobStatus.status !== "completed"
  const isDone = jobStatus?.status === "completed"

  return (
    <div className="space-y-8 pb-10">
      <header className="flex items-center justify-between border-b border-white/5 pb-6">
        <div className="flex items-center gap-4">
          <div className="h-10 w-10 rounded-xl bg-blue-500/20 border border-blue-500/30 flex items-center justify-center">
            <Upload className="h-5 w-5 text-blue-400" />
          </div>
          <div>
            <h1 className="text-3xl font-black tracking-tighter text-foreground uppercase">Bulk Scanner</h1>
            <p className="text-[10px] text-muted-foreground uppercase font-black tracking-[0.3em]">
              Upload CSV · Analyze up to 100 URLs or emails in parallel
            </p>
          </div>
        </div>
        <div className="flex gap-3">
          <Button onClick={downloadSample} variant="outline" className="border-blue-500/20 text-blue-400 hover:bg-blue-500/10 rounded-xl text-[10px] font-black uppercase tracking-widest h-9 px-4">
            <Download className="h-3.5 w-3.5 mr-2" />
            Sample CSV
          </Button>
          {isDone && (
            <>
              <Button onClick={runClustering} disabled={clustering || clusters.length > 0} className={cn("rounded-xl text-[10px] font-black uppercase tracking-widest h-9 px-4 shadow-[0_0_15px_rgba(37,99,235,0.3)]", clusters.length > 0 ? "bg-purple-600/50 text-white/50 cursor-not-allowed" : "bg-purple-600 hover:bg-purple-500 text-white")}>
                {clustering ? <Loader2 className="h-3.5 w-3.5 mr-2 animate-spin" /> : <Lightbulb className="h-3.5 w-3.5 mr-2" />}
                Discover Campaigns
              </Button>
              <Button onClick={exportResults} className="bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-[10px] font-black uppercase tracking-widest h-9 px-4">
                <Download className="h-3.5 w-3.5 mr-2" />
                Export Results
              </Button>
            </>
          )}
        </div>
      </header>

      {/* Drop Zone */}
      {!jobId && (
        <div
          onDragOver={e => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          onClick={() => fileRef.current?.click()}
          className={cn(
            "border-2 border-dashed rounded-3xl p-16 flex flex-col items-center gap-6 cursor-pointer transition-all duration-300",
            dragging ? "border-blue-500/60 bg-blue-500/5" : "border-white/10 hover:border-blue-500/30 hover:bg-white/3"
          )}
        >
          <input ref={fileRef} type="file" accept=".csv" className="hidden" onChange={e => { const f = e.target.files?.[0]; if (f) uploadFile(f) }} />
          {uploading
            ? <Loader2 className="h-12 w-12 text-blue-400 animate-spin" />
            : <Upload className={cn("h-12 w-12 transition-colors", dragging ? "text-blue-400" : "text-slate-600")} />
          }
          <div className="text-center space-y-2">
            <p className="text-lg font-black uppercase tracking-tight text-foreground">
              {uploading ? "Uploading..." : "Drop CSV file here"}
            </p>
            <p className="text-sm text-slate-500">or click to browse · Max 100 rows · Columns: <code className="text-blue-400 text-[11px]">url</code> or <code className="text-blue-400 text-[11px]">email</code></p>
          </div>
          {error && <p className="text-sm text-red-400 font-mono">{error}</p>}
        </div>
      )}

      {/* Progress */}
      <AnimatePresence>
        {jobStatus && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
            <Card className="card-cyber p-6 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {isRunning
                    ? <Loader2 className="h-5 w-5 text-blue-400 animate-spin" />
                    : <CheckCircle className="h-5 w-5 text-emerald-400" />
                  }
                  <div>
                    <p className="text-sm font-black uppercase tracking-tight text-foreground">
                      {isRunning ? `Analyzing ${jobStatus.completed} of ${jobStatus.total}...` : `Complete — ${jobStatus.total} items analyzed`}
                    </p>
                    <p className="text-[9px] font-mono text-slate-500">{jobId}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-2xl font-black text-blue-400 font-mono">{jobStatus.progress_percent}%</span>
                  {!isRunning && (
                    <Button onClick={() => { setJobId(null); setJobStatus(null); setResults([]) }} variant="ghost" size="icon" className="h-8 w-8 text-slate-600 hover:text-slate-400 rounded-lg">
                      <X className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              </div>

              <div className="h-2 bg-white/5 rounded-full overflow-hidden">
                <motion.div className="h-full bg-blue-500 rounded-full" animate={{ width: `${jobStatus.progress_percent}%` }} transition={{ duration: 0.5 }} />
              </div>

              {isDone && jobStatus.summary && (
                <div className="grid grid-cols-4 gap-3 pt-2">
                  {[
                    { label: "Phishing", value: jobStatus.summary.phishing, color: "text-red-400 bg-red-500/10 border-red-500/10" },
                    { label: "Suspicious", value: jobStatus.summary.suspicious, color: "text-amber-400 bg-amber-500/10 border-amber-500/10" },
                    { label: "Clean", value: jobStatus.summary.clean, color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/10" },
                    { label: "Errors", value: jobStatus.summary.errors, color: "text-slate-400 bg-white/5 border-white/5" },
                  ].map((s, i) => (
                    <div key={i} className={cn("p-3 rounded-xl border text-center space-y-1", s.color)}>
                      <p className="text-2xl font-black tracking-tighter">{s.value}</p>
                      <p className="text-[8px] font-black uppercase tracking-widest opacity-70">{s.label}</p>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            {/* Results Table */}
            {results.length > 0 && (
              <Card className="card-cyber overflow-hidden">
                <div className="p-4 border-b border-white/5 flex items-center gap-2">
                  <BarChart2 className="h-4 w-4 text-blue-400" />
                  <span className="text-[10px] font-black uppercase tracking-widest text-slate-300">Results</span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-[11px]">
                    <thead><tr className="border-b border-white/5">
                      {["#", "Input", "Verdict", "Score", "Speed"].map(h => (
                        <th key={h} className="text-left px-4 py-3 text-[8px] font-black uppercase tracking-widest text-slate-600">{h}</th>
                      ))}
                    </tr></thead>
                    <tbody>
                      {results.map(r => (
                        <tr key={r.row} className="border-b border-white/5 hover:bg-white/3">
                          <td className="px-4 py-2.5 text-slate-600 font-mono">{r.row}</td>
                          <td className="px-4 py-2.5 max-w-[280px]"><p className="font-mono text-slate-400 truncate">{r.input}</p></td>
                          <td className="px-4 py-2.5">
                            {r.verdict === "ERROR" ? (
                              <Badge className="bg-slate-500/10 text-slate-400 border-slate-500/20 text-[7px] uppercase font-bold">Error</Badge>
                            ) : (
                              <div className={cn("flex items-center gap-1.5 text-[9px] font-black uppercase",
                                r.verdict.includes("PHISHING") || r.verdict === "CONFIRMED_THREAT" ? "text-red-400"
                                  : r.verdict === "SUSPICIOUS" ? "text-amber-400" : "text-emerald-400"
                              )}>
                                {r.verdict.includes("PHISHING") || r.verdict === "CONFIRMED_THREAT"
                                  ? <ShieldAlert className="h-3 w-3" />
                                  : r.verdict === "SUSPICIOUS" ? <AlertTriangle className="h-3 w-3" /> : <ShieldCheck className="h-3 w-3" />}
                                {r.verdict.replace("_", " ")}
                              </div>
                            )}
                          </td>
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-2">
                              <div className="w-16 h-1.5 bg-white/5 rounded-full overflow-hidden">
                                <div className={cn("h-full rounded-full", r.threat_score >= 0.65 ? "bg-red-500" : r.threat_score >= 0.35 ? "bg-amber-500" : "bg-emerald-500")} style={{ width: `${r.threat_score * 100}%` }} />
                              </div>
                              <span className="font-mono text-slate-400">{Math.round(r.threat_score * 100)}%</span>
                            </div>
                          </td>
                          <td className="px-4 py-2.5 text-slate-500 font-mono">{r.inference_ms}ms</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            )}

            {/* Inferred Campaigns (Clusters) */}
            {clusters.length > 0 && (
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="space-y-4">
                <div className="flex items-center gap-3 border-b border-white/5 pb-2 mt-8">
                  <Lightbulb className="h-5 w-5 text-purple-400" />
                  <h3 className="text-sm font-black uppercase tracking-widest text-slate-200">
                    Inferred Zero-Day Campaigns
                  </h3>
                  <Badge className="bg-purple-500/10 text-purple-400 border-purple-500/20 text-[8px] uppercase tracking-widest">
                    {clusters.length} Clusters Found
                  </Badge>
                </div>
                
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  {clusters.filter(c => c.size > 1).map((cluster, i) => (
                    <Card key={i} className="card-cyber overflow-hidden border-purple-500/20 bg-purple-500/5">
                      <div className="p-5">
                        <div className="flex items-center justify-between mb-4">
                          <div className="flex items-center gap-2">
                            <Users className="h-4 w-4 text-purple-400" />
                            <span className="text-[11px] font-black tracking-widest text-slate-300 uppercase">
                              {cluster.cluster_id}
                            </span>
                          </div>
                          <Badge className={cn("text-[8px] font-black uppercase", 
                            cluster.overall_verdict === "CRITICAL" ? "bg-red-500/20 text-red-400 border-red-500/30" : 
                            "bg-amber-500/20 text-amber-400 border-amber-500/30"
                          )}>
                            {cluster.overall_verdict}
                          </Badge>
                        </div>
                        
                        <div className="space-y-3 mb-4">
                          <div className="flex items-center gap-3">
                            <div className="h-8 w-8 rounded bg-white/5 flex items-center justify-center text-xs font-mono font-bold text-slate-300">
                              {cluster.size}
                            </div>
                            <div className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">
                              Correlated Events
                            </div>
                          </div>
                          
                          {cluster.common_traits?.length > 0 && (
                            <div className="bg-black/20 rounded border border-white/5 p-3 space-y-1.5">
                              {cluster.common_traits.map((trait: string, j: number) => (
                                <div key={j} className="flex gap-2 text-[10px] text-slate-300">
                                  <span className="text-purple-400/50 mt-0.5">▪</span>
                                  <span>{trait}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                        
                        <div className="flex items-center justify-between mt-4 py-2 border-t border-white/5">
                          <span className="text-[9px] text-slate-500 uppercase tracking-widest">Avg Risk Score</span>
                          <span className="text-xs font-mono font-bold text-slate-300">
                            {Math.round(cluster.avg_risk_score * 100)}%
                          </span>
                        </div>
                      </div>
                    </Card>
                  ))}
                  {clusters.filter(c => c.size > 1).length === 0 && (
                    <div className="col-span-full border border-white/10 rounded-xl p-8 text-center text-slate-500 text-[11px] uppercase tracking-widest">
                      No multi-event campaigns detected in this batch.
                    </div>
                  )}
                </div>
              </motion.div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
