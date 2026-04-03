"use client"

import React, { useEffect, useState } from "react"
import { ShieldAlert, Globe, Activity, ShieldCheck, Target, Flag, Search, Trash2, Eye, Loader2, MousePointer2, CheckCircle, XCircle } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { RelationshipList } from "./RelationshipList"
import { cn } from "@/lib/utils"
import { type GraphNode, executeResponse } from "@/lib/api"

type BtnState = "idle" | "loading" | "success" | "error"

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001"

interface DetailsPanelProps {
  selectedNode: GraphNode | null
}

const NODE_COLORS: Record<string, string> = {
  actor: "#ef4444",
  campaign: "#f59e0b",
  domain: "#3b82f6",
  ip: "#10b981",
  technique: "#8b5cf6",
}

const RISK_COLOR: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-green-400",
}

async function fetchNodeDetail(node: GraphNode): Promise<any> {
  if (node.type === "actor") {
    const res = await fetch(`${API_BASE}/api/v1/intelligence/actor/${encodeURIComponent(node.id)}`)
    if (res.ok) return res.json()
  }
  if (node.type === "campaign") {
    const res = await fetch(`${API_BASE}/api/v1/intelligence/campaign/${encodeURIComponent(node.id)}`)
    if (res.ok) return res.json()
  }
  // For domain/ip/technique nodes return the embedded data
  return node.data || {}
}

export function DetailsPanel({ selectedNode }: DetailsPanelProps) {
  const [detail, setDetail] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [btnStates, setBtnStates] = useState<Record<string, BtnState>>({})

  const runAction = async (key: string, action: string, target: Record<string, unknown>) => {
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

  useEffect(() => {
    if (!selectedNode) {
      setDetail(null)
      return
    }
    setLoading(true)
    setDetail(null)
    fetchNodeDetail(selectedNode)
      .then(setDetail)
      .catch(() => setDetail(selectedNode.data || {}))
      .finally(() => setLoading(false))
  }, [selectedNode])

  // ── No selection state ────────────────────────────────────────────────────
  if (!selectedNode) {
    return (
      <div className="h-full flex flex-col space-y-6 animate-in fade-in slide-in-from-right-8 duration-700">
        <Card className="card-cyber overflow-hidden flex-1 flex items-center justify-center">
          <div className="flex flex-col items-center gap-4 p-8 text-center">
            <div className="h-16 w-16 rounded-2xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
              <MousePointer2 className="h-8 w-8 text-purple-400/60" />
            </div>
            <div className="space-y-1">
              <p className="text-sm font-bold text-slate-300 uppercase tracking-widest">No Node Selected</p>
              <p className="text-[10px] text-slate-600 uppercase font-bold tracking-widest">Click any node in the graph to inspect its threat profile</p>
            </div>
            <div className="flex flex-wrap gap-2 justify-center mt-2">
              {[
                { label: "Threat Actor", color: "#ef4444" },
                { label: "Campaign", color: "#f59e0b" },
                { label: "Domain IOC", color: "#3b82f6" },
                { label: "IP Address", color: "#10b981" },
              ].map(({ label, color }) => (
                <div key={label} className="flex items-center gap-1.5 px-2 py-1 rounded-full border border-white/5 bg-white/3">
                  <div className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
                  <span className="text-[8px] font-bold uppercase tracking-widest text-slate-500">{label}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>
    )
  }

  const nodeColor = NODE_COLORS[selectedNode.type] || "#3b82f6"
  const typeLabel = selectedNode.type.toUpperCase()

  // ── Loading state ─────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="h-full flex flex-col space-y-6 animate-in fade-in duration-300">
        <Card className="card-cyber overflow-hidden flex-1 flex items-center justify-center">
          <div className="flex flex-col items-center gap-3">
            <Loader2 className="h-8 w-8 animate-spin" style={{ color: nodeColor }} />
            <span className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Loading {selectedNode.label}...</span>
          </div>
        </Card>
      </div>
    )
  }

  // ── Actor / Campaign detail ───────────────────────────────────────────────
  const isActorOrCampaign = selectedNode.type === "actor" || selectedNode.type === "campaign"
  const mitreTactics: string[] = detail?.mitre_techniques || detail?.techniques || detail?.mitre || []
  const description: string = detail?.description || detail?.summary || ""
  const riskLevel: string = (detail?.threat_level || detail?.risk_level || detail?.severity || selectedNode?.data?.risk || "medium").toString().toLowerCase()
  const name: string = detail?.name || detail?.id || selectedNode.label

  // Build relationship list from detail
  // Actors have: campaigns[], mitre_techniques[], summary
  // Campaigns have: iocs.domains[], iocs.ips[], actor, techniques[]
  const relationships: { name: string; type: "actor" | "domain" | "campaign" | "ip"; relation: string }[] = []
  if (detail?.campaigns?.length) {
    detail.campaigns.slice(0, 3).forEach((c: string) => relationships.push({ name: c, type: "campaign", relation: "Active Campaign" }))
  }
  const iocDomains: string[] = detail?.iocs?.domains || detail?.ioc_domains || []
  const iocIps: string[] = detail?.iocs?.ips || detail?.ioc_ips || []
  iocDomains.slice(0, 3).forEach((d: string) => relationships.push({ name: d, type: "domain", relation: "Command & Control" }))
  iocIps.slice(0, 2).forEach((ip: string) => relationships.push({ name: ip, type: "ip", relation: "Infrastructure IP" }))
  if (detail?.actor && detail.actor !== "Unknown") {
    relationships.push({ name: detail.actor, type: "actor", relation: "Attributed Actor" })
  }
  // Generic node data rows for domain/ip/technique
  const dataEntries = Object.entries(detail || {}).filter(([k]) =>
    !["description", "summary", "name", "id", "mitre_techniques", "techniques", "mitre",
      "ioc_domains", "ioc_ips", "related_campaigns", "threat_actors"].includes(k)
  ).slice(0, 8)

  return (
    <div className="h-full flex flex-col space-y-4 animate-in fade-in slide-in-from-right-8 duration-700 overflow-y-auto">
      {/* Entity Summary */}
      <Card className="card-cyber overflow-hidden group shrink-0" style={{ borderTopColor: nodeColor + "60" }}>
        <CardHeader className="p-5 border-b border-white/5 space-y-2" style={{ background: nodeColor + "08" }}>
          <div className="flex items-center justify-between">
            <Badge className="text-[8px] h-5 rounded-full px-3 uppercase font-bold tracking-widest animate-pulse border"
                   style={{ backgroundColor: nodeColor + "15", color: nodeColor, borderColor: nodeColor + "30" }}>
              {typeLabel}
            </Badge>
            <ShieldAlert className="h-4 w-4" style={{ color: nodeColor }} />
          </div>
          <div className="space-y-1">
            <CardTitle className="text-xl font-black tracking-tighter text-foreground uppercase leading-tight" style={{ color: undefined }}>
              {name}
            </CardTitle>
          </div>
        </CardHeader>

        <CardContent className="p-5 space-y-4">
          <div className="grid grid-cols-2 gap-2">
            <div className="p-3 rounded-xl bg-white/3 border border-white/5">
              <span className="text-[8px] text-slate-600 uppercase font-bold tracking-widest mb-1 block">Risk Level</span>
              <span className={cn("text-base font-black tracking-tighter font-mono capitalize", RISK_COLOR[riskLevel] || "text-slate-300")}>
                {riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1)}
              </span>
            </div>
            <div className="p-3 rounded-xl bg-white/3 border border-white/5">
              <span className="text-[8px] text-slate-600 uppercase font-bold tracking-widest mb-1 block">Entity Type</span>
              <span className="text-base font-black text-slate-200 tracking-tighter font-mono capitalize">{selectedNode.type}</span>
            </div>
          </div>

          {mitreTactics.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <Flag className="h-3 w-3 text-red-400" />
                <h4 className="text-[9px] font-bold uppercase tracking-widest text-slate-500">MITRE ATT&CK</h4>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {mitreTactics.slice(0, 6).map((tag: string, i: number) => (
                  <Badge key={i} variant="outline" className="border-red-500/20 text-red-400 text-[8px] h-5 rounded-lg px-2 uppercase font-bold tracking-widest cursor-pointer hover:bg-red-500/10 transition-all">
                    {tag}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {description && (
            <div className="space-y-1">
              <h4 className="text-[9px] font-bold uppercase tracking-widest text-slate-500">Profile</h4>
              <p className="text-[10px] text-slate-400 leading-relaxed italic line-clamp-4">{description}</p>
            </div>
          )}

          {/* Generic key-value rows for non-actor/campaign nodes */}
          {!isActorOrCampaign && dataEntries.length > 0 && (
            <div className="space-y-1">
              {dataEntries.map(([k, v]) => (
                <div key={k} className="flex justify-between text-[9px] py-1 border-b border-white/3">
                  <span className="text-slate-500 uppercase font-bold">{k.replace(/_/g, " ")}</span>
                  <span className="text-slate-300 truncate ml-2 max-w-[140px]">{String(v)}</span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Relationships */}
      {relationships.length > 0 && (
        <Card className="card-cyber overflow-hidden p-5 shrink-0">
          <RelationshipList items={relationships} />
        </Card>
      )}

      {/* Activity + Actions */}
      <Card className="card-cyber p-5 flex flex-col justify-between shrink-0">
        <div className="space-y-3">
          <h4 className="text-[9px] font-bold uppercase tracking-widest text-slate-500">Observed Activity</h4>
          <div className="h-16 w-full flex items-end justify-between gap-0.5">
            {[40, 70, 45, 90, 65, 30, 85, 40, 55, 75, 95, 60, 40, 70, 45, 90, 65, 30, 85, 40, 55, 75, 95, 60].map((h, i) => (
              <div
                key={i}
                className="flex-1 rounded-t-sm transition-all duration-500 hover:scale-y-110"
                style={{
                  height: `${h}%`,
                  backgroundColor: i > 15 && i < 20 ? nodeColor + "60" : "rgba(255,255,255,0.05)",
                }}
              />
            ))}
          </div>
          <div className="flex justify-between text-[7px] text-slate-600 uppercase font-bold tracking-widest">
            <span>T-24h</span><span>T-12h</span><span>Now</span>
          </div>
        </div>

        <div className="pt-4 border-t border-white/5 grid grid-cols-3 gap-2 mt-4">
          {[
            {
              key: "investigate",
              label: "Investigate",
              icon: Search,
              cls: "bg-blue-500/10 text-blue-400 hover:border-blue-500/30 hover:bg-blue-500/15",
              action: () => runAction("investigate", "alert_team", {
                node_id: selectedNode?.id, node_type: selectedNode?.type, action: "investigate",
              }),
            },
            {
              key: "block_ioc",
              label: "Block IOC",
              icon: Trash2,
              cls: "bg-red-500/10 text-red-400 hover:border-red-500/30 hover:bg-red-500/15",
              action: () => runAction("block_ioc", "block_ioc", {
                node_id: selectedNode?.id, node_type: selectedNode?.type,
                domains: iocDomains, ips: iocIps,
              }),
            },
            {
              key: "watch",
              label: "Add Watch",
              icon: Eye,
              cls: "bg-blue-500/10 text-blue-400 hover:border-blue-500/30 hover:bg-blue-500/15",
              action: () => runAction("watch", "alert_team", {
                node_id: selectedNode?.id, node_type: selectedNode?.type, action: "watchlist",
              }),
            },
          ].map((btn) => {
            const st = btnStates[btn.key] ?? "idle"
            return (
              <button
                key={btn.key}
                onClick={btn.action}
                disabled={st === "loading"}
                className={cn(
                  "flex flex-col items-center justify-center h-12 rounded-xl border border-white/5 transition-all hover:scale-105 active:scale-95 gap-1 disabled:opacity-60 disabled:cursor-not-allowed disabled:hover:scale-100",
                  st === "success" ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                    : st === "error" ? "bg-red-500/10 border-red-500/40 text-red-400"
                    : btn.cls
                )}
              >
                {st === "loading" ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  : st === "success" ? <CheckCircle className="h-3.5 w-3.5" />
                  : st === "error" ? <XCircle className="h-3.5 w-3.5" />
                  : <btn.icon className="h-3.5 w-3.5" />}
                <span className="text-[7px] font-bold uppercase tracking-widest">
                  {st === "success" ? "Done" : st === "error" ? "Error" : btn.label}
                </span>
              </button>
            )
          })}
        </div>
      </Card>
    </div>
  )
}
