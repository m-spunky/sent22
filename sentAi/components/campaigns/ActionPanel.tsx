"use client"

import React, { useState } from "react"
import { ShieldAlert, Globe, MessageSquare, Activity, ShieldCheck, Loader2, CheckCircle, XCircle } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { cn } from "@/lib/utils"
import { executeResponse } from "@/lib/api"
import type { Campaign } from "@/lib/api"

type BtnState = "idle" | "loading" | "success" | "error"

interface ActionPanelProps {
  campaign?: Campaign | null
}

export function ActionPanel({ campaign }: ActionPanelProps) {
  const [btnStates, setBtnStates] = useState<Record<string, BtnState>>({})

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

  const actions = [
    {
      key: "quarantine",
      label: "Quarantine",
      icon: ShieldAlert,
      cls: "border-red-500/20 hover:border-red-500/40 text-red-400 hover:bg-red-500/8",
      desc: "Isolate related assets",
      handler: () => run("quarantine", "quarantine", {
        campaign_id: campaign?.id,
        actor: campaign?.actor,
        domains: campaign?.iocs?.domains ?? [],
      }),
    },
    {
      key: "block_domains",
      label: "Block Domains",
      icon: Globe,
      cls: "border-orange-500/20 hover:border-orange-500/40 text-orange-400 hover:bg-orange-500/8",
      desc: "Update sinkholes",
      handler: () => run("block_domains", "block_ioc", {
        campaign_id: campaign?.id,
        domains: campaign?.iocs?.domains ?? [],
        ips: campaign?.iocs?.ips ?? [],
      }),
    },
    {
      key: "notify_team",
      label: "Notify Team",
      icon: MessageSquare,
      cls: "border-blue-500/20 hover:border-blue-500/40 text-blue-400 hover:bg-blue-500/8",
      desc: "Send security alerts",
      handler: () => run("notify_team", "alert_team", {
        campaign_id: campaign?.id,
        campaign_name: campaign?.name,
        risk_level: campaign?.risk_level,
        actor: campaign?.actor,
      }),
    },
    {
      key: "escalate",
      label: "Escalate L3",
      icon: Activity,
      cls: "border-amber-500/20 hover:border-amber-500/40 text-amber-400 hover:bg-amber-500/8",
      desc: "Alert global response",
      handler: () => run("escalate", "alert_team", {
        campaign_id: campaign?.id,
        escalation_level: "L3",
        campaign_name: campaign?.name,
        actor: campaign?.actor,
      }),
    },
  ]

  return (
    <Card className="card-cyber border-t-2 border-t-blue-500/30 overflow-hidden relative bg-blue-500/3">
      <div className="absolute top-0 right-0 p-8 opacity-10">
         <ShieldCheck className="h-24 w-24 text-blue-400" />
      </div>
      <CardContent className="p-8 flex flex-col md:flex-row items-center justify-between gap-8 relative z-10">
         <div className="space-y-3 text-center md:text-left">
            <h2 className="text-xl font-bold tracking-tight text-slate-200 uppercase font-mono">Response Operations</h2>
            <p className="text-xs text-slate-500 uppercase tracking-widest font-mono">
               Deploy automated remediation for active campaign
            </p>
         </div>

         <div className="flex flex-wrap items-center justify-center gap-3">
            {actions.map((btn) => {
              const state = btnStates[btn.key] ?? "idle"
              return (
                <button
                  key={btn.key}
                  onClick={btn.handler}
                  disabled={state === "loading"}
                  className={cn(
                    "flex flex-col items-center justify-center h-20 w-36 rounded-xl border font-bold uppercase tracking-wider text-[9px] transition-all hover:scale-105 active:scale-95 font-mono gap-1.5 p-3 disabled:opacity-60 disabled:cursor-not-allowed disabled:hover:scale-100",
                    btn.cls,
                    state === "success" && "border-emerald-500/40 bg-emerald-500/8 text-emerald-400",
                    state === "error" && "border-red-500/50 bg-red-500/10 text-red-300",
                  )}
                >
                  {state === "loading" ? <Loader2 className="h-5 w-5 animate-spin" />
                    : state === "success" ? <CheckCircle className="h-5 w-5 text-emerald-400" />
                    : state === "error" ? <XCircle className="h-5 w-5 text-red-400" />
                    : <btn.icon className="h-5 w-5" />}
                  <span className="leading-tight text-center">
                    {state === "success" ? "Done" : state === "error" ? "Failed" : btn.label}
                  </span>
                  <span className="text-[7px] font-normal lowercase italic opacity-60">{btn.desc}</span>
                </button>
              )
            })}
         </div>
      </CardContent>
    </Card>
  )
}
