"use client"

import React from "react"
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts"
import { Activity } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"

interface DataPoint {
  time: string
  threat_count: number
  type_breakdown?: Record<string, number>
}

interface Props {
  data?: DataPoint[]
  hours?: number
  totalThreats?: number
}

function formatHour(isoString: string): string {
  try {
    const d = new Date(isoString)
    return d.getUTCHours().toString().padStart(2, "0") + ":00"
  } catch {
    return isoString
  }
}

interface TooltipPayloadItem {
  color: string
  name: string
  value: number
}

const CustomTooltip = ({ active, payload, label }: { active?: boolean; payload?: TooltipPayloadItem[]; label?: string }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-[#111827] border border-blue-500/20 rounded-lg p-3 text-xs shadow-xl">
      <p className="text-slate-400 mb-2 font-mono">{label}</p>
      {payload.map((p, i) => (
        <div key={i} className="flex items-center gap-2">
          <div className="h-2 w-2 rounded-full" style={{ backgroundColor: p.color }} />
          <span className="text-slate-300 capitalize">{p.name}</span>
          <span className="text-slate-400 ml-auto font-mono">{p.value}</span>
        </div>
      ))}
    </div>
  )
}

export function ThreatTimeline({ data = [], hours = 24, totalThreats = 0 }: Props) {
  const chartData = data.map(d => ({
    time: formatHour(d.time),
    phishing: d.type_breakdown?.phishing || 0,
    malware: d.type_breakdown?.malware || 0,
    behavioral: d.type_breakdown?.behavioral || 0,
    other: d.type_breakdown?.other || 0,
    total: d.threat_count,
  }))

  return (
    <Card className="card-cyber overflow-hidden">
      <CardHeader className="p-5 border-b border-white/5 flex flex-row items-center justify-between">
        <div className="space-y-1">
          <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
            <Activity className="h-3.5 w-3.5 text-blue-400" />
            Threat Activity — {hours}h Window
          </CardTitle>
          <CardDescription className="text-[10px] text-slate-500 uppercase tracking-widest">
            {totalThreats.toLocaleString()} events detected
          </CardDescription>
        </div>
        <Badge variant="outline" className="text-[9px] border-blue-500/20 text-blue-400 uppercase">
          Live
          <span className="ml-1.5 h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse inline-block" />
        </Badge>
      </CardHeader>
      <CardContent className="p-4">
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={chartData} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="phishing" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="malware" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="behavioral" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(59,130,246,0.07)" />
            <XAxis
              dataKey="time"
              tick={{ fill: "#475569", fontSize: 9, fontFamily: "JetBrains Mono" }}
              interval={Math.floor(chartData.length / 6)}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: "#475569", fontSize: 9, fontFamily: "JetBrains Mono" }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip content={<CustomTooltip />} />
            <Area type="monotone" dataKey="phishing" stroke="#ef4444" strokeWidth={1.5} fill="url(#phishing)" name="phishing" />
            <Area type="monotone" dataKey="malware" stroke="#f59e0b" strokeWidth={1.5} fill="url(#malware)" name="malware" />
            <Area type="monotone" dataKey="behavioral" stroke="#3b82f6" strokeWidth={1.5} fill="url(#behavioral)" name="behavioral" />
          </AreaChart>
        </ResponsiveContainer>

        <div className="flex items-center gap-4 mt-2 justify-center">
          {[
            { color: "#ef4444", label: "Phishing" },
            { color: "#f59e0b", label: "Malware" },
            { color: "#3b82f6", label: "Behavioral" },
          ].map(item => (
            <div key={item.label} className="flex items-center gap-1.5">
              <div className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color }} />
              <span className="text-[9px] text-slate-500 uppercase tracking-widest font-mono">{item.label}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
