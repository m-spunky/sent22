"use client"

import React from "react"
import { BarChart, Bar, XAxis, YAxis, Cell, Tooltip, ResponsiveContainer } from "recharts"
import { Zap } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"

interface ShapEntry {
  feature: string
  value: number
}

interface Props {
  shapValues?: Record<string, number>
  title?: string
}

interface TooltipPayload {
  value: number
  payload: { fill: string }
  name: string
}

const CustomTooltip = ({ active, payload, label }: { active?: boolean; payload?: TooltipPayload[]; label?: string }) => {
  if (!active || !payload?.length) return null
  const val = payload[0].value
  return (
    <div className="bg-[#111827] border border-blue-500/20 rounded-lg p-2.5 text-xs shadow-xl">
      <p className="text-slate-400 mb-1 font-mono text-[10px] uppercase">{label}</p>
      <div className="flex items-center gap-2">
        <div className="h-2 w-2 rounded-full" style={{ backgroundColor: val >= 0 ? "#ef4444" : "#10b981" }} />
        <span className="text-slate-200 font-bold font-mono">{val > 0 ? "+" : ""}{(val * 100).toFixed(1)}%</span>
      </div>
    </div>
  )
}

export function ShapChart({ shapValues, title = "Feature Attribution (SHAP)" }: Props) {
  // Build entries from shap values — sort by absolute value
  const entries: ShapEntry[] = shapValues
    ? Object.entries(shapValues)
        .map(([feature, value]) => ({
          feature: feature.replace(/_/g, " ").slice(0, 22),
          value: Math.round(value * 100) / 100,
        }))
        .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
        .slice(0, 8)
    : [
        { feature: "newly registered", value: 0.20 },
        { feature: "brand impersonation", value: 0.18 },
        { feature: "auth in domain", value: 0.15 },
        { feature: "high risk tld", value: 0.12 },
        { feature: "urlhaus confirmed", value: 0.50 },
        { feature: "no mx record", value: 0.08 },
        { feature: "long subdomain", value: 0.06 },
        { feature: "https", value: -0.04 },
      ]

  return (
    <Card className="card-cyber overflow-hidden">
      <CardHeader className="p-5 border-b border-white/5">
        <div className="space-y-1">
          <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
            <Zap className="h-3.5 w-3.5 text-amber-400" />
            {title}
          </CardTitle>
          <CardDescription className="text-[10px] text-slate-500 uppercase tracking-widest">
            Contribution to threat score · red = risk ↑ · green = risk ↓
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent className="p-4">
        <ResponsiveContainer width="100%" height={Math.max(180, entries.length * 28)}>
          <BarChart
            data={entries}
            layout="vertical"
            margin={{ top: 0, right: 30, left: 0, bottom: 0 }}
          >
            <XAxis
              type="number"
              tick={{ fill: "#475569", fontSize: 9, fontFamily: "JetBrains Mono" }}
              tickFormatter={v => `${v > 0 ? "+" : ""}${(v * 100).toFixed(0)}%`}
              axisLine={false}
              tickLine={false}
              domain={["auto", "auto"]}
            />
            <YAxis
              type="category"
              dataKey="feature"
              width={130}
              tick={{ fill: "#64748b", fontSize: 9, fontFamily: "JetBrains Mono" }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(59,130,246,0.05)" }} />
            <Bar dataKey="value" radius={[0, 3, 3, 0]} maxBarSize={14}>
              {entries.map((entry, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={entry.value >= 0 ? "#ef4444" : "#10b981"}
                  fillOpacity={0.75 + Math.abs(entry.value) * 0.25}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  )
}
