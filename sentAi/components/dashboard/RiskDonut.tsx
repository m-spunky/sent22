"use client"

import React from "react"
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts"
import { TrendingUp } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"

interface Props {
  data?: { name: string; value: number; color: string }[]
  totalScore?: number
  riskLabel?: string
}

const DEFAULT_DATA = [
  { name: "Phishing", value: 65, color: "#ef4444" },
  { name: "Malware", value: 20, color: "#f59e0b" },
  { name: "Behavioral", value: 10, color: "#3b82f6" },
  { name: "Other", value: 5, color: "#8b5cf6" },
]

interface TooltipPayload {
  name: string
  value: number
  payload: { color: string }
}

const CustomTooltip = ({ active, payload }: { active?: boolean; payload?: TooltipPayload[] }) => {
  if (!active || !payload?.length) return null
  const p = payload[0]
  return (
    <div className="bg-[#111827] border border-blue-500/20 rounded-lg p-2 text-xs shadow-xl">
      <div className="flex items-center gap-2">
        <div className="h-2 w-2 rounded-full" style={{ backgroundColor: p.payload.color }} />
        <span className="text-slate-300">{p.name}</span>
        <span className="text-slate-400 font-mono ml-1">{p.value}%</span>
      </div>
    </div>
  )
}

export function RiskDonut({ data = DEFAULT_DATA, totalScore = 78, riskLabel = "Elevated" }: Props) {
  return (
    <Card className="card-cyber overflow-hidden h-full">
      <CardHeader className="p-5 border-b border-white/5">
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
              <TrendingUp className="h-3.5 w-3.5 text-amber-400" />
              Risk Distribution
            </CardTitle>
            <CardDescription className="text-[10px] text-slate-500 uppercase tracking-widest">
              Category breakdown
            </CardDescription>
          </div>
          <div className="h-2 w-2 rounded-full bg-amber-400 animate-pulse" />
        </div>
      </CardHeader>

      <CardContent className="p-4 flex flex-col items-center gap-4">
        {/* Donut chart */}
        <div className="relative w-40 h-40">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={44}
                outerRadius={64}
                paddingAngle={3}
                dataKey="value"
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} strokeWidth={0} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
          {/* Center text */}
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="text-3xl font-bold text-slate-200 font-mono">{totalScore}</span>
            <span className="text-[10px] text-slate-500 uppercase tracking-widest">%</span>
          </div>
        </div>

        {/* Legend */}
        <div className="w-full space-y-2">
          {data.map(item => (
            <div key={item.name} className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-[10px] text-slate-400 uppercase tracking-widest font-mono">{item.name}</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-16 h-1 bg-white/5 rounded-full overflow-hidden">
                  <div className="h-full rounded-full" style={{ width: `${item.value}%`, backgroundColor: item.color }} />
                </div>
                <span className="text-[10px] text-slate-500 font-mono w-8 text-right">{item.value}%</span>
              </div>
            </div>
          ))}
        </div>

        <div className="w-full pt-3 border-t border-white/5 flex justify-between items-center">
          <span className="text-[9px] text-slate-500 uppercase tracking-widest">Risk Level</span>
          <span className="text-[10px] font-bold text-amber-400 uppercase font-mono">{riskLabel}</span>
        </div>
      </CardContent>
    </Card>
  )
}
