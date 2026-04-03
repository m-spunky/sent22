"use client"

import React from "react"
import { ShieldCheck, User, Globe, Target, Activity } from "lucide-react"
import { cn } from "@/lib/utils"

export type NodeType = "actor" | "domain" | "campaign" | "ip"

interface NodeProps {
  id: string
  label: string
  type: NodeType
  x: number
  y: number
  active?: boolean
  onClick?: () => void
}

const typeStyles = {
  actor: {
    bg: "bg-destructive/10",
    border: "border-destructive/40",
    text: "text-destructive",
    glow: "shadow-[0_0_15px_rgba(255,77,109,0.3)]",
    icon: User
  },
  domain: {
    bg: "bg-blue-500/10",
    border: "border-blue-500/40",
    text: "text-blue-400",
    glow: "shadow-[0_0_15px_rgba(59,130,246,0.3)]",
    icon: Globe
  },
  campaign: {
    bg: "bg-purple-500/10",
    border: "border-purple-500/40",
    text: "text-purple-400",
    glow: "shadow-[0_0_15px_rgba(168,85,247,0.3)]",
    icon: Target
  },
  ip: {
    bg: "bg-yellow-500/10",
    border: "border-yellow-500/40",
    text: "text-yellow-400",
    glow: "shadow-[0_0_15px_rgba(234,179,8,0.3)]",
    icon: Activity
  }
}

export function Node({ label, type, x, y, active, onClick }: NodeProps) {
  const styles = typeStyles[type]
  const Icon = styles.icon
  
  return (
    <div 
      className={cn(
        "absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer transition-all duration-500 group select-none",
        active ? "scale-125 z-20" : "hover:scale-110 z-10"
      )}
      style={{ left: `${x}%`, top: `${y}%` }}
      onClick={onClick}
    >
      <div className={cn(
        "h-16 w-16 rounded-full border-2 flex items-center justify-center relative transition-all duration-300",
        styles.bg,
        styles.border,
        active ? styles.glow : "group-hover:" + styles.glow
      )}>
        {/* Pulse Effect for Active */}
        {active && (
           <div className={cn("absolute inset-[-4px] rounded-full border border-inherit animate-[ping_1.5s_linear_infinite] opacity-40")} />
        )}
        
        <Icon className={cn("h-6 w-6 transition-colors", styles.text)} />
        
        {/* Label and Subtitle */}
        <div className="absolute top-full mt-3 flex flex-col items-center">
           <span className={cn(
             "text-[10px] font-black uppercase tracking-[0.2em] whitespace-nowrap px-2 py-0.5 rounded border border-transparent transition-all",
             active ? "bg-foreground text-background" : "text-foreground group-hover:text-blue-400 group-hover:bg-white/5"
           )}>
             {label}
           </span>
           <span className="text-[7px] text-muted-foreground uppercase font-black tracking-widest mt-1 opacity-60">
             {type}
           </span>
        </div>
      </div>
    </div>
  )
}
