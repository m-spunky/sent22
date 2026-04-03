"use client"

import React from "react"
import { LucideIcon } from "lucide-react"
import { Card } from "@/components/ui/card"
import { cn } from "@/lib/utils"

interface InputTypeCardProps {
  title: string
  description: string
  icon: LucideIcon
  active: boolean
  onClick: () => void
}

export function InputTypeCard({ title, description, icon: Icon, active, onClick }: InputTypeCardProps) {
  return (
    <Card
      onClick={onClick}
      className={cn(
        "relative p-5 cursor-pointer transition-all duration-300 rounded-2xl border flex flex-col items-start gap-4 h-full",
        "hover:-translate-y-1 group",
        active
          ? "bg-blue-500/5 border-blue-500/40 shadow-[0_0_25px_rgba(59,130,246,0.15)] ring-1 ring-blue-500/20"
          : "bg-[#0D1B2A] border-white/10 hover:border-blue-500/20"
      )}
    >
      <div className={cn(
        "absolute top-4 right-4 h-1.5 w-1.5 rounded-full transition-all duration-500",
        active ? "bg-blue-400 animate-pulse shadow-[0_0_8px_rgba(59,130,246,0.6)]" : "bg-white/10"
      )} />

      <div className={cn(
        "p-3 rounded-xl border transition-colors",
        active
          ? "bg-blue-500/20 border-blue-500/30 text-blue-400"
          : "bg-white/5 border-white/5 text-muted-foreground group-hover:text-blue-400 group-hover:border-blue-500/20 group-hover:bg-blue-500/5"
      )}>
        <Icon className="h-5 w-5" />
      </div>

      <div className="space-y-1">
        <h4 className={cn(
          "text-sm font-black uppercase tracking-wider transition-colors",
          active ? "text-blue-300" : "text-muted-foreground group-hover:text-foreground"
        )}>{title}</h4>
        <p className="text-[10px] text-muted-foreground leading-relaxed font-medium">
          {description}
        </p>
      </div>

      {active && (
        <div className="absolute inset-x-0 bottom-0 h-0.5 bg-gradient-to-r from-transparent via-blue-500/40 to-transparent" />
      )}
    </Card>
  )
}
