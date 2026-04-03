"use client"

import React from "react"
import { MessageSquare, ShieldCheck, MoreHorizontal, PanelLeftOpen, PanelLeftClose, Plus } from "lucide-react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

interface ChatHeaderProps {
  historyOpen?: boolean
  onToggleHistory?: () => void
  onNewChat?: () => void
}

export function ChatHeader({ historyOpen, onToggleHistory, onNewChat }: ChatHeaderProps) {
  return (
    <header className="h-16 w-full flex items-center justify-between px-4 md:px-6 border-b border-white/5 bg-[#0D1B2A]/40 backdrop-blur-md rounded-t-3xl">
      <div className="flex items-center space-x-3">
        {/* History toggle (desktop) */}
        {onToggleHistory && (
          <Button
            variant="ghost" size="icon"
            onClick={onToggleHistory}
            className="hidden lg:flex h-8 w-8 text-muted-foreground hover:text-blue-400 hover:bg-blue-500/10 rounded-lg"
            title={historyOpen ? "Hide history" : "Show history"}
          >
            {historyOpen ? <PanelLeftClose className="h-4 w-4" /> : <PanelLeftOpen className="h-4 w-4" />}
          </Button>
        )}

        <div className="h-9 w-9 rounded-xl bg-blue-500/20 flex items-center justify-center border border-blue-500/30 shadow-xl shadow-blue-500/10">
          <MessageSquare className="h-4 w-4 text-blue-400" />
        </div>
        <div className="space-y-0.5">
          <div className="flex items-center space-x-2">
            <h1 className="text-lg font-black tracking-tight text-foreground uppercase leading-none">SentinelChat</h1>
            <div className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
          </div>
          <p className="text-[9px] text-muted-foreground uppercase font-black tracking-[0.1em] opacity-80 leading-none">
            AI Cybersecurity Operations Assistant
            <span className="mx-2 text-white/5">|</span>
            <span className="text-blue-400 font-normal lowercase italic">v2.4-LLM-Inference</span>
          </p>
        </div>
      </div>

      <div className="flex items-center space-x-2">
        <div className="hidden lg:flex flex-col items-end mr-3">
          <p className="text-[8px] text-muted-foreground uppercase font-black tracking-[0.2em] leading-none mb-1">Inference Status</p>
          <div className="flex items-center space-x-1.5">
            <span className="text-[8px] font-bold text-emerald-400 italic lowercase leading-none">Healthy & Optimized</span>
            <div className="h-1 w-1 rounded-full bg-emerald-400" />
          </div>
        </div>
        {onNewChat && (
          <Button
            variant="ghost" size="icon"
            onClick={onNewChat}
            className="h-8 w-8 text-muted-foreground hover:text-blue-400 hover:bg-blue-500/10 rounded-lg"
            title="New conversation"
          >
            <Plus className="h-4 w-4" />
          </Button>
        )}
        <Button variant="ghost" size="icon" className="h-8 w-8 text-muted-foreground hover:text-blue-400 hover:bg-blue-500/10 rounded-lg">
          <ShieldCheck className="h-4 w-4" />
        </Button>
        <Button variant="ghost" size="icon" className="h-8 w-8 text-muted-foreground hover:text-blue-400 hover:bg-blue-500/10 rounded-lg">
          <MoreHorizontal className="h-4 w-4" />
        </Button>
      </div>
    </header>
  )
}
