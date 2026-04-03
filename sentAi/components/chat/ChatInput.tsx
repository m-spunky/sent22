"use client"

import React, { useState, useRef, useCallback } from "react"
import { Send, Filter, Sparkles } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"

interface ChatInputProps {
  onSend?: (message: string) => void
  disabled?: boolean
}

export function ChatInput({ onSend, disabled }: ChatInputProps) {
  const [value, setValue] = useState("")
  const inputRef = useRef<HTMLInputElement>(null)

  const handleSend = useCallback(() => {
    const text = value.trim()
    if (!text || disabled) return
    onSend?.(text)
    setValue("")
  }, [value, disabled, onSend])

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  return (
    <div className="p-4 pt-0 mt-auto bg-gradient-to-t from-[#0D1B2A] to-transparent">
      <div className="relative group w-full">
        <div className="absolute -inset-1 bg-blue-500/10 rounded-3xl blur-xl opacity-0 group-focus-within:opacity-100 transition-opacity duration-700 pointer-events-none" />

        <div className="relative flex items-center bg-[#0D1B2A]/80 backdrop-blur-xl border border-blue-500/15 group-focus-within:border-blue-500/40 rounded-3xl p-2 pl-6 shadow-2xl transition-all duration-300">
          <div className="flex items-center text-muted-foreground mr-4 group-focus-within:text-blue-400 transition-colors">
            <Sparkles className="h-5 w-5" />
          </div>

          <Input
            ref={inputRef}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about threats, campaigns, or security insights..."
            disabled={disabled}
            className="flex-1 bg-transparent border-none focus-visible:ring-0 text-sm font-bold placeholder:text-muted-foreground/30 h-10 px-0 disabled:opacity-50"
          />

          <div className="flex items-center space-x-2 mr-2">
            <Button variant="ghost" size="icon" className="h-10 w-10 text-muted-foreground hover:text-blue-400 hover:bg-blue-500/10 rounded-2xl transition-colors">
              <Filter className="h-4 w-4" />
            </Button>
            <div className="h-6 w-px bg-white/5 mx-1" />
            <Button
              size="icon"
              onClick={handleSend}
              disabled={disabled || !value.trim()}
              className="h-10 w-10 rounded-2xl bg-blue-600 text-white hover:bg-blue-500 shadow-[0_0_15px_rgba(59,130,246,0.3)] transition-all hover:scale-110 active:scale-90 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {disabled ? (
                <div className="h-4 w-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
              ) : (
                <Send className="h-4 w-4" />
              )}
            </Button>
          </div>
        </div>

        <div className="flex items-center justify-between mt-2 px-4">
          <div className="flex items-center space-x-6">
            <div className="flex items-center space-x-1.5 opacity-40 hover:opacity-100 transition-opacity cursor-pointer">
              <kbd className="text-[8px] bg-blue-500/10 text-blue-400 font-black px-1.5 py-0.5 rounded border border-blue-500/20 uppercase tracking-tighter shadow-lg">Enter</kbd>
              <span className="text-[8px] text-muted-foreground font-black uppercase tracking-widest leading-none">Send</span>
            </div>
          </div>

          <div className="flex items-center space-x-2 opacity-60">
            <div className={`h-1.5 w-1.5 rounded-full ${disabled ? "bg-amber-400 animate-pulse" : "bg-emerald-400"}`} />
            <span className={`text-[8px] uppercase font-black tracking-widest leading-none ${disabled ? "text-amber-400" : "text-emerald-400"}`}>
              {disabled ? "Processing..." : "SentinelChat Active"}
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}
