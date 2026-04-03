"use client"

import React, { useState, useEffect } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import {
  ShieldCheck, LayoutDashboard, Search, Inbox, Globe,
  History, MessageSquare, ChevronRight, Wifi, WifiOff, Upload
} from "lucide-react"
import { cn } from "@/lib/utils"
import { ThemeToggle } from "@/components/ThemeToggle"

const navItems = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard, exact: true },
  { href: "/dashboard/analyze", label: "Analyze", icon: Search, badge: "PS-01", badgeColor: "bg-blue-500/10 text-blue-400 border-blue-500/20" },
  { href: "/dashboard/inbox", label: "Gmail Inbox", icon: Inbox, badge: "Live", badgeColor: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" },
  { href: "/dashboard/sandbox", label: "URL Sandbox", icon: Globe },
  { href: "/dashboard/bulk", label: "Bulk Scan", icon: Upload },
  { href: "/dashboard/history", label: "History", icon: History },
  { href: "/dashboard/chat", label: "SentinelChat", icon: MessageSquare, badge: "AI", badgeColor: "bg-amber-500/10 text-amber-400 border-amber-500/20" },
]

export function Sidebar({ collapsed }: { collapsed?: boolean }) {
  const pathname = usePathname()
  const [gmailConnected, setGmailConnected] = useState(false)
  const [backendOnline, setBackendOnline] = useState(false)

  useEffect(() => {
    fetch("/api/v1/gmail/status")
      .then(r => r.json())
      .then(d => { setGmailConnected(d.connected); setBackendOnline(true) })
      .catch(() => setBackendOnline(false))
  }, [])

  return (
    <aside className="h-full w-64 sidebar-bg flex flex-col">
      {/* Logo */}
      <Link href="/" className="flex items-center gap-3 px-5 py-5 border-b border-white/5 group">
        <div className="h-9 w-9 bg-blue-500/20 rounded-xl flex items-center justify-center border border-blue-500/30 group-hover:scale-110 transition-transform shadow-[0_0_15px_rgba(59,130,246,0.3)]">
          <ShieldCheck className="h-5 w-5 text-blue-400" />
        </div>
        <div className="flex flex-col leading-none">
          <span className="text-sm font-black tracking-tighter text-foreground uppercase">SentinelAI</span>
          <span className="text-[8px] text-blue-400/80 font-black tracking-[0.3em] uppercase mt-0.5">Fusion v3.0</span>
        </div>
      </Link>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto py-4 px-3 space-y-0.5">
        <div className="mb-3 px-2">
          <p className="text-[8px] font-black uppercase tracking-[0.4em] text-slate-600">Detection Suite</p>
        </div>

        {navItems.map((item) => {
          const isActive = item.exact ? pathname === item.href : pathname.startsWith(item.href)
          const Icon = item.icon
          return (
            <Link key={item.href} href={item.href}>
              <div className={cn(
                "group relative flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 cursor-pointer",
                isActive
                  ? "bg-blue-500/10 text-blue-400"
                  : "text-slate-500 hover:text-slate-300 hover:bg-white/5"
              )}>
                {isActive && (
                  <div className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-6 bg-blue-400 rounded-r-full shadow-[0_0_8px_rgba(59,130,246,0.6)]" />
                )}
                <Icon className={cn("h-4 w-4 flex-shrink-0 transition-colors", isActive ? "text-blue-400" : "text-slate-600 group-hover:text-slate-400")} />
                <span className="text-[11px] font-bold uppercase tracking-wider flex-1">{item.label}</span>
                {item.badge && (
                  <span className={cn("text-[7px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded border", item.badgeColor || "bg-blue-500/10 text-blue-400 border-blue-500/20")}>
                    {item.badge}
                  </span>
                )}
                {!item.badge && isActive && <ChevronRight className="h-3 w-3 opacity-40" />}
                {item.href === "/dashboard/inbox" && (
                  <div className={cn("h-1.5 w-1.5 rounded-full", gmailConnected ? "bg-emerald-400 animate-pulse" : "bg-slate-700")} />
                )}
              </div>
            </Link>
          )
        })}
      </nav>

      {/* Bottom Status */}
      <div className="px-4 py-4 border-t border-white/5 space-y-2.5">
        <div className="flex items-center justify-between text-[9px] font-bold uppercase tracking-widest">
          <span className="text-slate-600">Backend API</span>
          <div className="flex items-center gap-1.5">
            {backendOnline
              ? <><Wifi className="h-3 w-3 text-emerald-400" /><span className="text-emerald-400">Online</span></>
              : <><WifiOff className="h-3 w-3 text-red-400" /><span className="text-red-400">Offline</span></>
            }
          </div>
        </div>
        <div className="flex items-center justify-between text-[9px] font-bold uppercase tracking-widest">
          <span className="text-slate-600">Gmail</span>
          <div className="flex items-center gap-1.5">
            <div className={cn("h-1.5 w-1.5 rounded-full", gmailConnected ? "bg-emerald-400 animate-pulse" : "bg-slate-700")} />
            <span className={gmailConnected ? "text-emerald-400" : "text-slate-600"}>{gmailConnected ? "Connected" : "Not linked"}</span>
          </div>
        </div>
        <div className="pt-2 border-t border-white/5 flex items-center gap-2.5">
          <div className="h-7 w-7 rounded-lg bg-gradient-to-br from-blue-500/30 to-purple-500/30 border border-blue-500/20 flex items-center justify-center text-[10px] font-black text-blue-300">S</div>
          <div className="flex flex-col leading-none flex-1">
            <span className="text-[10px] font-bold text-slate-300">SOC Analyst</span>
            <span className="text-[8px] text-slate-600 uppercase tracking-widest">PS-01 Mode</span>
          </div>
          <ThemeToggle />
        </div>
      </div>
    </aside>
  )
}
