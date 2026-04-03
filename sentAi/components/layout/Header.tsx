"use client"

import React, { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import { getThreatFeed, ThreatFeedEvent } from "@/lib/api"
import {
  ShieldCheck,
  Menu,
  Search,
  Bell,
  Camera,
  PanelLeftOpen,
  PanelLeftClose,
  Filter,
  HelpCircle
} from "lucide-react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet"
import { Sidebar } from "./Sidebar"
import { cn } from "@/lib/utils"
import { useGlobalStore } from "@/lib/global-store"

interface HeaderProps {
  sidebarCollapsed: boolean
  setSidebarCollapsed: (collapsed: boolean) => void
}

export function Header({ sidebarCollapsed, setSidebarCollapsed }: HeaderProps) {
  const { visualSandboxEnabled, setVisualSandboxEnabled } = useGlobalStore()
  const router = useRouter()
  const [notifications, setNotifications] = useState<ThreatFeedEvent[]>([])

  useEffect(() => {
    getThreatFeed(4).then(d => setNotifications(d.events)).catch(() => {})
  }, [])

  return (
    <header className="h-14 w-full flex items-center justify-between px-4 md:px-6 bg-[#0d1117]/80 backdrop-blur-sm border-b border-blue-500/8 relative z-40">
      <div className="flex items-center space-x-4">
        {/* 📱 Mobile Menu Trigger - SHADCN SHEET */}
        <Sheet>
          <SheetTrigger asChild>
            <Button variant="ghost" size="icon" className="lg:hidden h-10 w-10 text-muted-foreground hover:text-accent hover:bg-accent/10 rounded-xl">
               <Menu className="h-6 w-6" />
            </Button>
          </SheetTrigger>
          <SheetContent side="left" className="p-0 border-r border-blue-500/10 w-60 bg-[#0d1117] shadow-2xl">
             <Sidebar />
          </SheetContent>
        </Sheet>

        {/* 🖥️ Desktop Collapse Toggle */}
        <Button 
          variant="ghost" 
          size="icon" 
          onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
          className="hidden lg:flex h-10 w-10 text-muted-foreground hover:text-accent hover:bg-accent/10 rounded-xl transition-all active:scale-95"
        >
           {sidebarCollapsed ? <PanelLeftOpen className="h-5 w-5" /> : <PanelLeftClose className="h-5 w-5" />}
        </Button>
        
        <div className="flex flex-col">
          <h2 className="text-sm font-bold tracking-tight text-slate-300 leading-none mb-1 font-mono">
            SentinelAI <span className="text-blue-400">Fusion</span>
          </h2>
          <div className="flex items-center gap-2">
            <div className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <p className="text-[9px] text-slate-500 uppercase font-mono tracking-widest">
              All systems operational
            </p>
          </div>
        </div>
      </div>

      <div className="flex items-center space-x-3 md:space-x-6">
        {/* Search Bar - Hidden on Mobile */}
        <div className="hidden lg:flex items-center relative group">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground group-focus-within:text-accent transition-colors transition-all duration-300" />
          <Input 
             onKeyDown={e => {
               if (e.key === "Enter" && e.currentTarget.value.trim()) {
                 router.push(`/dashboard/history?q=${encodeURIComponent(e.currentTarget.value)}`)
               }
             }}
             className="w-full md:w-64 xl:w-80 bg-[#070D14] border-white/5 focus:border-accent/40 rounded-xl pl-10 text-xs font-bold transition-all focus:ring-accent/20 placeholder:text-muted-foreground/40 shadow-inner" 
             placeholder="Search platform..."
          />
          <div className="absolute right-3 flex items-center space-x-1 opacity-10 group-focus-within:opacity-100 transition-opacity">
            <kbd className="text-[8px] bg-accent/20 text-accent font-black px-1.5 py-0.5 rounded border border-accent/20">K</kbd>
          </div>
        </div>

        {/* Visual Sandbox global toggle */}
        <button
          onClick={() => setVisualSandboxEnabled(!visualSandboxEnabled)}
          title={visualSandboxEnabled ? "Visual Sandbox ON — screenshots captured globally" : "Visual Sandbox OFF — click to enable globally"}
          className={cn(
            "hidden lg:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-[9px] font-black uppercase tracking-widest transition-all",
            visualSandboxEnabled
              ? "bg-purple-500/15 border-purple-500/30 text-purple-300 shadow-[0_0_10px_rgba(168,85,247,0.15)]"
              : "bg-white/3 border-white/8 text-slate-500 hover:border-white/20 hover:text-slate-400"
          )}
        >
          <Camera className={cn("h-3.5 w-3.5", visualSandboxEnabled ? "text-purple-400" : "text-slate-600")} />
          <span className="hidden xl:inline">Visual Sandbox</span>
          <span className={cn(
            "h-3.5 w-6 rounded-full flex items-center transition-all flex-shrink-0",
            visualSandboxEnabled ? "bg-purple-500/50" : "bg-white/10"
          )}>
            <span className={cn(
              "h-2.5 w-2.5 rounded-full transition-all mx-0.5",
              visualSandboxEnabled ? "bg-purple-300" : "bg-slate-600"
            )} style={{ transform: visualSandboxEnabled ? "translateX(10px)" : "translateX(0)" }} />
          </span>
        </button>

        <div className="flex items-center space-x-1 md:space-x-2 border-l border-white/5 pl-4 md:pl-6 h-10">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-9 w-9 md:h-10 md:w-10 text-muted-foreground hover:text-accent hover:bg-accent/10 rounded-xl relative transition-all active:scale-90">
                <Bell className="h-4 w-4 md:h-5 md:w-5" />
                {notifications.length > 0 && (
                  <Badge className="bg-destructive text-destructive-foreground text-[8px] h-4 min-w-4 flex items-center justify-center rounded-full p-0 absolute -top-1 -right-1 border-2 border-[#070D14] shadow-lg shadow-destructive/20 animate-in zoom-in duration-500">
                    {notifications.length}
                  </Badge>
                )}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-[85vw] md:w-80 bg-[#0D1B2A] border-blue-500/20 rounded-2xl p-2 shadow-2xl backdrop-blur-xl">
               <div className="p-3 border-b border-white/5 mb-2">
                 <h4 className="text-xs font-black uppercase tracking-widest text-accent">Real-time Alerts</h4>
               </div>
               {notifications.length === 0 ? (
                 <div className="p-4 text-center text-xs text-slate-500 font-mono">No recent alerts.</div>
               ) : (
                 notifications.map(n => (
                   <DropdownMenuItem key={n.id} className="p-3 rounded-xl focus:bg-accent/10 cursor-pointer border border-transparent focus:border-accent/20 transition-all">
                      <div className="flex space-x-3 w-full">
                        <div className={cn("h-10 w-10 shrink-0 rounded-xl flex items-center justify-center border", 
                          n.severity === "critical" ? "bg-red-500/10 border-red-500/20 text-red-400" :
                          n.severity === "high" ? "bg-orange-500/10 border-orange-500/20 text-orange-400" :
                          "bg-blue-500/10 border-blue-500/20 text-blue-400"
                        )}>
                          <Filter className="h-5 w-5" />
                        </div>
                        <div className="flex-1 w-full overflow-hidden">
                          <p className="text-xs font-black text-foreground leading-none truncate">{n.title}</p>
                          <p className="text-[10px] text-muted-foreground mt-1 line-clamp-2 opacity-70 italic lowercase break-words">{n.description}</p>
                        </div>
                      </div>
                   </DropdownMenuItem>
                 ))
               )}
            </DropdownMenuContent>
          </DropdownMenu>

          <Button variant="ghost" size="icon" className="hidden sm:flex h-9 w-9 md:h-10 md:w-10 text-muted-foreground hover:text-accent hover:bg-accent/10 rounded-xl transition-all">
             <HelpCircle className="h-4 w-4 md:h-5 md:w-5" />
          </Button>

          <div className="hidden sm:block mx-2 h-4 w-px bg-white/5" />

          <Button variant="ghost" className="p-0 h-9 w-9 md:h-10 md:w-10 rounded-full border border-accent/20 shadow-xl shadow-accent/5 overflow-hidden transition-all hover:scale-105 active:scale-95 group ring-offset-black focus:ring-2 focus:ring-accent ml-2">
             <div className="h-full w-full bg-accent/20 flex items-center justify-center text-accent font-black group-hover:bg-accent/30 transition-all">
               <span className="text-xs">A4</span>
             </div>
          </Button>
        </div>
      </div>
    </header>
  )
}
