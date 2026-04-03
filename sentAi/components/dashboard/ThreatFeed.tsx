"use client"

import React, { useEffect, useState, useRef } from "react"
import { ShieldAlert, Fingerprint, Activity, Clock, Wifi, WifiOff } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { getThreatFeed, WS_BASE, type ThreatFeedEvent } from "@/lib/api"

const SEVERITY_ROW: Record<string, string> = {
  critical: "border-l-2 border-red-500/50 hover:bg-red-500/5",
  high: "border-l-2 border-orange-500/50 hover:bg-orange-500/5",
  medium: "border-l-2 border-amber-500/50 hover:bg-amber-500/5",
  low: "border-l-2 border-blue-500/50 hover:bg-blue-500/5",
}

const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-blue-500",
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/20",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  medium: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  low: "bg-blue-500/10 text-blue-400 border-blue-500/20",
}

const STATIC_EVENTS: ThreatFeedEvent[] = [
  { id: "1", type: "phishing", title: "BEC Attack Intercepted", description: "Spear-phishing targeting CFO — FIN7 infrastructure detected", severity: "critical", timestamp: "", time_ago: "2m ago" },
  { id: "2", type: "malware", title: "Malicious Attachment Blocked", description: "PDF with embedded macro payload — GIBON loader signature", severity: "high", timestamp: "", time_ago: "15m ago" },
  { id: "3", type: "behavioral", title: "Credential Stuffing Detected", description: "847 automated login attempts from 192.168.45.21 (UA)", severity: "critical", timestamp: "", time_ago: "32m ago" },
  { id: "4", type: "policy", title: "SPF/DKIM Failure Spike", description: "12 emails failed authentication from spoofed finance domain", severity: "medium", timestamp: "", time_ago: "1h ago" },
  { id: "5", type: "phishing", title: "QR Code Phishing Attempt", description: "QR code points to HR portal clone — 91% visual similarity", severity: "high", timestamp: "", time_ago: "2h ago" },
]

export function ThreatFeed({ compact = false }: { compact?: boolean }) {
  const [events, setEvents] = useState<ThreatFeedEvent[]>([])
  const [wsConnected, setWsConnected] = useState(false)
  const [newEventId, setNewEventId] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)

  // Fetch initial events from REST API
  useEffect(() => {
    const load = async () => {
      try {
        const data = await getThreatFeed(10)
        setEvents(data.events)
      } catch {
        // keep static fallback
      }
    }
    load()
  }, [])

  // Connect WebSocket for real-time events
  useEffect(() => {
    let reconnectTimer: NodeJS.Timeout

    const connect = () => {
      try {
        const ws = new WebSocket(`${WS_BASE}/api/v1/stream`)
        wsRef.current = ws

        ws.onopen = () => setWsConnected(true)

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data)
            if (data.type === "heartbeat" || data.type === "connected" || data.type === "pong") return

            // New threat event
            const newEvent: ThreatFeedEvent = {
              id: data.id || `ws_${Date.now()}`,
              type: data.type || "phishing",
              title: data.title || "Threat Detected",
              description: data.description || "",
              severity: (data.severity as ThreatFeedEvent["severity"]) || "high",
              timestamp: data.timestamp || new Date().toISOString(),
              time_ago: "just now",
            }
            setEvents(prev => [newEvent, ...prev.slice(0, 9)])
            setNewEventId(newEvent.id)
            setTimeout(() => setNewEventId(null), 3000)
          } catch {
            // ignore parse errors
          }
        }

        ws.onclose = () => {
          setWsConnected(false)
          reconnectTimer = setTimeout(connect, 5000)
        }

        ws.onerror = () => ws.close()

        // Ping to keep alive
        const pingInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send("ping")
        }, 25000)

        return () => clearInterval(pingInterval)
      } catch {
        reconnectTimer = setTimeout(connect, 5000)
      }
    }

    connect()
    return () => {
      clearTimeout(reconnectTimer)
      wsRef.current?.close()
    }
  }, [])

  const allEvents = events.length > 0 ? events : STATIC_EVENTS
  const displayEvents = compact ? allEvents.slice(0, 4) : allEvents

  return (
    <Card className="card-cyber overflow-hidden flex flex-col h-full">
      <CardHeader className="p-5 border-b border-white/5 flex flex-row items-center justify-between shrink-0">
        <div className="space-y-1">
          <CardTitle className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
            <Activity className="h-3.5 w-3.5 text-blue-400" />
            Live Threat Feed
          </CardTitle>
          <CardDescription className="text-[10px] text-slate-500 uppercase tracking-widest flex items-center gap-1.5">
            Real-time monitoring
            <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          {wsConnected ? (
            <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/20 text-[9px] uppercase">
              <Wifi className="h-2.5 w-2.5 mr-1" />
              Live
            </Badge>
          ) : (
            <Badge className="bg-slate-500/10 text-slate-500 border-slate-500/20 text-[9px] uppercase">
              <WifiOff className="h-2.5 w-2.5 mr-1" />
              Polling
            </Badge>
          )}
        </div>
      </CardHeader>

      <CardContent className="flex-1 overflow-y-auto p-0">
        <div className="divide-y divide-white/5">
          {displayEvents.map((event) => (
            <div
              key={event.id}
              className={cn(
                "pl-3 pr-4 py-3 transition-all duration-300 cursor-pointer",
                SEVERITY_ROW[event.severity] || "hover:bg-white/5",
                event.id === newEventId && "bg-blue-500/5 animate-pulse"
              )}
            >
              <div className="flex items-start gap-3">
                <div className="mt-1.5 flex flex-col items-center gap-1">
                  <div className={cn("h-2 w-2 rounded-full shrink-0", SEVERITY_DOT[event.severity] || "bg-slate-500")} />
                </div>

                <div className="flex-1 min-w-0 space-y-1">
                  <div className="flex items-start justify-between gap-2">
                    <h4 className="text-[11px] font-bold text-slate-300 leading-tight uppercase tracking-tight">
                      {event.title}
                    </h4>
                    <div className="flex items-center gap-1 text-[9px] text-slate-500 uppercase shrink-0 font-mono">
                      <Clock className="h-2.5 w-2.5" />
                      {event.time_ago || "now"}
                    </div>
                  </div>
                  <p className="text-[10px] text-slate-500 leading-relaxed line-clamp-2">
                    {event.description}
                  </p>
                  <Badge className={cn(
                    "text-[8px] h-4 rounded px-2 py-0 border font-bold uppercase tracking-widest mt-1",
                    SEVERITY_BADGE[event.severity] || "bg-slate-500/10 text-slate-400"
                  )}>
                    {event.severity}
                  </Badge>
                </div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>

      <div className="p-3 border-t border-white/5 shrink-0">
        <Button variant="ghost" className="w-full text-[9px] font-bold uppercase tracking-widest text-slate-500 h-7 rounded-lg hover:bg-white/5 hover:text-blue-400">
          View all incident logs →
        </Button>
      </div>
    </Card>
  )
}
