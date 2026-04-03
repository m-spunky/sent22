"use client"

import React, { useState, useEffect, useRef, useCallback } from "react"
import { ChatHeader } from "@/components/chat/ChatHeader"
import { ChatMessage } from "@/components/chat/ChatMessage"
import { ChatInput } from "@/components/chat/ChatInput"
import { ContextPanel } from "@/components/chat/ContextPanel"
import { ScrollArea } from "@/components/ui/scroll-area"
import { sendChatMessage } from "@/lib/api"
import { MessageSquare, Plus, Clock, Trash2, ChevronLeft, ChevronRight } from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"

interface Message {
  role: "ai" | "user"
  content: string
  sources?: string[]
  suggestions?: string[]
  loading?: boolean
}

interface ChatSession {
  id: string
  title: string
  createdAt: string
  messages: Message[]
  conversationId?: string
}

const INITIAL_MESSAGES: Message[] = [
  {
    role: "ai",
    content: "Good day, Analyst. I'm SentinelChat — your AI cybersecurity operations assistant. I have full access to your SentinelAI Fusion platform data: your scan history, accuracy metrics, detected tactics, impersonated brands, and the threat knowledge graph.\n\nHow can I assist you today?",
    suggestions: [
      "What were my last 5 phishing detections?",
      "What's my false positive rate?",
      "Which brand was most impersonated in my scans?",
      "Show active threat campaigns",
    ],
  },
]

const STORAGE_KEY = "sentinelchat_sessions"
const ACTIVE_KEY = "sentinelchat_active"

function generateId() {
  return `chat_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`
}

function generateTitle(messages: Message[]): string {
  const first = messages.find(m => m.role === "user")
  if (!first) return "New Conversation"
  const text = first.content.trim()
  return text.length > 42 ? text.slice(0, 42) + "…" : text
}

function loadSessions(): ChatSession[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? JSON.parse(raw) : []
  } catch { return [] }
}

function saveSessions(sessions: ChatSession[]) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(sessions)) } catch {}
}

export default function ChatPage() {
  const [sessions, setSessions] = useState<ChatSession[]>([])
  const [activeId, setActiveId] = useState<string>("")
  const [messages, setMessages] = useState<Message[]>(INITIAL_MESSAGES)
  const [conversationId, setConversationId] = useState<string | undefined>()
  const [isLoading, setIsLoading] = useState(false)
  const [historyOpen, setHistoryOpen] = useState(true)
  const scrollRef = useRef<HTMLDivElement>(null)
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Bootstrap: load sessions from localStorage
  useEffect(() => {
    const stored = loadSessions()
    setSessions(stored)
    const lastId = localStorage.getItem(ACTIVE_KEY)
    if (lastId && stored.find(s => s.id === lastId)) {
      const session = stored.find(s => s.id === lastId)!
      setActiveId(lastId)
      setMessages(session.messages)
      setConversationId(session.conversationId)
    } else if (stored.length > 0) {
      const latest = stored[0]
      setActiveId(latest.id)
      setMessages(latest.messages)
      setConversationId(latest.conversationId)
    } else {
      // First ever session
      const id = generateId()
      setActiveId(id)
      setMessages(INITIAL_MESSAGES)
    }
  }, [])

  // Auto-scroll
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [messages])

  // Debounced save — called whenever messages/conversationId change
  const persistSession = useCallback((id: string, msgs: Message[], convId?: string) => {
    if (!id || msgs.length <= 1) return // don't save empty sessions
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
    saveTimerRef.current = setTimeout(() => {
      setSessions(prev => {
        const idx = prev.findIndex(s => s.id === id)
        const updated: ChatSession = {
          id,
          title: generateTitle(msgs),
          createdAt: idx >= 0 ? prev[idx].createdAt : new Date().toISOString(),
          messages: msgs,
          conversationId: convId,
        }
        const next = idx >= 0
          ? [updated, ...prev.filter((_, i) => i !== idx)]
          : [updated, ...prev]
        saveSessions(next.slice(0, 30)) // keep last 30 sessions
        return next.slice(0, 30)
      })
    }, 800)
  }, [])

  useEffect(() => {
    if (activeId) {
      localStorage.setItem(ACTIVE_KEY, activeId)
      persistSession(activeId, messages, conversationId)
    }
  }, [messages, conversationId, activeId, persistSession])

  const startNewChat = useCallback(() => {
    const id = generateId()
    setActiveId(id)
    setMessages(INITIAL_MESSAGES)
    setConversationId(undefined)
    localStorage.setItem(ACTIVE_KEY, id)
  }, [])

  const loadSession = useCallback((session: ChatSession) => {
    setActiveId(session.id)
    setMessages(session.messages)
    setConversationId(session.conversationId)
    localStorage.setItem(ACTIVE_KEY, session.id)
  }, [])

  const deleteSession = useCallback((id: string, e: React.MouseEvent) => {
    e.stopPropagation()
    setSessions(prev => {
      const next = prev.filter(s => s.id !== id)
      saveSessions(next)
      return next
    })
    if (id === activeId) {
      startNewChat()
    }
  }, [activeId, startNewChat])

  const handleSend = useCallback(async (text: string) => {
    if (!text.trim() || isLoading) return

    setMessages(prev => [...prev, { role: "user", content: text }])
    setIsLoading(true)
    setMessages(prev => [...prev, { role: "ai", content: "", loading: true }])

    try {
      const result = await sendChatMessage(text, conversationId)
      setConversationId(result.conversation_id)
      setMessages(prev => {
        const updated = [...prev]
        updated[updated.length - 1] = {
          role: "ai",
          content: result.response,
          sources: result.sources,
          suggestions: result.suggested_followups,
          loading: false,
        }
        return updated
      })
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : "Connection error. Is the backend running on port 8001?"
      setMessages(prev => {
        const updated = [...prev]
        updated[updated.length - 1] = {
          role: "ai",
          content: `⚠ SentinelChat inference error: ${errMsg}`,
          loading: false,
        }
        return updated
      })
    } finally {
      setIsLoading(false)
    }
  }, [isLoading, conversationId])

  const handleSuggestion = useCallback((suggestion: string) => {
    handleSend(suggestion)
  }, [handleSend])

  const formatDate = (iso: string) => {
    const d = new Date(iso)
    const now = new Date()
    const diff = now.getTime() - d.getTime()
    const days = Math.floor(diff / 86400000)
    if (days === 0) return "Today"
    if (days === 1) return "Yesterday"
    if (days < 7) return `${days}d ago`
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" })
  }

  // Group sessions by date bucket
  const sessionGroups: { label: string; items: ChatSession[] }[] = []
  const today: ChatSession[] = [], yesterday: ChatSession[] = [], older: ChatSession[] = []
  sessions.filter(s => s.id !== activeId || messages.length > 1).forEach(s => {
    const bucket = formatDate(s.createdAt)
    if (bucket === "Today") today.push(s)
    else if (bucket === "Yesterday") yesterday.push(s)
    else older.push(s)
  })
  // Current session at top if it has messages
  const currentSession = activeId ? { id: activeId, title: generateTitle(messages), createdAt: new Date().toISOString(), messages, conversationId } : null
  if (currentSession && messages.length > 1) today.unshift(currentSession as ChatSession)
  if (today.length > 0) sessionGroups.push({ label: "Today", items: today })
  if (yesterday.length > 0) sessionGroups.push({ label: "Yesterday", items: yesterday })
  if (older.length > 0) sessionGroups.push({ label: "Earlier", items: older })

  return (
    <div className="flex h-[calc(100vh-80px)] w-full gap-4 animate-in fade-in slide-in-from-bottom-6 duration-1000">

      {/* ── History Sidebar ─────────────────────────────────────────────────── */}
      <div className={cn(
        "hidden lg:flex flex-col transition-all duration-300 overflow-hidden",
        historyOpen ? "w-60 opacity-100" : "w-0 opacity-0 pointer-events-none"
      )}>
        <div className="flex flex-col h-full card-cyber overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-white/5">
            <div className="flex items-center gap-2">
              <Clock className="h-3.5 w-3.5 text-blue-400" />
              <span className="text-[10px] font-black uppercase tracking-widest text-slate-300">History</span>
            </div>
            <Button
              variant="ghost" size="icon"
              onClick={startNewChat}
              className="h-7 w-7 rounded-lg bg-blue-500/10 text-blue-400 hover:bg-blue-500/20 transition-all"
              title="New Conversation"
            >
              <Plus className="h-3.5 w-3.5" />
            </Button>
          </div>

          {/* Session List */}
          <div className="flex-1 overflow-y-auto py-2 space-y-1 px-2">
            {sessionGroups.length === 0 ? (
              <div className="flex flex-col items-center justify-center gap-2 py-8 text-center">
                <MessageSquare className="h-8 w-8 text-slate-700" />
                <p className="text-[9px] text-slate-600 uppercase font-bold tracking-widest">No history yet</p>
              </div>
            ) : (
              sessionGroups.map(group => (
                <div key={group.label}>
                  <p className="text-[8px] font-black uppercase tracking-widest text-slate-600 px-2 py-1.5">{group.label}</p>
                  {group.items.map(session => (
                    <button
                      key={session.id}
                      onClick={() => loadSession(session)}
                      className={cn(
                        "w-full text-left px-3 py-2 rounded-lg transition-all group flex items-center justify-between gap-2 hover:bg-blue-500/8",
                        session.id === activeId ? "bg-blue-500/12 border border-blue-500/20" : "border border-transparent"
                      )}
                    >
                      <div className="min-w-0 flex-1">
                        <p className={cn(
                          "text-[10px] font-bold truncate leading-tight",
                          session.id === activeId ? "text-blue-300" : "text-slate-400 group-hover:text-slate-200"
                        )}>
                          {session.title}
                        </p>
                        <p className="text-[8px] text-slate-600 mt-0.5">{formatDate(session.createdAt)}</p>
                      </div>
                      <button
                        onClick={(e) => deleteSession(session.id, e)}
                        className="opacity-0 group-hover:opacity-60 hover:!opacity-100 transition-opacity shrink-0"
                      >
                        <Trash2 className="h-3 w-3 text-slate-500 hover:text-red-400" />
                      </button>
                    </button>
                  ))}
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* ── Chat Area ───────────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col card-cyber overflow-hidden relative">
        <ChatHeader
          historyOpen={historyOpen}
          onToggleHistory={() => setHistoryOpen(o => !o)}
          onNewChat={startNewChat}
        />

        <div
          ref={scrollRef}
          className="flex-1 overflow-y-auto p-4 md:p-8 space-y-2 scroll-smooth"
        >
          {messages.map((msg, i) => (
            <ChatMessage
              key={i}
              role={msg.role}
              content={msg.content}
              sources={msg.sources}
              suggestions={msg.suggestions}
              loading={msg.loading}
              onSuggestionClick={handleSuggestion}
            />
          ))}
        </div>

        <ChatInput onSend={handleSend} disabled={isLoading} />
      </div>

      {/* ── Context Panel ───────────────────────────────────────────────────── */}
      <div className="hidden lg:flex lg:w-72 flex-col h-full bg-transparent overflow-hidden">
        <ScrollArea className="flex-1 pr-1">
          <ContextPanel />
        </ScrollArea>
      </div>
    </div>
  )
}
