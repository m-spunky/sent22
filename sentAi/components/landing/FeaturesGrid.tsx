"use client"

import React from "react"
import {
  Mail, Globe, QrCode, Upload, BrainCircuit, ShieldAlert,
  MessageSquare, Eye, Cpu
} from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

const features = [
  {
    title: "Email & URL Detection",
    desc: "5-layer AI fusion: NLP language model, URL reputation/WHOIS, visual brand matching via CLIP, email header SPF/DKIM/DMARC, and threat intelligence correlation.",
    icon: ShieldAlert,
    gradient: "from-blue-500/20 to-blue-500/5",
    iconColor: "text-blue-400",
    borderHover: "hover:border-blue-500/40 hover:shadow-[0_0_50px_rgba(59,130,246,0.1)]",
    badge: "PS-01 · Core",
    badgeColor: "text-blue-400 border-blue-500/30 bg-blue-500/10",
  },
  {
    title: "Gmail Inbox Integration",
    desc: "Connect your Gmail via OAuth2 to automatically scan your entire inbox. Every email gets a risk score. One-click quarantine or mark-safe from within the platform.",
    icon: Mail,
    gradient: "from-emerald-500/20 to-emerald-500/5",
    iconColor: "text-emerald-400",
    borderHover: "hover:border-emerald-500/40 hover:shadow-[0_0_50px_rgba(16,185,129,0.1)]",
    badge: "Live · OAuth2",
    badgeColor: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
  },
  {
    title: "URL Deep Sandbox",
    desc: "Unwind redirect chains, validate SSL certificates, scrape DOM for password fields and credential harvesting, and capture screenshots via Apify browser automation.",
    icon: Globe,
    gradient: "from-purple-500/20 to-purple-500/5",
    iconColor: "text-purple-400",
    borderHover: "hover:border-purple-500/40 hover:shadow-[0_0_50px_rgba(168,85,247,0.1)]",
    badge: "PS-01 · Sandbox",
    badgeColor: "text-purple-400 border-purple-500/30 bg-purple-500/10",
  },
  {
    title: "QR Quishing Detection",
    desc: "Upload a QR code image. The platform decodes the embedded URL using computer vision, then runs the full 5-layer phishing analysis pipeline on the extracted link.",
    icon: QrCode,
    gradient: "from-amber-500/20 to-amber-500/5",
    iconColor: "text-amber-400",
    borderHover: "hover:border-amber-500/40 hover:shadow-[0_0_50px_rgba(245,158,11,0.1)]",
    badge: "Multi-Modal",
    badgeColor: "text-amber-400 border-amber-500/30 bg-amber-500/10",
  },
  {
    title: "Bulk CSV Analysis",
    desc: "Upload a CSV of up to 100 URLs or email samples. Processed in parallel with live progress tracking, summary breakdown, and exportable results — ideal for SOC triage.",
    icon: Upload,
    gradient: "from-red-500/20 to-red-500/5",
    iconColor: "text-red-400",
    borderHover: "hover:border-red-500/40 hover:shadow-[0_0_50px_rgba(239,68,68,0.1)]",
    badge: "Batch · 100x",
    badgeColor: "text-red-400 border-red-500/30 bg-red-500/10",
  },
  {
    title: "SentinelChat + Dark Web",
    desc: "AI security chatbot (PS-04) for natural language threat queries. HaveIBeenPwned dark web monitoring (PS-05) checks sender domains against known breach databases in real time.",
    icon: MessageSquare,
    gradient: "from-slate-500/20 to-slate-500/5",
    iconColor: "text-slate-400",
    borderHover: "hover:border-slate-500/40 hover:shadow-[0_0_50px_rgba(100,116,139,0.1)]",
    badge: "PS-04 · PS-05",
    badgeColor: "text-slate-400 border-slate-500/30 bg-slate-500/10",
  },
]

export function FeaturesGrid() {
  return (
    <section id="features" className="relative py-16 md:py-24 px-6 bg-background overflow-hidden border-t border-border/50">
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 h-[900px] w-[900px] bg-blue-500/5 rounded-full blur-[200px] -z-10" />

      <div className="max-w-7xl mx-auto space-y-16">
        <div className="max-w-3xl space-y-5">
          <div className="flex items-center space-x-3 text-blue-400/60 uppercase font-black tracking-[0.4em] text-[10px]">
            <Cpu className="h-4 w-4" />
            <span>Platform Capabilities</span>
          </div>
          <h2 className="text-4xl md:text-6xl font-black tracking-tighter text-foreground uppercase leading-[1.0]">
            Everything You Need<br />
            <span className="text-blue-400">To Stop Phishing.</span>
          </h2>
          <p className="text-lg text-muted-foreground/80 font-medium leading-relaxed max-w-2xl">
            Built for PS-01 evaluation metrics — accuracy, false positive rate, detection speed, and explainability —
            with PS-02 through PS-05 as bonus coverage.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 animate-in fade-in slide-in-from-bottom-12 duration-1000 delay-300">
          {features.map((feature, i) => (
            <Card
              key={i}
              className={cn(
                "group card-cyber overflow-hidden border-white/8 p-0 transform transition-all duration-500 hover:-translate-y-2 relative",
                feature.borderHover
              )}
            >
              <div className={cn(
                "absolute inset-0 bg-gradient-to-br opacity-0 group-hover:opacity-100 transition-opacity duration-700",
                feature.gradient
              )} />

              <CardContent className="p-7 relative z-10 space-y-6">
                <div className="flex items-start justify-between">
                  <div className={cn(
                    "h-12 w-12 rounded-xl bg-muted flex items-center justify-center border border-border/50 transition-all group-hover:scale-110 shadow-xl",
                  )}>
                    <feature.icon className={cn("h-6 w-6", feature.iconColor)} />
                  </div>
                  <Badge variant="outline" className={cn("text-[8px] font-black uppercase tracking-widest", feature.badgeColor)}>
                    {feature.badge}
                  </Badge>
                </div>

                <div className="space-y-2">
                  <h4 className="text-lg font-black uppercase tracking-tight text-foreground">{feature.title}</h4>
                  <p className="text-muted-foreground/70 leading-relaxed font-medium text-sm group-hover:text-muted-foreground transition-all">
                    {feature.desc}
                  </p>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </section>
  )
}
