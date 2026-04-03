import React from "react"
import Link from "next/link"
import { ShieldCheck, Twitter, Github, Linkedin, Mail } from "lucide-react"

export function LandingFooter() {
  return (
    <footer className="relative py-32 px-6 bg-muted border-t border-border/50 overflow-hidden">
      <div className="absolute bottom-[-10%] right-[-10%] h-[400px] w-[500px] bg-blue-500/3 rounded-full blur-[140px] -z-1" />

      <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-4 gap-16 items-start">
        <div className="md:col-span-2 space-y-8">
           <Link href="/" className="flex items-center space-x-3 group">
              <div className="h-10 w-10 bg-blue-500/10 rounded-xl flex items-center justify-center border border-blue-500/20 group-hover:scale-110 transition-transform">
                 <ShieldCheck className="h-6 w-6 text-blue-400" />
              </div>
              <div className="flex flex-col h-full justify-center">
                 <span className="text-xl font-black tracking-tighter text-foreground uppercase">SentinelAI</span>
                 <span className="text-[10px] text-blue-400/80 font-black tracking-[0.3em] uppercase">Fusion</span>
              </div>
           </Link>
           <p className="max-w-xs text-sm text-muted-foreground/60 leading-relaxed font-medium uppercase tracking-widest text-[10px]">
              Unified cyber intelligence and multi-modal AI detection infrastructure for global enterprise security.
           </p>
           <div className="flex items-center space-x-6">
              {[Twitter, Github, Linkedin, Mail].map((Icon, i) => (
                <Link key={i} href="#" className="h-10 w-10 rounded-xl bg-white/5 border border-white/5 flex items-center justify-center text-muted-foreground hover:text-blue-400 hover:border-blue-500/30 transition-all hover:-translate-y-1">
                   <Icon className="h-5 w-5" />
                </Link>
              ))}
           </div>
        </div>

        <div className="space-y-8">
           <h4 className="text-[10px] font-black uppercase tracking-[0.4em] text-blue-400">Platform</h4>
           <div className="flex flex-col space-y-4">
              {["Analysis Console", "Security Dashboard", "Threat Explorer", "Fusion API"].map((l) => (
                <Link key={l} href="#" className="text-xs font-black uppercase tracking-widest text-muted-foreground/60 hover:text-blue-400 transition-colors hover:translate-x-1 transition-all">{l}</Link>
              ))}
           </div>
        </div>

        <div className="space-y-8">
           <h4 className="text-[10px] font-black uppercase tracking-[0.4em] text-blue-400">Resources</h4>
           <div className="flex flex-col space-y-4">
              {["Intelligence Feed", "Security Docs", "Operational Telemetry", "Incident Support"].map((l) => (
                <Link key={l} href="#" className="text-xs font-black uppercase tracking-widest text-muted-foreground/60 hover:text-blue-400 transition-colors hover:translate-x-1 transition-all">{l}</Link>
              ))}
           </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto pt-24 mt-24 border-t border-white/5 flex flex-col md:flex-row items-center justify-between gap-8 opacity-40">
         <p className="text-[9px] font-black uppercase tracking-widest text-muted-foreground">© 2026 SentinelAI Fusion Intelligence. Securely Verified.</p>
         <div className="flex items-center space-x-8">
            <Link href="#" className="text-[9px] font-black uppercase tracking-widest text-muted-foreground hover:text-blue-400 transition-colors">Privacy Policy</Link>
            <Link href="#" className="text-[9px] font-black uppercase tracking-widest text-muted-foreground hover:text-blue-400 transition-colors">Terms of Service</Link>
         </div>
      </div>
    </footer>
  )
}
