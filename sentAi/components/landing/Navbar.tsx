"use client"

import React, { useState, useEffect } from "react"
import Link from "next/link"
import { ShieldCheck, Menu, X, ArrowRight } from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { ThemeToggle } from "@/components/ThemeToggle"

export function Navbar() {
  const [scrolled, setScrolled] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 20)
    window.addEventListener("scroll", handleScroll)
    return () => window.removeEventListener("scroll", handleScroll)
  }, [])

  const navLinks = [
    { name: "Features", href: "#features" },
    { name: "How It Works", href: "#process" },
    { name: "Dashboard", href: "/dashboard" },
    { name: "Analyzer", href: "/dashboard/analyze" },
  ]

  return (
    <nav
      className={cn(
        "fixed top-0 left-0 right-0 z-[100] transition-all duration-500 border-b",
        scrolled
          ? "bg-background/80 backdrop-blur-xl border-blue-500/10 py-3"
          : "bg-transparent border-transparent py-6"
      )}
    >
      <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
        {/* Logo */}
        <Link href="/" className="flex items-center space-x-3 group animate-in fade-in slide-in-from-left-4 duration-1000">
           <div className="h-10 w-10 bg-blue-500/20 rounded-xl flex items-center justify-center border border-blue-500/30 group-hover:scale-110 transition-transform shadow-[0_0_15px_rgba(59,130,246,0.3)]">
              <ShieldCheck className="h-6 w-6 text-blue-400" />
           </div>
           <div className="flex flex-col h-full justify-center leading-none">
              <span className="text-xl font-black tracking-tighter text-foreground uppercase">SentinelAI</span>
              <span className="text-[10px] text-blue-400/80 font-black tracking-[0.3em] uppercase">Fusion</span>
           </div>
        </Link>

        {/* Desktop Links */}
        <div className="hidden md:flex items-center space-x-8 animate-in fade-in duration-1000 delay-200">
           {navLinks.map((link) => (
             <Link
               key={link.name}
               href={link.href}
               className="text-xs font-black uppercase tracking-widest text-muted-foreground hover:text-blue-400 transition-colors relative group"
             >
                {link.name}
                <span className="absolute -bottom-1 left-0 w-0 h-px bg-blue-400 transition-all duration-300 group-hover:w-full" />
             </Link>
           ))}
        </div>

        {/* CTA */}
        <div className="hidden md:flex items-center space-x-3 animate-in fade-in slide-in-from-right-4 duration-1000">
           <ThemeToggle />
           <Link href="/dashboard">
              <Button variant="ghost" className="text-[10px] font-black uppercase tracking-widest text-foreground hover:text-blue-400 hover:bg-blue-500/5 rounded-xl px-6">
                 Sign In
              </Button>
           </Link>
           <Link href="/dashboard/analyze">
              <Button className="bg-blue-600 text-white rounded-xl px-6 py-6 text-[10px] font-black uppercase tracking-widest hover:bg-blue-500 shadow-[0_0_20px_rgba(59,130,246,0.3)] transition-all active:scale-95 group">
                 Launch Console
                 <ArrowRight className="ml-2 h-4 w-4 transition-transform group-hover:translate-x-1" />
              </Button>
           </Link>
        </div>

        {/* Mobile Toggle */}
        <button
          className="md:hidden text-muted-foreground hover:text-foreground transition-colors"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
        >
           {mobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
        </button>
      </div>

      {/* Mobile Menu */}
      <div className={cn(
        "fixed inset-0 bg-background/95 backdrop-blur-2xl z-[90] transition-all duration-500 md:hidden pt-32 px-10 flex flex-col items-center space-y-10",
        mobileMenuOpen ? "opacity-100 translate-y-0" : "opacity-0 -translate-y-full pointer-events-none"
      )}>
         {navLinks.map((link) => (
           <Link
             key={link.name}
             href={link.href}
             onClick={() => setMobileMenuOpen(false)}
             className="text-2xl font-black uppercase tracking-widest text-foreground hover:text-blue-400"
           >
              {link.name}
           </Link>
         ))}
         <div className="h-px w-20 bg-blue-500/20" />
         <Link href="/dashboard" className="w-full max-w-xs">
           <Button className="w-full bg-blue-600 text-white rounded-2xl py-8 text-lg font-black uppercase tracking-widest">
              Get Started
           </Button>
         </Link>
      </div>
    </nav>
  )
}
