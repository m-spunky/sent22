"use client"

import React, { useEffect, useState } from "react"
import { Sun, Moon } from "lucide-react"
import { cn } from "@/lib/utils"

export function ThemeToggle({ className }: { className?: string }) {
  const [theme, setTheme] = useState<"dark" | "light">("dark")

  useEffect(() => {
    const saved = localStorage.getItem("sentinel-theme") as "dark" | "light" | null
    const initial = saved || "dark"
    setTheme(initial)
    document.documentElement.classList.remove("dark", "light")
    document.documentElement.classList.add(initial)
  }, [])

  const toggle = () => {
    const next = theme === "dark" ? "light" : "dark"
    setTheme(next)
    document.documentElement.classList.remove("dark", "light")
    document.documentElement.classList.add(next)
    localStorage.setItem("sentinel-theme", next)
  }

  return (
    <button
      onClick={toggle}
      aria-label="Toggle theme"
      className={cn(
        "flex items-center justify-center h-7 w-7 rounded-lg border transition-all hover:scale-105 active:scale-95",
        theme === "dark"
          ? "bg-slate-800 border-white/10 text-slate-400 hover:text-amber-400 hover:border-amber-500/30"
          : "bg-amber-50 border-amber-200 text-amber-600 hover:text-amber-700",
        className
      )}
    >
      {theme === "dark"
        ? <Sun className="h-3.5 w-3.5" />
        : <Moon className="h-3.5 w-3.5" />
      }
    </button>
  )
}
