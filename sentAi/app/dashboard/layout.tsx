"use client"

import React, { useState } from "react"
import { Sidebar } from "@/components/layout/Sidebar"
import { Header } from "@/components/layout/Header"
import { GlobalStoreProvider } from "@/lib/global-store"
import { cn } from "@/lib/utils"

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <GlobalStoreProvider>
    <div className="flex h-screen w-screen overflow-hidden" style={{ backgroundColor: "var(--bg-base)", color: "var(--fg)" }}>
      {/* Desktop Sidebar */}
      <div
        className={cn(
          "hidden lg:block h-full transition-all duration-300 ease-in-out relative z-50",
          collapsed ? "w-16" : "w-60"
        )}
      >
        <Sidebar collapsed={collapsed} />
      </div>

      {/* Content */}
      <div className="flex-1 flex flex-col h-full overflow-hidden relative" style={{ backgroundColor: "var(--bg-base)" }}>
        {/* Ambient glows */}
        <div className="absolute top-0 right-0 h-[35vh] w-[35vw] bg-blue-500/4 rounded-full blur-[120px] pointer-events-none" />
        <div className="absolute bottom-0 left-0 h-[25vh] w-[25vw] bg-amber-500/3 rounded-full blur-[100px] pointer-events-none" />
        
        {/* Global Toolbar */}
        <Header 
          sidebarCollapsed={collapsed} 
          setSidebarCollapsed={setCollapsed} 
        />
        
        {/* Viewport for specific page content */}
        <main className="flex-1 overflow-y-auto overflow-x-hidden scroll-smooth scrollbar-thin scrollbar-thumb-accent/20 scrollbar-track-transparent">
           <div className="p-4 md:p-6 lg:p-8 pb-12 w-full max-w-[1920px] mx-auto">
             {children}
           </div>
        </main>
      </div>
    </div>
    </GlobalStoreProvider>
  )
}
