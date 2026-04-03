"use client"

import React, { useState } from "react"
import { Search, Mail, Globe, Upload, History, CornerDownRight, Zap } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

export function InputPanel() {
  const [loading, setLoading] = useState(false)
  
  const handleAnalyze = () => {
    setLoading(true)
    setTimeout(() => setLoading(false), 2000)
  }

  const recentScans = [
    { type: "Email", target: "invoice_942.eml", result: "Phishing", time: "2m ago" },
    { type: "URL", target: "secure-auth.net/pay", result: "Malicious", time: "15m ago" },
    { type: "Email", target: "hr_manual_v2.eml", result: "Safe", time: "2h ago" },
  ]

  return (
    <Card className="card-cyber flex flex-col h-full group">
      <CardHeader className="p-6 border-b border-white/5 bg-accent/5">
        <div className="flex items-center justify-between">
           <div className="space-y-1">
             <CardTitle className="text-sm font-black uppercase tracking-[0.2em] text-foreground flex items-center">
               <Zap className="h-4 w-4 mr-2 text-accent" />
               Analysis Input
             </CardTitle>
             <CardDescription className="text-[10px] text-muted-foreground uppercase font-black tracking-widest leading-none mt-1">
                SentinelAI Inference Core v2.4
             </CardDescription>
           </div>
           <Badge variant="outline" className="text-[8px] h-5 px-2 py-0 border-accent/20 text-accent font-black uppercase tracking-widest bg-accent/5">
              Live Engine
           </Badge>
        </div>
      </CardHeader>
      
      <CardContent className="p-6 space-y-6 flex-1 flex flex-col">
        <Tabs defaultValue="email" className="w-full">
          <TabsList className="grid grid-cols-2 bg-[#0D1B2A]/40 border border-white/5 p-1 rounded-xl mb-6">
            <TabsTrigger value="email" className="rounded-lg text-xs font-black uppercase tracking-widest data-[state=active]:bg-accent data-[state=active]:text-accent-foreground data-[state=active]:shadow-lg active:scale-95 transition-all">
               <Mail className="h-3.5 w-3.5 mr-2" />
               Email Content
            </TabsTrigger>
            <TabsTrigger value="url" className="rounded-lg text-xs font-black uppercase tracking-widest data-[state=active]:bg-accent data-[state=active]:text-accent-foreground data-[state=active]:shadow-lg active:scale-95 transition-all">
               <Globe className="h-3.5 w-3.5 mr-2" />
               URL Scan
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="email" className="space-y-4 animate-in fade-in duration-300">
            <Textarea 
              placeholder="Paste raw email headers or body content here..." 
              className="h-64 bg-[#0D1B2A]/40 border-white/5 focus:border-accent/40 rounded-xl text-xs font-medium placeholder:text-muted-foreground/30 resize-none p-4 leading-relaxed"
            />
          </TabsContent>
          
          <TabsContent value="url" className="space-y-4 animate-in fade-in duration-300">
             <div className="relative group">
                <Globe className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground group-focus-within:text-accent transition-colors" />
                <Input 
                  placeholder="https://suspected-domain.com/login" 
                  className="bg-[#0D1B2A]/40 border-white/5 focus:border-accent/40 rounded-xl pl-12 h-14 text-sm font-bold placeholder:text-muted-foreground/30 accent-glow focus:ring-accent/20"
                />
             </div>
             <div className="p-4 rounded-xl border border-white/5 bg-white/5 flex items-center justify-between group/upload cursor-pointer hover:bg-white/10 transition-colors">
                <div className="flex items-center space-x-3">
                   <div className="h-10 w-10 rounded-lg bg-accent/10 flex items-center justify-center border border-accent/20">
                      <Upload className="h-5 w-5 text-accent" />
                   </div>
                   <div>
                      <h4 className="text-[10px] font-black uppercase tracking-widest text-foreground">Bulk URLs</h4>
                      <p className="text-[8px] text-muted-foreground mt-0.5 italic lowercase">Upload .csv or .txt file</p>
                   </div>
                </div>
                <CornerDownRight className="h-4 w-4 text-muted-foreground opacity-0 group-hover/upload:opacity-100 transition-all group-hover/upload:translate-x-1" />
             </div>
          </TabsContent>
        </Tabs>
        
        <div className="pt-4 border-t border-white/5 flex flex-col space-y-6 flex-1">
           <Button 
              onClick={handleAnalyze}
              disabled={loading}
              className={cn(
                "w-full h-14 rounded-2xl text-lg font-black uppercase tracking-[0.2em] transition-all active:scale-95 shadow-2xl relative overflow-hidden",
                loading ? "bg-muted cursor-not-allowed" : "bg-accent text-accent-foreground hover:bg-accent/90 accent-glow"
              )}
           >
              {loading ? (
                <div className="flex items-center space-x-2">
                   <div className="h-4 w-4 border-2 border-accent-foreground/30 border-t-accent-foreground rounded-full animate-spin" />
                   <span>Processing Intelligence...</span>
                </div>
              ) : "Execute Full Analysis"}
           </Button>

           <div className="space-y-3 mt-auto">
              <div className="flex items-center justify-between text-[8px] font-black uppercase tracking-widest text-muted-foreground border-b border-white/5 pb-2">
                 <div className="flex items-center">
                    <History className="h-3 w-3 mr-1" />
                    Recent Telemetry Scans
                 </div>
                 <span className="text-accent underline cursor-pointer hover:opacity-80">History</span>
              </div>
              
              <div className="space-y-2">
                {recentScans.map((scan, i) => (
                  <div key={i} className="flex items-center justify-between px-3 py-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors border border-transparent hover:border-white/5 cursor-pointer">
                    <div className="flex items-center space-x-2">
                      <div className={cn(
                        "h-1.5 w-1.5 rounded-full animate-pulse",
                        scan.result === "Phishing" || scan.result === "Malicious" ? "bg-destructive shadow-[0_0_5px_rgba(255,77,109,0.5)]" : "bg-green-500"
                      )} />
                      <span className="text-[10px] font-bold text-foreground truncate w-32">{scan.target}</span>
                    </div>
                    <span className="text-[8px] font-black text-muted-foreground uppercase opacity-60 tracking-tighter">{scan.time}</span>
                  </div>
                ))}
              </div>
           </div>
        </div>
      </CardContent>
    </Card>
  )
}
