"use client"
import React from "react"
import { KillChain } from "@/lib/api"

/**
 * ColorCodedKillChain — QW-4: Visual kill chain with color-coded stages,
 * risk indicators, and animated flow connections.
 */
export default function ColorCodedKillChain({ killChain }: { killChain?: KillChain }) {
  if (!killChain || !killChain.kill_chain_stages?.length) return null

  const stages = killChain.kill_chain_stages

  const riskColors: Record<string, { bg: string; text: string; glow: string }> = {
    critical: { bg: "rgba(220, 38, 38, 0.15)", text: "#ef4444", glow: "0 0 12px rgba(220, 38, 38, 0.3)" },
    high:     { bg: "rgba(239, 68, 68, 0.12)", text: "#f87171", glow: "0 0 8px rgba(239, 68, 68, 0.2)" },
    medium:   { bg: "rgba(245, 158, 11, 0.12)", text: "#fbbf24", glow: "0 0 8px rgba(245, 158, 11, 0.2)" },
    low:      { bg: "rgba(16, 185, 129, 0.10)", text: "#34d399", glow: "none" },
  }

  const stageIcons: Record<string, string> = {
    "Initial Access": "🎯",
    "Execution": "⚡",
    "Persistence": "🔄",
    "Privilege Escalation": "📈",
    "Defense Evasion": "🛡️",
    "Credential Access": "🔑",
    "Discovery": "🔍",
    "Lateral Movement": "↔️",
    "Collection": "📦",
    "Command & Control": "📡",
    "Exfiltration": "📤",
    "Impact": "💥",
    "Financial Impact": "💰",
  }

  const getRiskLevel = (score: number): string => {
    if (score >= 0.75) return "critical"
    if (score >= 0.5) return "high"
    if (score >= 0.25) return "medium"
    return "low"
  }

  return (
    <div style={{
      background: "rgba(255,255,255,0.03)",
      border: "1px solid rgba(255,255,255,0.08)",
      borderRadius: 14,
      padding: "18px 20px",
      marginBottom: 16,
    }}>
      <div style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        marginBottom: 16,
      }}>
        <span style={{ fontSize: 16 }}>⛓️</span>
        <span style={{ fontSize: 14, fontWeight: 700, color: "rgba(255,255,255,0.9)", letterSpacing: 0.3 }}>
          Attack Kill Chain
        </span>
        {killChain.attack_vector && (
          <span style={{
            fontSize: 10,
            fontWeight: 600,
            color: "#818cf8",
            background: "rgba(129, 140, 248, 0.12)",
            padding: "2px 8px",
            borderRadius: 6,
          }}>
            {killChain.attack_vector}
          </span>
        )}
      </div>

      {/* Kill chain flow */}
      <div style={{
        display: "flex",
        gap: 0,
        alignItems: "stretch",
        overflowX: "auto",
        paddingBottom: 4,
      }}>
        {stages.map((stage: any, i: number) => {
          const risk = getRiskLevel(stage.risk_score || 0)
          const colors = riskColors[risk]
          const icon = stageIcons[stage.phase] || "⚙️"
          const isActive = (stage.risk_score || 0) > 0

          return (
            <React.Fragment key={stage.phase}>
              {/* Stage card */}
              <div style={{
                background: isActive ? colors.bg : "rgba(255,255,255,0.02)",
                border: `1px solid ${isActive ? colors.text + "30" : "rgba(255,255,255,0.06)"}`,
                borderRadius: 10,
                padding: "10px 14px",
                minWidth: 120,
                flex: 1,
                boxShadow: isActive ? colors.glow : "none",
                opacity: isActive ? 1 : 0.4,
                transition: "all 0.3s ease",
              }}>
                <div style={{ fontSize: 18, marginBottom: 4 }}>{icon}</div>
                <div style={{
                  fontSize: 11,
                  fontWeight: 700,
                  color: isActive ? colors.text : "rgba(255,255,255,0.3)",
                  marginBottom: 4,
                  lineHeight: 1.3,
                }}>
                  {stage.phase}
                </div>
                <div style={{
                  fontSize: 18,
                  fontWeight: 800,
                  color: isActive ? colors.text : "rgba(255,255,255,0.15)",
                }}>
                  {Math.round((stage.risk_score || 0) * 100)}%
                </div>
                {stage.indicators?.length > 0 && (
                  <div style={{
                    fontSize: 10,
                    color: "rgba(255,255,255,0.4)",
                    marginTop: 4,
                    lineHeight: 1.3,
                  }}>
                    {stage.indicators.length} indicator{stage.indicators.length > 1 ? "s" : ""}
                  </div>
                )}
              </div>

              {/* Connector arrow */}
              {i < stages.length - 1 && (
                <div style={{
                  display: "flex",
                  alignItems: "center",
                  padding: "0 4px",
                  color: isActive ? colors.text : "rgba(255,255,255,0.1)",
                  fontSize: 14,
                  flexShrink: 0,
                }}>
                  →
                </div>
              )}
            </React.Fragment>
          )
        })}
      </div>

      {/* Overall risk footer */}
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        marginTop: 12,
        paddingTop: 10,
        borderTop: "1px solid rgba(255,255,255,0.06)",
      }}>
        <span style={{ fontSize: 11, color: "rgba(255,255,255,0.4)" }}>
          {stages.filter((s: any) => (s.risk_score || 0) > 0).length} / {stages.length} stages active
        </span>
        {killChain.estimated_impact && (
          <span style={{
            fontSize: 10,
            fontWeight: 600,
            color: killChain.estimated_impact.level === "HIGH" ? "#ef4444" :
                   killChain.estimated_impact.level === "CRITICAL" ? "#dc2626" :
                   killChain.estimated_impact.level === "MEDIUM" ? "#f59e0b" : "#34d399",
            background: killChain.estimated_impact.level === "HIGH" ? "rgba(239,68,68,0.12)" :
                        killChain.estimated_impact.level === "CRITICAL" ? "rgba(220,38,38,0.15)" :
                        killChain.estimated_impact.level === "MEDIUM" ? "rgba(245,158,11,0.12)" : "rgba(16,185,129,0.1)",
            padding: "3px 10px",
            borderRadius: 6,
          }}>
            Impact: {killChain.estimated_impact.level}
          </span>
        )}
      </div>
    </div>
  )
}
