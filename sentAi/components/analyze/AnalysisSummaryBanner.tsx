"use client"
import React from "react"
import { AnalysisResult } from "@/lib/api"

/**
 * AnalysisSummaryBanner — renders QW-1 (Powered By), QW-2 (Inference Time), 
 * QW-3 (Confidence Interval), QW-5 ("So What?" one-line summary),
 * and Enhancement 9 (Detection Latency Gauge) in a single premium card.
 */
export default function AnalysisSummaryBanner({ result }: { result: AnalysisResult }) {
  const ci = result.confidence_interval
  const timeDetail = result.inference_time_detail
  const soWhat = result.so_what
  const inferenceMs = result.inference_time_ms

  // Color mapping for verdict
  const verdictColors: Record<string, { bg: string; text: string; border: string; accent: string }> = {
    SAFE:       { bg: "rgba(16, 185, 129, 0.08)", text: "#10b981", border: "rgba(16, 185, 129, 0.25)", accent: "#059669" },
    SUSPICIOUS: { bg: "rgba(245, 158, 11, 0.08)", text: "#f59e0b", border: "rgba(245, 158, 11, 0.25)", accent: "#d97706" },
    PHISHING:   { bg: "rgba(239, 68, 68, 0.08)", text: "#ef4444", border: "rgba(239, 68, 68, 0.25)", accent: "#dc2626" },
    CRITICAL:   { bg: "rgba(220, 38, 38, 0.12)", text: "#dc2626", border: "rgba(220, 38, 38, 0.35)", accent: "#b91c1c" },
  }

  const vc = verdictColors[result.verdict] || verdictColors.SAFE
  const score = Math.round(result.threat_score * 100)

  // Latency gauge (Enhancement 9)
  const latencyLabel = timeDetail?.label || (inferenceMs < 500 ? "Lightning" : inferenceMs < 2000 ? "Fast" : "Moderate")
  const latencyColor = inferenceMs < 500 ? "#10b981" : inferenceMs < 2000 ? "#f59e0b" : inferenceMs < 5000 ? "#ef4444" : "#dc2626"

  return (
    <div style={{
      background: vc.bg,
      border: `1px solid ${vc.border}`,
      borderRadius: 16,
      padding: "20px 24px",
      marginBottom: 20,
    }}>
      {/* So What? Banner */}
      {soWhat && (
        <div style={{
          fontSize: 15,
          fontWeight: 600,
          color: vc.text,
          marginBottom: 16,
          display: "flex",
          alignItems: "center",
          gap: 8,
          lineHeight: 1.5,
        }}>
          <span style={{
            background: vc.accent,
            color: "white",
            padding: "2px 8px",
            borderRadius: 6,
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: 0.5,
            flexShrink: 0,
          }}>
            SO WHAT?
          </span>
          <span>{soWhat}</span>
        </div>
      )}

      {/* Stats Row */}
      <div style={{
        display: "flex",
        gap: 24,
        flexWrap: "wrap",
        alignItems: "center",
      }}>
        {/* Confidence Interval */}
        {ci && (
          <div style={{
            background: "rgba(255,255,255,0.06)",
            borderRadius: 10,
            padding: "10px 16px",
            minWidth: 140,
          }}>
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.5)", marginBottom: 4, fontWeight: 600, letterSpacing: 0.5 }}>
              CONFIDENCE INTERVAL
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 22, fontWeight: 700, color: vc.text }}>
                {score}%
              </span>
              <span style={{ fontSize: 12, color: "rgba(255,255,255,0.4)" }}>
                ±{Math.round((ci.upper - ci.lower) * 50)}%
              </span>
            </div>
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", marginTop: 2 }}>
              Range: {Math.round(ci.lower * 100)}–{Math.round(ci.upper * 100)}%
            </div>
            {/* Visual bar */}
            <div style={{
              height: 4,
              borderRadius: 2,
              background: "rgba(255,255,255,0.08)",
              marginTop: 6,
              position: "relative",
              overflow: "hidden",
            }}>
              <div style={{
                position: "absolute",
                left: `${ci.lower * 100}%`,
                width: `${(ci.upper - ci.lower) * 100}%`,
                height: "100%",
                background: vc.text,
                borderRadius: 2,
                opacity: 0.6,
              }} />
              <div style={{
                position: "absolute",
                left: `${score}%`,
                width: 3,
                height: "100%",
                background: vc.accent,
                borderRadius: 1,
                transform: "translateX(-1px)",
              }} />
            </div>
          </div>
        )}

        {/* Latency Gauge (Enhancement 9) */}
        <div style={{
          background: "rgba(255,255,255,0.06)",
          borderRadius: 10,
          padding: "10px 16px",
          minWidth: 130,
        }}>
          <div style={{ fontSize: 11, color: "rgba(255,255,255,0.5)", marginBottom: 4, fontWeight: 600, letterSpacing: 0.5 }}>
            DETECTION SPEED
          </div>
          <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
            <span style={{ fontSize: 22, fontWeight: 700, color: latencyColor }}>
              {inferenceMs < 1000 ? `${inferenceMs}ms` : `${(inferenceMs / 1000).toFixed(1)}s`}
            </span>
            <span style={{
              fontSize: 11,
              fontWeight: 600,
              color: latencyColor,
              background: `${latencyColor}20`,
              padding: "2px 6px",
              borderRadius: 4,
            }}>
              {latencyLabel}
            </span>
          </div>
          {/* Speed gauge bar */}
          <div style={{
            height: 4,
            borderRadius: 2,
            background: "rgba(255,255,255,0.08)",
            marginTop: 8,
            position: "relative",
            overflow: "hidden",
          }}>
            <div style={{
              width: `${Math.max(5, Math.min(100, 100 - (inferenceMs / 100)))}%`,
              height: "100%",
              background: `linear-gradient(90deg, ${latencyColor}, ${latencyColor}aa)`,
              borderRadius: 2,
              transition: "width 0.5s ease",
            }} />
          </div>
        </div>

        {/* Models Used (QW-1: Powered By) */}
        <div style={{
          background: "rgba(255,255,255,0.06)",
          borderRadius: 10,
          padding: "10px 16px",
          flex: 1,
          minWidth: 200,
        }}>
          <div style={{ fontSize: 11, color: "rgba(255,255,255,0.5)", marginBottom: 6, fontWeight: 600, letterSpacing: 0.5 }}>
            POWERED BY
          </div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {[
              { name: "Sentinel Fusion XGB", color: "#818cf8" },
              { name: "Gemma-3 12B", color: "#3b82f6" },
              { name: "BERT Phishing", color: "#8b5cf6" },
              { name: "CLIP Vision", color: "#06b6d4" },
              { name: "XGBoost URL", color: "#10b981" },
            ].map((model) => (
              <span key={model.name} style={{
                fontSize: 10,
                fontWeight: 600,
                color: model.color,
                background: `${model.color}18`,
                border: `1px solid ${model.color}30`,
                padding: "3px 8px",
                borderRadius: 6,
                letterSpacing: 0.3,
              }}>
                {model.name}
              </span>
            ))}
          </div>
          <div style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", marginTop: 6 }}>
            5-layer ensemble • 125 features • OSINT-enriched
          </div>
        </div>
      </div>
    </div>
  )
}
