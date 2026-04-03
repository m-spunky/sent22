"use client"

import React, { useEffect, useRef, useState, useCallback } from "react"
import { ZoomIn, ZoomOut, RotateCcw, Maximize2, Loader2 } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { getKnowledgeGraph, type GraphData, type GraphNode } from "@/lib/api"

interface GraphViewProps {
  onNodeSelect?: (node: GraphNode | null) => void
}

// Node colors matching backend spec
const NODE_COLORS: Record<string, string> = {
  actor: "#ef4444",
  campaign: "#f59e0b",
  domain: "#3b82f6",
  ip: "#10b981",
  technique: "#8b5cf6",
}

const NODE_RADII: Record<string, number> = {
  actor: 18,
  campaign: 14,
  domain: 10,
  ip: 8,
  technique: 7,
}

interface SimNode extends GraphNode {
  x?: number
  y?: number
  vx?: number
  vy?: number
  fx?: number | null
  fy?: number | null
}

interface SimLink {
  source: SimNode | string
  target: SimNode | string
  relationship: string
}

export function GraphView({ onNodeSelect }: GraphViewProps) {
  const svgRef = useRef<SVGSVGElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [graphData, setGraphData] = useState<GraphData | null>(null)
  const [loading, setLoading] = useState(true)
  const [selectedNode, setSelectedNode] = useState<SimNode | null>(null)
  const [transform, setTransform] = useState({ x: 0, y: 0, k: 1 })
  const simulationRef = useRef<ReturnType<typeof import("d3").forceSimulation> | null>(null)
  const [filterType, setFilterType] = useState<string | null>(null)
  const onNodeSelectRef = useRef(onNodeSelect)
  onNodeSelectRef.current = onNodeSelect

  // Load graph data
  const loadGraph = useCallback(async () => {
    try {
      const data = await getKnowledgeGraph(2)
      setGraphData(data)
    } catch (e) {
      console.error("Graph load failed:", e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadGraph()
  }, [loadGraph])

  // Build D3 force simulation
  useEffect(() => {
    if (!graphData || !svgRef.current || !containerRef.current) return

    const container = containerRef.current
    const width = container.clientWidth || 800
    const height = container.clientHeight || 500

    // Dynamically import D3 to avoid SSR issues
    import("d3").then((d3) => {
      const svg = d3.select(svgRef.current!)
      svg.selectAll("*").remove()

      // Filter nodes
      const nodes: SimNode[] = (graphData.nodes as SimNode[]).filter(
        n => !filterType || n.type === filterType
      ).slice(0, 120) // Cap at 120 for performance

      const nodeIds = new Set(nodes.map(n => n.id))
      const links: SimLink[] = graphData.edges
        .filter(e => nodeIds.has(e.source as string) && nodeIds.has(e.target as string))
        .map(e => ({ ...e, source: e.source as string, target: e.target as string }))

      // Set up zoom
      const zoom = d3.zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.2, 4])
        .on("zoom", (event) => {
          g.attr("transform", event.transform.toString())
          setTransform({ x: event.transform.x, y: event.transform.y, k: event.transform.k })
        })

      svg.call(zoom)

      const g = svg.append("g")

      // Arrow markers
      svg.append("defs").selectAll("marker")
        .data(Object.keys(NODE_COLORS))
        .enter()
        .append("marker")
        .attr("id", d => `arrow-${d}`)
        .attr("viewBox", "0 -5 10 10")
        .attr("refX", 20)
        .attr("refY", 0)
        .attr("markerWidth", 6)
        .attr("markerHeight", 6)
        .attr("orient", "auto")
        .append("path")
        .attr("d", "M0,-5L10,0L0,5")
        .attr("fill", d => NODE_COLORS[d] || "#3b82f6")
        .attr("opacity", 0.5)

      // Force simulation
      const simulation = d3.forceSimulation(nodes)
        .force("link", d3.forceLink<SimNode, SimLink>(links)
          .id(d => d.id)
          .distance(80)
          .strength(0.3))
        .force("charge", d3.forceManyBody().strength(-200))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collision", d3.forceCollide().radius(((d: any) => (NODE_RADII[d.type] || 10) + 8) as any))

      simulationRef.current = simulation as any

      // Draw links
      const link = g.append("g").attr("class", "links")
        .selectAll("line")
        .data(links)
        .enter()
        .append("line")
        .attr("stroke", "rgba(59,130,246,0.15)")
        .attr("stroke-width", 1)

      // Draw nodes
      const node = g.append("g").attr("class", "nodes")
        .selectAll("g")
        .data(nodes)
        .enter()
        .append("g")
        .attr("cursor", "pointer")
        .call(
          d3.drag<SVGGElement, SimNode>()
            .on("start", (event, d) => {
              if (!event.active) simulation.alphaTarget(0.3).restart()
              d.fx = d.x
              d.fy = d.y
            })
            .on("drag", (event, d) => {
              d.fx = event.x
              d.fy = event.y
            })
            .on("end", (event, d) => {
              if (!event.active) simulation.alphaTarget(0)
              d.fx = null
              d.fy = null
            })
        )
        .on("click", (_, d) => {
          setSelectedNode(d)
          onNodeSelectRef.current?.(d)
        })

      // Node circles
      node.append("circle")
        .attr("r", d => NODE_RADII[d.type] || 10)
        .attr("fill", d => NODE_COLORS[d.type] || "#3b82f6")
        .attr("fill-opacity", 0.85)
        .attr("stroke", d => NODE_COLORS[d.type] || "#3b82f6")
        .attr("stroke-width", 2)
        .attr("stroke-opacity", 0.4)
        .style("filter", d => `drop-shadow(0 0 6px ${NODE_COLORS[d.type] || "#3b82f6"}60)`)

      // Node glow ring (for actors/campaigns)
      node.filter(d => d.type === "actor" || d.type === "campaign")
        .append("circle")
        .attr("r", d => (NODE_RADII[d.type] || 10) + 5)
        .attr("fill", "none")
        .attr("stroke", d => NODE_COLORS[d.type] || "#3b82f6")
        .attr("stroke-width", 1)
        .attr("stroke-opacity", 0.2)

      // Labels (only for actors and campaigns)
      node.filter(d => d.type === "actor" || d.type === "campaign")
        .append("text")
        .attr("dy", d => (NODE_RADII[d.type] || 10) + 14)
        .attr("text-anchor", "middle")
        .attr("fill", "#94a3b8")
        .attr("font-size", "10px")
        .attr("font-family", "JetBrains Mono, monospace")
        .attr("font-weight", "600")
        .text(d => d.label.length > 16 ? d.label.slice(0, 14) + "…" : d.label)

      // Tick simulation
      simulation.on("tick", () => {
        link
          .attr("x1", d => (d.source as SimNode).x || 0)
          .attr("y1", d => (d.source as SimNode).y || 0)
          .attr("x2", d => (d.target as SimNode).x || 0)
          .attr("y2", d => (d.target as SimNode).y || 0)

        node.attr("transform", d => `translate(${d.x || 0},${d.y || 0})`)
      })

      // Initial zoom to fit
      setTimeout(() => {
        const bounds = (g.node() as SVGGElement)?.getBBox()
        if (bounds) {
          const dx = bounds.width, dy = bounds.height
          const x = bounds.x + dx / 2, y = bounds.y + dy / 2
          const scale = Math.min(0.9, 0.9 / Math.max(dx / width, dy / height))
          const tx = width / 2 - scale * x
          const ty = height / 2 - scale * y
          svg.transition().duration(750).call(
            zoom.transform,
            d3.zoomIdentity.translate(tx, ty).scale(scale)
          )
        }
      }, 800)
    })

    return () => {
      simulationRef.current?.stop()
    }
  }, [graphData, filterType])

  const handleZoom = (factor: number) => {
    if (!svgRef.current) return
    import("d3").then((d3) => {
      d3.select(svgRef.current!).transition().duration(300).call(
        d3.zoom<SVGSVGElement, unknown>().scaleBy as any,
        factor
      )
    })
  }

  const handleReset = () => {
    if (!svgRef.current) return
    import("d3").then((d3) => {
      d3.select(svgRef.current!).transition().duration(500).call(
        (d3.zoom<SVGSVGElement, unknown>().transform as any),
        d3.zoomIdentity
      )
    })
  }

  const nodeTypes = [
    { type: "actor", label: "Threat Actor", color: "#ef4444" },
    { type: "campaign", label: "Campaign", color: "#f59e0b" },
    { type: "domain", label: "Domain IOC", color: "#3b82f6" },
    { type: "ip", label: "IP Address", color: "#10b981" },
    { type: "technique", label: "Technique", color: "#8b5cf6" },
  ]

  return (
    <Card className="card-cyber overflow-hidden h-full flex flex-col">
      <CardHeader className="p-5 border-b border-white/5 flex flex-row items-center justify-between shrink-0">
        <div className="space-y-1">
          <CardTitle className="text-xs font-bold uppercase tracking-widest text-blue-400 flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-blue-400 animate-pulse" />
            Intelligence Knowledge Graph
          </CardTitle>
          <CardDescription className="text-[10px] text-slate-500 uppercase tracking-widest">
            {graphData ? `${graphData.total_nodes} nodes · ${graphData.total_edges} edges` : "Loading..."}
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-[9px] border-blue-500/20 text-blue-400 uppercase">
            {Math.round(transform.k * 100)}%
          </Badge>
        </div>
      </CardHeader>

      <CardContent className="p-0 flex-1 relative overflow-hidden" ref={containerRef}>
        {/* Grid background */}
        <div className="absolute inset-0 bg-grid opacity-40 pointer-events-none" />

        {loading ? (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="flex flex-col items-center gap-3">
              <Loader2 className="h-8 w-8 text-blue-400 animate-spin" />
              <span className="text-xs text-slate-500 uppercase tracking-widest">Loading graph...</span>
            </div>
          </div>
        ) : (
          <svg ref={svgRef} className="w-full h-full" />
        )}

        {/* Legend */}
        <div className="absolute right-4 top-4 p-3 rounded-lg bg-[#0a0e1a]/80 border border-blue-500/10 backdrop-blur-sm z-20 space-y-2">
          {nodeTypes.map(nt => (
            <button
              key={nt.type}
              onClick={() => setFilterType(filterType === nt.type ? null : nt.type)}
              className={`flex items-center gap-2.5 w-full text-left transition-opacity ${filterType && filterType !== nt.type ? "opacity-30" : ""}`}
            >
              <div className="h-2.5 w-2.5 rounded-full shrink-0" style={{ backgroundColor: nt.color, boxShadow: `0 0 6px ${nt.color}60` }} />
              <span className="text-[9px] font-bold uppercase tracking-widest text-slate-400">{nt.label}</span>
            </button>
          ))}
        </div>

        {/* Controls */}
        <div className="absolute bottom-4 left-4 p-1.5 rounded-lg bg-[#0a0e1a]/80 border border-blue-500/10 backdrop-blur-sm z-20 flex items-center gap-1">
          <Button variant="ghost" size="icon" className="h-8 w-8 text-slate-400 hover:text-blue-400 hover:bg-blue-500/10 rounded-md" onClick={() => handleZoom(1.3)}>
            <ZoomIn className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" className="h-8 w-8 text-slate-400 hover:text-blue-400 hover:bg-blue-500/10 rounded-md" onClick={() => handleZoom(0.7)}>
            <ZoomOut className="h-4 w-4" />
          </Button>
          <div className="w-px h-5 bg-white/10" />
          <Button variant="ghost" size="icon" className="h-8 w-8 text-slate-400 hover:text-blue-400 hover:bg-blue-500/10 rounded-md" onClick={handleReset}>
            <RotateCcw className="h-4 w-4" />
          </Button>
        </div>

        {/* Click hint */}
        {!selectedNode && !loading && (
          <div className="absolute bottom-4 right-4 px-3 py-2 rounded-lg bg-[#0a0e1a]/80 border border-blue-500/10 backdrop-blur-sm z-20">
            <span className="text-[9px] text-slate-500 uppercase font-bold tracking-widest">Click any node to inspect →</span>
          </div>
        )}
        {/* Selected indicator */}
        {selectedNode && (
          <div className="absolute bottom-4 right-4 flex items-center gap-2 px-3 py-2 rounded-lg bg-[#111827]/90 border z-20 animate-in fade-in duration-150"
               style={{ borderColor: (NODE_COLORS[selectedNode.type] || "#3b82f6") + "40" }}>
            <div className="h-2 w-2 rounded-full animate-pulse" style={{ backgroundColor: NODE_COLORS[selectedNode.type] || "#3b82f6" }} />
            <span className="text-[9px] font-bold uppercase tracking-widest text-slate-300 max-w-[140px] truncate">{selectedNode.label}</span>
            <button onClick={() => { setSelectedNode(null); onNodeSelectRef.current?.(null) }}
                    className="text-slate-500 hover:text-slate-300 text-[10px] ml-1">✕</button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
