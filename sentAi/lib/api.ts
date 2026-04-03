const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001"
export const WS_BASE = (process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8001")

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ModelBreakdown {
  nlp: {
    score: number; weight: number; tactics: string[]; explanation: string
    top_phrases?: string[]; phishing_intent?: string
  }
  url: {
    score: number; weight: number; top_features: string[]; shap_values: Record<string, number>
    features?: Record<string, number | boolean | string>
  }
  visual: {
    score: number; weight: number; matched_brand: string; similarity: number
    screenshot_url?: string   // legacy: base64 data URL
    screenshot_path?: string  // preferred: /screenshots/filename.jpg served from backend
  }
  header: {
    score: number; weight: number; flags: string[]
    spf_result: string; dkim_result: string; dmarc_result: string
  }
}

export interface DetectedTactic {
  name: string
  mitre_id: string
  confidence: number
}

export interface ThreatIntelligence {
  campaign_id: string
  threat_actor: string
  actor_confidence: number
  related_domains: string[]
  global_reach: string[]
}

export interface DarkWebExposure {
  domain: string
  breach_count: number
  total_exposed: number
  dark_web_risk: "HIGH" | "MEDIUM" | "LOW" | "NONE" | "UNKNOWN"
  breaches: { name: string; date: string; pwn_count?: number; data_classes?: string[]; source?: string }[]
  paste_count?: number
  sources?: string[]
}

export interface KillChainStage {
  stage: string
  technique: string
  mitre_id: string
  description: string
  risk_score: number
  active: boolean
  color: string
  ps_coverage: string
  phase?: string
  ps?: string
  indicators?: string[]
}

export interface KillChain {
  stages?: KillChainStage[]
  kill_chain_stages?: KillChainStage[]
  overall_risk: string
  financial_impact?: string
  containment_steps?: string[]
  attack_vector?: string
  active_stage_count?: number
  estimated_impact?: {
    level: string
    financial_risk_usd: string
  }
}

export interface LLMFingerprint {
  ai_generated_probability: number
  ai_confidence: number
  is_likely_ai: boolean
  detection_method: string
  stylometric_scores: {
    sentence_length_std?: number
    type_token_ratio?: number
    template_phrase_density?: number
    punctuation_regularity?: number
    coherence_overlap?: number
  }
  perplexity: {
    variance: number
    score: number
  }
  llm_assessment: {
    is_ai: boolean
    probability: number
    reasoning: string
    source: string
  }
  signals: string[]
  verdict: "LIKELY_AI" | "POSSIBLY_AI" | "LIKELY_HUMAN" | "UNKNOWN"
}

export interface AnalysisResult {
  event_id: string
  status: string
  threat_score: number
  verdict: "SAFE" | "SUSPICIOUS" | "PHISHING" | "CRITICAL" | "CONFIRMED_THREAT"
  confidence: number
  model_breakdown: ModelBreakdown
  detected_tactics: DetectedTactic[]
  threat_intelligence: ThreatIntelligence
  explanation_narrative: string
  recommended_action: string
  inference_time_ms: number
  timestamp: string
  urls_analyzed: string[]
  dark_web_exposure?: DarkWebExposure
  kill_chain?: KillChain
  input_type?: "email" | "url" | "headers"
  llm_fingerprint?: LLMFingerprint
  sender_first_contact?: {
    is_first_contact: boolean
    first_seen?: string
    domain?: string
    risk_boost?: number
    flag?: string
  }
  confidence_interval?: {
    lower: number
    upper: number
    confidence_pct: number
  }
  inference_time_detail?: {
    total_ms: number
    label: string
  }
  so_what?: string
}

export interface ChatResponse {
  response: string
  sources: string[]
  suggested_actions: string[]
  suggested_followups: string[]
  conversation_id: string
}

export interface ThreatFeedEvent {
  id: string
  type: string
  title: string
  description: string
  severity: "critical" | "high" | "medium" | "low"
  timestamp: string
  time_ago: string
}

export interface DashboardMetrics {
  threats_detected: number
  emails_analyzed: number
  active_campaigns: number
  avg_response_time_ms: number
  false_positive_rate: number
  ai_accuracy: number
}

export interface GraphNode {
  id: string
  label: string
  type: string
  risk: string
  data: Record<string, unknown>
}

export interface GraphEdge {
  source: string
  target: string
  relationship: string
}

export interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
  total_nodes: number
  total_edges: number
}

export interface Campaign {
  id: string
  name: string
  actor: string
  status: string
  start_date: string
  last_activity: string
  target_sector: string[]
  ioc_count: number
  risk_level: string
  description: string
  techniques: string[]
  iocs: { domains: string[]; ips: string[]; hashes: string[] }
  targets: string[]
  timeline: { date: string; event: string }[]
}

export interface DeepDiveResult {
  chain_id: string
  source_event_id?: string
  analyzed_at: string
  chain_stages: {
    stage: string
    label: string
    [key: string]: any
  }[]
  overall_risk: number
  overall_verdict: string
  chain_narrative: string
  attachment_result?: {
    filename: string
    risk_score: number
    risk_level: string
    findings: string[]
  }
  execution_trace?: any
  stage_count: number
}

// ── API Functions ─────────────────────────────────────────────────────────────

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || `API error: ${res.status}`)
  }
  return res.json()
}

export async function analyzeEmail(content: string): Promise<AnalysisResult> {
  return apiFetch("/api/v1/analyze/email", {
    method: "POST",
    body: JSON.stringify({ content, options: { run_visual: true, run_threat_intel: true } }),
  })
}

export async function analyzeUrl(url: string): Promise<AnalysisResult> {
  return apiFetch("/api/v1/analyze/url", {
    method: "POST",
    body: JSON.stringify({ url }),
  })
}

export async function runDeepDive(url: string, eventId?: string): Promise<DeepDiveResult> {
  return apiFetch("/api/v1/analyze/deep-dive", {
    method: "POST",
    body: JSON.stringify({ url, event_id: eventId }),
  })
}

export async function sendChatMessage(
  message: string,
  conversationId?: string,
  context?: Record<string, unknown>
): Promise<ChatResponse> {
  return apiFetch("/api/v1/chat", {
    method: "POST",
    body: JSON.stringify({ message, conversation_id: conversationId, context }),
  })
}

export async function getDashboardMetrics(): Promise<DashboardMetrics> {
  return apiFetch("/api/v1/dashboard/metrics")
}

export async function getThreatFeed(limit = 20): Promise<{ events: ThreatFeedEvent[] }> {
  return apiFetch(`/api/v1/dashboard/feed?limit=${limit}`)
}

export async function getThreatTimeline(hours = 24): Promise<{
  data_points: { time: string; threat_count: number; type_breakdown: Record<string, number> }[]
}> {
  return apiFetch(`/api/v1/dashboard/timeline?hours=${hours}`)
}

export async function getKnowledgeGraph(depth = 2, entityType?: string): Promise<GraphData> {
  const params = new URLSearchParams({ depth: String(depth) })
  if (entityType) params.set("entity_type", entityType)
  return apiFetch(`/api/v1/intelligence/graph?${params}`)
}

export async function getCampaigns(): Promise<{ campaigns: Campaign[] }> {
  return apiFetch("/api/v1/campaigns")
}

export async function getCampaign(campaignId: string): Promise<Campaign> {
  return apiFetch(`/api/v1/intelligence/campaign/${campaignId}`)
}

export async function getThreatActor(actorId: string) {
  return apiFetch(`/api/v1/intelligence/actor/${actorId}`)
}

export async function correlateIOCs(domains: string[], ips: string[] = [], hashes: string[] = []) {
  return apiFetch("/api/v1/intelligence/correlate", {
    method: "POST",
    body: JSON.stringify({ iocs: { domains, ips, hashes } }),
  })
}

export async function executeResponse(
  action: string,
  target: Record<string, unknown>,
  confirmed = true
) {
  return apiFetch("/api/v1/response/execute", {
    method: "POST",
    body: JSON.stringify({ action, target, analyst_confirmation: confirmed }),
  })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

export function verdictColor(verdict: string): string {
  switch (verdict) {
    case "CRITICAL": return "text-red-500"
    case "PHISHING": return "text-orange-500"
    case "SUSPICIOUS": return "text-yellow-500"
    case "SAFE": return "text-emerald-500"
    default: return "text-muted-foreground"
  }
}

export function verdictBg(verdict: string): string {
  switch (verdict) {
    case "CRITICAL": return "bg-red-500/10 border-red-500/30 text-red-400"
    case "PHISHING": return "bg-orange-500/10 border-orange-500/30 text-orange-400"
    case "SUSPICIOUS": return "bg-yellow-500/10 border-yellow-500/30 text-yellow-400"
    case "SAFE": return "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
    default: return "bg-muted text-muted-foreground"
  }
}

export function severityColor(severity: string): string {
  switch (severity) {
    case "critical": return "text-red-400"
    case "high": return "text-orange-400"
    case "medium": return "text-yellow-400"
    case "low": return "text-blue-400"
    default: return "text-muted-foreground"
  }
}

// ── New endpoints ─────────────────────────────────────────────────────────────

export async function getActors(): Promise<{ actors: Campaign[] }> {
  return apiFetch("/api/v1/actors")
}

export async function getCampaignDetail(campaignId: string): Promise<Campaign> {
  return apiFetch(`/api/v1/campaigns/${campaignId}`)
}

export async function generateReport(eventId: string, analystName?: string): Promise<Response> {
  const res = await fetch(`${API_BASE}/api/v1/reports/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ event_id: eventId, analyst_name: analystName || "Security Analyst", include_iocs: true, include_mitre: true }),
  })
  return res
}

export async function getEventResult(eventId: string): Promise<AnalysisResult> {
  return apiFetch(`/api/v1/events/${eventId}/result`)
}

export async function searchIntelligence(query: string) {
  return apiFetch("/api/v1/intelligence/search", {
    method: "POST",
    body: JSON.stringify({ query }),
  })
}

export async function listCampaigns(params?: {
  actor?: string
  status?: string
  risk_level?: string
  search?: string
  limit?: number
}) {
  const qs = new URLSearchParams()
  if (params?.actor) qs.set("actor", params.actor)
  if (params?.status) qs.set("status", params.status)
  if (params?.risk_level) qs.set("risk_level", params.risk_level)
  if (params?.search) qs.set("search", params.search)
  if (params?.limit) qs.set("limit", String(params.limit))
  return apiFetch<{ campaigns: Campaign[]; total: number }>(`/api/v1/campaigns?${qs}`)
}

// ── PS-01 New Endpoints ───────────────────────────────────────────────────────

export async function analyzeHeaders(headers: string): Promise<AnalysisResult> {
  return apiFetch("/api/v1/analyze/headers", {
    method: "POST",
    body: JSON.stringify({ headers }),
  })
}

export async function sandboxUrl(url: string, depth = "standard") {
  return apiFetch("/api/v1/sandbox/analyze", {
    method: "POST",
    body: JSON.stringify({ url, depth }),
  })
}

export async function getHistoryStats() {
  return apiFetch("/api/v1/history/stats")
}

export async function getHistoryList(page = 1, limit = 15, verdict?: string) {
  const qs = new URLSearchParams({ page: String(page), limit: String(limit) })
  if (verdict && verdict !== "ALL") qs.set("verdict", verdict)
  return apiFetch(`/api/v1/history?${qs}`)
}

export async function submitFeedback(event_id: string, feedback_type: "correct" | "false_positive" | "missed", note?: string) {
  return apiFetch("/api/v1/feedback", {
    method: "POST",
    body: JSON.stringify({ event_id, feedback_type, note }),
  })
}

export async function getGmailStatus() {
  return apiFetch("/api/v1/gmail/status")
}

export async function connectGmailDemo() {
  return apiFetch("/api/v1/gmail/demo-connect")
}

export async function getGmailInbox(page = 1, riskFilter = "ALL") {
  return apiFetch(`/api/v1/gmail/inbox?page=${page}&risk_filter=${riskFilter}`)
}

export async function analyzeGmailMessage(messageId: string) {
  return apiFetch(`/api/v1/gmail/analyze/${messageId}`, { method: "POST" })
}
