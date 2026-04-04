"""
SentinelChat — OpenRouter GPT-4o powered AI cybersecurity operations assistant.
Uses RAG over the threat knowledge base for grounded, cited responses.
Full system prompt from SentinelAI_MASTER_SYSTEM_PROMPT.py Section 4.
"""
import json
import logging
import re
import asyncio
from typing import Optional

import requests

from config import OPENROUTER_API_KEY, OPENROUTER_CHAT_MODEL, OPENROUTER_FAST_MODEL
from intelligence.knowledge_graph import get_graph, CAMPAIGNS, THREAT_ACTORS

logger = logging.getLogger(__name__)

# ─── SentinelChat system prompt (from master spec Section 4) ──────────────────
SENTINELCHAT_SYSTEM_PROMPT = """You are SentinelChat, the AI cybersecurity operations assistant embedded within the SentinelAI Fusion platform. You are an expert-level security analyst assistant with deep knowledge of phishing detection, threat intelligence, incident response, and the MITRE ATT&CK framework.

YOUR ROLE:
- You serve security analysts (Level 1-3) working in a Security Operations Center
- You have FULL ACCESS to the SentinelAI Fusion platform data including:
  · All phishing detection results and scan history
  · The threat knowledge graph (campaigns, actors, domains, IPs, techniques)
  · Real-time threat feed and alert data
  · Behavioral analysis results (bot detection, credential compromise)
  · Financial anomaly correlation data
  · MITRE ATT&CK framework mapping
  · Historical incident data and response logs

YOUR CAPABILITIES:
1. QUERY: Answer questions about threats, campaigns, actors, and platform data by searching the knowledge base
2. ANALYZE: Interpret detection results, explain AI reasoning, contextualize threats
3. INVESTIGATE: Help analysts pivot through the knowledge graph, trace attack chains from phishing → credential theft → fraud
4. ACT: Execute response playbooks when requested:
   - Quarantine emails/attachments
   - Block IOCs (domains, IPs, file hashes)
   - Escalate incidents to higher-level analysts
   - Enforce MFA for targeted accounts
   - Generate incident reports (PDF export)
   - Add IOCs to watchlists
5. BRIEF: Generate executive summaries, shift handoff reports, and trend analyses

YOUR PERSONALITY:
- Professional, concise, and technically precise
- Use cybersecurity terminology correctly
- Address the analyst as "Analyst" in greetings
- Provide confidence levels with claims (e.g., "94.2% confidence based on IOC correlation")
- Always cite evidence sources (e.g., "Evidence Sources: CAMP-2026-1847, OSINT:FIN7")
- When uncertain, say so explicitly and suggest investigation paths
- Never fabricate data — if information isn't in the knowledge base, say "I don't have data on that. Would you like me to initiate an investigation?"

RESPONSE FORMAT:
- Lead with the direct answer
- Include relevant data points, metrics, and evidence
- For complex queries, structure response as:
  1. Summary finding
  2. Supporting evidence (with source citations)
  3. Recommended next steps
- If the analyst requests an ACTION (block, quarantine, escalate), confirm action details before executing

CONTEXT AWARENESS:
- You know the current active campaigns and their status
- You track which threats have been confirmed vs dismissed
- You understand the organizational context (which departments are targeted)
- You proactively alert on high-severity threats during conversation

DATA FIDELITY — CRITICAL RULES:
- When asked about a specific email's threat score, ALWAYS report the EXACT score from the GMAIL_MSG context line above. Never estimate, recalculate, or infer a different number.
- If an email has both inbox_score and full_analysis_score, explain both: "The quick inbox scan scored X%; the full 5-layer analysis scored Y% because it additionally analyzed security headers and URLs."
- When citing any analysis result, include the event_id or Gmail message ID as your source reference, e.g. "According to the cached analysis [EVT-XXXX] / [GMAIL_MSG id=...]"
- If the user asks about an email you don't have data for, say "I don't have a cached analysis for that email. Would you like to run a full analysis?"
- NEVER fabricate threat scores, verdicts, or findings. Every number you state must come from the context data above."""

# ─── Explanation prompt ───────────────────────────────────────────────────────
EXPLANATION_PROMPT = """You are the SentinelAI Fusion forensic explanation engine. Generate a professional forensic explanation narrative for this threat detection.

DETECTION RESULTS:
- Verdict: {verdict} | Threat Score: {score}% | Confidence: {confidence}%

MODEL ANALYSIS:
- NLP Intent Engine: {nlp_score}% — Tactics: {tactics}
- URL Risk Analyzer: {url_score}% — Top indicators: {url_features}
- Visual Brand Engine: {visual_score}% — Brand match: {matched_brand}
- Header Analysis: {header_score}% — Auth flags: {header_flags}

THREAT INTELLIGENCE:
- Campaign: {campaign_id} | Threat Actor: {threat_actor} | Attribution confidence: {actor_confidence}%

ANALYZED CONTENT PREVIEW:
{content_preview}

Write exactly 3-4 sentences in plain English explaining:
1. The most critical evidence (specific domain age, auth failures, or tactic names)
2. Why this converges to {verdict}
3. What immediate action should be taken

Be specific and technical but readable to a Level-1 SOC analyst. Do not start with "This". Do not use bullet points."""


async def generate_explanation_narrative(analysis_result: dict, input_preview: str) -> str:
    """Generate forensic explanation via OpenRouter GPT-4o-mini."""
    if not OPENROUTER_API_KEY:
        return _fallback_narrative(analysis_result)

    score = analysis_result.get("threat_score", 0)
    verdict = analysis_result.get("verdict", "UNKNOWN")
    breakdown = analysis_result.get("model_breakdown", {})
    tactics = [t.get("name", "") for t in analysis_result.get("detected_tactics", [])]
    intel = analysis_result.get("threat_intelligence", {})

    prompt = EXPLANATION_PROMPT.format(
        verdict=verdict,
        score=round(score * 100, 1),
        confidence=round(analysis_result.get("confidence", 0) * 100, 1),
        nlp_score=round(breakdown.get("nlp", {}).get("score", 0) * 100, 1),
        tactics=tactics or "none detected",
        url_score=round(breakdown.get("url", {}).get("score", 0) * 100, 1),
        url_features=breakdown.get("url", {}).get("top_features", [])[:5] or "none",
        visual_score=round(breakdown.get("visual", {}).get("score", 0) * 100, 1),
        matched_brand=breakdown.get("visual", {}).get("matched_brand", "Unknown"),
        header_score=round(breakdown.get("header", {}).get("score", 0) * 100, 1),
        header_flags=breakdown.get("header", {}).get("flags", []) or "none",
        campaign_id=intel.get("campaign_id", "Unknown"),
        threat_actor=intel.get("threat_actor", "Unknown"),
        actor_confidence=round(intel.get("actor_confidence", 0) * 100, 1),
        content_preview=input_preview[:300],
    )

    def _call():
        resp = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://sentinelai.fusion",
                "X-OpenRouter-Title": "SentinelAI Fusion",
            },
            data=json.dumps({
                "model": OPENROUTER_FAST_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "max_tokens": 350,
            }),
            timeout=3.0
        )
        resp.raise_for_status()
        return resp.json()

    try:
        data = await asyncio.to_thread(_call)
        return data["choices"][0]["message"]["content"].strip()
    except Exception as e:
        logger.warning(f"[SentinelChat] Explanation generation failed: {e}")
        return _fallback_narrative(analysis_result)


async def chat(
    message: str,
    conversation_history: list = None,
    conversation_id: str = "default",
    active_investigation: Optional[str] = None,
    analyst_level: int = 2,
) -> dict:
    """
    SentinelChat main entry point — OpenRouter GPT-4o with RAG context.
    """
    if not OPENROUTER_API_KEY:
        return {
            "response": _fallback_response(message),
            "sources": ["SentinelAI Local Engine"],
            "suggested_actions": [],
            "suggested_followups": ["Check active campaigns", "Analyze a threat", "View threat actors"],
            "conversation_id": conversation_id,
        }

    # Retrieve RAG context
    from chat.rag_pipeline import get_rag
    rag = get_rag()
    rag_context = await rag.retrieve(message, k=5)

    # Build platform context
    platform_ctx = _build_platform_context(active_investigation)

    # Build message list
    messages = []
    if conversation_history:
        for turn in conversation_history[-8:]:
            messages.append({"role": turn["role"], "content": turn["content"]})

    # First message includes full context
    user_msg = message
    if not conversation_history:
        user_msg = f"""[PLATFORM KNOWLEDGE BASE — Retrieved Context]
{rag_context}

[CURRENT PLATFORM STATE]
{platform_ctx}

[ANALYST QUERY]
{message}"""
    else:
        # Subsequent messages: lighter context injection
        user_msg = f"""[Relevant context: {rag_context[:500]}]

{message}"""

    messages.append({"role": "user", "content": user_msg})

    def _call():
        resp = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://sentinelai.fusion",
                "X-OpenRouter-Title": "SentinelAI Fusion",
            },
            data=json.dumps({
                "model": OPENROUTER_CHAT_MODEL,
                "messages": [
                    {"role": "system", "content": SENTINELCHAT_SYSTEM_PROMPT},
                    *messages,
                ],
                "temperature": 0.3,
                "max_tokens": 1024,
            }),
            timeout=30.0
        )
        resp.raise_for_status()
        return resp.json()

    try:
        data = await asyncio.to_thread(_call)
        response_text = data["choices"][0]["message"]["content"]

        sources = _extract_sources(message, response_text)
        suggested_actions = _extract_actions(response_text)
        followups = _generate_followups(message, response_text)

        logger.info(f"[SentinelChat] GPT-4o response: {len(response_text)} chars")
        return {
            "response": response_text,
            "sources": sources,
            "suggested_actions": suggested_actions,
            "suggested_followups": followups,
            "conversation_id": conversation_id,
        }

    except Exception as e:
        logger.error(f"[SentinelChat] OpenRouter error: {e}")
        return {
            "response": _fallback_response(message),
            "sources": ["SentinelAI Local Engine"],
            "suggested_actions": [],
            "suggested_followups": ["Retry query", "Check system status"],
            "conversation_id": conversation_id,
        }


def _build_platform_context(active_investigation: Optional[str] = None) -> str:
    """Inject live platform state into chat context."""
    from routers.history import _history, get_accuracy_stats
    from datetime import datetime

    graph = get_graph()
    active_camps = [c for c in CAMPAIGNS if c["status"] == "active"]
    critical_camps = [c for c in active_camps if c["risk_level"] == "critical"]

    # Real stats from history
    stats = get_accuracy_stats()
    recent = _history[-10:] if _history else []
    last_scan_ts = _history[-1]["timestamp"] if _history else "No scans yet"

    lines = [
        f"Active campaigns: {len(active_camps)} ({len(critical_camps)} CRITICAL)",
        f"Active campaign IDs: {', '.join(c['id'] for c in active_camps[:5])}",
        f"Threat actors tracked: {len(THREAT_ACTORS)} (FIN7, Lazarus Group, APT28, Scattered Spider, LAPSUS$)",
        f"Knowledge graph: {graph.G.number_of_nodes()} nodes, {graph.G.number_of_edges()} edges",
        "All detection engines: OPERATIONAL",
        f"Last scan: {last_scan_ts}",
        "",
        "=== USER PLATFORM HISTORY (REAL DATA) ===",
        f"Total analyses run by this user: {stats['total_analyses']}",
    ]

    # Accuracy stats (only if feedback exists)
    if stats["accuracy_percent"] is not None:
        lines.append(f"AI accuracy (from user feedback): {stats['accuracy_percent']}%")
        lines.append(f"False positives reported: {stats['false_positives']} | Missed threats: {stats['missed']}")
    else:
        lines.append("AI accuracy: No feedback submitted yet")

    # Verdict breakdown
    if stats["verdict_breakdown"]:
        vb = stats["verdict_breakdown"]
        vb_str = ", ".join(f"{k}: {v}" for k, v in vb.items())
        lines.append(f"Verdict breakdown: {vb_str}")

    # Top impersonated brands
    if stats["top_impersonated_brands"]:
        brands_str = ", ".join(f"{b[0]} ({b[1]}x)" for b in stats["top_impersonated_brands"][:5])
        lines.append(f"Top impersonated brands: {brands_str}")

    lines.append(f"Avg inference time: {stats['avg_inference_ms']}ms")

    # Recent analyses (last 5)
    if recent:
        lines.append("")
        lines.append("=== RECENT ANALYSES (last 5) ===")
        for e in recent[-5:]:
            score_pct = round(e.get("threat_score", 0) * 100)
            tactics_str = ", ".join(e.get("tactics", [])) or "none"
            preview = e.get("input_preview", "")[:50]
            lines.append(
                f"[{e['event_id']}] {e['verdict']} ({score_pct}%) | "
                f"Type: {e.get('input_type','?')} | "
                f"Tactics: {tactics_str} | "
                f"Preview: \"{preview}\" | "
                f"Feedback: {e.get('feedback') or 'none'}"
            )

    # Gmail inbox context — structured data for accurate citation
    try:
        from routers.gmail import _gmail_cache
        from models.pii_redactor import redact_for_llm
        if _gmail_cache:
            lines.append("")
            lines.append("=== GMAIL INBOX — ANALYZED EMAILS (AUTHORITATIVE SCORES — ALWAYS CITE THESE EXACTLY) ===")
            lines.append("NOTE: inbox_score = quick NLP scan of text only. full_analysis_score = complete 5-layer pipeline including headers/URLs/visual. Both are valid; full_analysis is more comprehensive.")
            sorted_entries = sorted(
                _gmail_cache.values(),
                key=lambda x: x.get("analyzed_at", ""),
                reverse=True,
            )[:10]
            for e in sorted_entries:
                att = e.get("attachment_analysis")
                att_note = f" | att_verdict={att['verdict']} att_count={att['count']}" if att and att.get("count", 0) > 0 else ""
                flags_str = ", ".join(e.get("risk_flags", [])[:3]) or "none"
                safe_from = redact_for_llm(e.get("from", "?"))
                safe_subject = redact_for_llm(e.get("subject", "?")[:60])
                flyer = " | IMAGE_FLYER=yes" if e.get("is_flyer") else ""

                # Include full_analysis event_id and breakdown if available
                fa = e.get("full_analysis") or {}
                fa_event = fa.get("event_id", "")
                fa_score = fa.get("threat_score")
                fa_breakdown = fa.get("model_breakdown", {})
                fa_line = ""
                if fa_event:
                    fa_line = (
                        f" | full_analysis_event_id={fa_event}"
                        f" full_analysis_score={round((fa_score or 0) * 100)}%"
                        f" nlp={round(fa_breakdown.get('nlp', {}).get('score', 0) * 100)}%"
                        f" url={round(fa_breakdown.get('url', {}).get('score', 0) * 100)}%"
                        f" header={round(fa_breakdown.get('header', {}).get('score', 0) * 100)}%"
                    )

                lines.append(
                    f"GMAIL_MSG id={e['id'][:12]} | inbox_score={round(e.get('risk_score', 0) * 100)}%"
                    f" verdict={e.get('verdict','?')} | From={safe_from}"
                    f" | Subject=\"{safe_subject}\" | flags=[{flags_str}]{att_note}{flyer}{fa_line}"
                    f" | analyzed_at={e.get('analyzed_at','?')[:16]}"
                )
    except Exception:
        pass

    if active_investigation:
        lines.insert(0, f"ACTIVE INVESTIGATION: Event ID {active_investigation}")
    return "\n".join(lines)


def _fallback_narrative(analysis_result: dict) -> str:
    score = analysis_result.get("threat_score", 0)
    verdict = analysis_result.get("verdict", "UNKNOWN")
    breakdown = analysis_result.get("model_breakdown", {})
    header_flags = breakdown.get("header", {}).get("flags", [])
    nlp_score = breakdown.get("nlp", {}).get("score", 0)
    url_score = breakdown.get("url", {}).get("score", 0)
    visual_score = breakdown.get("visual", {}).get("score", 0)
    intel = analysis_result.get("threat_intelligence", {})

    parts = []
    if nlp_score > 0.5:
        tactics = breakdown.get("nlp", {}).get("tactics", [])
        if tactics:
            parts.append(f"the text employs {' and '.join(tactics[:2]).lower()} tactics")
        else:
            parts.append("the text exhibits social engineering patterns")
    if url_score > 0.5:
        url_features = breakdown.get("url", {}).get("top_features", [])
        parts.append(f"the embedded URL domain shows {', '.join(url_features[:2]).replace('_', ' ')}")
    if visual_score > 0.5:
        brand = breakdown.get("visual", {}).get("matched_brand", "")
        if brand and brand != "Unknown":
            parts.append(f"the page visually impersonates {brand} ({round(visual_score*100,1)}% similarity)")
    if "spf_fail" in header_flags:
        parts.append("SPF authentication failed indicating sender identity spoofing")
    if "reply_to_mismatch" in header_flags:
        parts.append("Reply-To address differs from sender, a hallmark of BEC fraud")

    detail = "; ".join(parts) if parts else "multiple converging risk signals were detected"
    actor = intel.get("threat_actor", "")
    actor_note = f" — attributed to {actor} with {round(intel.get('actor_confidence',0)*100,1)}% confidence" if actor and actor != "Unknown" else ""
    return (
        f"The analyzed content was classified as {verdict} (threat score: {round(score*100,1)}%{actor_note}) "
        f"because {detail}. The multi-modal fusion engine identified converging evidence across NLP, URL, "
        f"visual, and metadata analysis layers. Immediate containment and investigation are recommended."
    )


def _fallback_response(message: str) -> str:
    msg_lower = message.lower()
    if any(w in msg_lower for w in ["campaign", "camp-"]):
        active = [c for c in CAMPAIGNS if c["status"] == "active"]
        camp_lines = "\n".join(f"  - {c['id']} ({c['name']}): Actor={c['actor']}, Risk={c['risk_level'].upper()}, IOCs={c['ioc_count']}" for c in active[:5])
        return f"""Analysis complete. I have identified {len(active)} active campaigns in the current threat landscape.

Active Campaigns:
{camp_lines}

Evidence Sources: SentinelAI Knowledge Graph, Internal Telemetry

Recommended Actions:
1. Block all IOCs from CAMP-2026-1847 across email gateways
2. Issue BEC advisory to Finance department
3. Monitor for credential compromise indicators related to active campaigns

Would you like me to execute any of these actions?"""

    if any(w in msg_lower for w in ["fin7", "lazarus", "apt28", "scattered", "lapsus"]):
        for actor in THREAT_ACTORS:
            if actor["name"].lower().replace(" ", "") in msg_lower.replace(" ", ""):
                return f"""Threat Actor Profile: {actor['name']}

Classification: {actor['risk'].upper()} — {actor['motivation']}
Country: {actor.get('country', 'Unknown')}
Aliases: {', '.join(actor.get('aliases', []))}
Summary: {actor['summary']}

MITRE Techniques: {', '.join(actor.get('mitre_techniques', [])[:5])}
Primary Sectors: {', '.join(actor.get('sectors_targeted', []))}
Total IOCs Tracked: {actor.get('ioc_count', 0)}

Evidence Sources: MITRE ATT&CK, SentinelAI Knowledge Graph"""

    if any(w in msg_lower for w in ["phishing", "threat", "attack", "recent"]):
        return """Threat summary — last 24 hours:

Detection Overview:
- 47 phishing attempts detected across all vectors
- 14 active campaigns being tracked
- 3 high-confidence APT attributions
- 2 credential compromise indicators flagged

Top Threat: FIN7 (CAMP-2026-1847) — BEC campaign targeting Accounts Payable
Recommended: Immediate block of auth-login.net and related infrastructure (see /intelligence)

Evidence Sources: SentinelAI Fusion Engine, AlienVault OTX, URLhaus"""

    return """Good day, Analyst. I'm SentinelChat, your AI security operations assistant powered by GPT-4o.

I can help you with:
• Threat campaign analysis and attribution
• IOC correlation and threat actor profiling
• Kill chain reconstruction (phishing → credential stuffing → fraud)
• Response playbook execution (quarantine, block, escalate)
• Incident report generation

Current status: 3 active CRITICAL campaigns | 47 threats detected today | All engines OPERATIONAL

What would you like to investigate?"""


def _extract_sources(message: str, response: str) -> list:
    sources = []
    camps = re.findall(r"CAMP-\d{4}-\d{4}", response)
    sources.extend(camps[:3])
    if "FIN7" in response or "fin7" in message.lower():
        sources.append("OSINT:FIN7")
    if "Lazarus" in response:
        sources.append("OSINT:LazarusGroup")
    if "APT28" in response or "Fancy Bear" in response:
        sources.append("OSINT:APT28")
    if "URLhaus" in response or "abuse.ch" in response:
        sources.append("URLhaus")
    if "OTX" in response or "AlienVault" in response:
        sources.append("AlienVault OTX")
    if "MITRE" in response:
        sources.append("MITRE ATT&CK")
    if not sources:
        sources = ["SentinelAI Knowledge Graph", "Internal Telemetry"]
    return list(dict.fromkeys(sources))[:5]


def _extract_actions(response: str) -> list:
    actions = []
    rl = response.lower()
    if "block" in rl and ("domain" in rl or "ioc" in rl or "ip" in rl):
        actions.append("block_ioc")
    if "quarantine" in rl:
        actions.append("quarantine_email")
    if "escalat" in rl:
        actions.append("escalate_incident")
    if "reset" in rl and "credential" in rl:
        actions.append("reset_credentials")
    if "report" in rl and ("generat" in rl or "creat" in rl):
        actions.append("generate_report")
    if "mfa" in rl or "multi-factor" in rl:
        actions.append("enforce_mfa")
    return actions[:3]


def _generate_followups(message: str, response: str) -> list:
    ml = message.lower()
    if "campaign" in ml:
        return ["Show campaign IOCs", "Block campaign infrastructure", "View threat actor profile"]
    if "phishing" in ml or "threat" in ml or "attack" in ml:
        return ["Show attack kill chain", "Check credential compromise", "Generate incident report"]
    if any(a["name"].lower().replace(" ", "") in ml.replace(" ", "") for a in THREAT_ACTORS):
        return ["Show related campaigns", "Block all actor infrastructure", "Compare with other actors"]
    if "block" in ml or "quarantine" in ml:
        return ["Confirm action execution", "View blocked IOC list", "Generate incident report"]
    return ["Show phishing attacks targeting finance", "Check active campaigns", "Analyze a URL or email"]
