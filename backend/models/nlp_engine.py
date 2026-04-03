"""
NLP Intent Engine — Analyzes email/message text for phishing intent.
Uses OpenRouter GPT-4o-mini for semantic understanding of manipulation tactics.
Falls back to enhanced heuristic analysis if API unavailable.
"""
import re
import json
import asyncio
import logging
from typing import Optional

import requests

from config import OPENROUTER_API_KEY, OPENROUTER_FAST_MODEL

logger = logging.getLogger(__name__)

# ─── MITRE ATT&CK tactic registry ────────────────────────────────────────────
TACTIC_MITRE_MAP = {
    "urgency":                  {"mitre_id": "T1566.001", "weight": 0.18},
    "authority_impersonation":  {"mitre_id": "T1656",     "weight": 0.15},
    "financial_lure":           {"mitre_id": "T1078",     "weight": 0.14},
    "credential_harvesting":    {"mitre_id": "T1056.003", "weight": 0.20},
    "suspicious_link":          {"mitre_id": "T1204.001", "weight": 0.12},
    "fear_threat":              {"mitre_id": "T1585",     "weight": 0.13},
    "spoofing":                 {"mitre_id": "T1566.002", "weight": 0.08},
    "reward_framing":           {"mitre_id": "T1585.002", "weight": 0.10},
    "bec_pattern":              {"mitre_id": "T1534",     "weight": 0.16},
    "executive_impersonation":  {"mitre_id": "T1656",     "weight": 0.17},
}

# ─── Heuristic fallback patterns ─────────────────────────────────────────────
TACTIC_PATTERNS = {
    "urgency": [
        r"\b(urgent|immediately|right away|asap|within \d+ hour|today only|expires|deadline|limited time|act now|don.t delay|critical action|time.sensitive)\b",
        r"\b(your account (will be|has been) (suspended|locked|disabled|terminated))\b",
        r"\b(verify (now|immediately|today)|confirm (now|immediately|your account))\b",
    ],
    "authority_impersonation": [
        r"\b(ceo|cfo|cto|president|director|manager|hr|payroll|it (department|team|helpdesk)|security (team|department))\b",
        r"\b(microsoft|google|apple|amazon|paypal|bank|irs|fbi|government|official)\b",
    ],
    "financial_lure": [
        r"\b(wire transfer|payment|invoice|refund|compensation|\$[\d,]+|funds|billing|overdue|amount.due)\b",
        r"\b(wire \$|transfer \$|send \$|pay \$)\b",
    ],
    "credential_harvesting": [
        r"\b(click (here|this link|below) to (verify|confirm|update|login|sign in|reset))\b",
        r"\b(update your (password|credentials|information|account))\b",
        r"\b(verify your (identity|account|email))\b",
        r"\b(login|sign.?in|password reset|re.?enter|re.?verify)\b",
    ],
    "suspicious_link": [
        r"https?://\S+",
        r"\b(click (here|below|this link))\b",
    ],
    "fear_threat": [
        r"\b(your account (will be|has been) (closed|deleted|suspended|flagged))\b",
        r"\b(failure to (comply|respond|verify) (will|may) result)\b",
        r"\b(legal (action|proceedings)|law enforcement)\b",
    ],
    "bec_pattern": [
        r"\b(wire transfer|wire \$|send funds|initiate payment|urgent payment|new banking details|change.*account.*number)\b",
        r"\b(confidential|do not discuss|don.t mention to anyone)\b",
    ],
    "executive_impersonation": [
        r"\b(from:.*ceo|from:.*cfo|from:.*president|from:.*director)\b",
        r"\b(this is (your|our) (ceo|cfo|president|boss)|i am the (ceo|cfo|president))\b",
    ],
}

BENIGN_SIGNALS = [
    r"\b(unsubscribe|privacy policy|terms of service|©|copyright)\b",
    r"\b(best regards|sincerely|thank you for your (business|order))\b",
    r"\b(invoice #[\w-]+|order #[\w-]+|ticket #[\w-]+)\b",
    r"\b(scheduled meeting|calendar invite|join us for)\b",
]

OBFUSCATION_PATTERNS = [
    r"[а-яёА-ЯЁ]",
    r"&#\d+;",
    r"%[0-9a-fA-F]{2}",
]

# ─── LLM prompt ───────────────────────────────────────────────────────────────
PHISHING_ANALYSIS_PROMPT = """You are an expert cybersecurity analyst specialized in phishing and social engineering detection.

Analyze the following email/text content for phishing indicators. Return ONLY a valid JSON object with these exact fields:
{{
  "intent_score": <float 0.0-1.0>,
  "detected_tactics": <list of strings from: ["urgency","authority_impersonation","financial_lure","credential_harvesting","suspicious_link","fear_threat","spoofing","reward_framing","bec_pattern","executive_impersonation"]>,
  "confidence": <float 0.0-1.0>,
  "explanation": "<2-3 sentence explanation>",
  "top_phrases": <list of suspicious phrases>,
  "phishing_intent": "<concise description of goal>"
}}

Key guidance:
- Urgency: time pressure, account suspension threats, "act now" language
- Authority impersonation: pretending to be CFO/CEO/IT/government/bank
- BEC pattern: Business Email Compromise - wire transfer requests, payment urgency
- Executive impersonation: specifically impersonating named executives
- If content looks legitimate (meeting invite, real business communication), score 0.05-0.15
- If content has 1-2 mild signals, score 0.3-0.5
- If content has strong multiple converging signals, score 0.7-0.95
- Reserve 0.95+ for clear, unambiguous phishing with multiple high-confidence tactics

Content to analyze:
---
{content}
---

Return ONLY the JSON object, no other text."""


async def analyze_text_llm(text: str) -> dict:
    """Use OpenRouter GPT-4o-mini for semantic phishing intent analysis."""
    if not OPENROUTER_API_KEY:
        raise ValueError("OPENROUTER_API_KEY not configured")

    # Truncate to 2000 chars for speed/cost
    content_preview = text[:2000] if len(text) > 2000 else text

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://sentinelai.fusion",
        "X-OpenRouter-Title": "SentinelAI Fusion",
    }

    payload = {
        "model": OPENROUTER_FAST_MODEL,
        "messages": [
            {
                "role": "user",
                "content": PHISHING_ANALYSIS_PROMPT.format(content=content_preview),
            }
        ],
        "temperature": 0.1,
        "max_tokens": 500,
        "response_format": {"type": "json_object"},
    }

    def _call():
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            data=json.dumps(payload),
        )
        response.raise_for_status()
        return response.json()

    data = await asyncio.to_thread(_call)

    raw_content = data["choices"][0]["message"]["content"]

    try:
        result = json.loads(raw_content.strip())
    except json.JSONDecodeError:
        # Fallback: strip markdown code blocks and retry
        cleaned = _clean_llm_json(raw_content)
        try:
            result = json.loads(cleaned)
        except Exception as e:
            logger.error(f"[NLP] JSON parse failed. Raw content: {raw_content[:200]!r}")
            raise e

    # Validate and clamp
    intent_score = float(result.get("intent_score", 0.1))
    intent_score = max(0.02, min(0.98, intent_score))

    confidence = float(result.get("confidence", 0.7))
    confidence = max(0.3, min(0.99, confidence))

    tactics_raw = result.get("detected_tactics", [])
    detected_tactics = []
    for t in tactics_raw:
        if not isinstance(t, str): continue
        t = t.strip().lower().replace(" ", "_")
        if t in TACTIC_MITRE_MAP:
            detected_tactics.append({
                "name": t.replace("_", " ").title(),
                "mitre_id": TACTIC_MITRE_MAP[t]["mitre_id"],
                "confidence": min(confidence + 0.05, 0.99),
            })

    return {
        "score": round(intent_score, 4),
        "confidence": round(confidence, 4),
        "detected_tactics": detected_tactics,
        "explanation": result.get("explanation", ""),
        "top_phrases": result.get("top_phrases", [])[:5],
        "phishing_intent": result.get("phishing_intent", ""),
        "feature_contributions": {t: TACTIC_MITRE_MAP[t]["weight"] for t in tactics_raw if t in TACTIC_MITRE_MAP},
        "source": "openrouter_gpt4o_mini",
    }


def analyze_text_heuristic(text: str) -> dict:
    """Enhanced heuristic fallback — used when OpenRouter is unavailable."""
    if not text or len(text.strip()) < 10:
        return {
            "score": 0.05, "confidence": 0.3, "detected_tactics": [],
            "explanation": "Insufficient content for analysis.",
            "feature_contributions": {}, "source": "heuristic_fallback",
        }

    text_lower = text.lower()
    detected = []
    total_weight = 0.0
    feature_contributions = {}

    for tactic_name, patterns in TACTIC_PATTERNS.items():
        match_count = sum(
            len(re.findall(p, text_lower, re.IGNORECASE)) for p in patterns
        )
        if match_count > 0:
            info = TACTIC_MITRE_MAP[tactic_name]
            contribution = min(info["weight"] * (1 + 0.1 * (match_count - 1)), info["weight"] * 1.5)
            total_weight += contribution
            feature_contributions[tactic_name] = round(contribution, 4)
            detected.append({
                "name": tactic_name.replace("_", " ").title(),
                "mitre_id": info["mitre_id"],
                "confidence": min(0.5 + 0.1 * match_count, 0.97),
            })

    # Obfuscation bonus
    for pat in OBFUSCATION_PATTERNS:
        if re.search(pat, text):
            total_weight += 0.06

    total_weight = min(total_weight, 0.97)

    # Benign reduction
    benign_hits = sum(1 for p in BENIGN_SIGNALS if re.search(p, text_lower, re.IGNORECASE))
    if benign_hits > 0:
        total_weight = max(total_weight - benign_hits * 0.04, 0.02)

    url_count = len(re.findall(r"https?://\S+", text))
    if url_count > 2:
        total_weight = min(total_weight + 0.05, 0.97)

    score = round(max(0.04, min(total_weight, 0.97)), 4)
    confidence = round(min(0.55 + score * 0.4, 0.97), 4)

    tactic_names = [t["name"] for t in detected]
    explanation = _build_heuristic_explanation(score, tactic_names, url_count)

    # Extract concrete phrases that matched
    top_phrases = []
    for tactic_name, patterns in TACTIC_PATTERNS.items():
        for pat in patterns:
            matches = re.findall(pat, text[:2000], re.IGNORECASE)
            for m in matches[:2]:
                phrase = m if isinstance(m, str) else m[0]
                if phrase and len(phrase) > 3 and phrase not in top_phrases:
                    top_phrases.append(phrase.strip())
                if len(top_phrases) >= 5:
                    break
            if len(top_phrases) >= 5:
                break

    phishing_intent = ""
    if tactic_names:
        if "Bec Pattern" in tactic_names or "Executive Impersonation" in tactic_names:
            phishing_intent = "BEC wire transfer fraud — impersonating executive to redirect funds"
        elif "Credential Harvesting" in tactic_names:
            phishing_intent = "Credential harvesting — trick victim into entering login details on fake page"
        elif "Authority Impersonation" in tactic_names:
            phishing_intent = "Authority impersonation — gain trust by posing as trusted organization"
        elif "Financial Lure" in tactic_names:
            phishing_intent = "Financial lure — entice victim with payment or refund to steal data"
        elif "Urgency" in tactic_names:
            phishing_intent = "Urgency manipulation — pressure victim into acting without verification"

    return {
        "score": score,
        "confidence": confidence,
        "detected_tactics": detected,
        "explanation": explanation,
        "top_phrases": top_phrases[:5],
        "phishing_intent": phishing_intent,
        "feature_contributions": feature_contributions,
        "url_count": url_count,
        "source": "heuristic_fallback",
    }


def _build_heuristic_explanation(score: float, tactic_names: list, url_count: int) -> str:
    if score < 0.2:
        return "Email content appears legitimate. No significant phishing indicators detected."
    parts = []
    if "Urgency" in tactic_names:
        parts.append("uses urgency manipulation tactics")
    if "Authority Impersonation" in tactic_names:
        parts.append("impersonates an authority figure or trusted organization")
    if "Bec Pattern" in tactic_names:
        parts.append("matches Business Email Compromise (BEC) wire transfer patterns")
    if "Executive Impersonation" in tactic_names:
        parts.append("impersonates a named executive")
    if "Credential Harvesting" in tactic_names:
        parts.append("attempts credential harvesting via deceptive link")
    if "Financial Lure" in tactic_names:
        parts.append("contains financial manipulation language")
    if "Fear Threat" in tactic_names:
        parts.append("uses fear and threat tactics")
    if url_count > 0:
        parts.append(f"contains {url_count} embedded URL(s)")
    if not parts:
        parts.append("exhibits patterns consistent with social engineering")
    base = "Heuristic analysis flags this content: " + ", ".join(parts) + "."
    if score > 0.8:
        base += f" Confidence: HIGH ({round(score * 100, 1)}%)."
    elif score > 0.5:
        base += f" Confidence: MEDIUM ({round(score * 100, 1)}%). Manual review recommended."
    return base


def _clean_llm_json(text: str) -> str:
    """Helper to extract JSON from a potentially messy LLM output."""
    # Find the indices of the first '{' and the last '}'
    start = text.find('{')
    end = text.rfind('}')
    
    if start != -1 and end != -1 and end > start:
        return text[start:end+1]
    
    # Generic cleanup as fallback
    text = re.sub(r"```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```", "", text)
    return text.strip()


async def analyze_text(text: str, input_type: str = "email") -> dict:
    """
    Main entry point.
    Runs GPT-4o-mini + BERT phishing model in parallel.
    Averages their scores for reproducible, measurable accuracy.
    Falls back gracefully when either is unavailable.
    """
    if not text or len(text.strip()) < 5:
        return {
            "score": 0.05, "confidence": 0.3, "detected_tactics": [],
            "explanation": "No content provided.", "feature_contributions": {},
        }

    # ── Run GPT-4o-mini and BERT in parallel ─────────────────────────────────
    try:
        from models.bert_phishing_model import predict as bert_predict
        gpt_task = asyncio.create_task(analyze_text_llm(text))
        bert_task = asyncio.create_task(bert_predict(text))
        gpt_result, bert_result = await asyncio.gather(gpt_task, bert_task, return_exceptions=True)
    except ImportError:
        # BERT not available — run GPT only
        gpt_result = await _run_gpt_safe(text)
        bert_result = None

    # ── Resolve GPT result ────────────────────────────────────────────────────
    if isinstance(gpt_result, Exception):
        logger.warning(f"[NLP] GPT-4o-mini failed: {gpt_result}")
        gpt_result = None
    if isinstance(bert_result, Exception):
        logger.warning(f"[NLP] BERT failed: {bert_result}")
        bert_result = None

    # ── Both available: ensemble average ─────────────────────────────────────
    if gpt_result and bert_result and bert_result.get("phishing_prob", -1) >= 0:
        gpt_score = gpt_result["score"]
        bert_prob = bert_result["phishing_prob"]

        # Weighted average: GPT-4o-mini 55%, BERT 45%
        ensemble_score = round(gpt_score * 0.55 + bert_prob * 0.45, 4)
        ensemble_score = max(0.02, min(0.98, ensemble_score))

        # Boost confidence when both models agree
        gpt_conf = gpt_result.get("confidence", 0.7)
        agreement = 1.0 - abs(gpt_score - bert_prob)  # 0=disagree, 1=perfect agreement
        ensemble_conf = round(min(gpt_conf * 0.7 + agreement * 0.3, 0.99), 4)

        logger.info(
            f"[NLP] Ensemble: GPT={gpt_score:.3f} BERT={bert_prob:.3f} "
            f"→ avg={ensemble_score:.3f} agreement={agreement:.2f}"
        )

        return {
            **gpt_result,
            "score": ensemble_score,
            "confidence": ensemble_conf,
            "gpt_score": gpt_score,
            "bert_score": bert_prob,
            "bert_label": bert_result.get("label"),
            "source": "ensemble_gpt4o_mini_bert",
        }

    # ── Only GPT available ────────────────────────────────────────────────────
    if gpt_result:
        logger.info(f"[NLP] GPT-4o-mini only: score={gpt_result['score']}")
        return gpt_result

    # ── Only BERT available ───────────────────────────────────────────────────
    if bert_result and bert_result.get("phishing_prob", -1) >= 0:
        bert_prob = bert_result["phishing_prob"]
        logger.info(f"[NLP] BERT only: prob={bert_prob:.3f}")
        heuristic = analyze_text_heuristic(text)
        # Blend BERT with heuristic
        blended = round(bert_prob * 0.65 + heuristic["score"] * 0.35, 4)
        return {
            **heuristic,
            "score": blended,
            "bert_score": bert_prob,
            "bert_label": bert_result.get("label"),
            "source": "bert_heuristic_blend",
        }

    # ── Full fallback: heuristics ─────────────────────────────────────────────
    logger.warning("[NLP] All models unavailable, using heuristics")
    return analyze_text_heuristic(text)


async def _run_gpt_safe(text: str):
    """Run GPT-4o-mini, returning None on failure instead of raising."""
    try:
        return await analyze_text_llm(text)
    except Exception as e:
        logger.warning(f"[NLP] GPT-4o-mini unavailable: {e}")
        return None
