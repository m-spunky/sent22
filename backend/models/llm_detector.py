"""
LLM Fingerprint Detector — Detects AI-generated phishing emails.

Three-pronged detection:
  1. Stylometric analysis   — pure Python statistical features
  2. BERT perplexity variance — token-level confidence spread (low → AI)
  3. Gemma-3-12B meta-analysis — LLM asked "was this written by AI?"

Ensemble scores are fused into a final ai_generated_probability (0-1).
"""
import re
import math
import json
import asyncio
import logging
from typing import Optional

import requests

from config import OPENROUTER_API_KEY, OPENROUTER_FAST_MODEL

logger = logging.getLogger(__name__)

# ── Known formulaic AI phishing phrases ───────────────────────────────────────
_TEMPLATE_PHRASES = [
    r"we have detected",
    r"your account has been",
    r"please click the link below",
    r"verify your (identity|account|information)",
    r"failure to (comply|respond|verify)",
    r"your account (will be|has been) (suspended|closed|locked|disabled)",
    r"click here to (verify|confirm|restore|update|secure)",
    r"immediate action (is )?required",
    r"unauthorized (activity|access|transaction)",
    r"for your (protection|security|safety)",
    r"as a (valued|loyal) (customer|member|user)",
    r"we (regret to inform|are writing to notify)",
    r"kindly (provide|submit|confirm|verify)",
    r"within (24|48|72) hours",
    r"if you did not (initiate|authorize|request)",
    r"to avoid (suspension|closure|termination|disruption)",
    r"update your (payment|billing|account) (information|details)",
    r"do not (ignore|disregard) this (email|message|notice)",
    r"take immediate action",
    r"important (notice|update|security alert)",
]

# ── Stylometric Analysis ──────────────────────────────────────────────────────

def _tokenize_sentences(text: str) -> list[str]:
    """Split text into sentences."""
    sentences = re.split(r'(?<=[.!?])\s+', text.strip())
    return [s.strip() for s in sentences if len(s.strip()) > 3]


def _tokenize_words(text: str) -> list[str]:
    """Split text into words."""
    return re.findall(r'\b[a-zA-Z]+\b', text.lower())


def compute_sentence_length_uniformity(text: str) -> dict:
    """
    AI writes sentences of similar length (low std dev).
    Humans vary widely. AI std < 4, humans std > 8.
    """
    sentences = _tokenize_sentences(text)
    if len(sentences) < 3:
        return {"std_dev": 0.0, "mean_length": 0.0, "score": 0.0, "signal": "insufficient_sentences"}

    lengths = [len(s.split()) for s in sentences]
    mean = sum(lengths) / len(lengths)
    variance = sum((l - mean) ** 2 for l in lengths) / len(lengths)
    std = math.sqrt(variance)

    # Score: low std = likely AI
    if std < 3.0:
        score = 0.85
    elif std < 5.0:
        score = 0.60
    elif std < 8.0:
        score = 0.30
    else:
        score = 0.10

    signal = (
        f"Sentence length std dev: {std:.1f} words "
        f"(AI typical: <4, human typical: >8)"
    )
    return {"std_dev": round(std, 2), "mean_length": round(mean, 1), "score": score, "signal": signal}


def compute_type_token_ratio(text: str) -> dict:
    """
    AI over-uses common words → low Type-Token Ratio.
    AI ≈ 0.3–0.5, humans ≈ 0.6–0.8.
    """
    words = _tokenize_words(text)
    if len(words) < 20:
        return {"ttr": 0.0, "score": 0.0, "signal": "insufficient_words"}

    # Use first 200 words for normalization (TTR is length-dependent)
    sample = words[:200]
    ttr = len(set(sample)) / len(sample)

    if ttr < 0.35:
        score = 0.90
    elif ttr < 0.50:
        score = 0.65
    elif ttr < 0.60:
        score = 0.35
    else:
        score = 0.10

    signal = f"Type-Token Ratio: {ttr:.2f} (AI typical: <0.5, human typical: >0.6)"
    return {"ttr": round(ttr, 3), "score": score, "signal": signal}


def compute_template_phrase_density(text: str) -> dict:
    """
    Count formulaic/template phishing phrases.
    High density → AI generated.
    """
    text_lower = text.lower()
    words = _tokenize_words(text)
    total_words = max(len(words), 1)

    match_count = 0
    matched_phrases = []
    for pattern in _TEMPLATE_PHRASES:
        matches = re.findall(pattern, text_lower, re.IGNORECASE)
        if matches:
            match_count += len(matches)
            matched_phrases.append(pattern.split(r"(")[0].replace("\\b", "").strip())

    density = match_count / total_words

    if density > 0.04:
        score = 0.85
    elif density > 0.025:
        score = 0.60
    elif density > 0.015:
        score = 0.35
    else:
        score = 0.10

    signal = (
        f"Template phrase density: {match_count} matches in {total_words} words "
        f"(density={density:.4f})"
    )
    return {
        "density": round(density, 4),
        "match_count": match_count,
        "matched_phrases": matched_phrases[:5],
        "score": score,
        "signal": signal,
    }


def compute_punctuation_regularity(text: str) -> dict:
    """
    AI rarely makes irregular punctuation or natural typos.
    Measure: ratio of special punctuation (!?...) and typo indicators.
    """
    sentences = _tokenize_sentences(text)
    if len(sentences) < 3:
        return {"score": 0.0, "signal": "insufficient_text"}

    # Count punctuation irregularities that humans produce
    excl = text.count("!")
    question = text.count("?")
    ellipsis = text.count("...")
    double_space = len(re.findall(r"  +", text))
    typo_indicators = len(re.findall(r"[a-z][A-Z]", text))  # mid-word caps = typos

    # Calculate a "human messiness" index
    total_chars = max(len(text), 1)
    messiness = (excl + question * 0.5 + ellipsis * 2 + double_space * 3 + typo_indicators * 4) / total_chars

    # Low messiness = likely AI (clean, perfect text)
    if messiness < 0.005:
        score = 0.75
    elif messiness < 0.015:
        score = 0.45
    elif messiness < 0.03:
        score = 0.20
    else:
        score = 0.05  # Very messy = human

    signal = f"Punctuation regularity score: {1.0 - messiness:.3f} (AI produces near-perfect punctuation)"
    return {"messiness_index": round(messiness, 4), "score": score, "signal": signal}


def compute_coherence_score(text: str) -> dict:
    """
    AI maintains perfect paragraph-to-paragraph coherence.
    Measure vocabulary overlap between consecutive paragraphs.
    Humans drift topic slightly.
    """
    paragraphs = [p.strip() for p in text.split("\n\n") if len(p.strip()) > 20]
    if len(paragraphs) < 2:
        # Try splitting by single newline
        paragraphs = [p.strip() for p in text.split("\n") if len(p.strip()) > 20]
    if len(paragraphs) < 2:
        return {"score": 0.0, "signal": "insufficient_paragraphs"}

    overlaps = []
    for i in range(len(paragraphs) - 1):
        words_a = set(_tokenize_words(paragraphs[i]))
        words_b = set(_tokenize_words(paragraphs[i + 1]))
        if words_a and words_b:
            overlap = len(words_a & words_b) / len(words_a | words_b)
            overlaps.append(overlap)

    if not overlaps:
        return {"score": 0.0, "signal": "could_not_compute_overlap"}

    avg_overlap = sum(overlaps) / len(overlaps)
    # AI has high, uniform overlap; humans vary more
    overlap_variance = sum((o - avg_overlap) ** 2 for o in overlaps) / len(overlaps)

    # High overlap + low variance = AI
    if avg_overlap > 0.3 and overlap_variance < 0.01:
        score = 0.80
    elif avg_overlap > 0.2 and overlap_variance < 0.02:
        score = 0.50
    else:
        score = 0.15

    signal = (
        f"Coherence consistency: avg_overlap={avg_overlap:.3f}, "
        f"variance={overlap_variance:.4f} (AI maintains near-perfect coherence)"
    )
    return {"avg_overlap": round(avg_overlap, 3), "variance": round(overlap_variance, 4), "score": score, "signal": signal}


def run_stylometric_analysis(text: str) -> dict:
    """Run all 5 stylometric checks and compute aggregate score."""
    sentence = compute_sentence_length_uniformity(text)
    ttr = compute_type_token_ratio(text)
    template = compute_template_phrase_density(text)
    punctuation = compute_punctuation_regularity(text)
    coherence = compute_coherence_score(text)

    # Weighted ensemble of stylometric signals
    weights = {
        "sentence_length": 0.20,
        "type_token_ratio": 0.20,
        "template_density": 0.25,
        "punctuation_regularity": 0.15,
        "coherence": 0.20,
    }

    scores = {
        "sentence_length": sentence["score"],
        "type_token_ratio": ttr["score"],
        "template_density": template["score"],
        "punctuation_regularity": punctuation["score"],
        "coherence": coherence["score"],
    }

    aggregate = sum(scores[k] * weights[k] for k in weights)
    aggregate = round(min(max(aggregate, 0.02), 0.98), 4)

    signals = []
    for check in [sentence, ttr, template, punctuation, coherence]:
        if check.get("signal") and check.get("score", 0) >= 0.35:
            signals.append(check["signal"])

    return {
        "aggregate_score": aggregate,
        "component_scores": {
            "sentence_length_std": sentence.get("std_dev", 0),
            "type_token_ratio": ttr.get("ttr", 0),
            "template_phrase_density": template.get("density", 0),
            "punctuation_regularity": round(1.0 - punctuation.get("messiness_index", 0), 3),
            "coherence_overlap": coherence.get("avg_overlap", 0),
        },
        "raw_scores": scores,
        "signals": signals,
    }


# ── BERT Perplexity Variance ──────────────────────────────────────────────────

def compute_perplexity_variance(text: str) -> dict:
    """
    Use BERT to measure token-level prediction confidence.
    AI text has unnaturally UNIFORM perplexity (low variance).
    Human text varies: simple phrases → complex structures.

    Returns perplexity_variance and a score (0-1, high = likely AI).
    """
    try:
        from models.bert_phishing_model import _get_pipeline
        clf = _get_pipeline()
        if clf is None:
            return {"score": 0.0, "signal": "bert_unavailable", "perplexity_variance": -1}

        tokenizer = clf.tokenizer
        model = clf.model

        import torch

        # Tokenize
        tokens = tokenizer(
            text[:512], return_tensors="pt", truncation=True, max_length=512
        )
        input_ids = tokens["input_ids"]

        if input_ids.shape[1] < 10:
            return {"score": 0.0, "signal": "text_too_short", "perplexity_variance": -1}

        with torch.no_grad():
            outputs = model(**tokens)
            logits = outputs.logits  # shape: [1, seq_len, num_classes]

            # For sequence classification models, we use the hidden states instead
            # Get the confidence from the classifier output
            probs = torch.softmax(logits, dim=-1)
            max_prob = probs.max().item()

            # Alternative: use the model's internal representations
            # Get hidden states if available
            if hasattr(outputs, 'hidden_states') and outputs.hidden_states:
                last_hidden = outputs.hidden_states[-1]
            else:
                # Use the logits confidence spread as a proxy
                # For classification models, we measure prediction entropy
                entropy = -(probs * torch.log(probs + 1e-10)).sum(dim=-1)
                entropy_val = entropy.mean().item()

                # Low entropy = model is very confident = text is predictable = likely AI
                if entropy_val < 0.2:
                    score = 0.80
                elif entropy_val < 0.4:
                    score = 0.55
                elif entropy_val < 0.6:
                    score = 0.30
                else:
                    score = 0.10

                signal = (
                    f"Perplexity proxy (prediction entropy): {entropy_val:.3f} "
                    f"(AI typical: <0.3, human typical: >0.5)"
                )
                return {
                    "perplexity_variance": round(entropy_val, 4),
                    "score": score,
                    "signal": signal,
                }

    except ImportError:
        logger.debug("[LLMDetector] torch/transformers not available for perplexity")
        return {"score": 0.0, "signal": "dependencies_unavailable", "perplexity_variance": -1}
    except Exception as e:
        logger.warning(f"[LLMDetector] Perplexity computation failed: {e}")
        return {"score": 0.0, "signal": f"error: {str(e)[:60]}", "perplexity_variance": -1}


# ── Gemma-3-12B Meta-Analysis ─────────────────────────────────────────────────

_LLM_DETECTION_PROMPT = """You are an expert forensic linguistics analyst specializing in detecting AI-generated text.

Analyze the following email text and determine if it was likely generated by an AI language model (such as ChatGPT, GPT-4, Claude, Gemini, etc.).

Key signals to look for:
1. Sentence length uniformity (AI writes sentences of similar length)
2. Lack of natural errors, typos, or informal language
3. Overly polished and grammatically perfect prose
4. Formulaic phrasing patterns ("We have detected...", "Your account has been...")
5. Unnatural vocabulary consistency (same register throughout)
6. Perfect paragraph transitions without topic drift
7. Absence of personal voice or stylistic quirks

Email to analyze:
---
{content}
---

Return ONLY a valid JSON object:
{{
  "is_ai_generated": <true/false>,
  "ai_probability": <float 0.0-1.0>,
  "confidence": <float 0.0-1.0>,
  "reasoning": "<2-3 sentence explanation of why you believe this is/isn't AI-generated>",
  "key_indicators": ["<list of specific signals detected>"]
}}"""


async def gemma_ai_detection(text: str) -> dict:
    """
    Ask Gemma-3-12B via OpenRouter: "Was this email written by AI?"
    Returns structured assessment.
    """
    if not OPENROUTER_API_KEY:
        return {
            "is_ai": False,
            "probability": 0.0,
            "confidence": 0.0,
            "reasoning": "OpenRouter API key not configured",
            "source": "unavailable",
        }

    content_preview = text[:1500]

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
                "messages": [
                    {"role": "user", "content": _LLM_DETECTION_PROMPT.format(content=content_preview)},
                ],
                "temperature": 0.1,
                "max_tokens": 400,
            }),
            timeout=15.0,
        )
        resp.raise_for_status()
        return resp.json()

    try:
        data = await asyncio.to_thread(_call)
        raw = data["choices"][0]["message"]["content"].strip()

        # Parse JSON from response
        # Find JSON in response
        start = raw.find("{")
        end = raw.rfind("}")
        if start != -1 and end != -1 and end > start:
            parsed = json.loads(raw[start:end + 1])
        else:
            parsed = json.loads(raw)

        probability = float(parsed.get("ai_probability", 0.0))
        probability = max(0.0, min(1.0, probability))

        return {
            "is_ai": parsed.get("is_ai_generated", False),
            "probability": round(probability, 4),
            "confidence": round(float(parsed.get("confidence", 0.5)), 4),
            "reasoning": parsed.get("reasoning", ""),
            "key_indicators": parsed.get("key_indicators", [])[:5],
            "source": "gemma_3_12b",
        }

    except json.JSONDecodeError as e:
        logger.warning(f"[LLMDetector] Gemma JSON parse failed: {e}")
        return {
            "is_ai": False,
            "probability": 0.0,
            "confidence": 0.0,
            "reasoning": "Failed to parse LLM response",
            "source": "gemma_error",
        }
    except Exception as e:
        logger.warning(f"[LLMDetector] Gemma AI detection failed: {e}")
        return {
            "is_ai": False,
            "probability": 0.0,
            "confidence": 0.0,
            "reasoning": f"API error: {str(e)[:80]}",
            "source": "gemma_error",
        }


# ── Main Entry Point ──────────────────────────────────────────────────────────

async def detect_llm_fingerprint(text: str) -> dict:
    """
    Run full LLM fingerprint detection ensemble.

    Returns:
    {
        "ai_generated_probability": float (0-1),
        "ai_confidence": float (0-1),
        "is_likely_ai": bool,
        "detection_method": str,
        "stylometric_scores": {...},
        "perplexity": {...},
        "llm_assessment": {...},
        "signals": [str, ...],
        "verdict": "LIKELY_AI" | "POSSIBLY_AI" | "LIKELY_HUMAN" | "UNKNOWN"
    }
    """
    if not text or len(text.strip()) < 30:
        return {
            "ai_generated_probability": 0.0,
            "ai_confidence": 0.0,
            "is_likely_ai": False,
            "detection_method": "insufficient_text",
            "stylometric_scores": {},
            "perplexity": {},
            "llm_assessment": {},
            "signals": [],
            "verdict": "UNKNOWN",
        }

    # Run all three detection methods in parallel
    stylometric_task = asyncio.to_thread(run_stylometric_analysis, text)
    perplexity_task = asyncio.to_thread(compute_perplexity_variance, text)
    gemma_task = gemma_ai_detection(text)

    stylometric, perplexity, gemma = await asyncio.gather(
        stylometric_task, perplexity_task, gemma_task,
        return_exceptions=True,
    )

    # Handle exceptions gracefully
    if isinstance(stylometric, Exception):
        logger.warning(f"[LLMDetector] Stylometric failed: {stylometric}")
        stylometric = {"aggregate_score": 0.0, "component_scores": {}, "raw_scores": {}, "signals": []}
    if isinstance(perplexity, Exception):
        logger.warning(f"[LLMDetector] Perplexity failed: {perplexity}")
        perplexity = {"score": 0.0, "signal": "error", "perplexity_variance": -1}
    if isinstance(gemma, Exception):
        logger.warning(f"[LLMDetector] Gemma failed: {gemma}")
        gemma = {"is_ai": False, "probability": 0.0, "confidence": 0.0, "reasoning": "Error", "source": "error"}

    # ── Fuse scores ──────────────────────────────────────────────────────────
    stylometric_score = stylometric.get("aggregate_score", 0.0)
    perplexity_score = perplexity.get("score", 0.0)
    gemma_probability = gemma.get("probability", 0.0)
    gemma_confidence = gemma.get("confidence", 0.0)

    # Determine which methods succeeded
    has_perplexity = perplexity.get("perplexity_variance", -1) >= 0
    has_gemma = gemma.get("source", "error") not in ("error", "unavailable", "gemma_error")

    # Weighted fusion based on availability
    if has_gemma and has_perplexity:
        # Full ensemble: Stylometric 30% + Perplexity 25% + Gemma 45%
        fused = stylometric_score * 0.30 + perplexity_score * 0.25 + gemma_probability * 0.45
        method = "full_ensemble"
    elif has_gemma:
        # Stylometric 40% + Gemma 60%
        fused = stylometric_score * 0.40 + gemma_probability * 0.60
        method = "stylometric_gemma"
    elif has_perplexity:
        # Stylometric 50% + Perplexity 50%
        fused = stylometric_score * 0.50 + perplexity_score * 0.50
        method = "stylometric_perplexity"
    else:
        # Stylometric only
        fused = stylometric_score
        method = "stylometric_only"

    fused = round(max(0.02, min(0.98, fused)), 4)

    # Confidence based on method availability and agreement
    method_scores = [stylometric_score]
    if has_perplexity:
        method_scores.append(perplexity_score)
    if has_gemma:
        method_scores.append(gemma_probability)

    if len(method_scores) > 1:
        agreement = 1.0 - (max(method_scores) - min(method_scores))
        confidence = round(min(0.5 + agreement * 0.4 + len(method_scores) * 0.05, 0.98), 4)
    else:
        confidence = round(min(0.4 + stylometric_score * 0.3, 0.70), 4)

    # Verdict
    if fused >= 0.70:
        verdict = "LIKELY_AI"
    elif fused >= 0.45:
        verdict = "POSSIBLY_AI"
    else:
        verdict = "LIKELY_HUMAN"

    # Collect all signals
    all_signals = list(stylometric.get("signals", []))
    if perplexity.get("signal") and perplexity.get("score", 0) >= 0.3:
        all_signals.append(perplexity["signal"])
    if gemma.get("key_indicators"):
        all_signals.extend(gemma["key_indicators"][:3])

    logger.info(
        f"[LLMDetector] Result: {verdict} (prob={fused}, method={method}, "
        f"stylo={stylometric_score:.2f}, perp={perplexity_score:.2f}, gemma={gemma_probability:.2f})"
    )

    return {
        "ai_generated_probability": fused,
        "ai_confidence": confidence,
        "is_likely_ai": fused >= 0.55,
        "detection_method": method,
        "stylometric_scores": stylometric.get("component_scores", {}),
        "perplexity": {
            "variance": perplexity.get("perplexity_variance", -1),
            "score": perplexity_score,
        },
        "llm_assessment": {
            "is_ai": gemma.get("is_ai", False),
            "probability": gemma_probability,
            "reasoning": gemma.get("reasoning", ""),
            "source": gemma.get("source", "unavailable"),
        },
        "signals": all_signals[:8],
        "verdict": verdict,
    }
