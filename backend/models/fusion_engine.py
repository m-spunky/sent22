"""
Fusion Engine — Combines NLP, URL, Visual, and Header model scores
into a unified threat verdict using attention-weighted ensemble.
"""
from typing import Optional


VERDICT_THRESHOLDS = {
    "SAFE": (0.0, 0.25),
    "SUSPICIOUS": (0.25, 0.55),
    "PHISHING": (0.55, 0.80),
    "CRITICAL": (0.80, 1.01),
}

# Default weights per input type (sum to 1.0)
DEFAULT_WEIGHTS = {
    "email": {"nlp": 0.35, "url": 0.28, "visual": 0.18, "header": 0.19},
    "url": {"nlp": 0.08, "url": 0.55, "visual": 0.30, "header": 0.07},
    "mixed": {"nlp": 0.32, "url": 0.30, "visual": 0.20, "header": 0.18},
}

RECOMMENDED_ACTIONS = {
    "SAFE": "monitor",
    "SUSPICIOUS": "flag_for_review",
    "PHISHING": "quarantine_and_block",
    "CRITICAL": "quarantine_block_and_alert",
}


def fuse_scores(
    nlp_result: dict,
    url_result: dict,
    header_result: dict,
    visual_score: float = 0.0,
    visual_confidence: float = 0.5,
    input_type: str = "email",
    threat_intel_boost: float = 0.0,
) -> dict:
    """
    Fuse individual model scores into a unified threat verdict.

    Args:
        nlp_result: Output from nlp_engine.analyze_text()
        url_result: Output from url_analyzer.score_url()
        header_result: Output from header_analyzer.analyze_headers()
        visual_score: Visual similarity score (0-1)
        visual_confidence: Confidence of visual model
        input_type: "email", "url", or "mixed"
        threat_intel_boost: Additional score boost from intel correlation (0-0.2)

    Returns:
        Unified fusion result matching the API spec.
    """
    weights = DEFAULT_WEIGHTS.get(input_type, DEFAULT_WEIGHTS["mixed"])

    nlp_score = nlp_result.get("score", 0.0)
    nlp_conf = nlp_result.get("confidence", 0.5)

    url_score = url_result.get("score", 0.0)
    url_conf = url_result.get("confidence", 0.5)

    header_score = header_result.get("score", 0.0)
    header_conf = header_result.get("confidence", 0.5)

    # Attention: down-weight models with low confidence
    def weighted_contribution(score, conf, weight):
        return score * conf * weight

    nlp_contrib = weighted_contribution(nlp_score, nlp_conf, weights["nlp"])
    url_contrib = weighted_contribution(url_score, url_conf, weights["url"])
    visual_contrib = weighted_contribution(visual_score, visual_confidence, weights["visual"])
    header_contrib = weighted_contribution(header_score, header_conf, weights["header"])

    # Normalize by total actual weight used
    total_weight = (
        nlp_conf * weights["nlp"]
        + url_conf * weights["url"]
        + visual_confidence * weights["visual"]
        + header_conf * weights["header"]
    )

    if total_weight < 0.01:
        raw_score = 0.1
    else:
        raw_score = (nlp_contrib + url_contrib + visual_contrib + header_contrib) / total_weight

    # Apply threat intel boost (if known campaign IOCs found)
    raw_score = min(raw_score + threat_intel_boost, 0.99)
    raw_score = max(raw_score, 0.02)

    threat_score = round(raw_score, 4)
    fusion_confidence = round(
        min(0.5 + threat_score * 0.48, 0.99), 4
    )

    # Determine verdict
    verdict = "SAFE"
    for v, (low, high) in VERDICT_THRESHOLDS.items():
        if low <= threat_score < high:
            verdict = v
            break

    # Detect tactics from all models
    all_tactics = nlp_result.get("detected_tactics", [])

    # Add URL-based tactics
    top_url_features = url_result.get("top_features", [])
    if "brand_impersonation" in top_url_features:
        all_tactics.append({"name": "Brand Impersonation", "mitre_id": "T1656", "confidence": url_conf})
    if "typosquatting" in top_url_features:
        all_tactics.append({"name": "Typosquatting", "mitre_id": "T1583.001", "confidence": url_conf})
    if "ip_as_host" in top_url_features:
        all_tactics.append({"name": "Suspicious Infrastructure", "mitre_id": "T1583.003", "confidence": url_conf})

    # Add header-based tactics
    header_flags = header_result.get("flags", [])
    if "spf_fail" in header_flags or "dkim_fail" in header_flags:
        all_tactics.append({"name": "Email Spoofing", "mitre_id": "T1566.002", "confidence": header_conf})
    if "reply_to_mismatch" in header_flags:
        all_tactics.append({"name": "Reply-To Manipulation", "mitre_id": "T1656", "confidence": header_conf})

    # Deduplicate tactics by mitre_id
    seen_ids = set()
    unique_tactics = []
    for t in all_tactics:
        if t.get("mitre_id") not in seen_ids:
            seen_ids.add(t.get("mitre_id"))
            unique_tactics.append(t)

    return {
        "threat_score": threat_score,
        "verdict": verdict,
        "confidence": fusion_confidence,
        "model_breakdown": {
            "nlp": {
                "score": round(nlp_score, 4),
                "weight": weights["nlp"],
                "tactics": [t["name"] for t in nlp_result.get("detected_tactics", [])],
                "explanation": nlp_result.get("explanation", ""),
                "top_phrases": nlp_result.get("top_phrases", []),
                "phishing_intent": nlp_result.get("phishing_intent", ""),
            },
            "url": {
                "score": round(url_score, 4),
                "weight": weights["url"],
                "top_features": top_url_features,
                "shap_values": url_result.get("shap_values", {}),
                "features": url_result.get("features", {}),
            },
            "visual": {
                "score": round(visual_score, 4),
                "weight": weights["visual"],
                "matched_brand": "Unknown",
                "similarity": round(visual_score, 4),
            },
            "header": {
                "score": round(header_score, 4),
                "weight": weights["header"],
                "flags": header_flags,
                "spf_result": header_result.get("spf_result", "unknown"),
                "dkim_result": header_result.get("dkim_result", "unknown"),
                "dmarc_result": header_result.get("dmarc_result", "none"),
            },
        },
        "detected_tactics": unique_tactics,
        "recommended_action": RECOMMENDED_ACTIONS.get(verdict, "monitor"),
    }
