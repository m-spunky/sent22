"""
Kill Chain Analyzer — PS2/PS3 compliance.
Maps phishing detection results to the full attack progression:
  PS-01 Phishing → PS-02 Credential Theft / Bot Attack → PS-03 Financial Fraud
"""


def build_kill_chain(result: dict) -> dict:
    """
    Given a phishing analysis result, build the complete kill chain narrative.
    Returns structured kill chain stages with risk amplifiers.
    """
    score = result.get("threat_score", 0)
    verdict = result.get("verdict", "CLEAN")
    tactics = [t.get("name", "") for t in result.get("detected_tactics", [])]
    breakdown = result.get("model_breakdown", {})
    nlp_flags = breakdown.get("nlp", {}).get("top_phrases", [])
    threat_intel = result.get("threat_intelligence", {})

    is_threat = verdict not in ("CLEAN",)
    is_financial = any(kw in str(nlp_flags).lower() for kw in ["bank", "paypal", "payment", "wire", "transfer", "account", "invoice", "billing"])
    is_credential = breakdown.get("visual", {}).get("matched_brand", "Unknown") != "Unknown" or "credential" in str(tactics).lower()
    actor = threat_intel.get("threat_actor", "Unknown")

    stages = []

    # Stage 1: Initial Compromise (PS-01)
    stages.append({
        "stage": 1,
        "phase": "Initial Access",
        "ps": "PS-01",
        "technique": "T1566 — Phishing",
        "description": _stage1_narrative(verdict, score, tactics),
        "risk_score": score,
        "active": is_threat,
        "color": "red" if score >= 0.65 else "amber" if score >= 0.35 else "blue",
    })

    # Stage 2: Credential Theft / Bot Execution (PS-02)
    cred_risk = min(score * 1.1, 1.0) if is_credential else score * 0.6
    stages.append({
        "stage": 2,
        "phase": "Credential Access",
        "ps": "PS-02",
        "technique": "T1078 — Valid Accounts",
        "description": _stage2_narrative(is_credential, actor, breakdown),
        "risk_score": round(cred_risk, 3),
        "active": is_threat and is_credential,
        "color": "red" if cred_risk >= 0.65 else "amber" if cred_risk >= 0.35 else "slate",
    })

    # Stage 3: Financial Fraud (PS-03)
    fraud_risk = min(score * 1.2, 1.0) if is_financial else score * 0.4
    stages.append({
        "stage": 3,
        "phase": "Financial Impact",
        "ps": "PS-03",
        "technique": "T1657 — Financial Theft",
        "description": _stage3_narrative(is_financial, fraud_risk, actor),
        "risk_score": round(fraud_risk, 3),
        "active": is_threat and is_financial,
        "color": "red" if fraud_risk >= 0.65 else "amber" if fraud_risk >= 0.35 else "slate",
    })

    # Stage 4: Lateral Movement / Data Exfiltration
    lateral_risk = score * 0.7 if is_threat else 0.0
    stages.append({
        "stage": 4,
        "phase": "Lateral Movement",
        "ps": "PS-02",
        "technique": "T1534 — Internal Spearphishing",
        "description": "Compromised credentials used to pivot through corporate systems, escalating privileges and exfiltrating sensitive data." if is_threat else "No lateral movement risk detected at this threat level.",
        "risk_score": round(lateral_risk, 3),
        "active": is_threat and score >= 0.7,
        "color": "red" if lateral_risk >= 0.65 else "amber" if lateral_risk >= 0.35 else "slate",
    })

    overall_kill_chain_risk = round(max(s["risk_score"] for s in stages), 3)
    active_stages = sum(1 for s in stages if s["active"])

    return {
        "kill_chain_stages": stages,
        "overall_risk": overall_kill_chain_risk,
        "active_stage_count": active_stages,
        "attack_vector": _determine_vector(breakdown, tactics),
        "estimated_impact": _estimate_impact(is_financial, is_credential, actor, score),
        "recommended_containment": _containment_steps(stages, score),
    }


def _stage1_narrative(verdict, score, tactics):
    if verdict == "CLEAN":
        return "No phishing indicators detected. Email appears legitimate."
    pct = round(score * 100)
    tactic_str = f" Tactics: {', '.join(tactics[:2])}." if tactics else ""
    return f"Phishing email identified with {pct}% confidence.{tactic_str} Social engineering designed to trick target into clicking malicious link or opening attachment."


def _stage2_narrative(is_cred, actor, breakdown):
    brand = breakdown.get("visual", {}).get("matched_brand", "Unknown")
    if not is_cred:
        return "Credential theft risk is low for this attack pattern."
    brand_str = f" The page impersonates {brand}." if brand != "Unknown" else ""
    actor_str = f" Attributed to {actor}." if actor != "Unknown" else ""
    return f"Landing page designed to harvest username and password.{brand_str}{actor_str} Stolen credentials enable account takeover within minutes of victim interaction."


def _stage3_narrative(is_financial, risk, actor):
    if not is_financial:
        return "No direct financial fraud indicators in this attack chain."
    pct = round(risk * 100)
    return f"Financial fraud probability: {pct}%. Attack chain targets banking or payment credentials. Historical data shows {actor if actor != 'Unknown' else 'similar actors'} monetize within 2–72 hours of credential theft via wire transfers or cryptocurrency conversion."


def _determine_vector(breakdown, tactics):
    visual_brand = breakdown.get("visual", {}).get("matched_brand", "Unknown")
    if visual_brand != "Unknown":
        return f"Brand Impersonation — {visual_brand}"
    if "urgency" in str(tactics).lower():
        return "Social Engineering — Urgency/Fear"
    if "spoofing" in str(tactics).lower():
        return "Sender Spoofing"
    return "Email-based Phishing"


def _estimate_impact(is_financial, is_credential, actor, score):
    if score < 0.35:
        return {"level": "LOW", "description": "Minimal impact expected.", "financial_risk_usd": "$0"}
    if is_financial and score >= 0.65:
        avg = "$12,000–$85,000" if actor == "FIN7" else "$5,000–$45,000"
        return {"level": "CRITICAL", "description": "Direct financial fraud likely.", "financial_risk_usd": avg}
    if is_credential:
        return {"level": "HIGH", "description": "Account takeover risk. Potential for follow-on fraud.", "financial_risk_usd": "$2,500–$15,000"}
    return {"level": "MEDIUM", "description": "Data exposure risk.", "financial_risk_usd": "$500–$5,000"}


def _containment_steps(stages, score):
    steps = []
    if score >= 0.35:
        steps.append("Quarantine the email immediately to prevent further interaction")
        steps.append("Block all domains and IPs identified as IOCs")
    if score >= 0.65:
        steps.append("Force password reset for all potentially exposed accounts")
        steps.append("Enable MFA on all accounts linked to the targeted email domain")
        steps.append("Notify security team and open incident ticket")
    if score >= 0.85:
        steps.append("Escalate to L3 SOC — possible active exploitation in progress")
        steps.append("Preserve forensic evidence before remediation")
        steps.append("Notify affected business units")
    return steps
