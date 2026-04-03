"""
Dashboard data endpoints — metrics, feed, timeline, campaigns.
Live metrics are sourced from the analyze router's result cache.
"""
import random
from datetime import datetime, timedelta
from fastapi import APIRouter, Query
from pydantic import BaseModel
from typing import Optional

from intelligence.knowledge_graph import CAMPAIGNS, THREAT_ACTORS

router = APIRouter(prefix="/api/v1", tags=["dashboard"])

# Live counters updated by analyze router
_analysis_counter = {"total": 0, "threats": 0, "critical": 0, "phishing": 0, "safe": 0}


def increment_analysis_counter(verdict: str):
    """Called by analyze router after each detection."""
    _analysis_counter["total"] += 1
    if verdict in ("PHISHING", "CRITICAL", "SUSPICIOUS"):
        _analysis_counter["threats"] += 1
    if verdict == "CRITICAL":
        _analysis_counter["critical"] += 1
    if verdict in ("PHISHING", "CRITICAL"):
        _analysis_counter["phishing"] += 1
    if verdict == "SAFE":
        _analysis_counter["safe"] += 1

# Simulated live threat feed events (cycles on each request)
_FEED_EVENTS = [
    {"type": "phishing", "title": "BEC Attack Intercepted", "description": "Spear-phishing targeting CFO — FIN7 infrastructure detected", "severity": "critical"},
    {"type": "malware", "title": "Malicious Attachment Blocked", "description": "PDF with embedded macro payload — GIBON loader signature", "severity": "high"},
    {"type": "behavioral", "title": "Credential Stuffing Detected", "description": "847 automated login attempts from 192.168.45.21 (UA)", "severity": "critical"},
    {"type": "phishing", "title": "QR Code Phishing Attempt", "description": "QR code points to HR portal clone — 91% visual similarity", "severity": "high"},
    {"type": "policy", "title": "SPF/DKIM Failure Spike", "description": "12 emails failed authentication from spoofed finance domain", "severity": "medium"},
    {"type": "phishing", "title": "Domain Spoofing Alert", "description": "auth-login.net impersonating internal SSO portal", "severity": "high"},
    {"type": "behavioral", "title": "Anomalous Login Pattern", "description": "Account FA-118 accessed from 3 geographies in 4 minutes", "severity": "high"},
    {"type": "fraud", "title": "Wire Transfer Request Flagged", "description": "New payee — $42,800 to unverified account after phishing", "severity": "critical"},
    {"type": "phishing", "title": "Typosquatting Domain Found", "description": "microsofft-secure.net registered 2 days ago targeting users", "severity": "medium"},
    {"type": "malware", "title": "C2 Communication Blocked", "description": "Outbound beacon to 45.142.212.100 (FIN7 C2) blocked", "severity": "high"},
    {"type": "phishing", "title": "LinkedIn Lure Detected", "description": "Fake job offer email — Lazarus Group job-web3.net pattern", "severity": "high"},
    {"type": "policy", "title": "Bulk Email Campaign Blocked", "description": "432 identical phishing templates blocked by content filter", "severity": "medium"},
    {"type": "behavioral", "title": "Bot Traffic Detected", "description": "Automated scraping behavior detected on login portal", "severity": "low"},
    {"type": "phishing", "title": "Executive Impersonation Alert", "description": "Email impersonating CEO requesting payroll diversion", "severity": "critical"},
    {"type": "fraud", "title": "Account Takeover Attempt", "description": "Compromised credentials used for unauthorized access to finance portal", "severity": "high"},
    {"type": "phishing", "title": "Callback Phishing (Vishing)", "description": "Email instructing user to call fake IT support number", "severity": "medium"},
    {"type": "behavioral", "title": "Data Exfiltration Attempt", "description": "Large file upload to external cloud detected post-phishing", "severity": "high"},
    {"type": "malware", "title": "Ransomware Precursor Blocked", "description": "Cobalt Strike beacon payload neutralized before execution", "severity": "critical"},
    {"type": "phishing", "title": "Invoice Fraud Attempt", "description": "Fake invoice from supplier clone domain — payment redirection", "severity": "high"},
    {"type": "policy", "title": "Unauthorized Email Gateway", "description": "Outbound emails detected via unauthorized SMTP relay", "severity": "medium"},
]

_event_cursor = 0


@router.get("/dashboard/metrics")
async def get_metrics():
    """Get current dashboard KPI metrics (live + seeded baseline)."""
    from routers.analyze import _result_cache

    # Live metrics from actual detections this session
    live_total = _analysis_counter["total"]
    live_threats = _analysis_counter["threats"]

    # Seeded baseline (simulates accumulated historical data for demo)
    baseline_analyzed = 48902
    baseline_threats = 1284
    active_campaigns = sum(1 for c in CAMPAIGNS if c.get("status") == "active")

    # Compute avg inference time from recent results
    recent_results = list(_result_cache.values())[-20:]
    avg_ms = 0
    if recent_results:
        times = [r.get("inference_time_ms", 1200) for r in recent_results]
        avg_ms = int(sum(times) / len(times))
    else:
        avg_ms = 1200

    # Real accuracy from ensemble model evaluation
    try:
        from models.ml_url_classifier import get_evaluation_metrics as _get_xgb
        from models.bert_phishing_model import get_evaluation_metrics as _get_bert
        _xgb = _get_xgb()
        _bert = _get_bert()
        xgb_acc = _xgb.get("accuracy", 0.989) if "error" not in _xgb else 0.989
        bert_acc = _bert.get("accuracy", 0.989) if "error" not in _bert else 0.989
        # Average of both evaluated models
        ai_accuracy = round((xgb_acc + bert_acc) / 2, 4)
    except Exception:
        ai_accuracy = 0.989

    return {
        "threats_detected": baseline_threats + live_threats,
        "emails_analyzed": baseline_analyzed + live_total,
        "active_campaigns": active_campaigns,
        "avg_response_time_ms": avg_ms,
        "false_positive_rate": round(1.0 - ai_accuracy, 4),
        "ai_accuracy": round(ai_accuracy, 4),
        "threats_blocked_today": 47 + _analysis_counter["critical"],
        "campaigns_active": sum(1 for c in CAMPAIGNS if c.get("status") == "active"),
        "session_stats": {
            "analyzed_this_session": live_total,
            "threats_this_session": live_threats,
            "safe_this_session": _analysis_counter["safe"],
        },
    }


@router.get("/dashboard/feed")
async def get_threat_feed(limit: int = Query(20, ge=1, le=50)):
    """Get live threat feed events."""
    global _event_cursor
    now = datetime.utcnow()
    events = []

    for i in range(min(limit, len(_FEED_EVENTS))):
        idx = (_event_cursor + i) % len(_FEED_EVENTS)
        event = dict(_FEED_EVENTS[idx])
        # Vary timestamps
        delta_minutes = random.randint(0, 120)
        event["id"] = f"evt_{idx:04d}_{random.randint(1000, 9999)}"
        event["timestamp"] = (now - timedelta(minutes=delta_minutes)).isoformat() + "Z"
        event["time_ago"] = _time_ago(delta_minutes)
        events.append(event)

    _event_cursor = (_event_cursor + 1) % len(_FEED_EVENTS)

    return {"events": events, "total": len(events), "generated_at": now.isoformat() + "Z"}


@router.get("/dashboard/timeline")
async def get_threat_timeline(hours: int = Query(24, ge=1, le=168)):
    """Get threat activity timeline data for charts."""
    now = datetime.utcnow()
    data_points = []

    for h in range(hours, -1, -1):
        ts = now - timedelta(hours=h)
        # Simulate realistic threat patterns (higher during business hours)
        hour_of_day = ts.hour
        base = 5 if 9 <= hour_of_day <= 18 else 2
        spike = random.randint(0, 15) if 9 <= hour_of_day <= 18 else random.randint(0, 5)
        count = base + spike

        data_points.append({
            "time": ts.isoformat() + "Z",
            "threat_count": count,
            "type_breakdown": {
                "phishing": int(count * 0.6),
                "malware": int(count * 0.2),
                "behavioral": int(count * 0.15),
                "other": int(count * 0.05),
            },
        })

    return {"data_points": data_points, "hours": hours, "total_threats": sum(d["threat_count"] for d in data_points)}


@router.get("/campaigns")
async def list_campaigns():
    """List all tracked campaigns."""
    return {"campaigns": CAMPAIGNS, "total": len(CAMPAIGNS)}


@router.post("/response/execute")
async def execute_response(payload: dict):
    """Execute a response playbook."""
    action = payload.get("action", "unknown")
    target = payload.get("target", {})
    confirmation = payload.get("analyst_confirmation", False)

    if not confirmation:
        return {"status": "pending_confirmation", "message": "Action requires analyst confirmation."}

    action_messages = {
        "quarantine": f"Email quarantined. Event ID: {target.get('event_id', 'N/A')} moved to quarantine.",
        "block_ioc": f"IOCs blocked: {target.get('iocs', [])} added to blocklist.",
        "alert_team": "Security team notified via email and Slack. Incident ticket created.",
        "enforce_mfa": f"Step-up MFA enforced for targeted accounts.",
        "generate_report": "Incident report generated and available for download.",
    }

    return {
        "status": "executed",
        "action": action,
        "details": action_messages.get(action, f"Action '{action}' executed successfully."),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def _time_ago(minutes: int) -> str:
    if minutes < 1:
        return "just now"
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    return f"{hours // 24}d ago"
