"""
Behavioral Analysis endpoints — PS-02 bot detection and PS-03 fraud correlation.
"""
from datetime import datetime
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from behavioral.bot_detector import analyze_session, analyze_credential_stuffing
from behavioral.fraud_correlator import (
    analyze_transaction,
    register_phishing_event,
    get_kill_chain_summary,
    get_recent_anomalies,
)

router = APIRouter(prefix="/api/v1/behavioral", tags=["behavioral"])


# ── Request Models ─────────────────────────────────────────────────────────────

class SessionAnalysisRequest(BaseModel):
    user_agent: Optional[str] = ""
    request_count: Optional[int] = 0
    session_duration_ms: Optional[float] = 0
    request_intervals_ms: Optional[list[float]] = None
    page_sequence: Optional[list[str]] = None
    click_positions: Optional[list[list[float]]] = None
    scroll_depths: Optional[list[float]] = None
    ip_address: Optional[str] = ""
    geo_changes: Optional[int] = 0
    failed_logins: Optional[int] = 0
    captcha_failures: Optional[int] = 0


class CredentialStuffingRequest(BaseModel):
    login_attempts: list[dict]
    time_window_minutes: Optional[int] = 10


class TransactionRequest(BaseModel):
    transaction: dict
    historical_transactions: Optional[list[dict]] = None
    linked_phishing_event_id: Optional[str] = None


class PhishingEventRequest(BaseModel):
    event_id: str
    threat_score: float
    verdict: str
    threat_data: Optional[dict] = None


# ── Bot Detection ──────────────────────────────────────────────────────────────

@router.post("/bot-detection")
async def detect_bot(request: SessionAnalysisRequest):
    """
    Analyze session signals for bot/automated behavior.
    Returns bot_score (0-1), risk level, and detected signals.
    """
    click_tuples = [tuple(c) for c in (request.click_positions or [])]
    result = analyze_session(
        user_agent=request.user_agent or "",
        request_count=request.request_count or 0,
        session_duration_ms=request.session_duration_ms or 0,
        request_intervals_ms=request.request_intervals_ms,
        page_sequence=request.page_sequence,
        click_positions=click_tuples,
        scroll_depths=request.scroll_depths,
        ip_address=request.ip_address or "",
        geo_changes=request.geo_changes or 0,
        failed_logins=request.failed_logins or 0,
        captcha_failures=request.captcha_failures or 0,
    )
    return {
        **result,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "module": "PS-02_BotDetection",
    }


@router.post("/credential-stuffing")
async def detect_credential_stuffing(request: CredentialStuffingRequest):
    """
    Analyze login attempts for credential stuffing patterns.
    """
    if not request.login_attempts:
        raise HTTPException(status_code=400, detail="login_attempts array required.")
    result = analyze_credential_stuffing(
        login_attempts=request.login_attempts,
        time_window_minutes=request.time_window_minutes or 10,
    )
    return {
        **result,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "module": "PS-02_CredentialStuffing",
    }


# ── Fraud Correlation ──────────────────────────────────────────────────────────

@router.post("/fraud-detection")
async def detect_fraud(request: TransactionRequest):
    """
    Analyze a financial transaction for fraud risk.
    Optionally correlates with a prior phishing detection event.
    """
    if not request.transaction:
        raise HTTPException(status_code=400, detail="transaction object required.")
    result = analyze_transaction(
        transaction=request.transaction,
        historical_transactions=request.historical_transactions,
        linked_phishing_event_id=request.linked_phishing_event_id,
    )
    return {
        **result,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "module": "PS-03_FraudCorrelation",
    }


@router.post("/register-phishing")
async def register_phishing(request: PhishingEventRequest):
    """Register a phishing event for downstream kill-chain correlation."""
    data = {
        "threat_score": request.threat_score,
        "verdict": request.verdict,
        **(request.threat_data or {}),
    }
    register_phishing_event(request.event_id, data)
    return {
        "status": "registered",
        "event_id": request.event_id,
        "message": "Phishing event registered for kill-chain correlation.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/kill-chain/{event_id}")
async def get_kill_chain(event_id: str):
    """Get the full PS-01 → PS-02 → PS-03 kill chain for a phishing event."""
    result = get_kill_chain_summary(event_id)
    if not result.get("found"):
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found in kill-chain tracker.")
    return result


@router.get("/anomalies")
async def list_anomalies(limit: int = 20):
    """Get recently detected transaction anomalies."""
    anomalies = get_recent_anomalies(limit=min(limit, 50))
    return {
        "anomalies": anomalies,
        "total": len(anomalies),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/stats")
async def behavioral_stats():
    """Get behavioral analysis module stats."""
    return {
        "module": "PS-02/PS-03 Behavioral Analysis",
        "capabilities": [
            "Session bot detection (request timing, UA analysis, behavioral entropy)",
            "Credential stuffing detection (distributed login anomalies)",
            "Financial fraud correlation (Isolation Forest scoring)",
            "Kill chain tracking: PS-01 → PS-02 → PS-03",
        ],
        "algorithms": ["Statistical anomaly scoring", "Coefficient of variation analysis", "Isolation Forest"],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
