"""
Fraud Correlation Engine — links phishing events to downstream financial fraud.
Uses Isolation Forest-inspired anomaly scoring to detect transaction anomalies
following phishing detection events. Implements PS-03 kill chain correlation:
  Phishing (PS-01) → Credential Stuffing (PS-02) → Financial Fraud (PS-03)
"""
import logging
import math
import time
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# In-memory event store: maps phishing event IDs to downstream activity
_phishing_events: dict[str, dict] = {}
_transaction_anomalies: list[dict] = []


def register_phishing_event(event_id: str, threat_data: dict):
    """Register a phishing detection event for downstream correlation."""
    _phishing_events[event_id] = {
        **threat_data,
        "registered_at": time.time(),
        "correlated_transactions": [],
        "correlated_logins": [],
    }
    # Prune old events (keep last 1000)
    if len(_phishing_events) > 1000:
        oldest = sorted(_phishing_events.keys(), key=lambda k: _phishing_events[k]["registered_at"])[:100]
        for k in oldest:
            del _phishing_events[k]


def _isolation_score(value: float, population: list[float]) -> float:
    """
    Isolation Forest-inspired anomaly score.
    Returns 0.5 = normal, approaching 1.0 = highly anomalous.
    """
    if not population or len(population) < 3:
        return 0.5

    mean = sum(population) / len(population)
    variance = sum((x - mean) ** 2 for x in population) / len(population)
    std = math.sqrt(variance) if variance > 0 else 1.0

    z_score = abs(value - mean) / std
    # Convert Z-score to 0-1 anomaly probability
    anomaly_prob = min(z_score / 4.0, 1.0)
    # Scale to 0.5-1.0 range for anomaly, 0-0.5 for normal
    return round(0.5 + anomaly_prob * 0.5, 4) if z_score > 2 else round(0.5 - (1 - z_score / 2) * 0.3, 4)


def analyze_transaction(
    transaction: dict,
    historical_transactions: Optional[list[dict]] = None,
    linked_phishing_event_id: Optional[str] = None,
) -> dict:
    """
    Analyze a financial transaction for fraud risk.

    transaction fields:
        amount: float
        currency: str
        recipient_account: str
        recipient_name: str
        is_new_payee: bool
        transaction_type: str (wire/ach/internal)
        initiated_by: str (user account)
        initiated_from_ip: str
        device_fingerprint: str
        timestamp: str ISO

    Returns:
        fraud_score: float 0-1
        is_anomalous: bool
        signals: list of flag strings
        recommended_action: str
        kill_chain_stage: str (if linked to phishing)
    """
    signals = []
    score = 0.0
    component_scores = {}

    amount = float(transaction.get("amount", 0))
    is_new_payee = transaction.get("is_new_payee", False)
    transaction_type = transaction.get("transaction_type", "unknown")
    recipient_name = transaction.get("recipient_name", "")
    initiated_by = transaction.get("initiated_by", "")

    # 1. New payee risk
    if is_new_payee:
        score += 0.30
        signals.append("new_unverified_payee")
    component_scores["new_payee"] = 0.30 if is_new_payee else 0.0

    # 2. High-value wire transfer
    high_value_threshold = 10_000
    if transaction_type == "wire" and amount > high_value_threshold:
        wire_score = min(0.20 + (amount - high_value_threshold) / 500_000, 0.45)
        score += wire_score
        signals.append(f"high_value_wire:${amount:,.0f}")
        component_scores["high_value"] = wire_score
    else:
        component_scores["high_value"] = 0.0

    # 3. Historical amount anomaly
    if historical_transactions:
        hist_amounts = [float(t.get("amount", 0)) for t in historical_transactions]
        amount_anomaly = _isolation_score(amount, hist_amounts)
        if amount_anomaly > 0.75:
            score += 0.25
            signals.append("amount_statistical_outlier")
        component_scores["amount_anomaly"] = amount_anomaly
    else:
        component_scores["amount_anomaly"] = 0.5

    # 4. Urgency indicators in transaction metadata
    urgency_keywords = ["urgent", "immediate", "asap", "today", "rush", "emergency"]
    memo = str(transaction.get("memo", "")).lower()
    if any(kw in memo for kw in urgency_keywords):
        score += 0.15
        signals.append("urgency_language_in_memo")

    # 5. After-hours transaction (outside business hours)
    try:
        ts = datetime.fromisoformat(transaction.get("timestamp", datetime.utcnow().isoformat()))
        if ts.hour < 7 or ts.hour > 20 or ts.weekday() >= 5:
            score += 0.10
            signals.append("after_hours_transaction")
    except Exception:
        pass

    # 6. Kill chain correlation with phishing event
    kill_chain_stage = "none"
    kill_chain_confidence = 0.0
    if linked_phishing_event_id and linked_phishing_event_id in _phishing_events:
        phishing_event = _phishing_events[linked_phishing_event_id]
        phishing_score = phishing_event.get("threat_score", 0.0)

        # High-confidence phishing + financial transaction = strong correlation
        correlation_boost = phishing_score * 0.35
        score += correlation_boost
        signals.append(f"linked_to_phishing_event:{linked_phishing_event_id}")
        kill_chain_stage = "PS-03_financial_fraud"
        kill_chain_confidence = round(phishing_score * 0.9, 4)

        # Update phishing event with correlated transaction
        _phishing_events[linked_phishing_event_id]["correlated_transactions"].append({
            "amount": amount,
            "recipient": recipient_name,
            "timestamp": transaction.get("timestamp"),
        })

    fraud_score = round(min(score, 0.99), 4)
    is_anomalous = fraud_score >= 0.60

    if fraud_score >= 0.80:
        recommended_action = "block_and_alert_security_team"
    elif fraud_score >= 0.60:
        recommended_action = "hold_pending_verification"
    elif fraud_score >= 0.35:
        recommended_action = "flag_for_manual_review"
    else:
        recommended_action = "allow_with_audit_log"

    result = {
        "fraud_score": fraud_score,
        "is_anomalous": is_anomalous,
        "signals": signals,
        "component_scores": component_scores,
        "recommended_action": recommended_action,
        "kill_chain_stage": kill_chain_stage,
        "kill_chain_confidence": kill_chain_confidence,
        "transaction_id": transaction.get("transaction_id", f"txn_{int(time.time())}"),
    }

    # Store as anomaly if flagged
    if is_anomalous:
        _transaction_anomalies.append({
            **result,
            "transaction": transaction,
            "detected_at": datetime.utcnow().isoformat() + "Z",
        })
        if len(_transaction_anomalies) > 500:
            _transaction_anomalies.pop(0)

    return result


def get_kill_chain_summary(phishing_event_id: str) -> dict:
    """Get the full kill chain summary for a phishing event."""
    if phishing_event_id not in _phishing_events:
        return {"found": False, "event_id": phishing_event_id}

    event = _phishing_events[phishing_event_id]
    return {
        "found": True,
        "event_id": phishing_event_id,
        "stage": "PS-01_phishing_detected",
        "threat_score": event.get("threat_score", 0),
        "verdict": event.get("verdict", "UNKNOWN"),
        "correlated_transactions": event.get("correlated_transactions", []),
        "correlated_logins": event.get("correlated_logins", []),
        "progression": {
            "PS-01_phishing": bool(event.get("threat_score", 0) > 0.5),
            "PS-02_credential_theft": bool(event.get("correlated_logins")),
            "PS-03_financial_fraud": bool(event.get("correlated_transactions")),
        },
    }


def get_recent_anomalies(limit: int = 20) -> list[dict]:
    """Get recently detected transaction anomalies."""
    return _transaction_anomalies[-limit:]
