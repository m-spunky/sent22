"""
Analysis History — persistent store for all phishing detection results.
Stores to memory + JSON file for demo persistence across restarts.
"""
import json
import os
import logging
from datetime import datetime
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/history", tags=["history"])

HISTORY_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "history.json")
_history: list[dict] = []
_MAX_ENTRIES = 1000


def _load_history():
    global _history
    try:
        os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, "r") as f:
                _history = json.load(f)
                logger.info(f"[History] Loaded {len(_history)} entries from disk")
    except Exception as e:
        logger.warning(f"[History] Could not load history file: {e}")
        _history = []


def _save_history():
    try:
        os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
        with open(HISTORY_FILE, "w") as f:
            json.dump(_history[-_MAX_ENTRIES:], f, indent=2)
    except Exception as e:
        logger.warning(f"[History] Could not save history: {e}")


def record_analysis(result: dict, input_type: str, input_preview: str = ""):
    """Called by analyze router after every successful analysis."""
    entry = {
        "event_id": result.get("event_id", ""),
        "timestamp": result.get("timestamp", datetime.utcnow().isoformat() + "Z"),
        "input_type": input_type,
        "input_preview": input_preview[:120],
        "verdict": result.get("verdict", "UNKNOWN"),
        "threat_score": result.get("threat_score", 0.0),
        "confidence": result.get("confidence", 0.0),
        "inference_time_ms": result.get("inference_time_ms", 0),
        "brand_impersonated": result.get("model_breakdown", {}).get("visual", {}).get("matched_brand", "Unknown"),
        "threat_actor": result.get("threat_intelligence", {}).get("threat_actor", "Unknown"),
        "urls_analyzed": result.get("urls_analyzed", []),
        "tactics": [t.get("name", "") for t in result.get("detected_tactics", [])[:3]],
        "feedback": None,  # filled by feedback router
    }
    _history.append(entry)
    if len(_history) > _MAX_ENTRIES:
        _history.pop(0)
    _save_history()
    return entry


def update_feedback(event_id: str, feedback_type: str):
    for entry in reversed(_history):
        if entry["event_id"] == event_id:
            entry["feedback"] = feedback_type
            _save_history()
            return True
    return False


def get_accuracy_stats() -> dict:
    """Calculate accuracy metrics from feedback loop."""
    total = len(_history)
    feedbacked = [e for e in _history if e.get("feedback")]
    correct = sum(1 for e in feedbacked if e["feedback"] == "correct")
    false_positives = sum(1 for e in feedbacked if e["feedback"] == "false_positive")
    missed = sum(1 for e in feedbacked if e["feedback"] == "missed")
    accuracy = round(correct / len(feedbacked) * 100, 1) if feedbacked else None

    verdict_counts = {}
    for e in _history:
        v = e.get("verdict", "UNKNOWN")
        verdict_counts[v] = verdict_counts.get(v, 0) + 1

    brand_counts = {}
    for e in _history:
        b = e.get("brand_impersonated", "Unknown")
        if b and b != "Unknown":
            brand_counts[b] = brand_counts.get(b, 0) + 1

    # Speed percentile
    times = [e["inference_time_ms"] for e in _history if e.get("inference_time_ms")]
    avg_time = round(sum(times) / len(times)) if times else 0

    return {
        "total_analyses": total,
        "feedbacked_count": len(feedbacked),
        "accuracy_percent": accuracy,
        "correct": correct,
        "false_positives": false_positives,
        "missed": missed,
        "verdict_breakdown": verdict_counts,
        "top_impersonated_brands": sorted(brand_counts.items(), key=lambda x: x[1], reverse=True)[:5],
        "avg_inference_ms": avg_time,
    }


# Load history on import
_load_history()


@router.get("")
async def list_history(
    page: int = 1,
    limit: int = 20,
    verdict: Optional[str] = None,
    input_type: Optional[str] = None,
):
    filtered = list(reversed(_history))
    if verdict:
        filtered = [e for e in filtered if e.get("verdict", "").upper() == verdict.upper()]
    if input_type:
        filtered = [e for e in filtered if e.get("input_type", "") == input_type]
    total = len(filtered)
    offset = (page - 1) * limit
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "items": filtered[offset: offset + limit],
    }


@router.get("/stats")
async def history_stats():
    return get_accuracy_stats()


@router.get("/trends")
async def history_trends():
    """Hour-by-hour threat trend for last 24 hours."""
    from collections import defaultdict
    buckets = defaultdict(lambda: {"phishing": 0, "suspicious": 0, "clean": 0, "total": 0})
    now = datetime.utcnow()
    for entry in _history:
        try:
            ts = datetime.fromisoformat(entry["timestamp"].replace("Z", ""))
            diff_h = int((now - ts).total_seconds() / 3600)
            if diff_h < 24:
                bucket_key = f"{(now.hour - diff_h) % 24:02d}:00"
                v = entry.get("verdict", "").upper()
                buckets[bucket_key]["total"] += 1
                if "PHISHING" in v or "CONFIRMED" in v:
                    buckets[bucket_key]["phishing"] += 1
                elif "SUSPICIOUS" in v:
                    buckets[bucket_key]["suspicious"] += 1
                else:
                    buckets[bucket_key]["clean"] += 1
        except Exception:
            pass
    return {"hourly": dict(buckets), "total_last_24h": sum(v["total"] for v in buckets.values())}


@router.delete("/{event_id}")
async def delete_history_entry(event_id: str):
    global _history
    before = len(_history)
    _history = [e for e in _history if e["event_id"] != event_id]
    _save_history()
    return {"deleted": before - len(_history)}
