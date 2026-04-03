"""
Feedback Loop — analysts mark detections as correct / false positive / missed.
Drives the live accuracy metric shown on the dashboard.
"""
import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Literal, Optional

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/feedback", tags=["feedback"])

_feedback_store: list[dict] = []


class FeedbackRequest(BaseModel):
    event_id: str
    feedback_type: Literal["correct", "false_positive", "missed"]
    note: Optional[str] = None


@router.post("")
async def submit_feedback(req: FeedbackRequest):
    """Submit analyst feedback on a detection result."""
    entry = {
        "event_id": req.event_id,
        "feedback_type": req.feedback_type,
        "note": req.note,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    # Remove any existing feedback for same event
    global _feedback_store
    _feedback_store = [f for f in _feedback_store if f["event_id"] != req.event_id]
    _feedback_store.append(entry)

    # Update history store
    try:
        from routers.history import update_feedback
        update_feedback(req.event_id, req.feedback_type)
    except Exception as e:
        logger.warning(f"[Feedback] Could not update history: {e}")

    return {
        "status": "recorded",
        "event_id": req.event_id,
        "feedback_type": req.feedback_type,
        "message": {
            "correct": "Thank you. This improves model calibration.",
            "false_positive": "Noted. Threshold will be adjusted for similar patterns.",
            "missed": "Noted. This sample will be used for model improvement.",
        }.get(req.feedback_type, "Feedback recorded."),
    }


@router.get("/summary")
async def feedback_summary():
    total = len(_feedback_store)
    correct = sum(1 for f in _feedback_store if f["feedback_type"] == "correct")
    fp = sum(1 for f in _feedback_store if f["feedback_type"] == "false_positive")
    missed = sum(1 for f in _feedback_store if f["feedback_type"] == "missed")
    return {
        "total_feedback": total,
        "correct": correct,
        "false_positives": fp,
        "missed": missed,
        "accuracy_percent": round(correct / total * 100, 1) if total else None,
        "false_positive_rate": round(fp / total * 100, 1) if total else None,
    }
