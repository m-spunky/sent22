"""
Bulk Analysis — CSV upload for batch phishing detection.
Processes up to 100 URLs or email subjects in parallel.
"""
import asyncio
import csv
import io
import uuid
import logging
from datetime import datetime
from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/bulk", tags=["bulk"])

# Job store: job_id → { status, total, completed, results[] }
_jobs: dict[str, dict] = {}
_MAX_ITEMS = 100


async def _process_bulk_job(job_id: str, items: list[dict]):
    """Background task: analyze all items and update job store."""
    from routers.analyze import _run_full_analysis
    job = _jobs[job_id]
    job["status"] = "processing"

    semaphore = asyncio.Semaphore(5)  # max 5 concurrent analyses

    async def analyze_one(idx: int, item: dict):
        async with semaphore:
            try:
                content = item.get("url") or item.get("email") or item.get("text", "")
                input_type = "url" if item.get("url") else "email"
                result = await _run_full_analysis(content, input_type)
                return {
                    "row": idx + 1,
                    "input": content[:80],
                    "verdict": result["verdict"],
                    "threat_score": result["threat_score"],
                    "confidence": result["confidence"],
                    "inference_ms": result["inference_time_ms"],
                    "event_id": result["event_id"],
                }
            except Exception as e:
                return {
                    "row": idx + 1,
                    "input": item.get("url", item.get("email", ""))[:80],
                    "verdict": "ERROR",
                    "threat_score": 0,
                    "confidence": 0,
                    "error": str(e)[:80],
                }
            finally:
                _jobs[job_id]["completed"] += 1

    tasks = [analyze_one(i, item) for i, item in enumerate(items)]
    results = await asyncio.gather(*tasks)
    job["results"] = list(results)
    job["status"] = "completed"
    job["completed_at"] = datetime.utcnow().isoformat() + "Z"

    # Summary stats
    verdicts = [r.get("verdict", "ERROR") for r in results]
    job["summary"] = {
        "total": len(results),
        "phishing": sum(1 for v in verdicts if "PHISHING" in v or "CONFIRMED" in v),
        "suspicious": sum(1 for v in verdicts if "SUSPICIOUS" in v),
        "clean": sum(1 for v in verdicts if "CLEAN" in v),
        "errors": sum(1 for v in verdicts if v == "ERROR"),
        "avg_score": round(sum(r.get("threat_score", 0) for r in results) / len(results), 3),
    }
    logger.info(f"[Bulk] Job {job_id} completed: {job['summary']}")


@router.post("/upload")
async def upload_csv(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Upload CSV file with URLs or emails for batch analysis."""
    if not file.filename or not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a CSV file.")

    content = await file.read()
    text = content.decode("utf-8-sig", errors="ignore")
    reader = csv.DictReader(io.StringIO(text))

    items = []
    for row in reader:
        # Accept columns: url, URL, email, Email, text, Text
        normalized = {k.lower().strip(): v.strip() for k, v in row.items()}
        if normalized.get("url"):
            items.append({"url": normalized["url"]})
        elif normalized.get("email"):
            items.append({"email": normalized["email"]})
        elif normalized.get("text"):
            items.append({"email": normalized["text"]})
        if len(items) >= _MAX_ITEMS:
            break

    if not items:
        raise HTTPException(status_code=400, detail="CSV must have columns: url, email, or text. No valid rows found.")

    job_id = f"bulk_{uuid.uuid4().hex[:8]}"
    _jobs[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "total": len(items),
        "completed": 0,
        "results": [],
        "summary": {},
        "created_at": datetime.utcnow().isoformat() + "Z",
        "completed_at": None,
    }

    background_tasks.add_task(_process_bulk_job, job_id, items)
    return {
        "job_id": job_id,
        "status": "queued",
        "total_items": len(items),
        "message": f"Analyzing {len(items)} items. Poll /api/v1/bulk/{job_id}/status for progress.",
    }


@router.get("/{job_id}/status")
async def job_status(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")
    progress = round(job["completed"] / job["total"] * 100) if job["total"] else 0
    return {
        "job_id": job_id,
        "status": job["status"],
        "total": job["total"],
        "completed": job["completed"],
        "progress_percent": progress,
        "summary": job.get("summary", {}),
    }


@router.get("/{job_id}/results")
async def job_results(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")
    if job["status"] != "completed":
        raise HTTPException(status_code=202, detail=f"Job still {job['status']}. {job['completed']}/{job['total']} done.")
    return job
