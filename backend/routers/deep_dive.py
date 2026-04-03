"""
Deep Dive — Multi-stage chain analysis.

Automatically chains: Email → URL extraction → Sandbox → (optional) file download → attachment analysis.
Provides a connected chain of findings from email through to payload delivery.
"""
import asyncio
import logging
import httpx
from datetime import datetime
from urllib.parse import urlparse
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from config import APIFY_API_TOKEN

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/analyze", tags=["deep-dive"])

# Max file download size for auto-attachment analysis (5MB)
MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024

# Content-types that trigger automatic file download + attachment analysis
_DOWNLOADABLE_TYPES = {
    "application/octet-stream", "application/pdf",
    "application/zip", "application/x-rar-compressed", "application/x-7z-compressed",
    "application/msword", "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/x-msdownload", "application/x-executable",
    "application/x-msdos-program", "application/java-archive",
    "application/vnd.ms-powerpoint",
}


class DeepDiveRequest(BaseModel):
    url: str
    event_id: Optional[str] = None  # Original email analysis event_id


async def _check_download(url: str) -> dict:
    """
    HEAD + partial GET to determine if the URL serves a file download.
    Returns file metadata and optionally the downloaded bytes.
    """
    result = {
        "is_download": False,
        "content_type": None,
        "content_length": 0,
        "filename": None,
        "data": None,
    }

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
            # HEAD request first
            head_resp = await client.head(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })

            ct = head_resp.headers.get("content-type", "").split(";")[0].strip().lower()
            cl = int(head_resp.headers.get("content-length", 0))
            cd = head_resp.headers.get("content-disposition", "")

            result["content_type"] = ct
            result["content_length"] = cl

            # Check for file download indicators
            is_file = (
                ct in _DOWNLOADABLE_TYPES
                or "attachment" in cd.lower()
                or ct.startswith("application/") and ct not in {"application/json", "application/xml", "application/javascript"}
            )

            if not is_file:
                return result

            # Extract filename from content-disposition or URL
            if "filename=" in cd:
                import re
                fn_match = re.search(r'filename[*]?=["\']?([^"\';\r\n]+)', cd)
                if fn_match:
                    result["filename"] = fn_match.group(1).strip()

            if not result["filename"]:
                path = urlparse(url).path
                if "." in path.split("/")[-1]:
                    result["filename"] = path.split("/")[-1][:100]

            # Size guard
            if cl > MAX_DOWNLOAD_BYTES:
                result["is_download"] = True
                result["skipped_reason"] = f"File too large: {cl} bytes (max {MAX_DOWNLOAD_BYTES})"
                return result

            # Actually download the file
            get_resp = await client.get(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })

            if get_resp.status_code == 200 and len(get_resp.content) > 0:
                result["is_download"] = True
                result["data"] = get_resp.content
                result["content_length"] = len(get_resp.content)

                if not result["filename"]:
                    # Try content-disposition from GET response
                    get_cd = get_resp.headers.get("content-disposition", "")
                    if "filename=" in get_cd:
                        import re
                        fn_match = re.search(r'filename[*]?=["\']?([^"\';\r\n]+)', get_cd)
                        if fn_match:
                            result["filename"] = fn_match.group(1).strip()

                # Default filename from content-type
                if not result["filename"]:
                    ext_map = {
                        "application/pdf": "downloaded.pdf",
                        "application/zip": "downloaded.zip",
                        "application/msword": "downloaded.doc",
                        "application/octet-stream": "downloaded.bin",
                    }
                    result["filename"] = ext_map.get(ct, "downloaded_file")

    except Exception as e:
        logger.warning(f"[DeepDive] Download check failed: {e}")
        result["error"] = str(e)[:80]

    return result


@router.post("/deep-dive")
async def deep_dive(req: DeepDiveRequest):
    """
    Multi-stage chain analysis:
    1. Run URL sandbox (redirect chain, SSL, DOM scraping)
    2. Check if final URL serves a downloadable file
    3. If file download → trigger attachment analysis
    4. Return connected chain of all intermediate findings
    """
    url = req.url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    chain_stages = []
    overall_risk = 0.0

    # ── Stage 1: URL Sandbox ──────────────────────────────────────────────────
    from routers.sandbox import _unwind_redirects, _get_ssl_info, _scrape_page_info, _compute_sandbox_risk

    hostname = urlparse(url).netloc
    redirect_chain, ssl_info, page_info = await asyncio.gather(
        _unwind_redirects(url),
        _get_ssl_info(hostname),
        _scrape_page_info(url),
        return_exceptions=True,
    )

    if isinstance(redirect_chain, Exception):
        redirect_chain = [url]
    if isinstance(ssl_info, Exception):
        ssl_info = {"valid": False, "error": str(ssl_info)[:80]}
    if isinstance(page_info, Exception):
        page_info = {"error": str(page_info)[:80]}

    sandbox_data = {
        "url": url,
        "redirect_chain": redirect_chain if isinstance(redirect_chain, list) else [url],
        "ssl_info": ssl_info if isinstance(ssl_info, dict) else {},
        "page_info": page_info if isinstance(page_info, dict) else {},
    }
    sandbox_risk = _compute_sandbox_risk(sandbox_data)

    final_url = redirect_chain[-1] if isinstance(redirect_chain, list) and redirect_chain else url

    chain_stages.append({
        "stage": "url_sandbox",
        "label": "URL Sandbox Analysis",
        "url": url,
        "final_url": final_url,
        "redirect_count": len(redirect_chain) - 1 if isinstance(redirect_chain, list) else 0,
        "risk_score": sandbox_risk["sandbox_risk_score"],
        "verdict": sandbox_risk["sandbox_verdict"],
        "flags": sandbox_risk["sandbox_flags"],
        "ssl_valid": ssl_info.get("valid") if isinstance(ssl_info, dict) else False,
        "page_title": page_info.get("title") if isinstance(page_info, dict) else "Unknown",
        "has_credential_form": page_info.get("credential_harvesting_detected", False) if isinstance(page_info, dict) else False,
    })
    overall_risk = max(overall_risk, sandbox_risk["sandbox_risk_score"])

    # ── Stage 2: File Download Check ──────────────────────────────────────────
    download_result = await _check_download(final_url)

    download_stage = {
        "stage": "download_check",
        "label": "File Download Detection",
        "url": final_url,
        "is_download": download_result["is_download"],
        "content_type": download_result["content_type"],
        "content_length": download_result["content_length"],
        "filename": download_result.get("filename"),
    }

    if download_result.get("skipped_reason"):
        download_stage["skipped"] = download_result["skipped_reason"]

    chain_stages.append(download_stage)

    # ── Stage 3: Attachment Analysis (if file was downloaded) ─────────────────
    attachment_result = None
    execution_trace = None

    if download_result["is_download"] and download_result.get("data"):
        from models.attachment_analyzer import (
            analyze_attachment_bytes, generate_execution_trace,
            enrich_trace_with_live_probing,
        )

        filename = download_result["filename"] or "downloaded_file"
        ct = download_result["content_type"] or ""
        data = download_result["data"]

        att_result = analyze_attachment_bytes(filename, ct, len(data), data)
        findings = att_result.get("findings", [])
        execution_trace = generate_execution_trace(filename, findings, data)

        # Enrich with LIVE URL probing
        try:
            execution_trace = await enrich_trace_with_live_probing(execution_trace, findings)
        except Exception as e:
            logger.warning(f"[DeepDive] Live probe enrichment failed: {e}")

        attachment_result = att_result

        chain_stages.append({
            "stage": "attachment_analysis",
            "label": "Payload Analysis",
            "filename": filename,
            "risk_score": att_result["risk_score"],
            "risk_level": att_result["risk_level"],
            "findings": att_result["findings"],
            "content_scanned": att_result.get("content_scanned", False),
        })
        overall_risk = max(overall_risk, att_result["risk_score"])

    # ── Build chain summary ───────────────────────────────────────────────────
    overall_verdict = (
        "CRITICAL" if overall_risk >= 0.85 else
        "PHISHING" if overall_risk >= 0.65 else
        "SUSPICIOUS" if overall_risk >= 0.35 else
        "CLEAN"
    )

    # Generate a narrative summary of the chain
    chain_narrative = _build_chain_narrative(chain_stages, overall_verdict)

    return {
        "chain_id": f"chain_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "source_event_id": req.event_id,
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "chain_stages": chain_stages,
        "overall_risk": round(overall_risk, 3),
        "overall_verdict": overall_verdict,
        "chain_narrative": chain_narrative,
        "attachment_result": attachment_result,
        "execution_trace": execution_trace,
        "stage_count": len(chain_stages),
    }


def _build_chain_narrative(stages: list, verdict: str) -> str:
    """Build a human-readable narrative of the attack chain."""
    parts = []
    for s in stages:
        if s["stage"] == "url_sandbox":
            rd_count = s.get("redirect_count", 0)
            if rd_count > 0:
                parts.append(f"URL redirected {rd_count} time(s) → landing page: \"{s.get('page_title', 'Unknown')}\"")
            else:
                parts.append(f"URL resolved directly to \"{s.get('page_title', 'Unknown')}\"")

            if s.get("has_credential_form"):
                parts.append("Landing page contains credential harvesting form (login/password fields)")
            if not s.get("ssl_valid"):
                parts.append("SSL certificate is invalid or self-signed")

        elif s["stage"] == "download_check":
            if s.get("is_download"):
                parts.append(f"URL serves file download: {s.get('filename', 'unknown')} ({s.get('content_type', 'unknown')})")
            else:
                parts.append("No file download detected at the URL")

        elif s["stage"] == "attachment_analysis":
            level = s.get("risk_level", "UNKNOWN")
            findings_count = len(s.get("findings", []))
            parts.append(f"Downloaded payload analyzed: {level} risk with {findings_count} finding(s)")
            if s.get("findings"):
                parts.append(f"Key finding: {s['findings'][0][:120]}")

    narrative = ". ".join(parts) + "."

    if verdict in ("CRITICAL", "PHISHING"):
        narrative += f" Overall verdict: {verdict} — quarantine recommended."
    elif verdict == "SUSPICIOUS":
        narrative += " Overall verdict: SUSPICIOUS — manual review recommended."
    else:
        narrative += " Overall verdict: CLEAN — no significant threats detected."

    return narrative
