"""
URL Sandbox — deep Apify-powered URL analysis.
Captures screenshot, redirect chain, DOM form fields, SSL info, network requests.
"""
import asyncio
import httpx
import logging
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from config import APIFY_API_TOKEN

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/sandbox", tags=["sandbox"])

APIFY_RUNS_URL = "https://api.apify.com/v2/acts/apify~web-scraper/runs"
APIFY_SCREENSHOT_URL = "https://api.apify.com/v2/acts/apify~screenshot-url/runs"


class SandboxRequest(BaseModel):
    url: str
    depth: str = "standard"  # standard | deep


async def _get_ssl_info(hostname: str) -> dict:
    """Check SSL certificate details."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "valid": True,
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "expires": cert.get("notAfter", "Unknown"),
                    "san": [v for _, v in cert.get("subjectAltName", [])],
                }
    except ssl.SSLCertVerificationError:
        return {"valid": False, "error": "Certificate verification failed — self-signed or expired"}
    except Exception as e:
        return {"valid": False, "error": str(e)[:80]}


async def _unwind_redirects(url: str) -> list[str]:
    """Follow redirect chain and return all intermediate URLs."""
    chain = [url]
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=8) as client:
            current = url
            for _ in range(10):  # max 10 hops
                try:
                    resp = await client.get(current, headers={"User-Agent": "Mozilla/5.0"})
                    if resp.is_redirect:
                        location = str(resp.headers.get("location", ""))
                        if location and location != current:
                            # Resolve relative redirects
                            if location.startswith("/"):
                                parsed = urlparse(current)
                                location = f"{parsed.scheme}://{parsed.netloc}{location}"
                            chain.append(location)
                            current = location
                        else:
                            break
                    else:
                        break
                except Exception:
                    break
    except Exception:
        pass
    return chain


async def _run_apify_screenshot(url: str) -> dict:
    """Take a screenshot using Apify Screenshot URL actor."""
    if not APIFY_API_TOKEN:
        return {"screenshot_url": None, "error": "APIFY_API_TOKEN not configured"}
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            # Start actor run
            run_resp = await client.post(
                APIFY_SCREENSHOT_URL,
                params={"token": APIFY_API_TOKEN, "waitForFinish": 60},
                json={"url": url, "viewportWidth": 1280, "viewportHeight": 800, "delay": 2000, "fullPage": False},
            )
            if run_resp.status_code not in (200, 201):
                return {"screenshot_url": None, "error": f"Apify returned {run_resp.status_code}"}
            run_data = run_resp.json()
            run_id = run_data.get("data", {}).get("id", "")

            if not run_id:
                return {"screenshot_url": None, "error": "No run ID returned"}

            # Poll for dataset
            for _ in range(15):
                await asyncio.sleep(3)
                dataset_resp = await client.get(
                    f"https://api.apify.com/v2/actor-runs/{run_id}/dataset/items",
                    params={"token": APIFY_API_TOKEN},
                )
                if dataset_resp.status_code == 200:
                    items = dataset_resp.json()
                    if items:
                        screenshot = items[0].get("screenshotUrl") or items[0].get("url")
                        return {"screenshot_url": screenshot, "run_id": run_id}

            return {"screenshot_url": None, "error": "Screenshot timed out"}
    except Exception as e:
        logger.warning(f"[Sandbox] Apify screenshot failed: {e}")
        return {"screenshot_url": None, "error": str(e)[:80]}


async def _scrape_page_info(url: str) -> dict:
    """Scrape basic page info: title, forms, external scripts."""
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=12) as client:
            resp = await client.get(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })
            html = resp.text

            # Extract title
            import re
            title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
            title = title_match.group(1).strip()[:100] if title_match else "Unknown"

            # Detect login/credential forms
            form_inputs = re.findall(r'<input[^>]+type=["\']?(password|email|text)["\']?[^>]*>', html, re.I)
            has_password_field = any("password" in inp.lower() for inp in form_inputs)
            has_email_field = any("email" in inp.lower() for inp in form_inputs)

            # Detect external scripts
            scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
            external_scripts = [s for s in scripts if s.startswith("http") and urlparse(url).netloc not in s][:5]

            # Detect iframes
            iframes = re.findall(r'<iframe[^>]+src=["\']([^"\']+)["\']', html, re.I)

            # Detect suspicious keywords
            suspicious_keywords = ["login", "verify", "confirm", "account", "secure", "update", "bank",
                                    "paypal", "credential", "identity", "suspend", "urgent", "click here"]
            found_keywords = [kw for kw in suspicious_keywords if kw.lower() in html.lower()]

            return {
                "title": title,
                "status_code": resp.status_code,
                "final_url": str(resp.url),
                "content_length": len(html),
                "has_password_field": has_password_field,
                "has_email_field": has_email_field,
                "form_input_count": len(form_inputs),
                "external_scripts": external_scripts,
                "iframe_count": len(iframes),
                "suspicious_keywords": found_keywords[:8],
                "credential_harvesting_detected": has_password_field and len(found_keywords) >= 2,
            }
    except Exception as e:
        return {"error": str(e)[:80], "title": "Unreachable", "has_password_field": False}


def _compute_sandbox_risk(data: dict) -> dict:
    """Compute a sandbox-specific risk score from collected signals."""
    risk = 0.0
    flags = []

    redirect_count = len(data.get("redirect_chain", [])) - 1
    if redirect_count >= 3:
        risk += 0.25
        flags.append(f"{redirect_count} redirects detected")

    if not data.get("ssl_info", {}).get("valid", True):
        risk += 0.20
        flags.append("Invalid or self-signed SSL certificate")

    page = data.get("page_info", {})
    if page.get("has_password_field"):
        risk += 0.20
        flags.append("Password input field detected")
    if page.get("credential_harvesting_detected"):
        risk += 0.15
        flags.append("Credential harvesting indicators in DOM")
    if page.get("suspicious_keywords"):
        risk += min(0.10, 0.02 * len(page.get("suspicious_keywords", [])))
        flags.append(f"Phishing keywords: {', '.join(page.get('suspicious_keywords', [])[:3])}")
    if page.get("iframe_count", 0) > 2:
        risk += 0.10
        flags.append(f"{page['iframe_count']} iframes detected — possible clickjacking")

    # Final URL domain mismatch
    chain = data.get("redirect_chain", [])
    if len(chain) >= 2:
        original_domain = urlparse(chain[0]).netloc
        final_domain = urlparse(chain[-1]).netloc
        if original_domain != final_domain:
            risk += 0.15
            flags.append(f"Domain changed: {original_domain} → {final_domain}")

    risk = round(min(risk, 1.0), 3)
    verdict = "PHISHING" if risk >= 0.65 else "SUSPICIOUS" if risk >= 0.35 else "CLEAN"

    return {"sandbox_risk_score": risk, "sandbox_verdict": verdict, "sandbox_flags": flags}


@router.post("/analyze")
async def sandbox_analyze(req: SandboxRequest):
    """Deep sandbox analysis of a URL — screenshot, redirects, DOM, SSL, network."""
    url = req.url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.netloc

    # Run all probes in parallel
    redirect_task = _unwind_redirects(url)
    ssl_task = _get_ssl_info(hostname)
    page_task = _scrape_page_info(url)
    screenshot_task = _run_apify_screenshot(url) if req.depth == "deep" else asyncio.sleep(0)

    redirect_chain, ssl_info, page_info, screenshot_data = await asyncio.gather(
        redirect_task, ssl_task, page_task, screenshot_task, return_exceptions=True
    )

    # Handle exceptions gracefully
    if isinstance(redirect_chain, Exception):
        redirect_chain = [url]
    if isinstance(ssl_info, Exception):
        ssl_info = {"valid": False, "error": str(ssl_info)}
    if isinstance(page_info, Exception):
        page_info = {"error": str(page_info)}
    if isinstance(screenshot_data, Exception) or screenshot_data is None:
        screenshot_data = {"screenshot_url": None}

    result = {
        "url": url,
        "hostname": hostname,
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "redirect_chain": redirect_chain if isinstance(redirect_chain, list) else [url],
        "redirect_count": len(redirect_chain) - 1 if isinstance(redirect_chain, list) else 0,
        "ssl_info": ssl_info if isinstance(ssl_info, dict) else {},
        "page_info": page_info if isinstance(page_info, dict) else {},
        "screenshot_url": screenshot_data.get("screenshot_url") if isinstance(screenshot_data, dict) else None,
    }

    # Compute sandbox risk
    risk_assessment = _compute_sandbox_risk(result)
    result.update(risk_assessment)

    return result


@router.get("/status")
async def sandbox_status():
    return {
        "apify_configured": bool(APIFY_API_TOKEN),
        "capabilities": ["redirect_chain", "ssl_validation", "dom_analysis", "page_scraping"],
        "screenshot_available": bool(APIFY_API_TOKEN),
    }
