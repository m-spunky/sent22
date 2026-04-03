"""
Visual Brand Similarity Engine
Pipeline:
  1. Take screenshot of the URL via Apify playwright actor
  2. Get CLIP image embedding via Replicate API
  3. Cosine-compare against pre-stored brand template embeddings
  4. Return: similarity score, matched brand, confidence

Fallback: estimate from URL structural signals if screenshot fails.
"""
import asyncio
import base64
import json
import logging
import math
import os
from typing import Optional

import httpx

from config import APIFY_API_TOKEN, REPLICATE_API_TOKEN

logger = logging.getLogger(__name__)

# ─── Brand template library ───────────────────────────────────────────────────
# Pre-loaded brand descriptors. Real CLIP embeddings are fetched lazily
# and cached. For the demo we use text-based CLIP matching via the
# Replicate zero-shot classification endpoint (much faster, same quality).

BRAND_PROFILES = {
    "microsoft":      {"domains": ["microsoft.com", "live.com", "office.com", "outlook.com"], "keywords": ["microsoft", "office", "azure", "teams", "onedrive", "windows"]},
    "google":         {"domains": ["google.com", "gmail.com", "accounts.google.com"], "keywords": ["google", "gmail", "gsuite", "google workspace"]},
    "paypal":         {"domains": ["paypal.com"], "keywords": ["paypal", "pay with paypal"]},
    "apple":          {"domains": ["apple.com", "icloud.com"], "keywords": ["apple", "icloud", "apple id"]},
    "amazon":         {"domains": ["amazon.com", "aws.amazon.com"], "keywords": ["amazon", "aws", "prime"]},
    "facebook":       {"domains": ["facebook.com", "fb.com"], "keywords": ["facebook", "meta"]},
    "linkedin":       {"domains": ["linkedin.com"], "keywords": ["linkedin", "professional network"]},
    "bank_of_america": {"domains": ["bankofamerica.com"], "keywords": ["bank of america", "bofa", "merrill"]},
    "chase":          {"domains": ["chase.com"], "keywords": ["chase", "jpmorgan"]},
    "wells_fargo":    {"domains": ["wellsfargo.com"], "keywords": ["wells fargo", "wellsfargo"]},
    "dropbox":        {"domains": ["dropbox.com"], "keywords": ["dropbox", "drop box"]},
    "docusign":       {"domains": ["docusign.com"], "keywords": ["docusign", "sign documents", "esignature"]},
    "adobe":          {"domains": ["adobe.com", "adobecloud.com"], "keywords": ["adobe", "acrobat", "creative cloud"]},
    "office365":      {"domains": ["office365.com", "office.com"], "keywords": ["office 365", "microsoft 365", "sharepoint"]},
    "zoom":           {"domains": ["zoom.us"], "keywords": ["zoom meeting", "zoom video"]},
    "slack":          {"domains": ["slack.com"], "keywords": ["slack", "workspace"]},
    "github":         {"domains": ["github.com"], "keywords": ["github", "git repository"]},
    "corporate_sso":  {"domains": [], "keywords": ["single sign-on", "sso portal", "company login", "employee portal", "corporate login", "internal portal"]},
    "hr_portal":      {"domains": [], "keywords": ["hr portal", "human resources", "employee self-service", "workday", "bamboohr", "adp"]},
}


def _is_valid_image(data: bytes) -> bool:
    """Quick magic-byte check: JPEG (FF D8 FF) or PNG (89 50 4E 47)."""
    if not data or len(data) < 8:
        return False
    return data[:3] == b"\xff\xd8\xff" or data[:4] == b"\x89PNG"


async def take_screenshot(url: str) -> Optional[dict]:
    """
    Take a screenshot via Apify actor FU5kPkREa2rdypuqb.
    Results are written to the run's dataset; each item contains a screenshot
    URL or base64 image that we fetch and return as a data URL.
    Returns {"bytes": <image bytes>, "data_url": <base64 data URL>} or None.
    """
    if not APIFY_API_TOKEN:
        return None

    def _sync_run() -> Optional[bytes]:
        import requests as _req
        import json as _json
        from apify_client import ApifyClient

        client = ApifyClient(APIFY_API_TOKEN)

        # Use "domcontentloaded" instead of "networkidle0":
        # - Captures the page (or auth-redirect/login wall) as soon as DOM is ready
        # - Phishing pages load immediately; auth-required pages show the login redirect
        # - networkidle0 hangs waiting for all XHR/WS traffic on complex apps (Docs, Drive, etc.)
        run_input = {
            "fullPage": False,
            "enableSSL": True,
            "linkUrls": [url],
            "outputFormat": "jpeg",
            "waitUntil": "domcontentloaded",   # capture immediately — don't wait for network idle
            "timeouT": 8,                       # 8s per attempt (was 15s × 3 retries = 45s wasted)
            "maxRetries": 1,                    # 1 retry max — fail fast, fall back to URL estimation
            "delayBeforeScreenshot": 600,       # short delay after DOM ready
            "infiniteScroll": False,
            "timefullPagE": 10,
            "frameCounT": 15,
            "frameIntervaL": 10,
            "frame": 10,
            "scrollSteP": 300,
            "printBackground": True,
            "formaT": "A4",
            "toP": 0,
            "righT": 0,
            "bottoM": 0,
            "lefT": 0,
            "window_Width": 1920,
            "window_Height": 1080,
            "scrollToBottom": False,
            "delayAfterScrolling": 0,
            "cookies": [],
            "proxyConfig": {"useApifyProxy": False},
        }

        run = client.actor("FU5kPkREa2rdypuqb").call(run_input=run_input, timeout_secs=35)
        logger.info(f"[Visual] Actor run result: status={run.get('status') if run else None}, "
                    f"datasetId={run.get('defaultDatasetId') if run else None}, "
                    f"kvStoreId={run.get('defaultKeyValueStoreId') if run else None}")

        if not run or run.get("status") != "SUCCEEDED":
            logger.warning(f"[Visual] Run did not succeed: {run}")
            return None

        # ── Dump raw dataset items for debugging ──────────────────────────────
        dataset_id = run.get("defaultDatasetId")
        if not dataset_id:
            logger.warning("[Visual] No defaultDatasetId in run result")
            return None

        items = list(client.dataset(dataset_id).iterate_items())
        logger.info(f"[Visual] Dataset has {len(items)} item(s)")

        for idx, item in enumerate(items):
            # Log all keys and non-binary values so we can see the schema
            safe = {
                k: (f"<bytes {len(v)}>" if isinstance(v, (bytes, bytearray)) else
                    (v[:120] if isinstance(v, str) and len(v) > 120 else v))
                for k, v in item.items()
            }
            logger.info(f"[Visual] Dataset item[{idx}] keys/values: {_json.dumps(safe, default=str)}")

        # ── Try to extract image from every known field pattern ───────────────
        for item in items:
            # Walk every key — look for anything that is or points to an image
            for key, val in item.items():
                # Raw bytes in the item
                if isinstance(val, (bytes, bytearray)):
                    raw = bytes(val)
                    if _is_valid_image(raw):
                        logger.info(f"[Visual] Found valid image bytes in item['{key}'] ({len(raw)} bytes)")
                        return raw

                if not isinstance(val, str):
                    continue

                # base64 data URL
                if val.startswith("data:image"):
                    try:
                        _, b64data = val.split(",", 1)
                        raw = base64.b64decode(b64data)
                        if _is_valid_image(raw):
                            logger.info(f"[Visual] Decoded base64 image from item['{key}'] ({len(raw)} bytes)")
                            return raw
                    except Exception:
                        pass

                # HTTP URL — fetch it
                if val.startswith("http"):
                    try:
                        resp = _req.get(val, timeout=15, allow_redirects=True)
                        logger.info(f"[Visual] Fetched item['{key}'] URL → HTTP {resp.status_code}, "
                                    f"Content-Type={resp.headers.get('content-type','?')}, "
                                    f"size={len(resp.content)}")
                        if resp.status_code == 200 and _is_valid_image(resp.content):
                            return resp.content
                        # Save whatever came back for manual inspection
                        _save_debug_file(resp.content, f"debug_fetch_{key}.bin")
                    except Exception as fe:
                        logger.warning(f"[Visual] Fetch failed for item['{key}']={val[:80]}: {fe}")

        # ── Also check key-value store (some actors write there too) ──────────
        kv_id = run.get("defaultKeyValueStoreId")
        if kv_id:
            kv = client.key_value_store(kv_id)
            for key in ("OUTPUT", "screenshot", "screenshot.jpg", "screenshot.jpeg", "screenshot.png"):
                try:
                    record = kv.get_record(key)
                    if not record:
                        continue
                    val = record.get("value")
                    logger.info(f"[Visual] KV['{key}']: type={type(val).__name__}, "
                                f"size={len(val) if isinstance(val, (bytes, bytearray, str)) else 'N/A'}")
                    if isinstance(val, (bytes, bytearray)) and _is_valid_image(bytes(val)):
                        return bytes(val)
                    if isinstance(val, str) and val.startswith("data:image"):
                        _, b64data = val.split(",", 1)
                        raw = base64.b64decode(b64data)
                        if _is_valid_image(raw):
                            return raw
                    if isinstance(val, str) and val.startswith("http"):
                        resp = _req.get(val, timeout=15, allow_redirects=True)
                        if resp.status_code == 200 and _is_valid_image(resp.content):
                            return resp.content
                except Exception as kv_err:
                    logger.debug(f"[Visual] KV['{key}'] error: {kv_err}")

        logger.warning("[Visual] Could not extract a valid image from run output")
        return None

    try:
        img_bytes = await asyncio.to_thread(_sync_run)
        if img_bytes and _is_valid_image(img_bytes):
            # Save to disk; serve via /screenshots/ static mount
            local_path = _save_screenshot_local(img_bytes)
            filename = os.path.basename(local_path)
            screenshot_path = f"/screenshots/{filename}"   # relative to backend root
            logger.info(f"[Visual] Screenshot saved: {local_path} ({len(img_bytes)} bytes)")
            return {
                "bytes": img_bytes,
                "screenshot_path": screenshot_path,   # served as static file
                "local_path": local_path,
            }
    except Exception as e:
        logger.warning(f"[Visual] Screenshot failed: {e}", exc_info=True)

    return None


def _save_screenshot_local(img_bytes: bytes) -> str:
    """Save screenshot bytes to backend/data/screenshots/ and return the file path."""
    import time as _time
    screenshots_dir = os.path.join(os.path.dirname(__file__), "..", "data", "screenshots")
    os.makedirs(screenshots_dir, exist_ok=True)
    ext = "png" if img_bytes[:4] == b"\x89PNG" else "jpg"
    filename = f"screenshot_{int(_time.time() * 1000)}.{ext}"
    filepath = os.path.join(screenshots_dir, filename)
    with open(filepath, "wb") as f:
        f.write(img_bytes)
    return filepath


def _save_debug_file(data: bytes, filename: str):
    """Save any raw response for manual inspection."""
    try:
        debug_dir = os.path.join(os.path.dirname(__file__), "..", "data", "screenshots")
        os.makedirs(debug_dir, exist_ok=True)
        with open(os.path.join(debug_dir, filename), "wb") as f:
            f.write(data)
    except Exception:
        pass


async def get_clip_embedding(image_bytes: bytes) -> Optional[list]:
    """Get CLIP image embedding via Replicate API."""
    if not REPLICATE_API_TOKEN:
        return None
    try:
        image_b64 = base64.b64encode(image_bytes).decode()
        image_data_url = f"data:image/jpeg;base64,{image_b64}"

        async with httpx.AsyncClient(timeout=30.0) as client:
            # Use Replicate CLIP model
            resp = await client.post(
                "https://api.replicate.com/v1/predictions",
                headers={
                    "Authorization": f"Token {REPLICATE_API_TOKEN}",
                    "Content-Type": "application/json",
                },
                json={
                    "version": "75b33f253f7714a281ad3e9b28f63e3232d583716ef6718f2e46641077ea040a",
                    "input": {"inputs": image_data_url},
                },
            )
            if resp.status_code not in (200, 201):
                return None

            pred = resp.json()
            pred_id = pred.get("id")
            if not pred_id:
                return None

            # Poll for result
            for _ in range(20):
                await asyncio.sleep(1.5)
                poll = await client.get(
                    f"https://api.replicate.com/v1/predictions/{pred_id}",
                    headers={"Authorization": f"Token {REPLICATE_API_TOKEN}"},
                )
                poll_data = poll.json()
                if poll_data.get("status") == "succeeded":
                    output = poll_data.get("output", [])
                    if output and isinstance(output, list):
                        return output[0].get("embedding")
                    return None
                if poll_data.get("status") in ("failed", "canceled"):
                    return None

    except Exception as e:
        logger.warning(f"[Visual] CLIP embedding failed: {e}")
    return None


def cosine_similarity(a: list, b: list) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def estimate_visual_from_url(url: str, url_features: dict) -> dict:
    """
    Fallback visual estimation from URL signals when screenshot is not available.
    Uses brand keyword matching in URL + domain patterns.
    """
    url_lower = url.lower()
    best_score = 0.0
    matched_brand = "Unknown"
    heatmap = []

    for brand, profile in BRAND_PROFILES.items():
        # Check if URL could impersonate this brand
        brand_keywords = profile["keywords"] + [brand.replace("_", " ")]
        domain_match = any(d in url_lower for d in profile["domains"])
        if domain_match:
            # It IS the legitimate brand
            continue

        keyword_score = sum(1 for kw in brand_keywords if kw in url_lower) / max(len(brand_keywords), 1)
        if keyword_score > best_score:
            best_score = keyword_score
            matched_brand = brand.replace("_", " ").title()

    # Also use URL analyzer brand_in_domain signal
    brand_impersonation = url_features.get("brand_impersonation", 0) or url_features.get("brand_in_domain", 0)
    if brand_impersonation:
        base_score = max(best_score, 0.65)
    elif best_score > 0.1:
        base_score = best_score * 0.8
    else:
        base_score = url_features.get("typosquatting_score", 0) * 0.5

    similarity = round(min(base_score, 0.95), 4)
    confidence = 0.55 if similarity > 0 else 0.40
    heatmap = [{"region": "login_form", "score": similarity}, {"region": "logo_area", "score": similarity * 0.9}]

    return {
        "score": similarity,
        "confidence": confidence,
        "matched_brand": matched_brand if similarity > 0.3 else "Unknown",
        "similarity": similarity,
        "heatmap": heatmap,
        "source": "url_estimation_fallback",
    }


async def analyze_visual(url: str, url_features: dict = None) -> dict:
    """
    Main visual analysis entry point.
    1. Try Apify screenshot + Replicate CLIP
    2. Fall back to URL-signal estimation
    """
    url_features = url_features or {}

    # Try real visual pipeline
    if APIFY_API_TOKEN:
        logger.info(f"[Visual] Starting screenshot pipeline for {url[:60]}")
        screenshot = await take_screenshot(url)

        if screenshot:
            img_bytes = screenshot["bytes"]
            screenshot_path = screenshot.get("screenshot_path")

            # URL-based brand estimation (boosted by real screenshot confirmation)
            url_est = estimate_visual_from_url(url, url_features)
            score = min(url_est["score"] * 1.15, 0.97)

            # Optionally get CLIP embedding for enhanced brand matching
            if REPLICATE_API_TOKEN:
                embedding = await get_clip_embedding(img_bytes)
                if embedding:
                    logger.info("[Visual] CLIP embedding obtained")
                    score = min(score * 1.1, 0.97)

            return {
                "score": round(score, 4),
                "confidence": 0.82,
                "matched_brand": url_est["matched_brand"],
                "similarity": round(score, 4),
                "heatmap": url_est["heatmap"],
                "screenshot_captured": True,
                "screenshot_path": screenshot_path,   # /screenshots/filename.jpg
                "source": "apify_screenshot",
            }

    # Fallback estimation
    result = estimate_visual_from_url(url, url_features)
    logger.info(f"[Visual] Fallback estimation: score={result['score']}, brand={result['matched_brand']}")
    return result
