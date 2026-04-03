"""
Dark Web Credential Exposure Check — PS-05 compliance.

Primary:   XposedOrNot (free, no API key, 2 req/sec)
           https://api.xposedornot.com — email + domain breach lookup
Secondary: HaveIBeenPwned domain list (free endpoint, no key required)
           https://haveibeenpwned.com/api/v3/breaches?Domain=

Results from both sources are merged for maximum coverage.
HIBP paid key (/breachedaccount/) is used only if HIBP_API_KEY is set.
"""
import asyncio
import logging
import re
from datetime import datetime

import httpx

from config import HIBP_API_KEY

logger = logging.getLogger(__name__)

XON_BASE = "https://api.xposedornot.com/v1"
HIBP_BASE = "https://haveibeenpwned.com/api/v3"

_cache: dict[str, dict] = {}
_CACHE_TTL = 3600  # 1 hour TTL


def _is_fresh(key: str) -> bool:
    entry = _cache.get(key)
    if not entry:
        return False
    return (datetime.utcnow().timestamp() - entry["ts"]) < _CACHE_TTL


# ── XposedOrNot ───────────────────────────────────────────────────────────────

async def _xon_domain(domain: str, client: httpx.AsyncClient) -> list[dict]:
    """XposedOrNot domain breach list — free, no key required."""
    try:
        resp = await client.get(
            f"{XON_BASE}/domain-breaches/{domain}",
            headers={"User-Agent": "SentinelAI-Fusion-v3"},
        )
        if resp.status_code == 200:
            data = resp.json()
            breaches_raw = data.get("domainBreaches", {}).get("breaches", [])
            return [
                {
                    "name": b if isinstance(b, str) else b.get("breach", "Unknown"),
                    "date": b.get("xposed_date", "") if isinstance(b, dict) else "",
                    "pwn_count": b.get("xposed_records", 0) if isinstance(b, dict) else 0,
                    "data_classes": b.get("xposed_data", "").split(";")[:4] if isinstance(b, dict) else [],
                    "verified": True,
                    "source": "xposedornot",
                }
                for b in breaches_raw[:5]
            ]
        return []
    except Exception as e:
        logger.debug(f"[CredentialCheck] XON domain lookup failed for {domain}: {e}")
        return []


async def _xon_email(email: str, client: httpx.AsyncClient) -> dict:
    """XposedOrNot email breach check — free, no key required."""
    try:
        resp = await client.get(
            f"{XON_BASE}/check-email/{email}",
            headers={"User-Agent": "SentinelAI-Fusion-v3"},
        )
        if resp.status_code == 200:
            data = resp.json()
            exposures = data.get("exposures", {})
            breaches = exposures.get("breaches", [])
            pastes = exposures.get("pastes", [])
            return {
                "breaches": breaches[:5],
                "paste_count": len(pastes),
                "breach_count": len(breaches),
            }
        if resp.status_code == 404:
            return {"breaches": [], "paste_count": 0, "breach_count": 0}
        return {}
    except Exception as e:
        logger.debug(f"[CredentialCheck] XON email lookup failed for {email}: {e}")
        return {}


# ── HaveIBeenPwned ────────────────────────────────────────────────────────────

async def _hibp_domain(domain: str, client: httpx.AsyncClient) -> list[dict]:
    """HIBP public domain breach list — free, no key required."""
    try:
        headers = {"User-Agent": "SentinelAI-Fusion-v3"}
        if HIBP_API_KEY:
            headers["hibp-api-key"] = HIBP_API_KEY
        resp = await client.get(
            f"{HIBP_BASE}/breaches",
            params={"Domain": domain},
            headers=headers,
        )
        if resp.status_code == 200:
            return [
                {
                    "name": b.get("Name", ""),
                    "date": b.get("BreachDate", ""),
                    "pwn_count": b.get("PwnCount", 0),
                    "data_classes": b.get("DataClasses", [])[:4],
                    "verified": b.get("IsVerified", False),
                    "source": "hibp",
                }
                for b in resp.json()[:5]
            ]
        return []
    except Exception as e:
        logger.debug(f"[CredentialCheck] HIBP domain lookup failed for {domain}: {e}")
        return []


async def _hibp_email(email: str, client: httpx.AsyncClient) -> list[dict]:
    """HIBP email breach check — requires API key."""
    if not HIBP_API_KEY:
        return []
    try:
        resp = await client.get(
            f"{HIBP_BASE}/breachedaccount/{email}",
            params={"truncateResponse": "false"},
            headers={"User-Agent": "SentinelAI-Fusion-v3", "hibp-api-key": HIBP_API_KEY},
        )
        if resp.status_code == 200:
            return [
                {
                    "name": b.get("Name", ""),
                    "date": b.get("BreachDate", ""),
                    "pwn_count": b.get("PwnCount", 0),
                    "data_classes": b.get("DataClasses", [])[:4],
                    "verified": b.get("IsVerified", False),
                    "source": "hibp",
                }
                for b in resp.json()[:5]
            ]
        return []
    except Exception as e:
        logger.debug(f"[CredentialCheck] HIBP email lookup failed: {e}")
        return []


# ── Merge helpers ─────────────────────────────────────────────────────────────

def _merge_breaches(lists: list[list[dict]]) -> list[dict]:
    """Deduplicate breach records by name across sources."""
    seen: set[str] = set()
    merged = []
    for lst in lists:
        for b in lst:
            key = (b.get("name") or "").lower()
            if key and key not in seen:
                seen.add(key)
                merged.append(b)
    return merged[:8]


def _risk_level(breach_count: int, paste_count: int = 0) -> str:
    if breach_count >= 3 or paste_count > 0:
        return "HIGH"
    if breach_count >= 1:
        return "MEDIUM"
    return "LOW"


# ── Public API ────────────────────────────────────────────────────────────────

async def check_domain_exposure(domain: str) -> dict:
    """
    Check if a domain appears in known data breaches.
    Queries XposedOrNot + HIBP in parallel, merges results.
    """
    cache_key = f"domain:{domain}"
    if _is_fresh(cache_key):
        return _cache[cache_key]["data"]

    async with httpx.AsyncClient(timeout=8.0) as client:
        xon_task = _xon_domain(domain, client)
        hibp_task = _hibp_domain(domain, client)
        xon_breaches, hibp_breaches = await asyncio.gather(xon_task, hibp_task)

    breaches = _merge_breaches([xon_breaches, hibp_breaches])
    total_exposed = sum(b.get("pwn_count", 0) for b in breaches)

    result = {
        "domain": domain,
        "breach_count": len(breaches),
        "breaches": breaches,
        "total_exposed": total_exposed,
        "dark_web_risk": _risk_level(len(breaches)),
        "sources": list({b.get("source", "unknown") for b in breaches}),
    }

    _cache[cache_key] = {"data": result, "ts": datetime.utcnow().timestamp()}
    return result


async def check_email_exposure(email: str) -> dict:
    """
    Check if an email address appears in known breaches.
    Uses XposedOrNot (free) + HIBP (if API key configured).
    """
    cache_key = f"email:{email}"
    if _is_fresh(cache_key):
        return _cache[cache_key]["data"]

    domain = email.split("@")[-1] if "@" in email else email

    async with httpx.AsyncClient(timeout=8.0) as client:
        xon_task = _xon_email(email, client)
        hibp_task = _hibp_email(email, client)
        xon_result, hibp_breaches = await asyncio.gather(xon_task, hibp_task)

    xon_breaches_normalized = [
        {"name": b if isinstance(b, str) else str(b), "date": "", "pwn_count": 0, "data_classes": [], "source": "xposedornot"}
        for b in xon_result.get("breaches", [])
    ]
    breaches = _merge_breaches([xon_breaches_normalized, hibp_breaches])
    paste_count = xon_result.get("paste_count", 0)

    result = {
        "email": email,
        "domain": domain,
        "breach_count": len(breaches),
        "breaches": breaches,
        "paste_count": paste_count,
        "at_risk": len(breaches) > 0 or paste_count > 0,
        "dark_web_risk": _risk_level(len(breaches), paste_count),
        "sources": list({b.get("source", "unknown") for b in breaches}),
        "total_exposed": sum(b.get("pwn_count", 0) for b in breaches),
    }

    _cache[cache_key] = {"data": result, "ts": datetime.utcnow().timestamp()}
    return result


async def check_sender_domain(from_header: str) -> dict:
    """Extract domain from email From header and check exposure."""
    domain_match = re.search(r"@([a-zA-Z0-9.-]+)", from_header)
    if not domain_match:
        return {"domain": None, "breach_count": 0, "dark_web_risk": "UNKNOWN"}
    domain = domain_match.group(1).lower().rstrip(".")
    return await check_domain_exposure(domain)
