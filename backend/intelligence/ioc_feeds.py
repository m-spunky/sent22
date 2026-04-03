"""
IOC Intelligence Feeds — Real-time threat enrichment from:
  • abuse.ch URLhaus (free API, no key needed)
  • abuse.ch MalwareBazaar (free API)
  • PhishTank (daily cache)
  • AlienVault OTX (public data)
Results are cached in-memory with 30-minute TTL.
"""
import asyncio
import hashlib
import json
import logging
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ─── In-memory cache (domain → result, with TTL) ─────────────────────────────
_cache: dict[str, dict] = {}
_CACHE_TTL = 1800  # 30 minutes


def _cache_key(feed: str, indicator: str) -> str:
    return hashlib.md5(f"{feed}:{indicator}".encode()).hexdigest()


def _get_cached(feed: str, indicator: str) -> Optional[dict]:
    key = _cache_key(feed, indicator)
    entry = _cache.get(key)
    if entry and (time.time() - entry["ts"]) < _CACHE_TTL:
        return entry["data"]
    return None


def _set_cache(feed: str, indicator: str, data: dict):
    key = _cache_key(feed, indicator)
    _cache[key] = {"ts": time.time(), "data": data}


# ─── URLhaus ──────────────────────────────────────────────────────────────────

async def check_urlhaus_domain(domain: str) -> dict:
    """Check a domain against abuse.ch URLhaus."""
    cached = _get_cached("urlhaus", domain)
    if cached is not None:
        return cached

    result = {"malicious": False, "source": "urlhaus", "url_count": 0, "tags": []}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": domain},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            data = resp.json()
            if data.get("query_status") == "is_host":
                result["malicious"] = True
                result["url_count"] = data.get("urls_count", 0)
                urls = data.get("urls", [])
                tags = set()
                for u in urls[:5]:
                    tags.update(u.get("tags", []))
                result["tags"] = list(tags)
                result["threat_type"] = data.get("urls", [{}])[0].get("threat", "malware")
    except Exception as e:
        logger.debug(f"[URLhaus] {domain}: {e}")

    _set_cache("urlhaus", domain, result)
    return result


async def check_urlhaus_url(url: str) -> dict:
    """Check a full URL against abuse.ch URLhaus."""
    cached = _get_cached("urlhaus_url", url)
    if cached is not None:
        return cached

    result = {"malicious": False, "source": "urlhaus"}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            data = resp.json()
            if data.get("query_status") == "is_available":
                result["malicious"] = True
                result["threat"] = data.get("threat")
                result["tags"] = data.get("tags", [])
    except Exception as e:
        logger.debug(f"[URLhaus URL] {url[:60]}: {e}")

    _set_cache("urlhaus_url", url, result)
    return result


# ─── MalwareBazaar ────────────────────────────────────────────────────────────

async def check_malwarebazaar_hash(file_hash: str) -> dict:
    """Check a file hash against abuse.ch MalwareBazaar."""
    cached = _get_cached("malwarebazaar", file_hash)
    if cached is not None:
        return cached

    result = {"malicious": False, "source": "malwarebazaar"}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": file_hash},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            data = resp.json()
            if data.get("query_status") == "hash_not_found":
                pass
            elif data.get("data"):
                entry = data["data"][0]
                result["malicious"] = True
                result["malware_family"] = entry.get("signature")
                result["file_type"] = entry.get("file_type")
                result["first_seen"] = entry.get("first_seen")
                result["tags"] = entry.get("tags", [])
    except Exception as e:
        logger.debug(f"[MalwareBazaar] {file_hash[:16]}: {e}")

    _set_cache("malwarebazaar", file_hash, result)
    return result


# ─── AlienVault OTX ───────────────────────────────────────────────────────────

async def check_otx_domain(domain: str) -> dict:
    """Check domain reputation on AlienVault OTX (public endpoint)."""
    cached = _get_cached("otx", domain)
    if cached is not None:
        return cached

    result = {"malicious": False, "source": "otx", "pulse_count": 0, "malware_families": [], "tags": []}
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers={"User-Agent": "SentinelAI-Fusion/1.0"},
                timeout=6.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                result["pulse_count"] = pulse_count
                result["malicious"] = pulse_count > 0
                pulses = data.get("pulse_info", {}).get("pulses", [])
                families = set()
                tags = set()
                for p in pulses[:10]:
                    families.update(p.get("malware_families", []))
                    tags.update(p.get("tags", []))
                result["malware_families"] = list(families)
                result["tags"] = list(tags)
                result["validation"] = data.get("validation", [])
    except Exception as e:
        logger.debug(f"[OTX] {domain}: {e}")

    _set_cache("otx", domain, result)
    return result


async def check_otx_ip(ip: str) -> dict:
    """Check IP reputation on AlienVault OTX."""
    cached = _get_cached("otx_ip", ip)
    if cached is not None:
        return cached

    result = {"malicious": False, "source": "otx_ip", "pulse_count": 0}
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"User-Agent": "SentinelAI-Fusion/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                result["pulse_count"] = pulse_count
                result["malicious"] = pulse_count > 2
                result["country"] = data.get("country_name")
                result["asn"] = data.get("asn")
    except Exception as e:
        logger.debug(f"[OTX IP] {ip}: {e}")

    _set_cache("otx_ip", ip, result)
    return result


# ─── Combined enrichment ─────────────────────────────────────────────────────

async def enrich_iocs(domains: list[str], ips: list[str] = None, urls: list[str] = None) -> dict:
    """
    Run all IOC checks in parallel and return unified enrichment result.
    Returns:
        malicious_domains: list of confirmed malicious domains
        malicious_ips: list of confirmed malicious IPs
        threat_families: list of detected malware/threat families
        risk_boost: float 0-0.30 (additional score boost)
        sources: list of sources that confirmed threats
    """
    ips = ips or []
    urls = urls or []

    tasks = []
    domain_indices = []
    ip_indices = []

    for d in domains[:5]:  # Limit to 5 domains per analysis
        tasks.append(check_urlhaus_domain(d))
        tasks.append(check_otx_domain(d))
        domain_indices.append(d)

    for ip in ips[:3]:
        tasks.append(check_otx_ip(ip))
        ip_indices.append(ip)

    if not tasks:
        return {"malicious_domains": [], "malicious_ips": [], "threat_families": [], "risk_boost": 0.0, "sources": []}

    results = await asyncio.gather(*tasks, return_exceptions=True)

    malicious_domains = []
    malicious_ips = []
    threat_families = set()
    sources = set()
    risk_boost = 0.0

    idx = 0
    for domain in domain_indices:
        # URLhaus result
        if idx < len(results) and isinstance(results[idx], dict):
            r = results[idx]
            if r.get("malicious"):
                malicious_domains.append(domain)
                threat_families.update(r.get("tags", []))
                sources.add("URLhaus")
                risk_boost += 0.15
        idx += 1

        # OTX result
        if idx < len(results) and isinstance(results[idx], dict):
            r = results[idx]
            if r.get("malicious"):
                if domain not in malicious_domains:
                    malicious_domains.append(domain)
                threat_families.update(r.get("malware_families", []))
                sources.add("AlienVault OTX")
                risk_boost += 0.10
        idx += 1

    for ip in ip_indices:
        if idx < len(results) and isinstance(results[idx], dict):
            r = results[idx]
            if r.get("malicious"):
                malicious_ips.append(ip)
                sources.add("AlienVault OTX")
                risk_boost += 0.08
        idx += 1

    return {
        "malicious_domains": malicious_domains,
        "malicious_ips": malicious_ips,
        "threat_families": list(threat_families),
        "risk_boost": round(min(risk_boost, 0.30), 4),
        "sources": list(sources),
    }
