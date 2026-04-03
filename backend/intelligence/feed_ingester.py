"""
OSINT Feed Ingester — Fetches fresh IOCs from free threat intelligence feeds
and merges them into the SentinelAI Knowledge Graph.

Feeds:
  • abuse.ch ThreatFox — IOCs with actor/malware attribution (free, no key)
  • abuse.ch URLhaus   — Recently reported malicious URLs (free, no key)
  • PhishTank          — Verified phishing URLs (free)

Background refresh: runs every 6 hours via asyncio task.
"""
import asyncio
import json
import os
import logging
from datetime import datetime
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_FEED_CACHE_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "osint_feed_cache.json")

# Track feed ingestion stats
_feed_stats = {
    "last_refresh": None,
    "threatfox_iocs": 0,
    "urlhaus_urls": 0,
    "phishtank_urls": 0,
    "total_ingested": 0,
    "errors": [],
}


# ── ThreatFox (abuse.ch) — IOCs with threat actor/malware attribution ────────

async def fetch_threatfox_iocs(days: int = 7) -> list[dict]:
    """
    Fetch recent IOCs from ThreatFox API.
    Returns domains, IPs, and URLs with malware family + actor attribution.
    """
    iocs = []
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "get_iocs", "days": days},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "ok":
                    raw_iocs = data.get("data", [])
                    for entry in raw_iocs[:200]:  # Limit to 200 per fetch
                        ioc_type = entry.get("ioc_type", "")
                        ioc_value = entry.get("ioc", "")
                        if ioc_type in ("domain", "ip:port", "url") and ioc_value:
                            iocs.append({
                                "type": "domain" if ioc_type == "domain" else (
                                    "ip" if ioc_type == "ip:port" else "url"
                                ),
                                "value": ioc_value.split(":")[0] if ioc_type == "ip:port" else ioc_value,
                                "malware": entry.get("malware", "unknown"),
                                "malware_printable": entry.get("malware_printable", ""),
                                "confidence": entry.get("confidence_level", 50),
                                "threat_type": entry.get("threat_type", ""),
                                "tags": entry.get("tags", []),
                                "reporter": entry.get("reporter", ""),
                                "first_seen": entry.get("first_seen_utc", ""),
                                "source": "threatfox",
                            })
                    logger.info(f"[FeedIngester] ThreatFox: fetched {len(iocs)} IOCs from last {days} days")
    except Exception as e:
        logger.warning(f"[FeedIngester] ThreatFox fetch failed: {e}")
        _feed_stats["errors"].append(f"ThreatFox: {str(e)[:60]}")

    return iocs


# ── URLhaus (abuse.ch) — Recent malicious URLs ───────────────────────────────

async def fetch_urlhaus_recent(limit: int = 100) -> list[dict]:
    """
    Fetch recently reported malicious URLs from URLhaus.
    """
    urls = []
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/",
                timeout=15.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get("urls", [])[:limit]:
                    url_val = entry.get("url", "")
                    if url_val:
                        urls.append({
                            "type": "url",
                            "value": url_val,
                            "threat": entry.get("threat", "malware_download"),
                            "tags": entry.get("tags") or [],
                            "host": entry.get("host", ""),
                            "date_added": entry.get("date_added", ""),
                            "status": entry.get("url_status", ""),
                            "source": "urlhaus",
                        })
                logger.info(f"[FeedIngester] URLhaus: fetched {len(urls)} recent URLs")
    except Exception as e:
        logger.warning(f"[FeedIngester] URLhaus fetch failed: {e}")
        _feed_stats["errors"].append(f"URLhaus: {str(e)[:60]}")

    return urls


# ── PhishTank — Verified phishing URLs ────────────────────────────────────────

async def fetch_phishtank_feed(limit: int = 100) -> list[dict]:
    """
    Fetch verified phishing URLs from PhishTank's online-valid feed.
    Note: PhishTank's JSON feed can be large, we limit entries.
    """
    urls = []
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            # Use the CSV-lite endpoint which is smaller
            resp = await client.get(
                "https://data.phishtank.com/data/online-valid.json.gz",
                headers={"User-Agent": "SentinelAI-Fusion/1.0 (phishtank research tool)"},
                timeout=20.0,
            )
            if resp.status_code == 200:
                import gzip
                try:
                    raw = gzip.decompress(resp.content)
                    data = json.loads(raw)
                except Exception:
                    data = resp.json()

                for entry in data[:limit]:
                    url_val = entry.get("url", "")
                    if url_val:
                        urls.append({
                            "type": "phishing_url",
                            "value": url_val,
                            "target": entry.get("target", "unknown"),
                            "verified": entry.get("verified", "yes") == "yes",
                            "submission_time": entry.get("submission_time", ""),
                            "source": "phishtank",
                        })
                logger.info(f"[FeedIngester] PhishTank: fetched {len(urls)} verified phishing URLs")
            else:
                logger.warning(f"[FeedIngester] PhishTank returned HTTP {resp.status_code}")
    except Exception as e:
        logger.warning(f"[FeedIngester] PhishTank fetch failed: {e}")
        _feed_stats["errors"].append(f"PhishTank: {str(e)[:60]}")

    return urls


# ── Merge into Knowledge Graph ────────────────────────────────────────────────

def merge_into_knowledge_graph(iocs: list[dict]):
    """
    Merge fetched IOCs into the SentinelAI knowledge graph.
    Adds domain/IP nodes and links them to threat actors where attribution exists.
    """
    try:
        from intelligence.knowledge_graph import get_graph

        kg = get_graph()
        graph = kg.G
        if graph is None:
            logger.warning("[FeedIngester] Knowledge graph not initialized")
            return 0

        added = 0
        for ioc in iocs:
            value = ioc.get("value", "")
            ioc_type = ioc.get("type", "")
            source = ioc.get("source", "osint")

            if not value:
                continue

            node_id = f"feed_{source}_{value[:50]}"

            # Skip if already in graph
            if graph.has_node(node_id):
                continue

            # Add the IOC node
            if ioc_type in ("domain", "url", "phishing_url"):
                graph.add_node(node_id, **{
                    "type": "domain" if ioc_type == "domain" else "malicious_url",
                    "label": value[:60],
                    "full_value": value,
                    "risk": "high",
                    "source": source,
                    "malware": ioc.get("malware_printable") or ioc.get("malware", ""),
                    "tags": ioc.get("tags", []),
                    "first_seen": ioc.get("first_seen") or ioc.get("date_added", ""),
                    "feed_ingested": True,
                })
            elif ioc_type == "ip":
                graph.add_node(node_id, **{
                    "type": "ip",
                    "label": value,
                    "risk": "high",
                    "source": source,
                    "malware": ioc.get("malware_printable") or ioc.get("malware", ""),
                    "feed_ingested": True,
                })

            # Try to link to existing threat actors based on malware family
            malware_family = (ioc.get("malware_printable") or ioc.get("malware", "")).lower()
            if malware_family:
                # Check if any actor is associated with this malware
                for node, data in graph.nodes(data=True):
                    if data.get("type") == "actor":
                        actor_campaigns = [
                            n for n in graph.neighbors(node)
                            if graph.nodes[n].get("type") == "campaign"
                        ]
                        for camp_id in actor_campaigns:
                            camp_data = graph.nodes[camp_id]
                            camp_name = camp_data.get("label", "").lower()
                            if malware_family in camp_name or any(
                                t in malware_family for t in camp_data.get("tags", [])
                            ):
                                graph.add_edge(camp_id, node_id, relation="distributes")
                                break

            added += 1

        logger.info(f"[FeedIngester] Merged {added} IOCs into knowledge graph (total nodes: {graph.number_of_nodes()})")
        return added

    except Exception as e:
        logger.warning(f"[FeedIngester] Knowledge graph merge failed: {e}")
        return 0


# ── Persistence ───────────────────────────────────────────────────────────────

def _save_feed_cache(iocs: list[dict]):
    """Save fetched IOCs to disk for persistence across restarts."""
    try:
        os.makedirs(os.path.dirname(_FEED_CACHE_PATH), exist_ok=True)
        cache = {
            "last_updated": datetime.utcnow().isoformat() + "Z",
            "ioc_count": len(iocs),
            "iocs": iocs[:500],  # Limit stored IOCs
        }
        with open(_FEED_CACHE_PATH, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        logger.warning(f"[FeedIngester] Cache save failed: {e}")


def _load_feed_cache() -> list[dict]:
    """Load previously fetched IOCs from disk."""
    try:
        if os.path.exists(_FEED_CACHE_PATH):
            with open(_FEED_CACHE_PATH, "r") as f:
                cache = json.load(f)
            return cache.get("iocs", [])
    except Exception as e:
        logger.warning(f"[FeedIngester] Cache load failed: {e}")
    return []


# ── Main ingestion function ───────────────────────────────────────────────────

async def ingest_all_feeds():
    """
    Fetch IOCs from all OSINT feeds and merge into the knowledge graph.
    Called on startup and then every 6 hours.
    """
    logger.info("[FeedIngester] Starting OSINT feed ingestion...")
    _feed_stats["errors"] = []

    all_iocs = []

    # Run all feeds in parallel
    threatfox_task = fetch_threatfox_iocs(days=7)
    urlhaus_task = fetch_urlhaus_recent(limit=100)
    phishtank_task = fetch_phishtank_feed(limit=100)

    results = await asyncio.gather(
        threatfox_task, urlhaus_task, phishtank_task,
        return_exceptions=True,
    )

    threatfox_iocs = results[0] if isinstance(results[0], list) else []
    urlhaus_urls = results[1] if isinstance(results[1], list) else []
    phishtank_urls = results[2] if isinstance(results[2], list) else []

    all_iocs.extend(threatfox_iocs)
    all_iocs.extend(urlhaus_urls)
    all_iocs.extend(phishtank_urls)

    # Merge into knowledge graph
    merged = merge_into_knowledge_graph(all_iocs)

    # Save to disk
    _save_feed_cache(all_iocs)

    # Update stats
    _feed_stats.update({
        "last_refresh": datetime.utcnow().isoformat() + "Z",
        "threatfox_iocs": len(threatfox_iocs),
        "urlhaus_urls": len(urlhaus_urls),
        "phishtank_urls": len(phishtank_urls),
        "total_ingested": merged,
    })

    logger.info(
        f"[FeedIngester] Done: ThreatFox={len(threatfox_iocs)}, "
        f"URLhaus={len(urlhaus_urls)}, PhishTank={len(phishtank_urls)}, "
        f"merged={merged}"
    )


async def feed_refresh_loop():
    """Background loop: ingest feeds every 6 hours."""
    while True:
        try:
            await ingest_all_feeds()
        except Exception as e:
            logger.warning(f"[FeedIngester] Refresh loop error: {e}")
        await asyncio.sleep(6 * 3600)  # 6 hours


def get_feed_stats() -> dict:
    """Return feed ingestion statistics for the dashboard/API."""
    return dict(_feed_stats)


# Load cached IOCs on module import (fast startup)
_cached = _load_feed_cache()
if _cached:
    logger.info(f"[FeedIngester] Loaded {len(_cached)} cached IOCs from disk")
