"""
Sender First-Contact tracker (Enhancement 6).
Maintains a JSON-file-backed cache of when domains were first seen.
Flags new domains to detect zero-day or burner domain usage.

Persistence: data/first_contact_cache.json (survives restarts).
"""
from datetime import datetime, timedelta
import json
import os
import logging

logger = logging.getLogger(__name__)

_CACHE_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "first_contact_cache.json")

# Domains considered "First Contact" if seen within the last N hours
FIRST_CONTACT_THRESHOLD_HOURS = 24

# Pre-seeded well-known domains (never flag these)
_PRESEED = {
    "google.com": "2010-01-01T00:00:00Z",
    "microsoft.com": "2010-01-01T00:00:00Z",
    "github.com": "2010-01-01T00:00:00Z",
    "apple.com": "2010-01-01T00:00:00Z",
    "amazon.com": "2010-01-01T00:00:00Z",
    "stripe.com": "2010-01-01T00:00:00Z",
    "paypal.com": "2010-01-01T00:00:00Z",
    "linkedin.com": "2010-01-01T00:00:00Z",
    "facebook.com": "2010-01-01T00:00:00Z",
    "twitter.com": "2010-01-01T00:00:00Z",
    "outlook.com": "2010-01-01T00:00:00Z",
    "yahoo.com": "2010-01-01T00:00:00Z",
    "netflix.com": "2010-01-01T00:00:00Z",
    "dropbox.com": "2010-01-01T00:00:00Z",
    "zoom.us": "2010-01-01T00:00:00Z",
    "slack.com": "2010-01-01T00:00:00Z",
}


def _load_cache() -> dict:
    """Load the domain cache from disk, merging with pre-seeded domains."""
    cache = dict(_PRESEED)
    try:
        if os.path.exists(_CACHE_PATH):
            with open(_CACHE_PATH, "r") as f:
                disk = json.load(f)
            if isinstance(disk, dict):
                cache.update(disk)
    except Exception as e:
        logger.warning(f"[FirstContact] Cache load error: {e}")
    return cache


def _save_cache(cache: dict):
    """Persist the domain cache to disk."""
    try:
        os.makedirs(os.path.dirname(_CACHE_PATH), exist_ok=True)
        with open(_CACHE_PATH, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        logger.warning(f"[FirstContact] Cache save error: {e}")


# Load once at module start; updated on every write
_DOMAIN_FIRST_SEEN: dict = _load_cache()


def _root_domain(domain: str) -> str:
    """Extract the root domain (e.g., sub.example.com → example.com)."""
    parts = domain.lower().strip().split(".")
    if len(parts) > 2:
        return f"{parts[-2]}.{parts[-1]}"
    return domain.lower().strip()


def check_and_track_domain(domain: str) -> dict:
    """
    Check if a domain is newly seen.
    If yes, track it and return a First Contact flag dict.
    Persists to JSON file on disk.
    """
    if not domain:
        return {"is_first_contact": False}

    root = _root_domain(domain)
    now = datetime.utcnow()
    now_iso = now.isoformat() + "Z"

    first_seen_str = _DOMAIN_FIRST_SEEN.get(root)

    # Totally new domain
    if not first_seen_str:
        _DOMAIN_FIRST_SEEN[root] = now_iso
        _save_cache(_DOMAIN_FIRST_SEEN)
        logger.info(f"[FirstContact] NEW domain registered: {root}")
        return {
            "is_first_contact": True,
            "first_seen": now_iso,
            "domain": root,
            "risk_boost": 0.15,
            "flag": "SENDER_FIRST_CONTACT_NEW",
        }

    # Check elapsed time since first seen
    try:
        first_seen_time = datetime.fromisoformat(first_seen_str.replace("Z", "+00:00"))
        if first_seen_time.tzinfo:
            first_seen_time = first_seen_time.replace(tzinfo=None)
        diff = now - first_seen_time
        hours_ago = int(diff.total_seconds() / 3600)

        if diff < timedelta(hours=FIRST_CONTACT_THRESHOLD_HOURS):
            return {
                "is_first_contact": True,
                "first_seen": first_seen_str,
                "domain": root,
                "risk_boost": 0.10,
                "flag": f"SENDER_FIRST_CONTACT_RECENT ({hours_ago}h ago)",
            }

    except Exception as e:
        logger.warning(f"[FirstContact] Date parse error for {domain}: {e}")

    return {
        "is_first_contact": False,
        "first_seen": first_seen_str,
        "domain": root,
    }


def get_all_tracked_domains() -> dict:
    """Return the full first-seen cache (for debugging / UI display)."""
    return dict(_DOMAIN_FIRST_SEEN)


def get_stats() -> dict:
    """Return summary statistics about the first-contact cache."""
    total = len(_DOMAIN_FIRST_SEEN)
    preseeded = len(_PRESEED)
    return {
        "total_tracked_domains": total,
        "preseeded_domains": preseeded,
        "learned_domains": total - preseeded,
        "cache_file": _CACHE_PATH,
        "threshold_hours": FIRST_CONTACT_THRESHOLD_HOURS,
    }


def get_sender_from_headers(content: str) -> str:
    """Extract sender domain from raw email headers."""
    import re
    match = re.search(r'^From:.*<.*?@(.*?)>', content, re.MULTILINE | re.IGNORECASE)
    if match:
        return match.group(1).strip()

    match = re.search(r'^From:.*?@([\w.-]+)', content, re.MULTILINE | re.IGNORECASE)
    if match:
        return match.group(1).strip()

    return ""
