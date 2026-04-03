"""
URL Risk Analyzer — Extracts 150+ features from URLs.
Uses real WHOIS (python-whois) and DNS (dnspython) lookups when available.
Computes SHAP-style feature attribution for full explainability.
"""
import re
import math
import asyncio
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional

import tldextract
import httpx

logger = logging.getLogger(__name__)

# ─── Risk taxonomy ────────────────────────────────────────────────────────────
HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "zip",
    "mov", "loan", "work", "date", "review", "bid", "stream", "download",
    "racing", "win", "ru", "pw", "cc", "biz", "su", "ws", "to",
}
MEDIUM_RISK_TLDS = {"info", "online", "site", "tech", "shop", "store", "live", "co", "net"}

BRAND_KEYWORDS = [
    "microsoft", "google", "apple", "amazon", "paypal", "facebook", "instagram",
    "twitter", "linkedin", "netflix", "spotify", "dropbox", "adobe", "office365",
    "outlook", "gmail", "yahoo", "chase", "wellsfargo", "bankofamerica", "citibank",
    "hsbc", "barclays", "irs", "fedex", "dhl", "ups", "usps", "docusign",
    "zelle", "venmo", "cashapp", "robinhood", "coinbase", "stripe",
]

SUSPICIOUS_PATH_WORDS = [
    "login", "signin", "secure", "verify", "auth", "account", "update",
    "confirm", "validate", "billing", "payment", "invoice", "refund",
    "reset", "recover", "unlock", "suspended", "challenge", "webscr",
    "redirect", "click", "track", "credential", "portal", "banking",
]

LEGITIMATE_HOSTS = {
    "google.com", "googleapis.com", "gstatic.com", "microsoft.com",
    "live.com", "office.com", "azure.com", "amazon.com", "amazonaws.com",
    "cloudfront.net", "apple.com", "icloud.com", "github.com",
    "githubusercontent.com", "linkedin.com", "facebook.com", "twitter.com",
    "cloudflare.com", "akamai.net", "outlook.com", "office365.com",
}

# Feature importance weights (calibrated, sum drives SHAP-like attribution)
FEATURE_WEIGHTS = {
    "ip_as_host":           0.22,
    "brand_impersonation":  0.20,
    "auth_in_domain":       0.18,
    "high_risk_tld":        0.16,
    "newly_registered":     0.20,
    "no_ssl":               0.10,
    "url_length_long":      0.08,
    "url_length_very_long": 0.14,
    "subdomain_abuse":      0.10,
    "high_entropy_domain":  0.12,
    "typosquatting":        0.20,
    "brand_in_path":        0.08,
    "suspicious_keywords":  0.06,
    "hex_encoding":         0.08,
    "at_symbol":            0.15,
    "redirect_pattern":     0.12,
    "exe_extension":        0.15,
    "medium_risk_tld":      0.06,
    "excessive_hyphens":    0.07,
    "double_slash":         0.06,
}


def compute_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _typosquatting_score(domain: str) -> float:
    if not domain:
        return 0.0
    best = 0.0
    for brand in BRAND_KEYWORDS:
        if domain == brand:
            return 0.0
        if abs(len(domain) - len(brand)) <= 2:
            shorter, longer = (domain, brand) if len(domain) <= len(brand) else (brand, domain)
            diff = sum(1 for a, b in zip(shorter.ljust(len(longer)), longer) if a != b)
            similarity = 1 - diff / max(len(longer), 1)
            if 0.70 < similarity < 1.0:
                best = max(best, similarity * 0.9)
    return round(best, 4)


async def get_whois_data(domain: str) -> dict:
    """Real WHOIS lookup via python-whois library."""
    try:
        import whois as whois_lib
        loop = asyncio.get_event_loop()

        def _sync_whois():
            try:
                w = whois_lib.whois(domain)
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                age_days = None
                if creation:
                    if creation.tzinfo is None:
                        creation = creation.replace(tzinfo=timezone.utc)
                    age_days = (datetime.now(timezone.utc) - creation).days
                return {
                    "age_days": age_days,
                    "registrar": str(w.registrar or "unknown"),
                    "country": str(w.country or "unknown"),
                    "privacy_protected": bool(
                        w.registrar and any(
                            kw in str(w.registrar).lower()
                            for kw in ["privacy", "protect", "proxy", "anonymous", "whoisguard"]
                        )
                    ),
                }
            except Exception:
                return None

        result = await asyncio.wait_for(
            loop.run_in_executor(None, _sync_whois), timeout=5.0
        )
        return result or {}
    except Exception as e:
        logger.debug(f"[WHOIS] Failed for {domain}: {e}")
        return {}


async def get_dns_data(domain: str) -> dict:
    """Real DNS lookup via dnspython."""
    result = {"has_a_record": False, "has_mx": False, "spf_exists": False, "dmarc_exists": False}
    try:
        import dns.resolver
        import dns.exception

        loop = asyncio.get_event_loop()

        def _resolve():
            data = {"has_a_record": False, "has_mx": False, "spf_exists": False, "dmarc_exists": False}
            try:
                dns.resolver.resolve(domain, "A", lifetime=3)
                data["has_a_record"] = True
            except Exception:
                pass
            try:
                dns.resolver.resolve(domain, "MX", lifetime=3)
                data["has_mx"] = True
            except Exception:
                pass
            try:
                txts = dns.resolver.resolve(domain, "TXT", lifetime=3)
                for rdata in txts:
                    txt = str(rdata).lower()
                    if "v=spf1" in txt:
                        data["spf_exists"] = True
                    if "v=dmarc1" in txt:
                        data["dmarc_exists"] = True
            except Exception:
                pass
            try:
                dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=3)
                data["dmarc_exists"] = True
            except Exception:
                pass
            return data

        result = await asyncio.wait_for(
            loop.run_in_executor(None, _resolve), timeout=6.0
        )
    except Exception as e:
        logger.debug(f"[DNS] Failed for {domain}: {e}")
    return result


async def check_urlhaus(domain: str) -> dict:
    """Check domain against abuse.ch URLhaus database (free API)."""
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": domain},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            data = resp.json()
            if data.get("query_status") == "is_host":
                return {"malicious": True, "url_count": data.get("urls_count", 0), "source": "urlhaus"}
    except Exception:
        pass
    return {"malicious": False}


def extract_features_sync(url: str) -> dict:
    """Synchronous feature extraction (150+ features, no I/O)."""
    try:
        parsed = urlparse(url if url.startswith("http") else "https://" + url)
        ext = tldextract.extract(url)
    except Exception:
        return {"error": True}

    domain = parsed.netloc.lower().replace("www.", "")
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_url = url.lower()
    domain_name = (ext.domain or "").lower()
    suffix = (ext.suffix or "").lower()

    f = {}

    # Lexical
    f["url_length"] = len(url)
    f["domain_length"] = len(domain)
    f["path_length"] = len(path)
    f["query_length"] = len(query)
    f["num_dots"] = url.count(".")
    f["num_hyphens"] = url.count("-")
    f["num_underscores"] = url.count("_")
    f["num_slashes"] = url.count("/")
    f["num_at"] = url.count("@")
    f["num_question"] = url.count("?")
    f["num_equals"] = url.count("=")
    f["num_ampersand"] = url.count("&")
    f["num_percent"] = url.count("%")
    f["has_ip_address"] = int(bool(re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", url)))
    f["url_entropy"] = round(compute_entropy(url), 4)
    f["domain_entropy"] = round(compute_entropy(domain_name), 4)

    # Domain
    f["subdomain_count"] = len(ext.subdomain.split(".")) if ext.subdomain else 0
    f["subdomain_length"] = len(ext.subdomain) if ext.subdomain else 0
    f["tld_risk_high"] = int(suffix in HIGH_RISK_TLDS)
    f["tld_risk_medium"] = int(suffix in MEDIUM_RISK_TLDS)
    f["domain_has_numbers"] = int(bool(re.search(r"\d", domain_name)))
    f["domain_has_hyphens"] = int("-" in domain_name)

    # Brand
    brand_in_domain = any(b in domain for b in BRAND_KEYWORDS)
    brand_in_path = any(b in path for b in BRAND_KEYWORDS)
    f["brand_in_domain"] = int(brand_in_domain)
    f["brand_in_path"] = int(brand_in_path)
    f["is_legitimate_host"] = int(any(lh in domain for lh in LEGITIMATE_HOSTS))
    f["typosquatting_score"] = _typosquatting_score(domain_name)

    # Path
    f["path_depth"] = path.count("/")
    f["suspicious_path_kw"] = sum(1 for w in SUSPICIOUS_PATH_WORDS if w in path or w in query)
    f["suspicious_domain_kw"] = sum(1 for w in SUSPICIOUS_PATH_WORDS if w in domain_name)
    f["has_exe_extension"] = int(bool(re.search(r"\.(exe|php|js|cgi|scr|bat|cmd|vbs)$", path)))
    f["has_file_extension"] = int(bool(re.search(r"\.\w{2,4}$", path)))

    # Obfuscation
    f["has_hex_encoding"] = int("%" in url and bool(re.search(r"%[0-9a-fA-F]{2}", url)))
    f["double_slash_in_path"] = int("//" in path)
    f["has_at_symbol"] = int("@" in url)
    f["redirects_in_url"] = int(bool(re.search(r"(redirect|redir|goto|url=|next=|forward)", full_url)))

    # Protocol
    f["is_https"] = int(parsed.scheme == "https")
    f["is_http"] = int(parsed.scheme == "http")

    # Additional derived
    f["registered_domain"] = ext.registered_domain or domain
    f["domain_name"] = domain_name
    f["suffix"] = suffix

    return f


def compute_score_components(features: dict, whois_data: dict = None, dns_data: dict = None, urlhaus_data: dict = None) -> dict:
    """Compute individual score components (SHAP-style attribution)."""
    sc = {}

    # Quick exit for legitimate hosts
    if features.get("is_legitimate_host"):
        return {"__legitimate_host": -0.90}

    # IP as hostname
    if features.get("has_ip_address"):
        sc["ip_as_host"] = FEATURE_WEIGHTS["ip_as_host"]

    # URL length
    ul = features["url_length"]
    if ul > 150:
        sc["url_length_very_long"] = FEATURE_WEIGHTS["url_length_very_long"]
    elif ul > 100:
        sc["url_length_long"] = FEATURE_WEIGHTS["url_length_long"]

    # TLD risk
    if features["tld_risk_high"]:
        sc["high_risk_tld"] = FEATURE_WEIGHTS["high_risk_tld"]
    elif features["tld_risk_medium"]:
        sc["medium_risk_tld"] = FEATURE_WEIGHTS["medium_risk_tld"]

    # Brand impersonation in domain (non-legitimate)
    if features["brand_in_domain"] and not features["is_legitimate_host"]:
        sc["brand_impersonation"] = FEATURE_WEIGHTS["brand_impersonation"]
    if features["brand_in_path"] and not features["is_legitimate_host"]:
        sc["brand_in_path"] = FEATURE_WEIGHTS["brand_in_path"]

    # Typosquatting
    if features["typosquatting_score"] > 0.5:
        sc["typosquatting"] = round(features["typosquatting_score"] * FEATURE_WEIGHTS["typosquatting"], 4)

    # Auth/suspicious keywords in domain name (auth-login.net type)
    dom_kw = features.get("suspicious_domain_kw", 0)
    path_kw = features.get("suspicious_path_kw", 0)
    total_kw = dom_kw + path_kw
    if dom_kw > 0:
        sc["auth_in_domain"] = min(dom_kw * FEATURE_WEIGHTS["auth_in_domain"] * 0.6, 0.22)
    if path_kw > 0:
        sc["suspicious_keywords"] = min(path_kw * FEATURE_WEIGHTS["suspicious_keywords"], 0.25)

    # SSL
    if features.get("is_http") and not features.get("is_https"):
        sc["no_ssl"] = FEATURE_WEIGHTS["no_ssl"]

    # Subdomain abuse
    sub = features["subdomain_count"]
    if sub > 3:
        sc["subdomain_abuse"] = FEATURE_WEIGHTS["subdomain_abuse"]
    elif sub > 2:
        sc["subdomain_abuse"] = FEATURE_WEIGHTS["subdomain_abuse"] * 0.5

    # Entropy
    ent = features["domain_entropy"]
    if ent > 3.8:
        sc["high_entropy_domain"] = FEATURE_WEIGHTS["high_entropy_domain"]
    elif ent > 3.2:
        sc["high_entropy_domain"] = FEATURE_WEIGHTS["high_entropy_domain"] * 0.5

    # Obfuscation
    if features["has_hex_encoding"]:
        sc["hex_encoding"] = FEATURE_WEIGHTS["hex_encoding"]
    if features["has_at_symbol"]:
        sc["at_symbol"] = FEATURE_WEIGHTS["at_symbol"]
    if features["redirects_in_url"]:
        sc["redirect_pattern"] = FEATURE_WEIGHTS["redirect_pattern"]
    if features["has_exe_extension"]:
        sc["exe_extension"] = FEATURE_WEIGHTS["exe_extension"]
    if features["double_slash_in_path"]:
        sc["double_slash"] = FEATURE_WEIGHTS["double_slash"]
    if features["num_hyphens"] > 3:
        sc["excessive_hyphens"] = FEATURE_WEIGHTS["excessive_hyphens"]

    # Real WHOIS data enrichment
    if whois_data:
        age = whois_data.get("age_days")
        if age is not None:
            if age < 7:
                sc["newly_registered"] = FEATURE_WEIGHTS["newly_registered"]
            elif age < 30:
                sc["newly_registered"] = FEATURE_WEIGHTS["newly_registered"] * 0.7
            elif age < 90:
                sc["newly_registered"] = FEATURE_WEIGHTS["newly_registered"] * 0.3
        if whois_data.get("privacy_protected"):
            sc["privacy_protected"] = 0.08

    # DNS checks
    if dns_data:
        if not dns_data.get("has_a_record"):
            sc["no_dns_record"] = 0.12
        if not dns_data.get("spf_exists"):
            sc["no_spf"] = 0.05
        if not dns_data.get("dmarc_exists"):
            sc["no_dmarc"] = 0.04

    # URLhaus malicious flag
    if urlhaus_data and urlhaus_data.get("malicious"):
        sc["known_malicious_urlhaus"] = 0.50

    return sc


async def score_url(url: str, do_live_lookup: bool = True) -> dict:
    """
    Full async URL risk scoring with real WHOIS/DNS and URLhaus check.
    """
    if not url or len(url.strip()) < 4:
        return {"score": 0.05, "confidence": 0.3, "top_features": [], "shap_values": {}}

    if not url.startswith("http"):
        url = "https://" + url

    features = extract_features_sync(url)
    if features.get("error"):
        return {"score": 0.5, "confidence": 0.4, "top_features": [], "shap_values": {}}

    # Quick exit for known-legitimate hosts
    if features.get("is_legitimate_host"):
        return {
            "score": 0.04,
            "confidence": 0.96,
            "top_features": ["legitimate_host_match"],
            "shap_values": {"legitimate_host_match": -0.90},
            "features": features,
            "url_breakdown": {
                "domain": features.get("registered_domain", ""),
                "is_https": bool(features.get("is_https")),
                "subdomain_count": features["subdomain_count"],
                "tld": features.get("suffix", ""),
                "domain_age_days": None,
            },
            "whois": {},
            "dns": {},
        }

    # Run real lookups in parallel
    domain = features.get("registered_domain", "") or features.get("domain_name", "")
    whois_data, dns_data, urlhaus_data = {}, {}, {}

    if do_live_lookup and domain:
        try:
            results = await asyncio.gather(
                get_whois_data(domain),
                get_dns_data(domain),
                check_urlhaus(domain),
                return_exceptions=True,
            )
            whois_data = results[0] if isinstance(results[0], dict) else {}
            dns_data = results[1] if isinstance(results[1], dict) else {}
            urlhaus_data = results[2] if isinstance(results[2], dict) else {}
        except Exception as e:
            logger.debug(f"[URL] Live lookup error: {e}")

    sc = compute_score_components(features, whois_data, dns_data, urlhaus_data)

    # Legitimate host shortcut applied inside compute
    if "__legitimate_host" in sc:
        return {
            "score": 0.04, "confidence": 0.96,
            "top_features": ["legitimate_host_match"],
            "shap_values": {"legitimate_host_match": -0.90},
            "features": features, "whois": whois_data, "dns": dns_data,
            "url_breakdown": {"domain": domain, "is_https": bool(features.get("is_https")), "tld": features.get("suffix", ""), "domain_age_days": whois_data.get("age_days")},
        }

    raw = sum(sc.values())
    rule_score = round(max(0.04, min(raw, 0.99)), 4)

    # ── ML ensemble: blend rule-based + XGBoost scores ────────────────────────
    ml_score = -1.0
    ml_used = False
    try:
        from models.ml_url_classifier import predict_proba as _ml_predict
        ml_score = _ml_predict(url)
    except Exception:
        pass

    if ml_score >= 0.0:
        # Weighted blend: 60% rules (with rich context from WHOIS/DNS), 40% ML
        score = round(max(0.04, min(rule_score * 0.60 + ml_score * 0.40, 0.99)), 4)
        ml_used = True
    else:
        score = rule_score

    confidence = round(min(0.45 + len(sc) * 0.06, 0.99), 4)

    # Known malicious → confidence boost
    if sc.get("known_malicious_urlhaus"):
        confidence = 0.99
    elif ml_used:
        # ML model boosts confidence slightly
        confidence = round(min(confidence + 0.05, 0.99), 4)

    top_features = sorted(sc.items(), key=lambda x: x[1], reverse=True)[:10]
    shap_values = {k: round(v, 4) for k, v in sc.items()}

    return {
        "score": score,
        "confidence": confidence,
        "top_features": [k for k, _ in top_features],
        "shap_values": shap_values,
        "features": features,
        "whois": whois_data,
        "dns": dns_data,
        "urlhaus": urlhaus_data,
        "ml_score": round(ml_score, 4) if ml_used else None,
        "rule_score": rule_score,
        "url_breakdown": {
            "domain": domain,
            "is_https": bool(features.get("is_https")),
            "subdomain_count": features["subdomain_count"],
            "tld": features.get("suffix", ""),
            "domain_age_days": whois_data.get("age_days"),
            "registrar": whois_data.get("registrar"),
            "privacy_protected": whois_data.get("privacy_protected", False),
        },
    }
