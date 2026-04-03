"""
Bot Detection Engine — statistical analysis of session signals.
Detects automated/scripted behavior patterns using request timing,
user-agent consistency, behavioral entropy, and anomaly scoring.
"""
import logging
import math
import time
from typing import Optional

logger = logging.getLogger(__name__)


# Known bot/scraper user-agent signatures
_BOT_UA_PATTERNS = [
    "python-requests", "curl/", "wget/", "scrapy", "httpx", "aiohttp",
    "go-http-client", "java/", "apache-httpclient", "libwww-perl",
    "mechanize", "httpclient", "okhttp", "phantom", "headless",
    "selenium", "webdriver", "puppeteer", "playwright", "cypress",
    "bot", "crawler", "spider", "scraper", "fetch",
]

# Suspicious request timing patterns (ms)
_MIN_HUMAN_INTERVAL_MS = 200   # Humans click < 200ms apart — very suspicious
_MAX_HUMAN_INTERVAL_MS = 300_000  # 5 minutes max idle before session timeout


def _compute_timing_score(request_intervals_ms: list[float]) -> float:
    """Score suspicious timing based on interval statistics."""
    if not request_intervals_ms:
        return 0.1

    n = len(request_intervals_ms)
    mean = sum(request_intervals_ms) / n
    variance = sum((x - mean) ** 2 for x in request_intervals_ms) / max(n, 1)
    std = math.sqrt(variance)
    cv = std / max(mean, 1.0)  # Coefficient of variation

    score = 0.0

    # Very fast requests (likely automated)
    fast_count = sum(1 for t in request_intervals_ms if t < _MIN_HUMAN_INTERVAL_MS)
    if fast_count / max(n, 1) > 0.5:
        score += 0.40

    # Extremely regular timing (bots have low CV)
    if cv < 0.15 and n > 5:
        score += 0.35  # Robotic regularity

    # Burst pattern detection
    if mean < 500 and n > 20:
        score += 0.25

    return min(score, 0.95)


def _compute_ua_score(user_agent: str) -> tuple[float, list[str]]:
    """Score user-agent string for bot signatures."""
    if not user_agent:
        return 0.7, ["missing_user_agent"]

    ua_lower = user_agent.lower()
    flags = []
    score = 0.0

    for pattern in _BOT_UA_PATTERNS:
        if pattern in ua_lower:
            flags.append(f"bot_ua_pattern:{pattern}")
            score = max(score, 0.85)

    # Check for missing common browser signals in UA
    has_browser_token = any(t in ua_lower for t in ["mozilla", "chrome", "safari", "firefox", "edge"])
    if not has_browser_token and not flags:
        flags.append("non_browser_ua")
        score = max(score, 0.55)

    return score, flags


def _compute_behavioral_entropy(
    page_sequence: list[str],
    click_positions: list[tuple],
    scroll_depths: list[float],
) -> float:
    """Measure entropy of behavioral signals — low entropy → robotic."""
    score = 0.0

    # Page sequence entropy
    if page_sequence and len(page_sequence) > 3:
        unique_pages = len(set(page_sequence))
        if unique_pages / len(page_sequence) < 0.3:
            score += 0.2  # Very repetitive navigation

    # Click position clustering (bots often click same coordinates)
    if click_positions and len(click_positions) > 5:
        unique_positions = len(set(click_positions))
        if unique_positions / len(click_positions) < 0.2:
            score += 0.25

    # Scroll depth uniformity (humans vary scroll depth)
    if scroll_depths and len(scroll_depths) > 3:
        scroll_var = sum((x - 0.5) ** 2 for x in scroll_depths) / len(scroll_depths)
        if scroll_var < 0.05:
            score += 0.2  # Always scrolling same amount = bot

    return min(score, 0.6)


def analyze_session(
    user_agent: str = "",
    request_count: int = 0,
    session_duration_ms: float = 0,
    request_intervals_ms: Optional[list[float]] = None,
    page_sequence: Optional[list[str]] = None,
    click_positions: Optional[list[tuple]] = None,
    scroll_depths: Optional[list[float]] = None,
    ip_address: str = "",
    geo_changes: int = 0,
    failed_logins: int = 0,
    captcha_failures: int = 0,
) -> dict:
    """
    Analyze a session for bot/automated behavior.

    Returns:
        bot_score: float 0-1 (probability of bot)
        is_bot: bool (threshold 0.65)
        confidence: float
        detected_signals: list of flag strings
        risk_level: str
        recommendation: str
    """
    signals = []
    component_scores = {}

    # 1. User-agent analysis
    ua_score, ua_flags = _compute_ua_score(user_agent)
    component_scores["user_agent"] = ua_score
    signals.extend(ua_flags)

    # 2. Request timing
    intervals = request_intervals_ms or []
    if request_count > 0 and session_duration_ms > 0 and not intervals:
        # Synthesize approximate intervals
        avg_interval = session_duration_ms / max(request_count, 1)
        intervals = [avg_interval] * request_count

    timing_score = _compute_timing_score(intervals)
    component_scores["timing"] = timing_score
    if timing_score > 0.5:
        signals.append("suspicious_request_timing")

    # 3. Request rate
    rate_score = 0.0
    if session_duration_ms > 0:
        requests_per_second = request_count / max(session_duration_ms / 1000, 0.001)
        if requests_per_second > 10:
            rate_score = 0.75
            signals.append(f"high_request_rate:{requests_per_second:.1f}rps")
        elif requests_per_second > 5:
            rate_score = 0.40
            signals.append("elevated_request_rate")
    component_scores["request_rate"] = rate_score

    # 4. Behavioral entropy
    entropy_score = _compute_behavioral_entropy(
        page_sequence or [], click_positions or [], scroll_depths or []
    )
    component_scores["behavioral_entropy"] = entropy_score
    if entropy_score > 0.3:
        signals.append("low_behavioral_entropy")

    # 5. Authentication anomalies
    auth_score = 0.0
    if failed_logins > 5:
        auth_score = min(0.4 + (failed_logins - 5) * 0.05, 0.85)
        signals.append(f"failed_login_spike:{failed_logins}")
    if captcha_failures > 2:
        auth_score = max(auth_score, 0.70)
        signals.append(f"captcha_failures:{captcha_failures}")
    component_scores["auth_anomaly"] = auth_score

    # 6. Geographic anomalies
    geo_score = 0.0
    if geo_changes > 1:
        geo_score = min(geo_changes * 0.25, 0.80)
        signals.append(f"geo_switching:{geo_changes}_locations")
    component_scores["geo_anomaly"] = geo_score

    # Weighted ensemble
    weights = {
        "user_agent": 0.25,
        "timing": 0.25,
        "request_rate": 0.20,
        "behavioral_entropy": 0.10,
        "auth_anomaly": 0.12,
        "geo_anomaly": 0.08,
    }
    bot_score = sum(component_scores[k] * weights[k] for k in weights)
    bot_score = round(min(bot_score, 0.99), 4)

    is_bot = bot_score >= 0.65
    confidence = round(min(0.5 + abs(bot_score - 0.5) * 1.5, 0.99), 4)

    if bot_score >= 0.80:
        risk_level = "CRITICAL"
        recommendation = "block_and_captcha_challenge"
    elif bot_score >= 0.65:
        risk_level = "HIGH"
        recommendation = "rate_limit_and_challenge"
    elif bot_score >= 0.40:
        risk_level = "MEDIUM"
        recommendation = "monitor_and_log"
    else:
        risk_level = "LOW"
        recommendation = "allow_with_monitoring"

    return {
        "bot_score": bot_score,
        "is_bot": is_bot,
        "confidence": confidence,
        "risk_level": risk_level,
        "recommendation": recommendation,
        "detected_signals": signals,
        "component_scores": component_scores,
        "request_count": request_count,
        "session_duration_ms": session_duration_ms,
    }


def analyze_credential_stuffing(
    login_attempts: list[dict],
    time_window_minutes: int = 10,
) -> dict:
    """
    Detect credential stuffing attacks from a list of login attempts.
    Each attempt: {"username": str, "ip": str, "success": bool, "timestamp": float}
    """
    if not login_attempts:
        return {"detected": False, "score": 0.0, "signals": []}

    signals = []
    score = 0.0

    unique_ips = set(a.get("ip", "") for a in login_attempts)
    unique_users = set(a.get("username", "") for a in login_attempts)
    failures = [a for a in login_attempts if not a.get("success", False)]
    failure_rate = len(failures) / max(len(login_attempts), 1)

    # High failure rate from many IPs → distributed stuffing
    if failure_rate > 0.85 and len(login_attempts) > 10:
        score += 0.40
        signals.append(f"high_failure_rate:{failure_rate:.1%}")

    # Many unique accounts targeted from few IPs → list-based attack
    if len(unique_users) > 20 and len(unique_ips) < 5:
        score += 0.35
        signals.append(f"account_enumeration:{len(unique_users)}_accounts_from_{len(unique_ips)}_ips")

    # Velocity: many attempts in short time
    if len(login_attempts) > 50 and time_window_minutes <= 10:
        score += 0.25
        signals.append(f"high_velocity:{len(login_attempts)}_attempts_in_{time_window_minutes}min")

    score = round(min(score, 0.99), 4)
    return {
        "detected": score >= 0.60,
        "score": score,
        "signals": signals,
        "unique_ips": len(unique_ips),
        "unique_accounts_targeted": len(unique_users),
        "failure_rate": round(failure_rate, 4),
        "total_attempts": len(login_attempts),
    }
