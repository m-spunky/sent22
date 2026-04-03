"""
Email Header Anomaly Detector — Analyzes SPF/DKIM/DMARC, routing, and header consistency.
"""
import re
from typing import Optional


def parse_headers(raw_headers: str) -> dict:
    """
    Parse raw email headers into a dict.
    Handles both colon-separated and raw MIME formats.
    """
    headers = {}
    if not raw_headers:
        return headers

    # Try to extract common headers via regex
    patterns = {
        "from": r"^From:\s*(.+)$",
        "reply_to": r"^Reply-To:\s*(.+)$",
        "return_path": r"^Return-Path:\s*(.+)$",
        "to": r"^To:\s*(.+)$",
        "subject": r"^Subject:\s*(.+)$",
        "date": r"^Date:\s*(.+)$",
        "x_mailer": r"^X-Mailer:\s*(.+)$",
        "x_originating_ip": r"^X-Originating-IP:\s*(.+)$",
        "received": r"^(Received:.+)$",
        "authentication_results": r"^Authentication-Results:\s*(.+)$",
        "received_spf": r"^Received-SPF:\s*(.+)$",
        "dkim_signature": r"^DKIM-Signature:\s*(.+)$",
        "dmarc": r"^DMARC.*:\s*(.+)$",
        "content_type": r"^Content-Type:\s*(.+)$",
        "message_id": r"^Message-ID:\s*(.+)$",
        "mime_version": r"^MIME-Version:\s*(.+)$",
    }

    for key, pattern in patterns.items():
        matches = re.findall(pattern, raw_headers, re.MULTILINE | re.IGNORECASE)
        if matches:
            headers[key] = matches[0].strip() if key != "received" else matches

    return headers


def analyze_headers(raw_content: str) -> dict:
    """
    Analyze email headers for anomalies and authentication failures.
    """
    headers = parse_headers(raw_content)

    flags = []
    score_components = {}

    # ── SPF Analysis ──────────────────────────────────────────────────────────
    spf_result = "unknown"
    spf_text = headers.get("received_spf", "") + headers.get("authentication_results", "")
    if "pass" in spf_text.lower():
        spf_result = "pass"
    elif "fail" in spf_text.lower() or "softfail" in spf_text.lower():
        spf_result = "fail"
        flags.append("spf_fail")
        score_components["spf_fail"] = 0.15

    # ── DKIM Analysis ─────────────────────────────────────────────────────────
    dkim_result = "unknown"
    dkim_sig = headers.get("dkim_signature", "")
    auth_results = headers.get("authentication_results", "").lower()

    if dkim_sig:
        if "pass" in auth_results:
            dkim_result = "pass"
        elif "fail" in auth_results or "none" in auth_results:
            dkim_result = "fail"
            flags.append("dkim_fail")
            score_components["dkim_fail"] = 0.12
    else:
        dkim_result = "none"
        flags.append("dkim_missing")
        score_components["dkim_missing"] = 0.08

    # ── DMARC Analysis ────────────────────────────────────────────────────────
    dmarc_result = "none"
    if "dmarc=pass" in auth_results:
        dmarc_result = "pass"
    elif "dmarc=fail" in auth_results or "dmarc=reject" in auth_results:
        dmarc_result = "fail"
        flags.append("dmarc_fail")
        score_components["dmarc_fail"] = 0.14

    # ── Reply-To / From Mismatch ──────────────────────────────────────────────
    from_header = headers.get("from", "")
    reply_to = headers.get("reply_to", "")
    return_path = headers.get("return_path", "")

    from_domain = _extract_domain(from_header)
    reply_domain = _extract_domain(reply_to)
    return_domain = _extract_domain(return_path)

    if reply_to and from_domain and reply_domain and from_domain != reply_domain:
        flags.append("reply_to_mismatch")
        score_components["reply_to_mismatch"] = 0.20

    if return_path and from_domain and return_domain and from_domain != return_domain:
        flags.append("return_path_mismatch")
        score_components["return_path_mismatch"] = 0.12

    # ── X-Mailer Anomaly ──────────────────────────────────────────────────────
    x_mailer = headers.get("x_mailer", "").lower()
    suspicious_mailers = ["emaillabs", "sendblaster", "massmailer", "bulkmailer", "swiftmailer"]
    if any(m in x_mailer for m in suspicious_mailers):
        flags.append("bulk_mailer_detected")
        score_components["bulk_mailer"] = 0.08

    # Missing critical headers
    if not headers.get("message_id"):
        flags.append("missing_message_id")
        score_components["missing_message_id"] = 0.06

    if not headers.get("date"):
        flags.append("missing_date_header")
        score_components["missing_date"] = 0.04

    # ── Routing Analysis ──────────────────────────────────────────────────────
    received_headers = headers.get("received", [])
    if isinstance(received_headers, list) and len(received_headers) > 6:
        flags.append("excessive_routing_hops")
        score_components["routing_anomaly"] = 0.07

    # Compute score
    raw_score = sum(score_components.values())
    score = round(max(0.04, min(raw_score, 0.98)), 4)

    # If no headers found, return low confidence neutral
    if not headers:
        return {
            "score": 0.30,
            "confidence": 0.35,
            "flags": ["no_parseable_headers"],
            "spf_result": "unknown",
            "dkim_result": "unknown",
            "dmarc_result": "unknown",
            "score_components": {},
        }

    n_signals = len(flags)
    confidence = round(min(0.40 + n_signals * 0.08, 0.97), 4)

    return {
        "score": score,
        "confidence": confidence,
        "flags": flags,
        "spf_result": spf_result,
        "dkim_result": dkim_result,
        "dmarc_result": dmarc_result,
        "from_domain": from_domain,
        "reply_domain": reply_domain if reply_to else None,
        "score_components": score_components,
    }


def _extract_domain(header_value: str) -> Optional[str]:
    """Extract domain from an email address in a header."""
    if not header_value:
        return None
    match = re.search(r"@([\w.\-]+)", header_value)
    return match.group(1).lower() if match else None
