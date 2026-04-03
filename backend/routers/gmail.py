"""
Gmail OAuth2 Integration — connect user's Gmail, score emails in real-time.
Real OAuth2 flow with Google API. Demo fallback only when credentials not set.
"""
import os
import json
import logging
import base64
import asyncio
import re
from datetime import datetime
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from typing import Optional

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/gmail", tags=["gmail"])

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8001/api/v1/gmail/callback")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

TOKEN_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "gmail_token.json")

# In-memory token store: session_id → {credentials, email, is_demo}
_token_store: dict[str, dict] = {}


def _save_token(session_data: dict):
    """Persist real OAuth token to disk so it survives backend restarts."""
    try:
        os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
        with open(TOKEN_FILE, "w") as f:
            json.dump(session_data, f, indent=2)
    except Exception as e:
        logger.warning(f"[Gmail] Could not save token: {e}")


def _load_token():
    """Load persisted OAuth token from disk on startup."""
    global _token_store
    try:
        if os.path.exists(TOKEN_FILE):
            with open(TOKEN_FILE, "r") as f:
                data = json.load(f)
            if data.get("is_demo") is False and data.get("credentials"):
                _token_store["real"] = data
                logger.info(f"[Gmail] Loaded persisted token for {data.get('email', 'unknown')}")
    except Exception as e:
        logger.warning(f"[Gmail] Could not load token: {e}")


# Load any persisted token on import
_load_token()

# ── Gmail Inbox Cache ─────────────────────────────────────────────────────────
GMAIL_CACHE_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "gmail_inbox_cache.json")
_gmail_cache: dict[str, dict] = {}  # msg_id → analyzed email entry


def _load_gmail_cache():
    global _gmail_cache
    try:
        if os.path.exists(GMAIL_CACHE_FILE):
            with open(GMAIL_CACHE_FILE, "r") as f:
                _gmail_cache = json.load(f)
            logger.info(f"[Gmail Cache] Loaded {len(_gmail_cache)} cached emails")
    except Exception as e:
        logger.warning(f"[Gmail Cache] Load failed: {e}")
        _gmail_cache = {}


def _save_gmail_cache():
    try:
        os.makedirs(os.path.dirname(GMAIL_CACHE_FILE), exist_ok=True)
        safe_cache = _json_safe(_gmail_cache)
        with open(GMAIL_CACHE_FILE, "w") as f:
            json.dump(safe_cache, f, indent=2)
        logger.debug(f"[Gmail Cache] Saved {len(_gmail_cache)} entries to disk")
    except Exception as e:
        logger.warning(f"[Gmail Cache] Save failed: {e}")


_load_gmail_cache()


def _json_safe(obj):
    """Recursively convert non-JSON-serializable types (numpy floats, datetimes, etc.)."""
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, bool) or obj is None or isinstance(obj, str):
        return obj
    if isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        import math
        return None if (math.isnan(obj) or math.isinf(obj)) else obj
    try:
        import numpy as np
        if isinstance(obj, np.integer): return int(obj)
        if isinstance(obj, np.floating): return float(obj)
        if isinstance(obj, np.ndarray): return obj.tolist()
        if isinstance(obj, np.bool_): return bool(obj)
    except ImportError:
        pass
    try:
        from datetime import datetime as _dt2, date
        if isinstance(obj, (_dt2, date)): return obj.isoformat()
    except ImportError:
        pass
    return str(obj)


def _strip_html(html_text: str) -> str:
    """Strip HTML tags and decode entities to plain text."""
    import html as _html
    # Remove script/style blocks completely
    html_text = re.sub(r'<(script|style)[^>]*>.*?</(script|style)>', ' ', html_text, flags=re.DOTALL | re.IGNORECASE)
    # Replace block-level tags with newlines for readability
    html_text = re.sub(r'<(br|p|div|tr|li|h[1-6])\b[^>]*>', '\n', html_text, flags=re.IGNORECASE)
    # Remove all remaining tags
    html_text = re.sub(r'<[^>]+>', ' ', html_text)
    # Decode HTML entities (&amp; &nbsp; etc.)
    html_text = _html.unescape(html_text)
    # Normalize whitespace
    html_text = re.sub(r'[ \t]+', ' ', html_text)
    html_text = re.sub(r'\n{3,}', '\n\n', html_text)
    return html_text.strip()


def _is_demo_mode() -> bool:
    return not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


def _has_real_token() -> bool:
    return any(v.get("is_demo") is False and "credentials" in v for v in _token_store.values())


def _get_real_session() -> Optional[dict]:
    for v in _token_store.values():
        if v.get("is_demo") is False and "credentials" in v:
            return v
    return None


# ── OAuth2 Flow ───────────────────────────────────────────────────────────────

@router.get("/auth-url")
async def get_auth_url(session_id: str = "default"):
    """Generate Google OAuth2 authorization URL."""
    if _is_demo_mode():
        return {
            "demo_mode": True,
            "auth_url": None,
            "message": "Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in backend/.env for real Gmail access.",
            "demo_connect_url": "/api/v1/gmail/demo-connect",
        }
    try:
        from google_auth_oauthlib.flow import Flow
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [GOOGLE_REDIRECT_URI],
                }
            },
            scopes=GMAIL_SCOPES,
            redirect_uri=GOOGLE_REDIRECT_URI,
        )
        auth_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
        )
        # Store code_verifier — required for PKCE token exchange
        _token_store[session_id] = {
            "state": state,
            "is_demo": False,
            "code_verifier": getattr(flow, "code_verifier", None),
        }
        return {"auth_url": auth_url, "state": state, "demo_mode": False}
    except ImportError:
        return {
            "demo_mode": True,
            "auth_url": None,
            "message": "google-auth-oauthlib not installed. Run: pip install google-auth-oauthlib",
        }


@router.get("/callback")
async def oauth_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    """Handle Google OAuth2 callback — exchange code for tokens."""
    if error:
        return RedirectResponse(url=f"{FRONTEND_URL}/dashboard/inbox?error={error}")

    if not code:
        return RedirectResponse(url=f"{FRONTEND_URL}/dashboard/inbox?error=no_code")

    try:
        import requests as _requests
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build

        # Retrieve PKCE code_verifier stored during auth-url generation
        pending = _token_store.get("default", {})
        code_verifier = pending.get("code_verifier")

        # Exchange authorization code for tokens directly — no oauthlib state validation
        token_payload = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        if code_verifier:
            token_payload["code_verifier"] = code_verifier

        logger.info(f"[Gmail] Exchanging code, PKCE verifier present: {bool(code_verifier)}")
        token_resp = _requests.post(
            "https://oauth2.googleapis.com/token",
            data=token_payload,
            timeout=15,
        )
        token_data = token_resp.json()

        logger.info(f"[Gmail] Token exchange response keys: {list(token_data.keys())}")
        if "error" in token_data:
            logger.error(f"[Gmail] Token exchange failed: {token_data}")
            return RedirectResponse(url=f"{FRONTEND_URL}/dashboard/inbox?error={token_data.get('error', 'token_error')}")

        access_token = token_data["access_token"]
        refresh_token = token_data.get("refresh_token", "")

        # Build credentials object and fetch user email
        credentials = Credentials(
            token=access_token,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            scopes=GMAIL_SCOPES,
        )
        service = build("gmail", "v1", credentials=credentials)
        profile = service.users().getProfile(userId="me").execute()
        email_address = profile.get("emailAddress", "unknown@gmail.com")

        session_data = {
            "is_demo": False,
            "credentials": {
                "token": access_token,
                "refresh_token": refresh_token,
                "token_uri": "https://oauth2.googleapis.com/token",
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "scopes": GMAIL_SCOPES,
            },
            "email": email_address,
            "connected_at": datetime.utcnow().isoformat(),
        }
        _token_store["real"] = session_data
        _save_token(session_data)

        logger.info(f"[Gmail] OAuth successful for {email_address}")
        return RedirectResponse(url=f"{FRONTEND_URL}/dashboard/inbox?connected=true")

    except Exception as e:
        import traceback
        logger.error(f"[Gmail] OAuth callback error: {e}\n{traceback.format_exc()}")
        return RedirectResponse(url=f"{FRONTEND_URL}/dashboard/inbox?error=oauth_failed")


@router.get("/demo-connect")
async def demo_connect():
    """Activate demo Gmail connection (no real OAuth — used when creds not set)."""
    _token_store["demo"] = {
        "is_demo": True,
        "email": "analyst@sentinelai.demo",
        "connected_at": datetime.utcnow().isoformat(),
    }
    return {
        "status": "connected",
        "demo_mode": True,
        "email": "analyst@sentinelai.demo",
        "message": "Demo inbox — 8 pre-classified sample emails.",
    }


@router.get("/status")
async def gmail_status():
    """Check Gmail connection status."""
    if _has_real_token():
        session = _get_real_session()
        return {
            "connected": True,
            "demo_mode": False,
            "email": session.get("email"),
            "message": "Real Gmail connected via OAuth2",
        }
    if "demo" in _token_store:
        return {
            "connected": True,
            "demo_mode": True,
            "email": "analyst@sentinelai.demo",
            "message": "Demo mode",
        }
    return {
        "connected": False,
        "demo_mode": _is_demo_mode(),
        "email": None,
    }


# ── Gmail API helpers ─────────────────────────────────────────────────────────

def _build_gmail_service(session: dict):
    """Build an authorized Gmail service from stored credentials."""
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build

    creds_data = session["credentials"]
    credentials = Credentials(
        token=creds_data["token"],
        refresh_token=creds_data.get("refresh_token"),
        token_uri=creds_data.get("token_uri", "https://oauth2.googleapis.com/token"),
        client_id=creds_data["client_id"],
        client_secret=creds_data["client_secret"],
        scopes=creds_data.get("scopes", GMAIL_SCOPES),
    )
    return build("gmail", "v1", credentials=credentials)


def _collect_body_parts(payload: dict, plains: list, htmls: list):
    """Recursively collect all text/plain and text/html body parts."""
    mime = payload.get("mimeType", "")
    data = payload.get("body", {}).get("data", "")
    if mime.startswith("text/plain") and data:
        decoded = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
        if decoded.strip():
            plains.append(decoded)
    elif mime.startswith("text/html") and data:
        decoded = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
        if decoded.strip():
            htmls.append(decoded)
    for part in payload.get("parts", []):
        _collect_body_parts(part, plains, htmls)


def _decode_body(payload: dict) -> str:
    """Extract body text. Prefers text/plain; falls back to stripped text/html."""
    plains, htmls = [], []
    _collect_body_parts(payload, plains, htmls)
    plain_text = "\n".join(plains).strip()
    if len(plain_text) >= 120:
        return plain_text
    if htmls:
        stripped = _strip_html("\n".join(htmls))
        if len(stripped) > len(plain_text):
            return stripped
    return plain_text


def _decode_mime_header(val: str) -> str:
    """Decode RFC 2047 encoded header values like =?UTF-8?B?...?=."""
    try:
        import email.header as _eh
        parts = _eh.decode_header(val or "")
        out = []
        for chunk, charset in parts:
            if isinstance(chunk, bytes):
                out.append(chunk.decode(charset or "utf-8", errors="replace"))
            else:
                out.append(str(chunk))
        return "".join(out)
    except Exception:
        return val or ""


def _extract_email_address(header_val: str) -> str:
    """Extract email address from 'Name <email@domain.com>' format."""
    m = re.search(r"<([^>]+)>", header_val)
    return m.group(1) if m else header_val.strip()


def _extract_attachments(payload: dict) -> list[dict]:
    """Recursively extract attachment metadata including inline (CID) images."""
    attachments = []
    for part in payload.get("parts", []):
        filename = part.get("filename", "")
        mime_type = part.get("mimeType", "")
        att_id = part.get("body", {}).get("attachmentId", "")
        size = part.get("body", {}).get("size", 0)

        # Explicit attachment (has filename) or inline image (has attachmentId + image/* MIME)
        if filename or (att_id and mime_type.startswith("image/")):
            if not filename:
                ext = mime_type.split("/")[-1].replace("jpeg", "jpg")
                filename = f"inline_image.{ext}"
            attachments.append({
                "attachment_id": att_id,
                "filename": filename,
                "mime_type": mime_type,
                "size_bytes": size,
                "inline": not bool(part.get("filename", "")),
            })
        # Recurse into nested parts
        if part.get("parts"):
            attachments.extend(_extract_attachments(part))
    return attachments


def _parse_full_msg(msg: dict) -> dict:
    """Extract all fields from a Gmail message payload including headers and attachments."""
    headers = {h["name"].lower(): h["value"] for h in msg.get("payload", {}).get("headers", [])}
    from_val = headers.get("from", "Unknown")
    from_match = re.match(r"^(.*?)\s*<(.+)>$", from_val)
    from_name = from_match.group(1).strip(' "') if from_match else from_val
    from_email = from_match.group(2) if from_match else from_val
    attachments = _extract_attachments(msg.get("payload", {}))
    return {
        "id": msg["id"],
        "from_email": from_email,
        "from_name": from_name,
        "subject": _decode_mime_header(headers.get("subject", "(No Subject)")),
        "date": headers.get("date", ""),
        "snippet": msg.get("snippet", "")[:300],
        "body": _decode_body(msg.get("payload", {})),
        "raw_headers": {k: v for k, v in headers.items()},
        "attachments": attachments,
        "is_read": "UNREAD" not in msg.get("labelIds", []),
        "has_attachments": len(attachments) > 0,
    }


def _fetch_attachment_bytes(service, message_id: str, attachment_id: str, max_bytes: int = 5 * 1024 * 1024) -> bytes:
    """Download one attachment's bytes from Gmail API. Returns empty bytes on failure."""
    try:
        att = service.users().messages().attachments().get(
            userId="me", messageId=message_id, id=attachment_id
        ).execute()
        raw = att.get("data", "")
        if not raw:
            return b""
        decoded = base64.urlsafe_b64decode(raw + "==")
        return decoded[:max_bytes]
    except Exception as e:
        logger.debug(f"[Gmail] Attachment download failed: {e}")
        return b""


async def _analyze_and_cache(msg: dict, session: dict = None) -> dict:
    """Fully analyze one Gmail message and write to cache."""
    from routers.analyze import _run_full_analysis
    from models.attachment_analyzer import analyze_attachments_with_bytes, _CONTENT_SCAN_EXTS, _ext
    from models.pii_redactor import redact_pii
    from datetime import datetime as _dt

    parsed = _parse_full_msg(msg)
    body_text = parsed['body'] or parsed['snippet']
    # Detect image-heavy / flyer emails (minimal text body, has image attachments)
    image_atts = [a for a in parsed["attachments"] if a.get("mime_type", "").startswith("image/")]
    is_flyer = len(body_text.strip()) < 200 and len(image_atts) > 0
    flyer_note = (
        f"\n\n[ANALYST NOTE: Image-heavy email — {len(image_atts)} embedded image(s) detected. "
        f"Text body is minimal ({len(body_text.strip())} chars). "
        f"This is a common phishing flyer format. Analysis relies heavily on sender authentication, "
        f"subject line, and image attachment inspection.]"
        if is_flyer else ""
    )

    email_content = (
        f"From: {parsed['from_name']} <{parsed['from_email']}>\n"
        f"Subject: {parsed['subject']}\n\n"
        f"{body_text}{flyer_note}"
    )
    # Redact PII before sending to LLM — original is kept in cache untouched
    llm_content, pii_redacted_types = redact_pii(email_content)

    try:
        full_analysis = await _run_full_analysis(llm_content, "email")
        verdict = full_analysis.get("verdict", "UNKNOWN")
        risk_score = full_analysis.get("threat_score", 0.0)
        risk_flags = [t.get("name", "") for t in full_analysis.get("detected_tactics", [])][:4]
    except Exception as e:
        logger.warning(f"[Gmail] Analysis failed for {msg['id']}: {e}")
        full_analysis = None
        verdict = "UNKNOWN"
        risk_score = 0.0
        risk_flags = []

    # ── Attachment deep scan ───────────────────────────────────────────────────
    attachments_with_data = []
    for att in parsed["attachments"]:
        entry = {**att, "data": None}
        # Only download bytes for file types worth scanning
        if session and att.get("attachment_id") and _ext(att.get("filename", "")) in _CONTENT_SCAN_EXTS:
            try:
                svc = _build_gmail_service(session)
                entry["data"] = await asyncio.get_running_loop().run_in_executor(
                    None, _fetch_attachment_bytes, svc, parsed["id"], att["attachment_id"]
                )
                logger.info(
                    f"[Gmail] Downloaded {len(entry['data'])} bytes for '{att.get('filename')}'"
                )
            except Exception as e:
                logger.debug(f"[Gmail] Byte fetch skipped for {att.get('filename')}: {e}")
        attachments_with_data.append(entry)

    try:
        attachment_analysis = analyze_attachments_with_bytes(attachments_with_data)
    except Exception as e:
        logger.warning(f"[Gmail] Attachment analysis failed for {parsed['id']}: {e}")
        attachment_analysis = {"count": 0, "max_risk": 0.0, "results": [], "verdict": "UNKNOWN", "content_scanned_count": 0}

    entry = {
        "id": parsed["id"],
        "from": parsed["from_email"],
        "from_name": parsed["from_name"],
        "subject": parsed["subject"],
        "snippet": parsed["snippet"],
        "body": parsed["body"],
        "date": parsed["date"],
        "raw_headers": parsed["raw_headers"],
        "attachments": parsed["attachments"],
        "attachment_analysis": attachment_analysis,
        "is_read": parsed["is_read"],
        "has_attachments": parsed["has_attachments"],
        "risk_score": risk_score,
        "verdict": verdict,
        "risk_flags": risk_flags,
        "full_analysis": full_analysis,
        "is_flyer": is_flyer,
        "pii_redacted": pii_redacted_types,
        "analyzed_at": _dt.utcnow().isoformat() + "Z",
    }

    # Boost risk_score if attachments are dangerous
    if attachment_analysis["max_risk"] > 0.65:
        entry["risk_score"] = min(risk_score + 0.15, 0.99)
        entry["risk_flags"] = risk_flags + [f"Dangerous attachment: {attachment_analysis['verdict']}"]

    _gmail_cache[parsed["id"]] = entry
    _save_gmail_cache()
    return entry


async def _fetch_real_inbox(session: dict, max_results: int = 10) -> list[dict]:
    """
    Fetch inbox with cache — only AI-analyze emails we haven't seen before.
    Returns cached results instantly; new emails are analyzed then cached.
    """
    loop = asyncio.get_running_loop()

    def _sync_list_and_fetch(new_ids: list) -> list:
        service = _build_gmail_service(session)
        msgs = []
        for mid in new_ids[:3]:  # Max 3 new analyses per refresh
            try:
                msg = service.users().messages().get(userId="me", id=mid, format="full").execute()
                msgs.append(msg)
            except Exception:
                continue
        return msgs

    def _sync_list_ids() -> list[str]:
        service = _build_gmail_service(session)
        result = service.users().messages().list(
            userId="me", labelIds=["INBOX"], maxResults=max_results
        ).execute()
        return [m["id"] for m in result.get("messages", [])]

    # 1. Get current message IDs (cheap list call)
    current_ids = await loop.run_in_executor(None, _sync_list_ids)

    # 2. Find IDs not yet in cache
    new_ids = [mid for mid in current_ids if mid not in _gmail_cache]
    logger.info(f"[Gmail Cache] {len(current_ids)} inbox msgs, {len(new_ids)} new to analyze")

    # 3. Fetch and analyze new emails in parallel (pass session for byte downloads)
    # return_exceptions=True prevents one failure from cancelling the others
    if new_ids:
        raw_new = await loop.run_in_executor(None, _sync_list_and_fetch, new_ids)
        if raw_new:
            results = await asyncio.gather(
                *[_analyze_and_cache(msg, session) for msg in raw_new],
                return_exceptions=True,
            )
            for i, r in enumerate(results):
                if isinstance(r, Exception):
                    mid = raw_new[i].get("id", "?")
                    logger.error(f"[Gmail] _analyze_and_cache failed for {mid}: {r}")

    # 4. Return all emails in current inbox order (from cache)
    result = []
    for mid in current_ids:
        if mid in _gmail_cache:
            result.append(_gmail_cache[mid])
    return result


# ── Demo fallback emails ──────────────────────────────────────────────────────

DEMO_EMAILS = [
    {"id": "demo_001", "from": "security@paypaI-verify.com", "from_name": "PayPal Security",
     "subject": "⚠️ Your account has been limited — Action Required",
     "snippet": "We noticed unusual activity on your account. Please verify your identity within 24 hours or your account will be suspended.",
     "date": "2026-03-27T09:12:00Z", "is_read": False, "has_attachments": False,
     "risk_score": 0.94, "verdict": "PHISHING",
     "risk_flags": ["Domain spoofing: paypaI (capital I)", "Urgency language", "No DMARC"]},
    {"id": "demo_002", "from": "noreply@github.com", "from_name": "GitHub",
     "subject": "Your pull request was merged",
     "snippet": "Congratulations! Your pull request #2847 has been merged into main.",
     "date": "2026-03-27T08:45:00Z", "is_read": True, "has_attachments": False,
     "risk_score": 0.02, "verdict": "CLEAN", "risk_flags": []},
    {"id": "demo_003", "from": "admin@secure-banking-update.xyz", "from_name": "Bank of America",
     "subject": "Important: Update your banking credentials immediately",
     "snippet": "Dear customer, your online banking access will expire unless you click below and update your information.",
     "date": "2026-03-27T07:33:00Z", "is_read": False, "has_attachments": True,
     "risk_score": 0.97, "verdict": "CONFIRMED_THREAT",
     "risk_flags": ["High-risk TLD (.xyz)", "Brand impersonation: Bank of America", "Credential harvesting"]},
    {"id": "demo_004", "from": "hr@yourcompany.com", "from_name": "HR Department",
     "subject": "Q1 2026 Performance Review Scheduled",
     "snippet": "Hi team, your Q1 performance review has been scheduled for April 3rd.",
     "date": "2026-03-26T17:20:00Z", "is_read": True, "has_attachments": True,
     "risk_score": 0.08, "verdict": "CLEAN", "risk_flags": []},
    {"id": "demo_005", "from": "support@micros0ft-helpdesk.com", "from_name": "Microsoft Support",
     "subject": "Your Microsoft 365 license expires in 2 days",
     "snippet": "Action required: Your Microsoft 365 subscription is about to expire. Click here to renew.",
     "date": "2026-03-26T14:05:00Z", "is_read": False, "has_attachments": False,
     "risk_score": 0.91, "verdict": "PHISHING",
     "risk_flags": ["Domain typosquatting: micros0ft", "Urgency: 2-day deadline", "No SPF record"]},
    {"id": "demo_006", "from": "newsletter@medium.com", "from_name": "Medium Daily Digest",
     "subject": "Your daily reading list: 5 stories picked for you",
     "snippet": "Based on your interests: The Future of AI in Healthcare, Why Rust is Replacing C++...",
     "date": "2026-03-26T08:00:00Z", "is_read": True, "has_attachments": False,
     "risk_score": 0.01, "verdict": "CLEAN", "risk_flags": []},
    {"id": "demo_007", "from": "invoice@quickbooks-billing.net", "from_name": "QuickBooks",
     "subject": "Invoice #INV-8847 requires your approval — $12,450.00",
     "snippet": "Please review and approve the attached invoice for payment processing.",
     "date": "2026-03-25T22:10:00Z", "is_read": False, "has_attachments": True,
     "risk_score": 0.76, "verdict": "SUSPICIOUS",
     "risk_flags": ["Domain mismatch from quickbooks.com", "High-value financial urgency"]},
    {"id": "demo_008", "from": "alerts@amazon.com", "from_name": "Amazon",
     "subject": "Your order #113-4859302-7 has shipped",
     "snippet": "Your order has shipped. Estimated delivery: March 29th.",
     "date": "2026-03-25T16:30:00Z", "is_read": True, "has_attachments": False,
     "risk_score": 0.03, "verdict": "CLEAN", "risk_flags": []},
]


# ── Inbox endpoint ────────────────────────────────────────────────────────────

@router.get("/inbox")
async def get_inbox(page: int = 1, limit: int = 20, risk_filter: Optional[str] = None):
    """Get inbox emails with AI risk scores. Uses real Gmail API when connected."""
    # Real OAuth token — fetch actual emails
    if _has_real_token():
        session = _get_real_session()
        try:
            all_emails = await _fetch_real_inbox(session)  # Always top 3 to control API costs
        except Exception as e:
            logger.error(f"[Gmail] Failed to fetch real inbox: {e}")
            raise HTTPException(status_code=500, detail=f"Gmail API error: {str(e)[:100]}")
    elif "demo" in _token_store:
        all_emails = DEMO_EMAILS
    else:
        raise HTTPException(status_code=401, detail="Gmail not connected.")

    # Normalise — old cache entries may be missing keys; use .get() everywhere
    for e in all_emails:
        e.setdefault("verdict", "UNKNOWN")
        e.setdefault("risk_score", 0.0)
        e.setdefault("risk_flags", [])
        e.setdefault("has_attachments", False)
        e.setdefault("is_read", True)
        e.setdefault("from_name", e.get("from", ""))
        e.setdefault("snippet", "")

    # Filter
    if risk_filter and risk_filter.upper() != "ALL":
        if risk_filter.upper() == "FLAGGED":
            all_emails = [e for e in all_emails if e.get("verdict", "UNKNOWN") not in ("CLEAN", "UNKNOWN")]
        else:
            all_emails = [e for e in all_emails if e.get("verdict", "UNKNOWN") == risk_filter.upper()]

    offset = (page - 1) * limit
    page_items = all_emails[offset: offset + limit]

    return {
        "total": len(all_emails),
        "page": page,
        "phishing_count": sum(1 for e in all_emails if e.get("verdict") in ("PHISHING", "CONFIRMED_THREAT")),
        "suspicious_count": sum(1 for e in all_emails if e.get("verdict") == "SUSPICIOUS"),
        "clean_count": sum(1 for e in all_emails if e.get("verdict") == "CLEAN"),
        "items": page_items,
        "is_demo": not _has_real_token(),
    }


@router.post("/analyze/{message_id}")
async def analyze_gmail_message(message_id: str):
    """Run full phishing analysis on a specific message."""
    from routers.analyze import _run_full_analysis
    from models.pii_redactor import redact_for_llm

    # Real OAuth: fetch message directly
    if _has_real_token():
        session = _get_real_session()
        try:
            loop = asyncio.get_event_loop()
            def _sync_get():
                service = _build_gmail_service(session)
                return service.users().messages().get(
                    userId="me", id=message_id, format="full"
                ).execute()
            msg = await loop.run_in_executor(None, _sync_get)
            headers = {h["name"].lower(): h["value"] for h in msg.get("payload", {}).get("headers", [])}
            from_val = headers.get("from", "")
            subject = headers.get("subject", "")
            body = _decode_body(msg.get("payload", {}))
            email_content = f"From: {from_val}\nSubject: {subject}\n\n{body or msg.get('snippet', '')}"
            result = await _run_full_analysis(redact_for_llm(email_content), "email")
            return {**result, "gmail_message_id": message_id}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e)[:100])

    # Demo: find in DEMO_EMAILS
    email = next((e for e in DEMO_EMAILS if e["id"] == message_id), None)
    if not email:
        raise HTTPException(status_code=404, detail=f"Message {message_id} not found")
    email_content = f"From: {email['from_name']} <{email['from']}>\nSubject: {email['subject']}\n\n{email['snippet']}"
    result = await _run_full_analysis(redact_for_llm(email_content), "email")
    return {**result, "gmail_message_id": message_id, "original_email": email}


@router.get("/message/{msg_id}")
async def get_cached_message(msg_id: str):
    """Return the full cached/analyzed email entry for use by the analyze page."""
    if msg_id in _gmail_cache:
        return _gmail_cache[msg_id]
    # Demo fallback
    demo = next((e for e in DEMO_EMAILS if e["id"] == msg_id), None)
    if demo:
        return demo
    raise HTTPException(status_code=404, detail=f"Message {msg_id} not found in cache")


@router.delete("/disconnect")
async def disconnect_gmail():
    _token_store.clear()
    try:
        if os.path.exists(TOKEN_FILE):
            os.remove(TOKEN_FILE)
    except Exception:
        pass
    return {"status": "disconnected"}
