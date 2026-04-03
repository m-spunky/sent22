"""
PII Redactor — strips sensitive personal data before sending email content to LLM APIs.

Replaces in-place:
  Email addresses        → [EMAIL]
  Phone numbers          → [PHONE]
  Credit card patterns   → [CARD]
  SSN patterns           → [SSN]
  Names in From/To/Cc headers → [NAME]

The original email is stored locally in cache untouched; only the LLM-bound
copy is sanitised.
"""
import re

# ── Patterns ──────────────────────────────────────────────────────────────────

# Standard email addresses
_EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')

# Phone: US/intl — +1 (555) 123-4567 / 555.123.4567 / 5551234567
_PHONE_RE = re.compile(
    r'(?<!\d)'
    r'(\+?1[\s.\-]?)?'
    r'(\(?\d{3}\)?[\s.\-]?)'
    r'(\d{3}[\s.\-]?)'
    r'(\d{4})'
    r'(?!\d)'
)

# Credit card: formatted groups like 4111 1111 1111 1111 or 4111-1111-1111-1111
_CARD_RE = re.compile(
    r'\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{1,4}\b'
    r'|\b\d{4}[\s\-]\d{6}[\s\-]\d{5}\b'   # Amex: 3782-822463-10010
)

# SSN: NNN-NN-NNNN or NNN NN NNNN
_SSN_RE = re.compile(r'\b\d{3}[\s\-]\d{2}[\s\-]\d{4}\b')

# Header names: "From: John Doe <..." — captures the display name before the angle bracket
_HEADER_NAME_RE = re.compile(
    r'^(From|To|Cc|Reply-To):\s+([^<\n\[]+?)\s*(?=<)',
    re.MULTILINE | re.IGNORECASE,
)


# ── Public API ─────────────────────────────────────────────────────────────────

def redact_pii(text: str) -> tuple[str, list[str]]:
    """
    Redact PII from *text*.
    Returns (redacted_text, list_of_unique_pii_types_found).
    Order matters: SSN before phone, card before email.
    """
    found: list[str] = []

    def _sub(pattern, replacement, label):
        nonlocal text
        new, n = pattern.subn(replacement, text)
        if n:
            found.append(label)
        text = new

    _sub(_SSN_RE,  "[SSN]",   "SSN")
    _sub(_CARD_RE, "[CARD]",  "CARD")
    _sub(_PHONE_RE, "[PHONE]", "PHONE")

    # Header display names
    new_text = _HEADER_NAME_RE.sub(lambda m: f"{m.group(1)}: [NAME] ", text)
    if new_text != text:
        found.append("NAME")
    text = new_text

    new_text = _EMAIL_RE.sub("[EMAIL]", text)
    if new_text != text:
        found.append("EMAIL")
    text = new_text

    return text, list(dict.fromkeys(found))  # deduplicated, insertion-ordered


def redact_for_llm(text: str) -> str:
    """Convenience wrapper — returns only the redacted text."""
    redacted, _ = redact_pii(text)
    return redacted
