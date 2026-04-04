# SentinelAI V2 — Gmail Extension: Detailed Specification

> Refined plan based on approval of V1 draft.
> Focus: Real-time inbox overlays + Extension detail screen + URL sandbox + Full Sentinel integration.

---

## 1. Overview & UX Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    COMPLETE USER JOURNEY                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [STEP 1] User opens Gmail in Chrome                           │
│           Extension content_script.js auto-injects             │
│           MutationObserver watches for email rows               │
│                    ↓                                            │
│  [STEP 2] Score pill appears on EACH email row (real-time)     │
│           Fetched lazily as rows render                         │
│           Shows: colored score + verdict badge                  │
│                    ↓                                            │
│  [STEP 3] User HOVERS the pill                                 │
│           Mini popup: score, top 2 flags, quick actions         │
│                    ↓                                            │
│  [STEP 4] User CLICKS "Detailed"                               │
│           Extension side panel opens (chrome.sidePanel API)    │
│           Shows: Full analysis + ALL urls + attachments         │
│           User can click any URL → Sandbox it live              │
│                    ↓                                            │
│  [STEP 5] User OPENS the email                                 │
│           If SUSPICIOUS/PHISHING/CRITICAL → Banner injected     │
│           inside email body at the top automatically            │
│                    ↓                                            │
│  [STEP 6] User clicks "View Full Report in Sentinel"           │
│           Opens platform tab: /analyze?event_id=evt_xxx         │
│           Full multi-layer analysis visible + Sentinel Chat     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Speed Strategy: How Real-Time Is Achieved

The main challenge is making the inbox overlay feel **instant**.

### 2.1 Two-Phase Analysis

```
PHASE 1: FAST (< 1 second) — shown immediately on inbox row
──────────────────────────────────────────────────────────
  Data used:    sender domain + subject line only
  API called:   POST /api/v1/analyze/quick
  New endpoint: lightweight — NLP on subject only + URLhaus
                header SPF check + first-contact lookup
  Returns:      { score, verdict, confidence }

PHASE 2: FULL (2–5 seconds) — loaded in background
──────────────────────────────────────────────────────────
  Data used:    full email body + headers + attachments
  API called:   POST /api/v1/analyze/email (existing)
  VT scan:      POST https://www.virustotal.com/api/v3/files
                (for each attachment)
  Returns:      complete 5-layer result + VT scores + URLs
```

### 2.2 Caching in Extension background.js

```
TTLCache:  Map<gmail_message_id, {phase1_result, phase2_result}>
TTL:       15 minutes
On reload: Cache persists via chrome.storage.session
```

Consequence: **each email is analyzed only once per 15 minutes**, even if the user refreshes Gmail or re-opens the extension.

---

## 3. Score Badge (Inbox Row Overlay)

### 3.1 Visual Design

```
Gmail Inbox Row (BEFORE extension):
 ┌──────────────────────────────────────────────────────────┐
 │  PayPal Security Alert     sender@phish.xyz   3 hours    │
 └──────────────────────────────────────────────────────────┘

Gmail Inbox Row (AFTER extension injects badge):
 ┌──────────────────────────────────────────────────────────┐
 │  PayPal Security Alert   sender@phish.xyz   3h  [● 87]  │
 └──────────────────────────────────────────────────────────┘
                                                    ↑
                              Pill: color-coded, score number
```

### 3.2 Badge States

| State | Color | Display |
|-------|-------|---------|
| Loading (Phase 1 pending) | Gray pulsing | `...` |
| SAFE (0–30) | Green `#22c55e` | `● 12` |
| SUSPICIOUS (30–60) | Amber `#f59e0b` | `● 45` |
| PHISHING (60–85) | Red `#ef4444` | `● 78` |
| CRITICAL (85–100) | Pulsing deep red `#b91c1c` | `● 94 ⚠` |

### 3.3 Hover Tooltip (Mini Card)

```
┌──────────────────────────────────────────────┐
│  🔴 PHISHING  Score: 87/100                  │
│  ─────────────────────────────────────────── │
│  ⚠ Credential Harvesting                    │
│  ⚠ First-Contact Domain                     │
│                                              │
│  Attachment: invoice.pdf  [3/72 VT engines]  │
│                                              │
│  [Detailed Analysis]  [Mark Safe]            │
└──────────────────────────────────────────────┘
```

---

## 4. Extension Side Panel (Detail Screen)

Triggered by clicking "Detailed Analysis" on the hover card.
Uses `chrome.sidePanel.open()` (Chrome MV3).

### 4.1 Sections in the Side Panel

```
┌─────────────────────────────────────────────────────┐
│  SENTINEL AI  [● PHISHING 87/100]  [✕ Close panel] │
├─────────────────────────────────────────────────────┤
│                                                     │
│  SCORE BREAKDOWN                                    │
│  ████████░░  NLP Content         78%               │
│  ███░░░░░░░  Email Headers       32%               │
│  ██████░░░░  URL Analysis        63%               │
│  ██████████  Attachment (VT)     91%               │
│                                                     │
├─────────────────────────────────────────────────────┤
│  DETECTED THREATS                                   │
│  ⚠ Credential Harvesting (T1056)  HIGH             │
│  ⚠ Urgency Manipulation           MEDIUM           │
│  ⚠ Brand Impersonation: PayPal    HIGH             │
│  ⚠ First-Contact Domain           HIGH             │
│                                                     │
├─────────────────────────────────────────────────────┤
│  ATTACHMENTS                                        │
│  📎 invoice.pdf   532 KB                           │
│     VirusTotal: 3/72 engines detected              │
│     Engines: Kaspersky, McAfee, Sophos             │
│     Family: Emotet                                 │
│     [🔗 View on VirusTotal]                        │
│                                                     │
├─────────────────────────────────────────────────────┤
│  EXTRACTED URLS (from email body)                   │
│  ─────────────────────────────────────────────────  │
│  1. https://paypal-secure.xyz/login                │
│     [● 89 PHISHING]  [Sandbox ▶]                  │
│                                                     │
│  2. https://tinyurl.com/3ab4cd                     │
│     [● 45 SUSPICIOUS] [Sandbox ▶]                 │
│                                                     │
│  3. https://legitimate-cdn.com/image.png           │
│     [● 5 SAFE]       [Sandbox ▶]                  │
│                                                     │
├─────────────────────────────────────────────────────┤
│  [🌐 View Full Report in Sentinel Platform]         │
│  [💬 Ask Sentinel Chat about this email]           │
│  [🚩 Report Phishing]  [✅ Mark as Safe]           │
└─────────────────────────────────────────────────────┘
```

### 4.2 URL Sandbox Panel (Inline in Side Panel)

When user clicks "Sandbox ▶" on any URL:

```
┌─────────────────────────────────────────────────────┐
│  SANDBOXING: https://paypal-secure.xyz/login        │
│  ──────────────────────── Loading ●●●               │
├─────────────────────────────────────────────────────┤
│  [Screenshot of the page]                           │
│  ┌───────────────────────────────────────────────┐  │
│  │    FAKE PAYPAL LOGIN PAGE                     │  │
│  │    [Username:  ___________________]           │  │
│  │    [Password:  ___________________]           │  │
│  │    [       LOG IN SECURELY       ]           │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  Redirect chain:  tinyurl.com → paypal-secure.xyz   │
│  SSL:  Invalid — self-signed certificate            │
│  Credential form: YES (password field detected)     │
│  Sandbox verdict: 🔴 PHISHING (score: 0.89)        │
│  Suspicious keywords: login, verify, confirm, bank  │
│                                                     │
│  [← Back to URL list]  [🔗 View full sandbox]      │
└─────────────────────────────────────────────────────┘
```

Backend called: `POST /api/v1/sandbox/analyze` (existing endpoint, depth: "deep")
Screenshot: Apify (fire-and-forget, shown when ready via polling)

---

## 5. In-Email Warning Banner (Auto-Injected)

When user opens a SUSPICIOUS / PHISHING / CRITICAL email:

```
Gmail Email View (top of email body):

┌────────────────────────────────────────────────────────────────┐
│ 🔴 SentinelAI — PHISHING DETECTED                             │
│                                                                │
│  Threat Score: 87/100   Confidence: 94%                       │
│                                                                │
│  ⚠ Credential Harvesting — This email attempts to steal       │
│    your login credentials via a fake PayPal page.             │
│                                                                │
│  ⚠ Brand Impersonation — Sender impersonates PayPal but        │
│    domain is paypal-secure.xyz (not paypal.com)               │
│                                                                │
│  ⚠ Dangerous Attachment — invoice.pdf detected by             │
│    3 out of 72 antivirus engines on VirusTotal                │
│                                                                │
│  ⚠ Suspicious Link — paypal-secure.xyz redirects to a        │
│    credential harvesting form.                                 │
│                                                                │
│  [📊 View Full Report]  [✅ Mark Safe]  [🚩 Report]           │
└────────────────────────────────────────────────────────────────┘
[... original email content below ...]
```

Banner is **ONLY shown** for verdict: SUSPICIOUS / PHISHING / CRITICAL.
SAFE emails: no banner, no interference.

---

## 6. Backend: New Endpoint Needed

### 6.1 New: Quick Analysis Endpoint (Phase 1 Speed)

```
POST /api/v1/analyze/quick

Request:
{
  "subject": "Your account has been limited",
  "sender": "security@paypaI-verify.com",
  "snippet": "We noticed unusual activity..."
}

Pipeline (parallel, targeting < 800ms total):
  - NLP on subject+snippet only (no BERT, heuristic only)
  - URLhaus blocklist check on sender domain
  - First-contact tracking on sender domain
  - SPF/DMARC record check (DNS only)

Response:
{
  "score": 0.87,
  "verdict": "PHISHING",
  "confidence": 0.78,
  "quick_flags": ["Domain spoofing", "First-contact domain"],
  "phase": "quick"
}
```

### 6.2 Existing Endpoints Used by Extension

| Action | Backend Endpoint | Status |
|--------|-----------------|--------|
| Quick inbox score | `POST /api/v1/analyze/quick` | NEW |
| Full email analysis | `POST /api/v1/analyze/email` | Existing |
| URL sandbox (fast) | `POST /api/v1/sandbox/analyze` | Existing |
| URL sandbox (visual) | `POST /api/v1/sandbox/analyze` depth=deep | Existing (Apify) |
| History save | Auto (inside `_run_full_analysis`) | Existing |
| Retrieve analysis | `GET /api/v1/gmail/message/{id}` | Existing |
| Get history | `GET /api/v1/history` | Existing |
| VT attachment scan | Via `POST /api/v1/analyze/attachment` | NEW (VT integration) |

---

## 7. Sentinel Platform Integration (Deep)

### 7.1 Every Extension Analysis → Saved to Platform

```python
# In record_analysis() — add source metadata
record_analysis(result, input_type, preview, source="gmail_extension")
```

New `source` field stored in history allows:
- Filter by source in History tab: "Gmail Extension" / "Platform" / "Bulk"
- Sentinel Chat recall: "Show all threats from my Gmail last week"
- Deep-link from extension: `/analyze?event_id=evt_xxx`

### 7.2 Sentinel Chat Integration

The extension side panel includes a "Ask Sentinel Chat" button that:
1. Opens the Sentinel platform chat tab
2. Pre-fills prompt: `"Analyze the phishing email from paypaI-verify.com with event ID evt_abc123"`
3. Chat uses `GET /api/v1/history` RAG context to answer

### 7.3 History Enrichment Fields

```json
{
  "event_id": "evt_abc123",
  "source": "gmail_extension",
  "gmail_message_id": "18f8a2b3c4d5e6f7",
  "gmail_subject": "Your account has been limited",
  "gmail_sender": "security@paypaI-verify.com",
  "urls_extracted": ["https://paypal-secure.xyz/login", "https://tinyurl.com/3ab"],
  "attachments_scanned": [
    { "filename": "invoice.pdf", "vt_score": 0.042, "detection_ratio": "3/72" }
  ],
  "sandbox_results": {},
  "timestamp": "2026-04-04T04:00:00Z"
}
```

---

## 8. Extension File Structure

```
sentinel-gmail-extension/
├── manifest.json              MV3, Gmail permissions
├── background/
│   └── background.js          Service worker: API calls, TTL cache
├── content/
│   ├── gmail_content.js       Main content script for Gmail DOM
│   ├── badge_injector.js      Score pill injection per email row
│   ├── banner_injector.js     Warning banner inside opened email
│   └── content.css            Styles for pill + banner
├── sidepanel/
│   ├── sidepanel.html         Extension side panel shell
│   ├── sidepanel.js           Side panel logic: analysis, URLs, sandbox
│   └── sidepanel.css          Side panel styles (dark theme, Sentinel-like)
├── popup/
│   ├── popup.html             Extension toolbar popup (status, settings)
│   └── popup.js
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── shared/
    ├── api.js                 API helper (fetch wrappers, base URL config)
    └── utils.js               Score → color, verdict → label
```

### 8.1 manifest.json Key Permissions

```json
{
  "manifest_version": 3,
  "name": "SentinelAI — Phishing Guard",
  "version": "1.0.0",
  "permissions": [
    "storage",
    "sidePanel",
    "identity"
  ],
  "host_permissions": [
    "https://mail.google.com/*",
    "http://localhost:8001/*",
    "https://<your-cloud-backend>/*"
  ],
  "content_scripts": [{
    "matches": ["https://mail.google.com/*"],
    "js": ["content/gmail_content.js", "content/badge_injector.js", "content/banner_injector.js"],
    "css": ["content/content.css"],
    "run_at": "document_idle"
  }],
  "background": {
    "service_worker": "background/background.js"
  },
  "side_panel": {
    "default_path": "sidepanel/sidepanel.html"
  },
  "action": {
    "default_popup": "popup/popup.html",
    "default_icon": "icons/icon48.png"
  }
}
```

---

## 9. Gmail DOM Selectors (Current as of 2026)

| Target | Selector | Notes |
|--------|----------|-------|
| Email list rows | `.zA` | Each conversation thread row |
| Email message ID | `[data-legacy-message-id]` | Unique per message |
| Opened email body | `.a3s.aiL` | Main readable body div |
| Sender email | `span[email]` attribute | Inside header |
| Subject in list | `.bog` or `.bqe` | Subject text span |
| Attachment area | `.aQH` | Attachment chip container |
| New row added | MutationObserver on `.AO` | Gmail inbox list container |

---

## 10. Implementation Phases

| Phase | Deliverable | Effort |
|-------|-------------|--------|
| **B1** | New backend endpoint `POST /api/v1/analyze/quick` | 0.5 day |
| **B2** | VirusTotal attachment integration in `/analyze/attachment` | 1 day |
| **B3** | History `source` field + deep-link support `?event_id=` | 0.5 day |
| **E1** | Extension scaffold (manifest + background service worker) | 0.5 day |
| **E2** | Score badge injection on inbox rows (Phase 1 quick scoring) | 1 day |
| **E3** | Hover tooltip mini card | 0.5 day |
| **E4** | Side panel: full analysis + extracted URLs | 1 day |
| **E5** | Side panel: inline URL sandbox with screenshot | 1 day |
| **E6** | In-email warning banner (auto-inject on open) | 0.5 day |
| **E7** | "View Full Report" + "Ask Sentinel Chat" deep-link buttons | 0.5 day |
| **T1** | End-to-end test: inbox → badge → panel → sandbox → platform | 0.5 day |

**Total: ~7 days for complete Gmail extension + backend wiring**

---

> Awaiting your go-ahead. Recommend starting with B1 (quick endpoint) + E1 + E2 as the first working demo.
