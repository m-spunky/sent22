# SentinelAI V2 — Enhancement Plan

> Draft for review. Three independent workstreams, each self-contained.

---

## Part 1 — API Speed: Analysis Component Time Rankings & Optimizations

### 1.1 Current Pipeline Flow

```
Email submitted
      │
  LAYER 1 (parallel)
  NLP Engine (BERT + OpenRouter LLM)     ~2,000–8,000 ms
  Header Analyzer (SPF/DKIM/DMARC)          ~50–200 ms
      │
  LAYER 2 (parallel)
  URL Analyzer (WHOIS+DNS+URLhaus+PhishTank) ~1–6 s
  LLM Fingerprint Detector                ~1,500–4,000 ms
      │
  LAYER 3 (optional, default OFF)
  Visual Sandbox (Apify screenshot)          ~15–60 s
      │
  LAYER 4
  Threat Intel + IOC Enrichment           ~500–3,000 ms
  First-Contact Tracking                     ~10–50 ms
      │
  LAYER 5
  Dark Web / HIBP Check (5s timeout)      ~500–5,000 ms
      │
  Explanation Narrative (OpenRouter LLM)  ~2,000–5,000 ms
  Kill Chain Build                           ~20–100 ms
  XGBoost Fusion Predict                      ~5–20 ms
```

### 1.2 Ranked by Time Cost (Slowest → Fastest)

| Rank | Component | Typical Time | Root Cause |
|------|-----------|-------------|------------|
| 1 (SLOWEST) | **Visual Sandbox (Apify)** | 15–60 s | External actor, cold starts |
| 2 | **NLP Engine** (BERT + OpenRouter) | 2–8 s | BERT lazy-load + 2x LLM calls |
| 3 | **LLM Fingerprint Detector** | 1.5–4 s | Separate OpenRouter call |
| 4 | **Explanation Narrative** (OpenRouter) | 2–5 s | Yet another LLM call |
| 5 | **URL Analyzer** (WHOIS+DNS+URLhaus) | 1–6 s | Sequential live lookups |
| 6 | **IOC Enrichment** (ThreatFox+URLhaus+PhishTank) | 0.5–3 s | 3 external HTTP calls |
| 7 | **Dark Web / HIBP** | 0.5–5 s | External API, 5s hard timeout |
| 8 | **Header Analyzer** | 50–200 ms | Pure local parsing |
| 9 | **First-Contact Tracking** | 10–50 ms | SQLite lookup |
| 10 | **Kill Chain Build** | 20–100 ms | Pure Python dict ops |
| 11 (FASTEST) | **XGBoost Fusion Predict** | 5–20 ms | In-process sklearn |

### 1.3 Proposed Optimizations

#### A — Batch all LLM calls into ONE request (biggest win)
Currently 3 separate OpenRouter calls:
- `nlp_engine.analyze_text()` → LLM call #1
- `llm_detector.detect_llm_fingerprint()` → LLM call #2
- `generate_explanation_narrative()` → LLM call #3

**Fix:** Merge into a single structured JSON prompt returning all three payloads at once.
**Expected saving: 4–14 seconds.**

#### B — Parallelize URL Analyzer sub-tasks
`url_analyzer.py` runs WHOIS → DNS → URLhaus → PhishTank **sequentially**.
**Fix:** Use `asyncio.gather()` for all four concurrently.
**Expected saving: 2–4 seconds.**

#### C — Mandatory BERT warm-up at startup
BERT model currently lazy-loads on first inference.
**Fix:** Pre-load `bert_phishing_model.py` inside the FastAPI `lifespan()`.
**Expected saving: 2–4 s on first request.**

#### D — Hard timeouts on all external calls

| Component | Current Timeout | Proposed |
|-----------|----------------|----------|
| Dark Web / HIBP | 5 s (done) | Keep |
| IOC Enrichment | None | 3 s |
| URL WHOIS lookup | None | 4 s |
| LLM calls (OpenRouter) | None | 8 s |

#### E — TTL cache for repeat URLs/domains
Same URL analyzed twice within 15 minutes → return cached result instantly.
Use `cachetools.TTLCache` (in-process) or Redis, keyed on `sha256(url)`.

#### F — Visual Sandbox: fire-and-forget (async WebSocket delivery)
Never block the main HTTP response on Apify. Return `visual_status: "pending"` + job ID immediately. Push the result via WebSocket when Apify finishes.
**Removes 15–60 s from the user's waiting time entirely.**

### 1.4 Expected Total Time After Optimizations

| Scenario | Before | After |
|----------|--------|-------|
| Email (no visual) | 8–22 s | 2–5 s |
| Email (with visual) | 25–80 s | 2–5 s (visual delivered async) |
| URL only | 5–15 s | 1–3 s |

---

## Part 2 — Attachment Scanning: VirusTotal Integration

### 2.1 Current State
`models/attachment_analyzer.py` (~57 KB) — static heuristics only:
- Extension/MIME check, entropy scan, macro detection
- Custom execution trace generation
- **No external AV engine consensus** → high false-negative rate on obfuscated payloads

### 2.2 Proposed: VirusTotal v3 API Flow

```
User uploads file
      ↓
POST https://www.virustotal.com/api/v3/files
  File <= 32 MB → standard upload
  32–650 MB    → large file upload URL
      ↓
GET https://www.virustotal.com/api/v3/analyses/{id}
  Polling every 3s, max 30s
      ↓
Parse response:
  stats.malicious  → primary score
  stats.suspicious → secondary signal
  results[]        → per-engine verdicts (65+ AV engines)
  names[]          → malware family names
      ↓
Derive Sentinel risk score:
  vt_score   = malicious / (malicious + suspicious + undetected)
  risk_level → CRITICAL  if malicious >= 5
               HIGH      if malicious >= 2
               MEDIUM    if suspicious >= 3
               LOW       otherwise
```

### 2.3 Fallback Chain

```
VirusTotal API  →  (quota / unavailable)  →  existing static analyzer
```

### 2.4 New Response Fields Added

```json
{
  "virustotal": {
    "scan_id": "abc123",
    "permalink": "https://www.virustotal.com/gui/file/abc123",
    "detection_ratio": "3 / 72",
    "malicious_engines": ["Kaspersky", "McAfee", "Sophos"],
    "malware_families": ["Emotet", "TrickBot"],
    "file_type": "PDF",
    "first_seen_utc": "2024-01-15",
    "vt_score": 0.042,
    "risk_level": "HIGH"
  }
}
```

### 2.5 Files to Modify

| File | Change |
|------|--------|
| `backend/models/attachment_analyzer.py` | Add `scan_with_virustotal()` coroutine |
| `backend/routers/analyze.py` | Call VT first in `/analyze/attachment` handler |
| `backend/.env` | Add `VIRUSTOTAL_API_KEY=<key>` |
| `sentAi/` frontend | Show VT badge, detection ratio, engine list, permalink |

### 2.6 VirusTotal Free Tier Limits

| Limit | Value |
|-------|-------|
| Requests/day | 500 |
| Requests/minute | 4 |
| Max file size | 32 MB |

Rate-limit handling: `asyncio.sleep(15)` on HTTP 429 + automatic fallback to static analyzer.

---

## Part 3 — Browser Extensions: Gmail & Outlook Inbox-Level Threat Scoring

### 3.1 Product UX Vision

**Inbox List View** — colored score pill on every email row:

```
Gmail / Outlook Inbox
+----------------------------------------------------------+
|  PayPal Security Alert     sender@phish.xyz       [RED 87]  |
|  John - Project Update     john@company.com      [GRN  5]  |
|  AWS Invoice               noreply@aws.com       [YLW 42]  |
+----------------------------------------------------------+
    Hover pill → mini threat card popup
```

**Opened Email View** — SentinelAI banner injected at top of email body:

```
+----------------------------------------------------------+
| [RED] THREAT DETECTED   Score: 87/100   Confidence: 94%  |
|  Credential Harvesting · Urgency Manipulation            |
|  SPF FAIL · DMARC None · First-Contact Domain            |
|  URL: paypal-secure.xyz → known phishing domain          |
|  Attachment: invoice.pdf → 3/72 AV detections (VT)       |
|  [View Full Report in Sentinel]  [Mark Safe]  [Report]   |
+----------------------------------------------------------+
```

### 3.2 Architecture

```
Browser Extension (Chrome MV3 / Edge)
├── manifest.json
├── content_script.js   ← DOM injection (Gmail OR Outlook variant)
├── background.js       ← service worker, API calls, TTL cache
└── popup/              ← toolbar popup

         content_script.js
              │
    MutationObserver    → watches email rows + opened email
    Email Parser        → extracts headers, body, sender
    Badge Injector      → adds score pill per row (lazy)
    Banner Injector     → analysis banner inside email on open
              │
    chrome.runtime.sendMessage({ action:"analyze", email })
              │
         background.js
    TTLCache<emailId, result>   (15-min cache, no duplicate calls)
              │
    fetch  POST /api/v1/analyze/email
              │
    SentinelAI Backend  (existing FastAPI — localhost:8001 or cloud)
    Full 5-layer pipeline
              │
    result stored via record_analysis() → history DB
              │
    GET /api/v1/history → Sentinel Chat can recall
```

### 3.3 Gmail Extension — DOM Specifics

| Target | DOM Selector |
|--------|-------------|
| Email rows | `.zA` (conversation row) |
| Email ID | `data-legacy-message-id` attribute |
| Body content | `.a3s.aiL` div |
| Headers | Gmail OAuth API (already implemented in `routers/gmail.py`) |
| Sender | `span[email]` attribute |

### 3.4 Outlook Extension — DOM Specifics

| Target | DOM Selector |
|--------|-------------|
| Email rows | `[role="option"]` in message list |
| Email ID | `data-convid` attribute |
| Body content | `.ReadingPaneContent .allowTextSelection` |
| Target URLs | `https://outlook.live.com/*`, `https://outlook.office365.com/*` |

### 3.5 Score Badge Color Logic

| Score | Verdict | Badge |
|-------|---------|-------|
| 0–30 | SAFE | Green pill |
| 30–60 | SUSPICIOUS | Yellow pill |
| 60–85 | PHISHING | Red pill |
| 85–100 | CRITICAL | Pulsing red pill |

Hover tooltip: score + verdict + top 2 detected tactics + "Open in Sentinel" link.

### 3.6 In-Email Banner Contents

1. **Score bar** — color-coded, animated fill
2. **Explainable flags** — each detected tactic with a 1-line human explanation
3. **Layer breakdown** — NLP / Header / URL / Attachment icons with sub-scores
4. **Attachment badge** — VirusTotal detection ratio if attachment present
5. **Action buttons** — "View Full Report", "Mark Safe", "Report Phishing"
6. **Loading skeleton** — shown while analysis runs (~2–5 s after optimization)

### 3.7 Sentinel Platform Integration (Full Circle)

Every extension-triggered analysis:
1. Calls `POST /api/v1/analyze/email` (existing endpoint, zero backend changes needed)
2. Backend runs `record_analysis()` → stored in history DB (already built)
3. Stores `source: "gmail_extension"` or `source: "outlook_extension"` metadata tag
4. Accessible at `GET /api/v1/history`
5. Sentinel Chat recall: "Show me the last phishing email from my Gmail"
6. "View Full Report" in banner deep-links to Sentinel platform with `?event_id=evt_xxx`

### 3.8 Extension Build Stack

| Concern | Tool |
|---------|------|
| Build | Vite + `vite-plugin-web-extension` |
| Content scripts | Vanilla JS + CSS (minimal overhead) |
| Popup | React component |
| Packaging | `web-ext build` → Chrome + Edge .crx |
| Manifest | MV3 |

---

## Implementation Sequence

| Phase | Work | Effort |
|-------|------|--------|
| P1 | API speed (batch LLM + URL parallelism + BERT warmup + timeouts + cache) | ~1 day |
| P2 | VirusTotal attachment integration + frontend VT badge | ~1 day |
| P3a | Gmail Extension MVP (badge + banner + history link) | ~2–3 days |
| P3b | Outlook Extension (port from Gmail, Outlook DOM targets) | ~1–2 days |
| P3c | Sentinel history source-tagging + Chat recall + deep-link | ~0.5 day |

---

> Awaiting your approval before implementation begins.
> Please confirm, modify, or reject any part of this plan.
