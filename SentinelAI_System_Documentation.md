# SentinelAI Fusion — Complete System Documentation

> **Project location:** `d:\Projects\sent\root\sent\sentinel\`
> **Documented:** April 2026 | **Version:** 3.0.0

---

## 1. System Overview

**SentinelAI Fusion** is a full-stack AI-powered phishing and threat detection platform. It is built as a Security Operations Center (SOC) tool that analyzes emails, URLs, headers, attachments, and QR codes to detect phishing, malware, Business Email Compromise (BEC), and other social engineering attacks.

The system has two main runtime components:

| Component | Technology | Port | Location |
|-----------|-----------|------|----------|
| **Backend** (API server) | Python 3.11 + FastAPI | `8001` | `backend/` |
| **SentiAI** (frontend) | Next.js 16 + React 19 | `3002` | `sentiAi/` |

---

## 2. Architecture

```
Browser (localhost:3002)
         |
    SentiAI (Next.js 16)
    - Dashboard, Analyze, Inbox, Chat,
      Intelligence, Campaigns, History,
      Bulk, Sandbox, Reports
    - lib/api.ts → all REST calls
         |
    HTTP REST / WebSocket
         |
    FastAPI Backend (:8001)
    - 15 registered routers
    - Static file server (/screenshots)
         |
    5-Layer Detection Engine
    NLP → URL → Visual → Header → Intel
         |
    Fusion Engine (XGBoost override)
         |
    External APIs:
    - OpenRouter (GPT-4o, Gemma-3)
    - Google Gmail API (OAuth2)
    - Apify (Playwright screenshots)
    - Replicate (CLIP embeddings)
    - URLhaus / OTX / HIBP
```

---

## 3. Backend Deep Dive

### 3.1 Entry Point: `backend/main.py`

FastAPI starts with a **lifespan event** that pre-warms on startup:
1. **Knowledge Graph** — NetworkX graph (5 actors, 50 campaigns, 200+ domains, 100+ IPs)
2. **RAG Pipeline** — ChromaDB vector store or keyword fallback for SentinelChat
3. **XGBoost URL Classifier** — logs F1/AUC/Accuracy
4. **BERT Phishing Model** — `ealvaradob/bert-finetuned-phishing`

Then registers 15 routers and mounts a static file server at `/screenshots`.

### 3.2 Config: `backend/config.py`

All secrets loaded from `.env` via `python-dotenv`:

| Variable | Purpose |
|----------|---------|
| `OPENROUTER_API_KEY` | GPT-4o and Gemma-3 for NLP/chat |
| `REPLICATE_API_TOKEN` | CLIP visual embeddings |
| `APIFY_API_TOKEN` | Playwright website screenshots |
| `GOOGLE_CLIENT_ID/SECRET` | Gmail OAuth2 |
| `GOOGLE_REDIRECT_URI` | OAuth callback URL |
| `HIBP_API_KEY` | HaveIBeenPwned dark web checks |
| `FRONTEND_URL` | CORS and OAuth redirect |
| `PORT` | Backend port (default: 8001) |

Feature flags are auto-set:
- `VISUAL_ANALYSIS_ENABLED` — requires Apify + Replicate tokens
- `GMAIL_ENABLED` — requires Google OAuth credentials
- `RAG_ENABLED` — always True; ChromaDB/keyword fallback

---

## 4. The 5-Layer Detection Pipeline

Every analysis goes through `routers/analyze.py → _run_full_analysis()`.

### Layer 1: NLP Intent Engine (`models/nlp_engine.py`)

Analyzes text for phishing manipulation tactics.

**Three-way cascade:**
```
analyze_text(content)
    GPT-4o-mini (OpenRouter) — semantic intent
        10 MITRE tactic categories:
        urgency, authority_impersonation, financial_lure,
        credential_harvesting, suspicious_link, fear_threat,
        spoofing, reward_framing, bec_pattern, executive_impersonation

    BERT (ealvaradob/bert-finetuned-phishing)
        Binary phishing/benign probability

    Ensemble: GPT 55% + BERT 45%
    (Falls back to regex heuristics if APIs unavailable)
```

**Output:** `score`, `confidence`, `detected_tactics`, `top_phrases`, `phishing_intent`, `explanation`

### Layer 2: URL Risk Analyzer (`models/url_analyzer.py`)

Scores URLs using 150+ features, WHOIS, DNS, and threat feeds.

```
score_url(url)
    Structural: entropy, length, TLD risk, brand in domain,
                typosquatting, subdomain abuse, obfuscation
    WHOIS: domain age (newly registered = high risk)
    DNS: A record, MX, SPF, DMARC
    URLhaus API: known malicious domain check

    Rule-based score (weighted sum of 20 signals)
    XGBoost ML score (trained on TREC-2007)
    Final: Rules 60% + XGBoost 40%
```

**Top feature weights:**

| Signal | Weight |
|--------|--------|
| IP as hostname | 0.22 |
| Brand impersonation | 0.20 |
| Newly registered (<30d) | 0.20 |
| Typosquatting | 0.20 |
| Auth keywords in domain | 0.18 |
| High-risk TLD (.tk/.ml/.xyz) | 0.16 |
| URLhaus malicious hit | +0.50 boost |

### Layer 3: Visual Brand Sandbox (`models/visual_engine.py`)

Screenshots the target URL and compares visual similarity to known brand templates.

```
analyze_visual(url)
    Apify Playwright Actor → full screenshot
    Save to backend/data/screenshots/
    Replicate CLIP (openai/clip-vit-large-patch14) → embedding
    Compare to 15+ brand reference embeddings
    Returns: matched_brand, similarity(0-1), screenshot_path
```

> **OFF by default** (slow). Enable with `options: { run_visual: true }`.

### Layer 4: Header Anomaly Detector (`models/header_analyzer.py`)

Parses raw email headers and checks the authentication chain.

**Checks:**
- **SPF** — pass/fail/softfail
- **DKIM** — signature presence + auth result
- **DMARC** — policy enforcement
- **Reply-To mismatch** — Reply-To domain ≠ From domain (BEC indicator)
- **Return-Path mismatch** — similar BEC signal
- **X-Mailer anomalies** — bulk mailer fingerprints
- **Missing Message-ID / Date** — always present in legitimate email
- **Excessive routing hops** — >6 Received headers

### Layer 5: Threat Intelligence (`intelligence/`)

Correlates domains/IPs against the knowledge graph and live feeds.

```
knowledge_graph.correlate_iocs(domains, ips)
    → Cross-references 50 campaigns × their IOC lists
    → Returns matched campaigns, actors, risk_elevation (0–0.30)

ioc_feeds.enrich_iocs(domains)
    → AlienVault OTX, URLhaus, PhishTank
    → Returns malicious_domains, risk_boost, sources
```

---

## 5. Fusion Engine (`models/fusion_engine.py`)

After all 5 layers run (parallel with asyncio.gather), scores are combined:

```
fuse_scores(nlp, url, header, visual, threat_intel_boost)
    Attention weighting: score × confidence × layer_weight
    Email:   NLP 35% + URL 28% + Visual 18% + Header 19%
    URL-only: NLP 8%  + URL 55% + Visual 30% + Header 7%

    Normalize by total effective weight
    Add threat_intel_boost (up to +0.30)

    Verdict thresholds:
      SAFE:       0.00 – 0.25
      SUSPICIOUS: 0.25 – 0.55
      PHISHING:   0.55 – 0.80
      CRITICAL:   0.80 – 1.00
```

### Sentinel Fusion XGBoost (`models/sentinel_fusion_model.py`)

After heuristic fusion, a **trained XGBoost** overrides the verdict:

- **Trained on:** 6,700 TREC-2007 real emails (5,182 spam / 1,518 ham)
- **Feature vector:** 125 features from the complete pipeline output
- **Split:** 70% train / 15% val / 15% test (stratified, stratified)
- **Files:** `models/fusion_xgb.pkl` (507 KB) + `models/fusion_xgb_meta.json`

This produces the **calibrated probability** shown as the threat score to the user.

---

## 6. Supporting Modules

### `engines/kill_chain.py` — Attack Chain (PS-02/PS-03)

Maps detection results to a 4-stage attack kill chain:
1. **Initial Access** (PS-01) — Phishing delivery
2. **Credential Access** (PS-02) — Login harvesting
3. **Financial Impact** (PS-03) — Wire fraud / ATO
4. **Lateral Movement** (PS-02) — Internal spread

### `engines/credential_check.py` — Dark Web (PS-05)

HIBP API checks for domain breach history. Returns breach count, risk level, data classes exposed.

### `behavioral/bot_detector.py` — Bot Detection (PS-02)

Session signal analysis for automated/credential-stuffing patterns.

### `behavioral/fraud_correlator.py` — Fraud Correlation (PS-03)

Isolation Forest ML model linking phishing events to financial anomalies.

### `chat/sentinel_chat.py` — SentinelChat AI (PS-04)

GPT-4o SOC assistant with:
- RAG over the threat knowledge base
- Full platform context: history, Gmail inbox, active campaigns
- Response actions: block IOCs, quarantine, escalate, generate report
- 8-turn conversation memory
- Fallback rule-based responder

### `chat/rag_pipeline.py` — Vector Knowledge Store

- ChromaDB (in-memory) indexed with actors, campaigns, MITRE techniques
- Keyword fallback when ChromaDB unavailable
- ~65+ documents indexed on startup

### `intelligence/knowledge_graph.py` — NetworkX Graph

- **5 actors:** FIN7, Lazarus Group, APT28, Scattered Spider, LAPSUS$
- **50 campaigns** (2024–2026) with IOCs, timelines, targets
- **100+ IPs** with country, ASN, reputation
- **50 MITRE techniques** mapped to actors
- D3.js-compatible graph export for Intelligence Explorer
- `correlate_iocs()` — matches domains against campaign IOC lists

### `models/attachment_analyzer.py` — File Threat Scanner

Scans PDF, DOCX, Excel, scripts, archives, executables:
- Dangerous MIME types, magic bytes, macro-enabled Office docs
- Executable extensions masquerading as documents
- Text extraction → NLP analysis pipeline

### `models/pii_redactor.py` — Privacy Protection

Redacts email addresses, phone numbers, SSNs, credit cards from content before sending to LLM. Prevents data leakage to AI providers.

### `routers/gmail.py` — Gmail Integration

- Full Google OAuth2 flow
- Inbox fetching: analyzes **new** emails only (cached)
- Cache persists to `data/gmail_inbox_cache.json`
- Attachment scan: downloads + scans via `attachment_analyzer`
- Demo mode: 8 pre-labeled sample emails

### `routers/stream.py` — WebSocket Live Updates

- `WS /api/v1/stream` — real-time JSON event stream
- Pipeline emits per-layer events: `pipeline_start → nlp → header → url → visual → intel → analysis_complete`
- Frontend shows live progress bars during analysis

### `routers/reports.py` — PDF Reports

`reportlab`-based PDF generation with verdict, threat score, model breakdown, IOCs, kill chain, recommended actions.

### `routers/sandbox.py` — URL Deep Sandbox

Multi-step analysis: screenshot capture, redirect chain, domain registration deep-dive.

### `routers/quishing.py` — QR Code Phishing

`pyzbar`/`opencv` QR decode → extract embedded URL → full analysis pipeline.

### `routers/bulk.py` — CSV Batch Analysis

CSV upload, parallel asyncio processing, aggregated results per row.

---

## 7. SentiAI Frontend (`sentiAi/`)

**Stack:** Next.js 16 (App Router), React 19, TypeScript, TailwindCSS v4, Shadcn UI, Framer Motion, Recharts, D3.js

### Pages (`app/dashboard/`)

| Route | Purpose |
|-------|---------|
| `/dashboard` | KPIs, threat feed, timeline charts |
| `/dashboard/analyze` | Submit email/URL/headers |
| `/dashboard/inbox` | Gmail inbox with per-email risk scores |
| `/dashboard/chat` | SentinelChat AI assistant |
| `/dashboard/intelligence` | D3.js threat knowledge graph explorer |
| `/dashboard/campaigns` | Campaign + threat actor tracking |
| `/dashboard/history` | Analysis history + feedback loop |
| `/dashboard/bulk` | CSV batch upload |
| `/dashboard/sandbox` | Deep URL sandbox |

### API Layer (`lib/api.ts`)

All calls through `apiFetch()`:
- Prepends `NEXT_PUBLIC_API_URL` (default: `http://localhost:8001`)
- Sets `Content-Type: application/json`
- Throws user-friendly errors on HTTP failures

Key TypeScript types: `AnalysisResult`, `ModelBreakdown`, `DetectedTactic`, `ThreatIntelligence`, `DarkWebExposure`, `KillChain`, `ChatResponse`, `Campaign`, `GraphData`

---

## 8. Data Storage

| File | Purpose |
|------|---------|
| `backend/data/history.json` | Analysis history (max 1,000 entries) |
| `backend/data/gmail_token.json` | Persisted Gmail OAuth token |
| `backend/data/gmail_inbox_cache.json` | Analyzed Gmail messages cache |
| `backend/data/screenshots/` | Apify screenshots |
| `backend/models/fusion_xgb.pkl` | Trained XGBoost model (507 KB) |
| `backend/models/fusion_xgb_meta.json` | Model metadata + metrics |

---

## 9. API Endpoint Reference

### Core Analysis
| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/analyze/email` | Full 5-layer email analysis |
| POST | `/api/v1/analyze/url` | Full URL + optional visual |
| POST | `/api/v1/analyze/headers` | Header forensics |
| POST | `/api/v1/analyze/attachment` | File threat scan |
| GET | `/api/v1/events/{id}/result` | Retrieve cached result |
| GET | `/api/v1/metrics` | Model evaluation metrics |

### Threat Intelligence
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/v1/intelligence/graph` | Knowledge graph (D3.js) |
| POST | `/api/v1/intelligence/correlate` | IOC correlation |
| GET | `/api/v1/intelligence/actor/{id}` | Threat actor profile |
| GET | `/api/v1/campaigns` | All campaigns |

### Dashboard
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/v1/dashboard/metrics` | KPI counters |
| GET | `/api/v1/dashboard/feed` | Live threat events |
| GET | `/api/v1/dashboard/timeline` | Chart data |
| WS | `/api/v1/stream` | Real-time events |

### Gmail
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/v1/gmail/status` | Connection status |
| GET | `/api/v1/gmail/auth-url` | OAuth2 URL |
| GET | `/api/v1/gmail/callback` | OAuth2 callback |
| GET | `/api/v1/gmail/demo-connect` | Demo mode |
| GET | `/api/v1/gmail/inbox` | Fetch + analyze inbox |
| POST | `/api/v1/gmail/analyze/{id}` | Analyze one message |

### Other
| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/chat` | SentinelChat message |
| GET | `/api/v1/history` | Analysis history |
| POST | `/api/v1/feedback` | Analyst feedback |
| POST | `/api/v1/reports/generate` | PDF report |
| POST | `/api/v1/sandbox/analyze` | Deep URL sandbox |
| POST | `/api/v1/quishing/decode` | QR code analyze |
| POST | `/api/v1/bulk/upload` | CSV batch |
| POST | `/api/v1/response/execute` | Execute playbook |

---

## 10. Copy-Paste Path Fixes Applied

These issues existed because the project was copied from another machine. All have been corrected:

### Fix 1: `backend/.env` — Wrong Domain URLs

```diff
- FRONTEND_URL=https://sentinel4me.duckdns.org
+ FRONTEND_URL=http://localhost:3002

- GOOGLE_REDIRECT_URI=https://sentinel4me.duckdns.org/api/v1/gmail/callback
+ GOOGLE_REDIRECT_URI=http://localhost:8001/api/v1/gmail/callback
```

**Impact:** CORS would reject frontend requests; Gmail OAuth login would fail (sending user to old domain).

### Fix 2: `sentiAi/.env.local` — Empty API URLs

```diff
- NEXT_PUBLIC_API_URL=
- NEXT_PUBLIC_WS_URL=
+ NEXT_PUBLIC_API_URL=http://localhost:8001
+ NEXT_PUBLIC_WS_URL=ws://localhost:8001
```

**Impact:** Falling back to hardcoded defaults; making explicit is cleaner and avoids future confusion.

### Fix 3: `sentiAi/next.config.ts` — Missing localhost in Dev Origins

```diff
- allowedDevOrigins: ["sentinel4me.duckdns.org"]
+ allowedDevOrigins: ["sentinel4me.duckdns.org", "localhost:3002", "localhost:3000"]
```

**Impact:** Next.js dev server would throw 403 errors for localhost cross-origin requests.

### Fix 4: `backend/main.py` — Missing CORS Port 3002

```diff
  allow_origins=[
      FRONTEND_URL,
      "http://localhost:3000",
      "http://localhost:3001",
+     "http://localhost:3002",
      ...
  ]
```

**Impact:** API calls from the frontend (port 3002) would be rejected by the backend CORS middleware.

---

## 11. How to Run Locally

### Backend
```powershell
cd d:\Projects\sent\root\sent\sentinel\backend
pip install -r requirements.txt
python main.py
# Swagger UI: http://localhost:8001/docs
# Health check: http://localhost:8001/health
```

### Frontend
```powershell
cd d:\Projects\sent\root\sent\sentinel\sentiAi
npm install
npm run dev
# Opens: http://localhost:3002
```

---

## 12. Key Data Flows

### Email Analysis Flow
```
User pastes email text
  → POST /api/v1/analyze/email
    → asyncio.gather(NLP, Header analysis) [parallel]
    → URL analysis (WHOIS + DNS + URLhaus)
    → [optional] Visual analysis (Apify + CLIP)
    → Threat intel (graph + OTX/URLhaus feeds)
    → Dark web check (HIBP)
    → fuse_scores() → heuristic verdict
    → generate_explanation_narrative() [GPT-4o-mini]
    → build_kill_chain()
    → predict_fusion() [XGBoost override]
    → record_analysis() [history.json]
    → emit WebSocket event [live feed]
  ← AnalysisResult JSON with full breakdown
```

### Gmail Inbox Flow
```
"Connect Gmail" → GET /api/v1/gmail/auth-url
  → Google OAuth consent
  → GET /api/v1/gmail/callback?code=...
    → Token exchange → store to memory + gmail_token.json
    → Redirect to /dashboard/inbox?connected=true

View inbox → GET /api/v1/gmail/inbox
  → Gmail API: list message IDs
  → For each NEW message:
    → Fetch full message (MIME)
    → Parse headers + body
    → Redact PII
    → Run full 5-layer analysis
    → Download + scan attachments
    → Save to gmail_inbox_cache.json
  → Return cached entries
```

### SentinelChat Flow
```
User message → POST /api/v1/chat
  → RAG retrieval (ChromaDB / keyword search)
  → Build platform context (history + Gmail + campaigns)
  → POST to OpenRouter GPT-4o:
      system: SENTINELCHAT_SYSTEM_PROMPT
      user: [RAG context] + [platform state] + [query]
  → Extract sources, suggested actions, followups
  ← response, sources, suggested_actions, followups
```

---

## 13. PS Coverage Summary

| PS | Domain | Coverage |
|----|--------|----------|
| **PS-01** | AI Phishing Detection | 5-layer ensemble, Gmail, QR/bulk/attachment |
| **PS-02** | Bot/Credential Stuffing | `bot_detector.py`, kill chain Stage 2 |
| **PS-03** | Financial Fraud | `fraud_correlator.py`, kill chain Stage 3, BEC |
| **PS-04** | Security Chatbot | SentinelChat (GPT-4o + RAG) |
| **PS-05** | Dark Web Monitoring | HIBP in every analysis |

---

*SentinelAI Fusion v3.0.0 — System Documentation*
