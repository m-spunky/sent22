# SENTINEL — System Documentation
### AI-Powered Multi-Vector Phishing Detection & Threat Intelligence Platform

> **Version**: 1.0 | **Date**: April 2026 | **Classification**: Internal Technical Documentation

---

## Table of Contents

1. [Problem Statement & Pain Points](#1-problem-statement--pain-points)
2. [Solution Overview](#2-solution-overview)
3. [System Architecture](#3-system-architecture)
   - [3.1 Backend — Core Analysis Engine](#31-backend--core-analysis-engine)
   - [3.2 Frontend — Real-Time Monitoring Dashboard](#32-frontend--real-time-monitoring-dashboard)
   - [3.3 Browser Extension — Gmail & Outlook](#33-browser-extension--gmail--outlook)
   - [3.4 WhatsApp & Telegram Bots](#34-whatsapp--telegram-bots)
   - [3.5 SentinelChat — Conversational Threat AI](#35-sentinelchat--conversational-threat-ai)
   - [3.6 Threat Intelligence Layer](#36-threat-intelligence-layer)
   - [3.7 Data Flow & System Connectivity](#37-data-flow--system-connectivity)
4. [Feasibility Analysis](#4-feasibility-analysis)
5. [Business Model](#5-business-model)
6. [Future Scope](#6-future-scope)

---

## 1. Problem Statement & Pain Points

### Base Challenge (PS-01)
The competition problem asks for an AI-powered phishing detection system that can:
- Detect modern phishing across emails, URLs, and attachments **in real time**
- Go beyond static rules to identify **AI-generated phishing** and **multi-stage attacks**
- Understand how attacks **evolve behaviorally**, not just syntactically
- **Explain every detection decision** clearly and trustworthily

### The Real-World Gap

#### 1.1 Attackers Have Industrialized
Modern phishing is no longer a lone criminal sending bad grammar emails. Today's attacks are:
- **LLM-generated**: Grammatically perfect, contextually aware, and indistinguishable from legitimate correspondence by naive filters
- **Polymorphic**: Each email in a campaign is slightly mutated to evade signature-based detection
- **Multi-stage**: An email leads to a landing page that leads to a credential stealer that leads to a wire transfer — existing tools only catch Stage 1
- **QR-code weaponized ("Quishing")**: Security gateways scan URLs in text, so attackers embed URLs inside QR code images attached to emails — a blind spot for legacy tools

#### 1.2 Defenders Are Blind
| Pain Point | Impact |
|------------|--------|
| Reactive tooling (rule-based blocklists) | Can't stop zero-day phishing campaigns |
| Single-vector analysis (email body only) | Misses header manipulation, visual brand spoofing, payload staging |
| Zero explainability | SOC analysts can't trust or tune black-box verdicts |
| Siloed email clients | Gmail plug-ins don't work in Outlook; mobile users are unprotected |
| No cross-threat correlation | A phishing email linked to a known APT28 campaign looks like an isolated incident |
| Analyst bottleneck | Analysts spend 60%+ of time on triage, not investigation |

#### 1.3 Compounding Problem Vectors (Brownie Points Addressed)
The platform also addresses:
- **PS-02 — Bot & Credential Stuffing**: The aftermath of phishing is automated credential abuse; detecting the attack without detecting what follows is half a solution
- **PS-03 — Fraud Detection**: Credential theft leads to fraudulent transactions; Sentinel closes the kill chain
- **PS-04 — Security Chatbot**: Analysts need instant, context-aware intelligence, not another dashboard to read
- **PS-05 — Dark Web Monitoring**: Compromised credentials end up on dark web forums; early detection enables pre-emptive action

#### 1.4 User Pain Summary
- **Individual Users**: Don't know when they're targeted; mobile/messaging apps have zero protection
- **SOC Analysts**: Drowning in alerts with no prioritization, no narrative, and no attribution
- **Enterprises**: Can't quantify risk, produce audit trails, or map incidents to threat campaigns
- **Security Teams**: No unified view across email, messaging, URLs, and attachments

---

## 2. Solution Overview

Sentinel is a **unified, multi-interface threat detection platform** built on a single central AI analysis API. Every interface — browser extension, web dashboard, WhatsApp bot, Telegram bot — is a window into the same 5-layer detection engine.

### Core Thesis
> Detection is only as good as its **worst-case input**. Sentinel is designed to extract signal even when the attacker optimizes every other vector.

### What Sentinel Delivers

| Requirement | Sentinel's Answer |
|-------------|-------------------|
| Content analysis | NLP engine with MITRE ATT&CK tactic mapping |
| Behavioral analysis | Bot detection + kill chain progression scoring |
| Multi-stage attack detection | Email → URL → Payload chain tracking |
| Attachment analysis | QR decode + Apify sandbox screenshot + CLIP visual similarity |
| Explainability | SHAP feature attribution + LLM narratives + model transparency panel |
| Real-time detection | WebSocket streaming pipeline + sub-500ms quick-tier |
| Cross-vector analysis | 5-layer attention-weighted fusion engine |
| AI phishing detection | LLM fingerprinting (perplexity, pattern entropy analysis) |
| Campaign clustering | Knowledge graph with 50+ active/historical campaigns |
| Sandbox simulation | Apify Playwright screenshot + CLIP brand similarity |
| Multi-interface access | Web + Extension (Gmail/Outlook) + WhatsApp + Telegram |
| Conversational querying | SentinelChat — RAG-powered AI assistant |

### Verdicts Produced
Every analysis returns one of four verdicts with a fusion score (0–100):

| Verdict | Score Range | Action |
|---------|-------------|--------|
| SAFE | 0–25 | Monitor |
| SUSPICIOUS | 25–55 | Flag for review |
| PHISHING | 55–80 | Quarantine & block |
| CRITICAL | 80–100 | Quarantine, block & alert |

---

## 3. System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        USER INTERFACES                               │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  ┌──────────┐  │
│  │ Chrome Ext.  │  │  Web Dashboard│  │ WhatsApp  │  │ Telegram │  │
│  │ Gmail/Outlook│  │  (Next.js)   │  │    Bot    │  │   Bot    │  │
│  └──────┬───────┘  └──────┬───────┘  └─────┬─────┘  └────┬─────┘  │
└─────────┼─────────────────┼────────────────┼──────────────┼────────┘
          │                 │                │              │
          └─────────────────┴────────┬───────┘              │
                                     │ REST API / WebSocket  │
                        ┌────────────▼──────────────────────┘
                        │     CENTRAL API (FastAPI, Port 8001)        │
                        │                                              │
                        │  ┌────────────────────────────────────────┐  │
                        │  │         5-LAYER FUSION ENGINE          │  │
                        │  │  NLP │ URL │ Header │ Visual │ Intel   │  │
                        │  └────────────────────────────────────────┘  │
                        │  ┌────────────┐  ┌──────────────────────┐   │
                        │  │ Kill Chain │  │  Threat Intel Graph  │   │
                        │  │  Analyzer  │  │  (5 Actors, 50 Camp) │   │
                        │  └────────────┘  └──────────────────────┘   │
                        │  ┌──────────────────────────────────────┐   │
                        │  │    SentinelChat (RAG + ChromaDB)     │   │
                        │  └──────────────────────────────────────┘   │
                        └──────────────────────────────────────────────┘
                                     │
                    ┌────────────────┼─────────────────┐
                    │                │                  │
              ┌─────▼──────┐ ┌──────▼─────┐ ┌─────────▼──────┐
              │ OpenRouter │ │  Replicate  │ │     Apify      │
              │ (GPT-4o)   │ │   (CLIP)   │ │  (Screenshot)  │
              └────────────┘ └────────────┘ └────────────────┘
```

---

### 3.1 Backend — Core Analysis Engine

**Location**: `backend/`  
**Framework**: FastAPI 0.115.6 (Python, async)  
**Port**: 8001

#### Architecture Diagram

```
backend/
├── main.py                    ← App entry, lifespan init, CORS
├── config.py                  ← Feature flags & env config
├── routers/
│   ├── analyze.py             ← Core analysis endpoints
│   ├── gmail.py               ← Gmail OAuth2 integration
│   ├── bulk.py                ← CSV batch processing
│   ├── campaigns.py           ← Campaign & actor intelligence
│   ├── history.py             ← Analysis history & stats
│   ├── dashboard.py           ← Metrics & KPI aggregation
│   ├── reports.py             ← PDF report generation
│   └── chat.py                ← SentinelChat endpoint
├── models/
│   ├── nlp_engine.py          ← NLP intent detection (Layer 1)
│   ├── url_analyzer.py        ← URL risk analysis (Layer 2)
│   ├── header_analyzer.py     ← Email auth analysis (Layer 3)
│   ├── visual_engine.py       ← Brand impersonation (Layer 4)
│   ├── fusion_engine.py       ← Attention-weighted ensemble
│   └── sentinel_fusion_model.py ← Intel correlation (Layer 5)
├── behavioral/
│   ├── bot_detector.py        ← Credential stuffing detection
│   └── fraud_correlator.py    ← Transaction anomaly analysis
├── engines/
│   └── kill_chain.py          ← Multi-stage attack progression
├── intelligence/
│   ├── knowledge_graph.py     ← NetworkX threat actor graph
│   └── feed_ingester.py       ← ThreatFox/URLhaus/PhishTank
└── chat/
    └── rag_pipeline.py        ← ChromaDB RAG for SentinelChat
```

#### Layer 1 — NLP Intent Engine (`models/nlp_engine.py`)

Performs semantic analysis of email/message content to detect psychological manipulation patterns.

**Model**: Google Gemma-3-12b-it via OpenRouter (heuristic fallback if unavailable)

**Detects 9 Phishing Tactics** with MITRE ATT&CK mappings:

| Tactic | MITRE ID | Pattern Example |
|--------|----------|-----------------|
| Urgency / Account Suspension | T1566.001 | "Your account will be closed in 24 hours" |
| Authority Impersonation | T1656 | "From the CEO's office..." |
| Financial Lure | T1078 | "You have unclaimed funds of $4,200" |
| Credential Harvesting | T1056.003 | "Verify your password to continue" |
| Suspicious Links | T1204.001 | Mismatched display vs actual URLs |
| Fear / Threat | T1585 | "Legal action will be taken unless..." |
| Spoofing | T1566.002 | Domain lookalikes in sender field |
| Reward Framing | T1585.002 | "You've been selected for a prize" |
| BEC Pattern | T1534 | Wire transfer / invoice redirect |

**Output**: `{ intent_score: 0.87, tactics: [...], suspicious_phrases: [...], mitre_techniques: [...] }`

**LLM Fingerprinting (Bonus)**: Detects AI-generated phishing via perplexity scoring and vocabulary entropy — catches attackers who used GPT/Claude to write convincing lures.

#### Layer 2 — URL Risk Analyzer (`models/url_analyzer.py`)

Performs 150+ feature extraction on URLs with SHAP-style contribution attribution.

**Feature Categories**:

| Category | Features |
|----------|----------|
| Domain | IP-as-hostname, brand impersonation, auth-in-domain, newly registered, risky TLD |
| Structure | URL length, subdomain depth, high-entropy domain, typosquatting detection |
| Encoding | Hex/Unicode encoding, @ symbol abuse, redirect chain depth |
| Real WHOIS | Domain age, registrar, privacy protection |
| Real DNS | A records, MX, SPF/DMARC presence |

**External Resolution**: Live WHOIS (python-whois) + DNS lookups (dnspython) for registration freshness signals.

**Output**: `{ url_risk_score: 0.72, top_features: [{feature, contribution}...], shap_values: {...} }`

#### Layer 3 — Email Header Analyzer (`models/header_analyzer.py`)

Detects authentication and routing manipulation in raw email headers.

**Checks Performed**:
- SPF: pass / fail / softfail / neutral
- DKIM: signature validation
- DMARC: policy alignment (reject/quarantine/none)
- Reply-To ≠ From domain mismatch
- X-Originating-IP inconsistency with claimed sender domain
- Suspicious routing hop patterns

**Output**: `{ header_score: 0.65, flags: [spf_fail, reply_to_mismatch, ...] }`

#### Layer 4 — Visual Brand Engine (`models/visual_engine.py`)

Detects brand impersonation via screenshot-based visual similarity.

**Pipeline**:
```
URL → Apify Playwright (screenshot) → Replicate CLIP (embedding)
    → Cosine similarity vs 20 brand templates → Brand match + confidence
```

**Supported Brands** (20): Microsoft, Google, PayPal, Apple, Amazon, Chase, Bank of America, Wells Fargo, Citibank, Netflix, Dropbox, DocuSign, LinkedIn, Facebook, Instagram, Twitter, Zoom, Slack, GitHub, Adobe

**Fallback**: Zero-shot CLIP classification if screenshot fails.

**Output**: `{ visual_score: 0.91, matched_brand: "Microsoft", similarity: 0.94 }`

#### Layer 5 — Threat Intelligence Correlation (`models/sentinel_fusion_model.py`)

Links extracted IOCs to known threat campaigns and actors.

**Knowledge Graph** (NetworkX, in-memory):
- 5 Threat Actors: FIN7, Lazarus Group, APT28, Scattered Spider, LAPSUS$
- 50+ Campaigns (active & historical): e.g., *Operation Wire Phantom*, *QR Mirage*, *Crypto Heist 2025*
- 200+ Domains with timestamps, registrars, risk levels
- 100+ IPs with geolocation and ASN data
- 50 MITRE Techniques cross-referenced to actors and campaigns

**OSINT Feed Ingestion** (auto-refresh every 6 hours):
- **ThreatFox**: Malware-attributed IOCs
- **URLhaus**: Actively reported malicious URLs
- **PhishTank**: Verified phishing URLs
- ~1,000+ fresh IOCs ingested on startup

**Output**: `{ intel_boost: 0.18, matched_campaign: "Operation Wire Phantom", actor: "APT28" }`

#### Fusion Engine (`models/fusion_engine.py`)

Combines all 5 layer outputs into a final verdict using attention-weighted ensemble logic.

**Default Weight Matrix by Input Type**:

| Layer | Email | URL-only | Mixed |
|-------|-------|----------|-------|
| NLP Intent | 35% | 8% | 32% |
| URL Risk | 28% | 55% | 30% |
| Visual Brand | 18% | 30% | 20% |
| Header Auth | 19% | 7% | 18% |
| Intel Boost | additive | additive | additive |

**Confidence-based dynamic scaling**: Low-confidence model outputs are down-weighted automatically — if Apify is rate-limited and CLIP gets a low confidence score, the engine rebalances to other layers.

#### Kill Chain Analyzer (`engines/kill_chain.py`)

Maps attack progression across the full threat lifecycle, connecting all three problem statements:

```
Stage 1 (PS-01): Initial Access
    ↓  Phishing email detected with score > 0.55
Stage 2 (PS-02): Credential Access
    ↓  Bot/credential-stuffing attempt detected post-click
Stage 3 (PS-03): Financial Impact
    ↓  Anomalous transaction correlated to credential leak
Stage 4: Lateral Movement
    ↓  Internal spearphishing from compromised account
```

Each stage gets independent risk scoring and MITRE technique attribution. This is Sentinel's primary differentiator over point solutions — it is the only system in the stack that reasons about **what happens after the click**.

#### Behavioral Analysis

**Bot Detector** (`behavioral/bot_detector.py`):
- Inter-request timing entropy (human vs. automated patterns)
- User-agent signature detection (Python, cURL, Selenium, Puppeteer)
- Session consistency checks
- Behavioral entropy scoring with Isolation Forest

**Fraud Correlator** (`behavioral/fraud_correlator.py`):
- Links phishing events to downstream transaction anomalies
- Isolation Forest anomaly detection on behavioral signals
- Generates kill-chain progression reports

#### REST API Endpoints

| Endpoint | Method | Purpose | Latency |
|----------|--------|---------|---------|
| `/api/v1/analyze/email` | POST | Full 5-layer pipeline | 2–5s |
| `/api/v1/analyze/url` | POST | URL-focused analysis | 1–3s |
| `/api/v1/analyze/headers` | POST | Header auth analysis | <500ms |
| `/api/v1/analyze/quick` | POST | Inbox-tier heuristic | <500ms |
| `/api/v1/quishing/decode` | POST | QR code decode + analyze | 1–2s |
| `/api/v1/sandbox/analyze` | POST | Screenshot + visual sim | 3–6s |
| `/api/v1/campaigns` | GET | Campaign intelligence | <100ms |
| `/api/v1/actors` | GET | Threat actor profiles | <100ms |
| `/api/v1/chat` | POST | SentinelChat message | 1–3s |
| `/api/v1/behavioral/detect-bot` | POST | Session bot analysis | <500ms |
| `/api/v1/behavioral/fraud-check` | POST | Transaction anomaly | <500ms |
| `/api/v1/reports/generate` | POST | PDF export | 1–2s |
| `/api/v1/gmail/inbox` | GET | Fetch & score inbox | 2–8s |
| `WS /api/v1/stream` | WS | Real-time pipeline events | streaming |

**Tech Stack**:
```
FastAPI 0.115.6 · Uvicorn 0.34.0 · Pydantic 2.10.6
OpenRouter (Gemma-3-12b-it) · Replicate (CLIP) · Apify (Playwright)
ChromaDB 0.5.15 · NetworkX 3.4.2 · scikit-learn
python-whois · dnspython · pyzbar (QR) · OpenCV · Google API Client
```

---

### 3.2 Frontend — Real-Time Monitoring Dashboard

**Location**: `sentAi/`  
**Framework**: Next.js 16.2.1 + React 19.2.4  
**Port**: 3002

#### Application Structure

```
sentAi/app/
├── page.tsx                   ← Landing page (hero, features, CTA)
└── dashboard/
    ├── layout.tsx             ← Sidebar + header shell
    ├── page.tsx               ← Overview metrics
    ├── analyze/page.tsx       ← Primary analysis workspace
    ├── bulk/page.tsx          ← CSV batch processing
    ├── intelligence/page.tsx  ← Threat actor & campaign explorer
    ├── campaigns/page.tsx     ← Campaign timeline
    ├── chat/page.tsx          ← SentinelChat UI
    ├── inbox/page.tsx         ← Gmail OAuth2 inbox
    ├── history/page.tsx       ← Analysis history & trends
    └── sandbox/page.tsx       ← URL sandbox viewer
```

#### Key Pages

**Analyze** (`dashboard/analyze/page.tsx`) — The primary analyst workspace:
- Multi-tab input: Email Body, URL, Email Headers, QR Code, Attachment
- Real-time pipeline visualization with per-layer progress indicators streamed via WebSocket
- Result surface:
  - `ThreatScoreCard`: Animated fusion score gauge
  - `TacticsCard`: Detected MITRE tactics with evidence snippets
  - `IntelCard`: Threat actor/campaign correlation with campaign timeline
  - `TransparencyPanel`: Model weight breakdown + confidence per layer
  - `EvidencePanel`: Supporting evidence with source citations
  - `DeepDivePanel`: Raw WHOIS/DNS/header data
  - `LLMFingerprintCard`: AI-generated content indicators
  - `ExecutionTraceCard`: Step-by-step analysis trace
  - `ColorCodedKillChain`: Visual progression through attack stages

**Intelligence Explorer** (`dashboard/intelligence/page.tsx`):
- D3.js network visualization of the knowledge graph
- Threat actor profiles with associated TTPs and campaigns
- IOC lookup against live threat feeds
- Campaign filtering by actor, status, risk level, and sector

**SentinelChat** (`dashboard/chat/page.tsx`):
- Multi-turn RAG-powered conversational interface
- Contextually aware: links responses to active analysis sessions
- Analyst-level context: can ask "What else has APT28 done this quarter?" and get structured answers
- Suggested queries auto-generated based on current detection context

**Tech Stack**:
```
Next.js 16 · React 19 · TypeScript
TailwindCSS 4 · shadcn/ui
Recharts 3 · D3.js 7 (network graphs)
Framer Motion 12 (animations)
Zustand (global state)
```

---

### 3.3 Browser Extension — Gmail & Outlook

**Location**: `sentinel-extension/`  
**Manifest**: V3  
**Permissions**: `storage`, `sidePanel`, `activeTab`, `scripting`, `tabs`

#### Architecture

```
sentinel-extension/
├── manifest.json                  ← V3 manifest, host permissions
├── background/background.js       ← Service worker (cache + queue)
├── content/
│   ├── gmail_content.js           ← Gmail inbox badge injection
│   ├── outlook_content.js         ← Outlook Web badge injection
│   └── content.css                ← Badge & tooltip styling
├── popup/
│   ├── popup.html                 ← Quick stats popup
│   └── popup.js                   ← Badge counts, status
├── sidepanel/
│   └── sidepanel.js               ← Deep analysis side panel
└── shared/
    └── api.js                     ← Central API client
```

#### Tiered Analysis Strategy

The extension applies intelligent degradation to avoid overwhelming the backend and to surface results within the user's natural reading speed:

| Tier | Trigger | Engine | Latency |
|------|---------|--------|---------|
| A (Full) | Emails 0–4 in view | 5-layer pipeline | 2–5s |
| B (LLM) | Emails 5–14 in view | NLP + URL only | 1–2s |
| C (Quick) | Emails 15+ in view | Heuristic scoring | <500ms |

#### Badge Injection

Badges are injected directly into email row DOM elements without disrupting Gmail/Outlook rendering:

```
[87% ★]  ← Red badge, full analysis, score 87
[34% ◆]  ← Amber badge, LLM-tier analysis
[12% ●]  ← Green badge, quick heuristic
[ ✓  ]   ← Trusted sender
[  ⟳ ]   ← Scanning in progress
```

Hover tooltip shows: verdict, top tactic, sender domain age, campaign match (if any).  
Click opens the **Side Panel** with the full analysis detail view.

#### Background Service Worker

- **Request queue**: Max 1 concurrent full analysis, 2 concurrent LLM analyses (prevents backend flooding)
- **Persistent cache**: 15-minute TTL in `chrome.storage.local` — survives Gmail's SPA navigation
- **Message routing**: Forwards content script requests to backend, returns results

#### Host Permissions

```json
"host_permissions": [
  "https://mail.google.com/*",
  "https://outlook.cloud.microsoft/*",
  "https://outlook.com/*",
  "https://outlook.live.com/*",
  "https://outlook.office.com/*",
  "https://outlook.office365.com/*",
  "http://localhost:8001/*",
  "https://sentinel-ai-backend.onrender.com/*"
]
```

---

### 3.4 WhatsApp & Telegram Bots

**Status**: Deployed externally, source maintained separately. Both bots use the **same central FastAPI API** as all other interfaces — no separate detection logic.

#### Interface Pattern

```
User → Bot (message with URL / email text / screenshot)
Bot  → POST /api/v1/analyze/{email|url|quick}
API  → Fusion Engine (5-layer)
API  → Response JSON
Bot  → Formatted reply with verdict, score, key evidence
User ← "⚠️ PHISHING (87%) — Microsoft impersonation, domain registered 3 days ago"
```

#### Capabilities via API
- URL analysis: paste any link, get verdict + WHOIS age + brand check
- Email text analysis: paste subject + body, get tactic detection
- Quick screenshot analysis: send image of suspicious email, get OCR + analysis
- History query: "show me my last 5 scans"
- SentinelChat integration: ask threat intelligence questions in natural language

#### Why This Architecture Matters
The bot interface proves the **API-first design** principle: any new interface (Slack, Teams, iOS app) can integrate Sentinel's detection capabilities in hours, not months, without touching the analysis engine.

---

### 3.5 SentinelChat — Conversational Threat AI

**Backend**: `chat/rag_pipeline.py` + `routers/chat.py`  
**Frontend**: `sentAi/app/dashboard/chat/page.tsx`  
**Available in**: Web dashboard, WhatsApp bot, Telegram bot

#### Architecture

```
User Query
    ↓
Semantic Search (sentence-transformers → ChromaDB)
    ↓
Context Retrieval (threat actors, campaigns, MITRE, platform docs)
    ↓
LLM (Gemma-3-12b-it via OpenRouter) + retrieved context
    ↓
Structured Response (answer + sources + follow-up suggestions)
```

#### Knowledge Base (ChromaDB Vector Store)

| Collection | Contents |
|------------|----------|
| Threat Actors | FIN7, Lazarus, APT28, Scattered Spider, LAPSUS$ profiles |
| Campaigns | 50+ campaign summaries with TTPs, victims, timeline |
| MITRE Techniques | 50 techniques with detection guidance |
| Platform Docs | How Sentinel works, endpoint reference, scoring guide |

#### Key Capability: Context-Aware Querying

Any analysis done through Sentinel is stored in the session context. Users can follow up with natural language:

```
→ "Why did this email score 87?"
← "The high score was driven by three signals: (1) the sender domain 
   secure-microsoft-login.com was registered 2 days ago, (2) the email 
   uses DKIM failure combined with a Reply-To mismatch, and (3) the 
   visual similarity to Microsoft's login page was 94%..."

→ "Has APT28 done this before?"
← "Yes. APT28's 'Operation Phantom Login' campaign (active Q3-Q4 2025) 
   used the same TLD pattern and targeted enterprise Office 365 users. 
   Victims included 3 European energy firms..."
```

This converts raw detection output into **analyst-grade intelligence narratives** accessible to non-technical users.

---

### 3.6 Threat Intelligence Layer

#### Knowledge Graph Structure (NetworkX)

```
[Threat Actor] ←─ attributed_to ─→ [Campaign]
     │                                  │
     ↓ uses_technique                   ↓ uses_domain
[MITRE Technique]              [Domain / IP IOC]
     │
     ↓ maps_to_tactic
[MITRE Tactic]
```

**5 Threat Actors Profiled**:
- **FIN7** — Financial sector, BEC and card skimming specialist
- **Lazarus Group** — North Korea-attributed, crypto heist and SWIFT fraud
- **APT28** (Fancy Bear) — Russian GRU, government and infrastructure targeting
- **Scattered Spider** — Social engineering specialist, SIM swapping, MFA bypass
- **LAPSUS$** — Insider threat and data extortion focus

**50+ Campaigns** including:
- *Operation Wire Phantom* — BEC campaign targeting CFOs
- *QR Mirage* — Quishing campaign bypassing email gateways
- *Crypto Heist 2025* — Lazarus Group crypto exchange targeting

#### Live OSINT Feed Ingestion

Auto-refreshes every 6 hours on startup:

| Feed | Provider | Data | Volume |
|------|----------|------|--------|
| ThreatFox | abuse.ch | Malware-attributed IOCs | 500+ IOCs |
| URLhaus | abuse.ch | Active malicious URLs | 300+ URLs |
| PhishTank | OpenPhish | Verified phishing URLs | 200+ URLs |

Total: ~1,000+ fresh IOCs in memory on startup.

---

### 3.7 Data Flow & System Connectivity

#### Primary: Email Threat Detection Flow

```
[Gmail / Outlook]
     │ User opens inbox
     ↓
[Extension Content Script]
     │ Extracts: subject, sender, snippet, message ID
     │ Checks local cache (15-min TTL)
     ↓
[Background Service Worker]
     │ Queue management (tier assignment, rate limiting)
     ↓
[Central API: POST /api/v1/analyze/quick or /email]
     │
     ├──► NLP Engine (tactic detection, MITRE mapping)
     ├──► URL Analyzer (150+ features, WHOIS/DNS)
     ├──► Header Analyzer (SPF/DKIM/DMARC)
     ├──► Visual Engine (Apify → CLIP → brand sim)
     └──► Intel Correlation (knowledge graph lookup)
          │
          ↓
     [Fusion Engine] → verdict + score + explanation
          │
          ↓
[Extension] → Badge injection into inbox row
     │ Hover: quick summary tooltip
     │ Click: full side panel analysis
     │
     ↓ (optional)
[SentinelChat] → "Tell me more about this threat"
```

#### Secondary: Dashboard Deep Analysis Flow

```
[Analyst] → Pastes email/URL/headers into Analyze page
     ↓
[WebSocket /api/v1/stream]
     │ Real-time pipeline events streamed:
     │  → "NLP analysis complete (0.87)"
     │  → "URL analysis complete (0.72)"
     │  → "Visual scan in progress..."
     ↓
[Frontend] → Updates progress bars per layer in real time
     ↓
[Final Result] → ThreatScoreCard + TacticsCard + IntelCard + EvidencePanel
     ↓
[Report Generation] → PDF export with full SHAP attribution
```

#### Tertiary: Intelligence Exploration Flow

```
[ThreatFox / URLhaus / PhishTank]
     │ (every 6 hours)
     ↓
[Feed Ingester] → Parses, deduplicates, risk-scores IOCs
     ↓
[Knowledge Graph] → Adds nodes and edges to NetworkX graph
     ↓
[Intelligence Explorer] → D3 network visualization
[Campaign Endpoint] → Filtered campaign/actor data
[SentinelChat] → RAG retrieval augmentation
```

---

## 4. Feasibility Analysis

### Technical Feasibility

| Component | Feasibility | Justification |
|-----------|-------------|---------------|
| 5-Layer NLP + URL + Header analysis | **High** | Proven open-source stack; runs on commodity hardware |
| Visual brand similarity (CLIP) | **High** | Replicate API; no GPU needed on server |
| Screenshot sandbox (Apify) | **High** | Managed service, pay-per-use, no browser infra needed |
| Knowledge graph (NetworkX) | **High** | In-memory; 1000+ nodes load in <2s |
| ChromaDB RAG | **High** | Lightweight, self-hosted vector store |
| Chrome Extension (MV3) | **High** | Shipped; tested on Gmail and Outlook Web |
| WhatsApp/Telegram bots | **High** | Standard webhook pattern; uses same API |
| LLM inference (OpenRouter) | **High** | No model hosting; API-based; multiple fallbacks |
| Real-time WebSocket streaming | **High** | Native FastAPI WebSocket support |

### Performance Feasibility

| Scenario | Latency | Scale |
|----------|---------|-------|
| Quick inbox scan (1 email) | <500ms | Unlimited parallel |
| Full 5-layer analysis | 2–5s | ~50 concurrent (with queue) |
| Visual sandbox analysis | 3–6s | Rate-limited by Apify |
| Knowledge graph query | <100ms | Single-server, in-memory |
| SentinelChat response | 1–3s | LLM API bottleneck |

### Operational Feasibility

- **Zero GPU requirement**: All heavy ML runs via external APIs (OpenRouter, Replicate, Apify)
- **Stateless backend**: Horizontal scaling is straightforward (Redis for shared cache)
- **Graceful degradation**: If any API key is missing, that layer is disabled and weights rebalance — the system never hard-fails
- **Cold start**: Backend initializes knowledge graph, OSINT feeds, and RAG in ~30 seconds

### Known Constraints

| Constraint | Mitigation |
|------------|------------|
| Apify rate limits visual analysis | Tiered system (Tier C skips visual) |
| OpenRouter latency variability | Timeout + heuristic fallback |
| Knowledge graph is in-memory | Survives restarts; persistence via NetworkX serialization |
| Gmail/Outlook DOM selectors change | ARIA attribute fallbacks in extension |
| WHOIS/DNS adds latency | Cached per domain for 1 hour |

---

## 5. Business Model

### Target Segments

| Segment | Pain | Value Proposition |
|---------|------|------------------|
| **SMB Employees** | No security team, email-first attack surface | Browser extension, WhatsApp/Telegram bot — zero friction |
| **Enterprise SOC Teams** | Alert fatigue, no campaign attribution | Dashboard + bulk analysis + kill chain mapping + export |
| **Managed Security Providers (MSSPs)** | Need multi-tenant tooling | API-first design, white-label potential |
| **Financial Institutions** | Phishing → fraud kill chain | Kill chain + fraud correlation (PS-01/02/03 integration) |

### Revenue Streams

#### Tier 1 — Free (Freemium)
- Chrome extension with basic badge scoring (quick-tier only)
- 50 analyses/month
- WhatsApp/Telegram bot (quick analysis only)
- Drives user acquisition and top-of-funnel

#### Tier 2 — Pro ($29/month per user)
- Full 5-layer analysis (unlimited)
- SentinelChat access
- Dashboard + history + trend analysis
- PDF report export
- Gmail OAuth integration

#### Tier 3 — Enterprise (Custom)
- Multi-tenant dashboard with org-level analytics
- API access with SLA
- Custom knowledge graph (organization-specific IOCs)
- SIEM/SOAR integration (Splunk, Microsoft Sentinel)
- Dedicated SOC analyst interface
- Bulk CSV processing
- White-label option

#### Tier 4 — API-as-a-Service
- Per-call pricing for third-party integrations
- Ideal for email security vendors embedding Sentinel as a detection layer
- Estimated: $0.005/quick call, $0.05/full analysis call

### Go-To-Market

1. **Bottom-up**: Free Chrome extension drives individual user adoption
2. **Land-and-expand**: Extension users inside enterprises upgrade to Pro, triggering IT team interest
3. **Partnership**: Co-sell with Microsoft 365 / Google Workspace resellers
4. **API channel**: Integrate with email security gateways (Proofpoint, Mimecast, Abnormal)

### Competitive Differentiation

| Feature | Sentinel | Proofpoint | Abnormal | VirusTotal |
|---------|----------|------------|----------|------------|
| 5-layer fusion | ✓ | Partial | Partial | ✗ |
| Explainability (SHAP) | ✓ | ✗ | ✗ | ✗ |
| Kill chain (PS-01/02/03) | ✓ | ✗ | ✗ | ✗ |
| Quishing (QR decode) | ✓ | ✓ | Partial | ✗ |
| Conversational AI (chat) | ✓ | ✗ | ✗ | ✗ |
| WhatsApp / Telegram access | ✓ | ✗ | ✗ | ✗ |
| Campaign clustering | ✓ | ✓ | ✓ | ✗ |
| Free tier (extension) | ✓ | ✗ | ✗ | ✓ |
| API-first multi-interface | ✓ | ✗ | ✗ | ✓ |

---

## 6. Future Scope

### Near-Term (3–6 months)

#### 6.1 Mobile Application
- iOS/Android native app with camera-based QR scanning
- Push notification on high-risk email detection (Gmail/Outlook mobile sync)
- Same API backend — UI work only

#### 6.2 Microsoft Teams & Slack Integration
- Bot that scans shared links and files in team channels
- Slash command: `/sentinel analyze https://suspicious-link.com`
- Webhook-based alert on CRITICAL verdict in monitored channels

#### 6.3 SIEM/SOAR Integration
- Splunk Add-on publishing IOCs to SIEM index
- Microsoft Sentinel Connector (Logic Apps workflow)
- PagerDuty/Opsgenie alert routing for CRITICAL verdicts
- STIX/TAXII format export for threat intel sharing

#### 6.4 Attachment Deep Analysis
- PDF parser: extract embedded URLs, macros, metadata from suspicious PDFs
- Office file analysis: detect malicious macros in .docx/.xlsx
- Dynamic attachment sandbox: execute in isolated VM and monitor syscalls

### Medium-Term (6–12 months)

#### 6.5 Federated Knowledge Graph
- Allow enterprise customers to contribute proprietary IOCs (e.g., internal threat hunting findings)
- Privacy-preserving sharing: federated learning approach for cross-org campaign detection without data leakage
- Build the first community-sourced SMB threat intelligence feed

#### 6.6 Proactive Campaign Monitoring
- Given a company's domain and brand assets, continuously monitor for:
  - Newly registered lookalike domains (e.g., `m1crosoft-secure.com`)
  - Dark web mentions of the company's credentials
  - Emerging campaigns targeting the company's sector
- Weekly digest reports for security teams

#### 6.7 Email Response Playbooks
- Auto-generated response actions per verdict: quarantine template, user awareness notification, IT escalation
- One-click "report phishing" that submits to PhishTank + internal SIEM
- Automated safe link rewriting in high-risk emails

#### 6.8 LLM Red Team Simulator
- Use the same NLP engine to *generate* training phishing emails
- Run them through the detection pipeline to measure robustness
- Continuously harden the model against attacker-side LLM use

### Long-Term (12–24 months)

#### 6.9 On-Premise / Air-Gapped Deployment
- Package as Docker Compose for enterprise on-prem deployment
- Replace OpenRouter with locally hosted LLM (Ollama + Llama 3)
- Replace Replicate CLIP with locally hosted model
- Critical for government and financial sector customers with data residency requirements

#### 6.10 Autonomous SOC Analyst Mode
- SentinelChat evolves from reactive Q&A to proactive investigation
- Automatically investigates triggered alerts: "I found a new IOC in this email that matches a known FIN7 campaign. I've already looked up the domain age (3 days), checked DNS (no SPF record), and flagged 2 other emails from the same sender. Recommend quarantine."
- Closes the loop from detection → investigation → recommendation without analyst intervention

#### 6.11 Regulatory Compliance Reporting
- Auto-generate GDPR/NIS2/DORA-compliant incident reports from analysis history
- Audit trail export in formats required by financial regulators (FCA, SEC)
- Map detected attacks to regulatory notification thresholds

#### 6.12 Predictive Threat Modeling
- Forecast next campaign type based on actor behavior patterns
- Sector-specific risk calendar: "FIN7 historically targets retail in Q4; elevated alert recommended for November"
- Adaptive threshold tuning: automatically adjust verdict thresholds based on observed false positive rates

---

## Appendix: Environment Configuration

```bash
# Required for core operation
OPENROUTER_API_KEY=...          # LLM inference (NLP engine, SentinelChat)
REPLICATE_API_TOKEN=...         # CLIP visual similarity
APIFY_API_TOKEN=...             # URL screenshot sandbox

# Optional integrations
ANTHROPIC_API_KEY=...           # Alternative LLM
GOOGLE_CLIENT_ID=...            # Gmail OAuth2
GOOGLE_CLIENT_SECRET=...        # Gmail OAuth2
VIRUSTOTAL_API_KEY=...          # Additional URL reputation
HIBP_API_KEY=...                # HaveIBeenPwned (dark web)

# Server config
PORT=8001
FRONTEND_URL=http://localhost:3002
```

## Appendix: Tech Stack Summary

| Layer | Technology | Version |
|-------|-----------|---------|
| Backend API | FastAPI | 0.115.6 |
| ASGI Server | Uvicorn | 0.34.0 |
| Frontend | Next.js | 16.2.1 |
| UI Framework | React | 19.2.4 |
| Styling | TailwindCSS | 4.x |
| Charting | Recharts + D3.js | 3.8 / 7.9 |
| State Management | Zustand | latest |
| LLM | Gemma-3-12b-it (OpenRouter) | — |
| Vision Model | CLIP (Replicate) | — |
| Web Scraping | Apify Playwright | — |
| Vector Database | ChromaDB | 0.5.15 |
| Graph Database | NetworkX | 3.4.2 |
| Anomaly Detection | scikit-learn Isolation Forest | — |
| Extension | Chrome MV3 | — |
| QR Decoding | pyzbar | — |
| DNS/WHOIS | dnspython / python-whois | — |

---

*Sentinel — Built for the hackathon. Designed for the real world.*
