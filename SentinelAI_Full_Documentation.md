# SentinelAI Fusion — Comprehensive Technical Documentation

> **Project:** SentinelAI Fusion  
> **Stack:** Next.js 14 (frontend) · FastAPI + Python 3.12 (backend)  
> **Version:** 3.0.0  
> **Primary PS:** PS-01 (AI-Powered Phishing Detection)  
> **Bonus Coverage:** PS-02 (Bot/Credential Stuffing) · PS-03 (Fraud Correlation) · PS-04 (Security Chatbot) · PS-05 (Dark Web Monitoring)

---

## 1. Problem Description

Phishing attacks are the **#1 initial access vector** in cyber breaches globally, responsible for over 36% of all confirmed incidents. Despite decades of rule-based email filters, attackers have evolved along three critical axes:

1. **AI-crafted lures** — LLMs (GPT-4, Claude, Gemini) now produce grammatically flawless, contextually aware phishing emails that bypass keyword and pattern-based detectors entirely.
2. **QR code phishing ("Quishing")** — Attackers embed malicious URLs inside QR codes so the raw link is never visible in the email body, making it invisible to standard URL scanners.
3. **Multi-vector kill chains** — A modern attack is a chain: phishing email → credential-harvesting clone page → account takeover → financial fraud within 2–72 hours.

### 1.1 Pain Points Addressed

| Pain Point | Why Existing Tools Fail |
|---|---|
| Single-layer detection | Most tools check only content OR URL — never both simultaneously with cross-correlation |
| No explainability | SOC analysts get a verdict with zero reasoning — "black box" decisions erode trust and slow triage |
| Static rule sets | Attackers iterate faster than signature update cycles can keep up |
| No kill-chain awareness | Detecting the phishing email doesn't model the downstream fraud it enables |
| AI-generated lure blindness | Templates trained on historical phishing fail when emails are GPT-authored |
| No visual brand detection | Pixel-perfect clones of PayPal or Microsoft portals are invisible to text analysis |
| Siloed inboxes | Security teams cannot retrospectively scan actual Gmail inboxes at scale |
| QR blind spot | No mainstream product covers QR-embedded malicious URLs |
| No threat actor attribution | Verdicts lack intelligence about which APT group is behind the campaign |

---

## 2. Key Solution Pillars

| Pillar | Technology |
|---|---|
| **5-Layer Parallel AI Fusion** | NLP (GPT + BERT) · URL (XGBoost + rules) · Visual (CLIP + Apify) · Header (SPF/DKIM/DMARC) · Threat Intel |
| **Explainable AI (XAI)** | SHAP-style attribution, MITRE ATT&CK tactic tagging, full transparency panel |
| **LLM Authorship Detection** | Stylometric analysis + BERT perplexity proxy + Gemma-3 meta-analysis |
| **Visual Brand Similarity** | Apify Playwright screenshot → CLIP embedding → cosine similarity vs 18 brand profiles |
| **Threat Knowledge Graph** | NetworkX graph of 5 APT actors, 50 campaigns, 200+ domains, 100+ IPs |
| **Kill Chain Modeling** | Maps detection to PS-01→PS-02→PS-03 progression with financial impact estimate |
| **Gmail Integration** | Full OAuth2 flow, batch inbox scanning, PII redaction before LLM processing |
| **QR Quishing Module** | pyzbar/OpenCV decode → full 5-layer analysis of embedded URL |
| **XGBoost Meta-Classifier** | Trained on 6,700 TREC-2007 emails, 125 features — calibrates the entire ensemble output |
| **Real-time WebSocket Feed** | Per-layer pipeline progress streamed live to the UI during analysis |

---

## 3. Project Structure

```
sent2/
├── backend/                        # FastAPI Python backend (port 8001)
│   ├── main.py                     # App factory, router mounting, lifespan hooks
│   ├── config.py                   # API keys, feature flags, model IDs
│   ├── models/                     # Detection & ML models
│   │   ├── nlp_engine.py           # GPT-4o-mini + BERT phishing NLP ensemble
│   │   ├── url_analyzer.py         # 150+ feature URL risk scorer (WHOIS+DNS+URLhaus)
│   │   ├── visual_engine.py        # Apify screenshot + Replicate CLIP brand detection
│   │   ├── header_analyzer.py      # SPF/DKIM/DMARC + routing forensics
│   │   ├── fusion_engine.py        # Attention-weighted ensemble fusion
│   │   ├── bert_phishing_model.py  # Fine-tuned BERT on ISCX-2016 dataset
│   │   ├── ml_url_classifier.py    # XGBoost URL classifier (31 features)
│   │   ├── sentinel_fusion_model.py# Meta-classifier XGBoost (125 features, TREC-2007)
│   │   ├── llm_detector.py         # AI authorship fingerprinting (3-pronged)
│   │   ├── attachment_analyzer.py  # File content inspection + execution trace
│   │   ├── campaign_clustering.py  # Unsupervised IOC campaign grouping
│   │   ├── first_contact.py        # Sender domain novelty / zero-day infra tracking
│   │   └── pii_redactor.py         # PII stripping before LLM API calls
│   ├── engines/
│   │   ├── kill_chain.py           # PS-01→PS-03 attack stage progression
│   │   └── credential_check.py     # HaveIBeenPwned dark web exposure (PS-05)
│   ├── intelligence/
│   │   ├── knowledge_graph.py      # NetworkX threat graph (actors/campaigns/IOCs)
│   │   ├── feed_ingester.py        # ThreatFox + URLhaus + PhishTank live feeds
│   │   └── ioc_feeds.py            # IOC enrichment from OSINT feeds
│   ├── behavioral/
│   │   ├── bot_detector.py         # PS-02 behavioral anomaly detection
│   │   └── fraud_correlator.py     # PS-03 fraud pattern correlation
│   ├── chat/
│   │   ├── rag_pipeline.py         # ChromaDB vector store + RAG
│   │   └── sentinel_chat.py        # Security chatbot + explanation generator
│   └── routers/                    # FastAPI endpoint handlers
│       ├── analyze.py              # Core 5-layer pipeline orchestrator (917 lines)
│       ├── sandbox.py              # Deep URL sandbox (redirects/SSL/DOM/screenshot)
│       ├── gmail.py                # Gmail OAuth2 + batch inbox analysis (764 lines)
│       ├── quishing.py             # QR code phishing detection
│       ├── bulk.py                 # CSV batch analysis
│       ├── dashboard.py            # KPI metrics, live feed, timeline
│       ├── campaigns.py            # Campaign + actor intelligence endpoints
│       ├── history.py              # Analysis history & trend stats
│       ├── reports.py              # PDF/JSON report generation
│       ├── stream.py               # WebSocket broadcast hub
│       ├── deep_dive.py            # Extended deep analysis endpoint
│       ├── behavioral.py           # Bot/credential-stuffing endpoints
│       ├── intelligence.py         # Knowledge graph explorer API
│       ├── feedback.py             # Analyst feedback collection
│       └── chat.py                 # SentinelChat conversational API
│
└── sentAi/                         # Next.js 14 frontend (port 3000)
    ├── app/
    │   ├── page.tsx                # Landing/marketing page
    │   └── dashboard/
    │       ├── layout.tsx          # Sidebar shell + theme
    │       ├── page.tsx            # Dashboard overview (KPIs, charts, feed)
    │       ├── analyze/page.tsx    # Main analysis interface
    │       ├── inbox/page.tsx      # Gmail inbox viewer
    │       ├── sandbox/page.tsx    # URL sandbox UI
    │       ├── bulk/page.tsx       # CSV bulk upload UI
    │       ├── campaigns/page.tsx  # Campaign intelligence explorer
    │       ├── chat/page.tsx       # SentinelChat AI assistant
    │       ├── history/page.tsx    # Past analysis records
    │       └── intelligence/page.tsx # Knowledge graph D3 explorer
    └── components/
        ├── analyze/                # 18 modular analysis result components
        ├── dashboard/              # KpiCard, RiskDonut, ThreatChart, ThreatFeed, ThreatTimeline
        ├── layout/                 # Sidebar, ThemeToggle
        └── ui/                    # shadcn/ui primitives (Button, Card, Badge, etc.)
```

---

## 4. Application Startup — `main.py`

FastAPI uses an **async lifespan context manager** to pre-warm all expensive components before the first HTTP request arrives. On startup:

1. **Knowledge Graph init** — `ThreatKnowledgeGraph()` is constructed: 5 actor nodes, 50 campaign nodes, 200+ domain nodes, 100+ IP nodes, 20 MITRE technique nodes are loaded into a NetworkX directed graph. Edge relationships (`CONDUCTS`, `USES_DOMAIN`, `CONTROLS`, `EMPLOYS`) are added. Reported as `N nodes, M edges`.

2. **RAG Pipeline init** — ChromaDB vector store is initialized with security knowledge documents for the SentinelChat assistant.

3. **XGBoost URL Classifier init** — Model weights loaded; F1, AUC, Accuracy printed to stdout.

4. **BERT** — Lazy-loaded on first inference (avoids a ~3 second startup delay).

5. **OSINT Feed ingestion** — `ingest_all_feeds()` fetches from ThreatFox, URLhaus, and PhishTank, merges IOCs into the graph, then starts `feed_refresh_loop()` as a background asyncio task (every 6 hours).

All 16 routers are mounted. A `/screenshots` static file server is created from `backend/data/screenshots/` to serve Apify-captured screenshots.

---

## 5. The Core 5-Layer Detection Pipeline — `routers/analyze.py`

This 917-line file orchestrates every analysis. All three input endpoints call the same internal `_run_full_analysis(content, input_type, options)` function.

### 5.1 Entry Points

| Endpoint | Input | Input Type |
|---|---|---|
| `POST /api/v1/analyze/email` | Raw email text | `"email"` |
| `POST /api/v1/analyze/url` | URL string | `"url"` |
| `POST /api/v1/analyze/headers` | Raw SMTP headers | `"email"` |
| `POST /api/v1/analyze/attachment` | Uploaded file | `"email"` (extracted text) |

### 5.2 Pre-Processing

- URLs are extracted from email bodies via regex: `https?://[^\s<>"{}|\\^`\[\]]+`
- Domains are parsed from each URL using `tldextract`
- A unique event ID (`evt_` + 8 hex chars) is generated for WebSocket tracking
- `pipeline_start` event is emitted to all WebSocket subscribers

### 5.3 Layer 1 — NLP + Header Analysis (parallel)

```python
nlp_result, header_result = await asyncio.gather(
    analyze_text(content, input_type),
    analyze_headers(content) if input_type == "email" else empty_header()
)
```

- NLP result emitted as WebSocket `step=1` with score, confidence, top detected tactics
- Header result emitted as `step=2` with SPF/DKIM/DMARC outcomes and flags

### 5.4 Layer 2 — URL Analysis + LLM Fingerprint (parallel)

```python
url_result, llm_fingerprint = await asyncio.gather(
    score_url(primary_url, do_live_lookup=True),
    detect_llm_fingerprint(content) if input_type == "email" else empty_llm()
)
```

- URL result emitted as `step=3` — domain age, blacklist hit, top risk features
- LLM fingerprint emitted at `step=3` — AI probability, verdict (`LIKELY_AI`/`POSSIBLY_AI`/`LIKELY_HUMAN`)

### 5.5 Layer 3 — Visual Sandbox (optional)

- Gated by `options.run_visual` (default `false` — Apify is slow)
- Calls `analyze_visual(url, url_features)` → Apify screenshot → CLIP brand similarity
- Result emitted as `step=4`

### 5.6 Layer 4 — Threat Intelligence + IOC Enrichment

- `graph.correlate_iocs(domains)` — checks input domains against all 50 campaign IOC domain lists in the in-memory knowledge graph
- `enrich_iocs(domains)` — fires live queries against URLhaus and PhishTank APIs
- `total_intel_boost` = knowledge_graph elevation + live IOC boost + first-contact boost, capped at `+0.40`
- Emitted as `step=5`

### 5.7 Layer 4b — Sender First-Contact Tracking

- `check_and_track_domain(sender_domain)` checks if this domain has ever appeared in any analysis
- If **first time seen**: adds `"First Contact Domain"` tactic tagged `T1583.001` to the result, with a risk boost
- Rationale: real attackers register fresh "burner" domains for each campaign — novelty is a strong phishing signal

### 5.8 Layer 5 — Dark Web Exposure (PS-05)

```python
dark_web_data = await asyncio.wait_for(
    check_domain_exposure(all_domains[0]),
    timeout=5.0
)
```

Queries HaveIBeenPwned v3 API for breach history associated with the domain. Returns `breach_count`, `dark_web_risk` level, `total_exposed` count.

### 5.9 Fusion

`fuse_scores(nlp, url, header, visual, input_type, threat_intel_boost)` aggregates all layer outputs into a single `threat_score` (0–1) and `verdict`.

### 5.10 Kill Chain + Explanation

- `build_kill_chain(result)` maps the result to 4 MITRE attack stages
- `generate_explanation_narrative(result, content_preview)` asks the LLM to write a 2-3 sentence plain-English explanation for the SOC analyst

### 5.11 XGBoost Meta-Classifier Override

```python
ml_prob = predict_fusion(result)   # returns -1.0 if model unavailable
if ml_prob >= 0:
    result["threat_score"] = ml_prob
    # Re-derive verdict from calibrated score
```

The XGBoost meta-classifier trained on 6,700 emails re-scores the complete result using 125 features extracted from the full pipeline output. If available, its calibrated probability replaces the heuristic fusion score.

### 5.12 Post-Processing & Side Effects

| Action | Detail |
|---|---|
| Confidence interval | `[score ± (1-conf)*0.25]` |
| Inference time label | Lightning (<500ms) · Fast (<2s) · Moderate (<5s) · Thorough |
| "So What?" summary | Verdict-specific one-liner for the analyst |
| Result cache | Stored in `_result_cache` dict, max 500 entries (LRU) |
| History recording | `record_analysis(result, input_type, preview)` |
| Dashboard counters | `increment_analysis_counter(verdict)` |
| WebSocket broadcast | `analysis_complete` event with full verdict + score |

---

## 6. NLP Engine — `models/nlp_engine.py`

### 6.1 MITRE-Tagged Tactic Registry

10 social engineering tactics are mapped to MITRE ATT&CK IDs with calibrated weights:

| Tactic | MITRE ID | Weight |
|---|---|---|
| Credential Harvesting | T1056.003 | 0.20 |
| Urgency | T1566.001 | 0.18 |
| Executive Impersonation | T1656 | 0.17 |
| BEC Pattern | T1534 | 0.16 |
| Authority Impersonation | T1656 | 0.15 |
| Financial Lure | T1078 | 0.14 |
| Fear / Threat | T1585 | 0.13 |
| Suspicious Link | T1204.001 | 0.12 |
| Reward Framing | T1585.002 | 0.10 |
| Spoofing | T1566.002 | 0.08 |

### 6.2 Three-Mode Detection Architecture

**Mode A — GPT-4o-mini via OpenRouter (primary LLM)**
- Structured prompt instructs the model to return a strict JSON object containing `intent_score`, `detected_tactics`, `confidence`, `explanation`, `top_phrases`, `phishing_intent`
- `temperature=0.1`, `max_tokens=500`, `response_format: json_object` for deterministic structured output
- Content truncated to 2,000 characters for latency/cost control
- Falls back gracefully on JSON parse failure (strips markdown code fences via `_clean_llm_json`)

**Mode B — Fine-tuned BERT (parallel)**
- `bert-base-uncased` fine-tuned on ISCX-2016 phishing corpus
- Returns `phishing_prob` (0.0–1.0) and a binary `label`
- Lazy-loaded: model weights fetched from HuggingFace Hub on first call

**Mode C — Heuristic Fallback**
- Regex pattern matching across 10 tactic buckets (each with 2-4 patterns)
- Obfuscation bonus: +0.06 per detected Cyrillic character / HTML entity / percent-encoded sequence
- Benign signal reduction: "unsubscribe", "privacy policy", "best regards", order/ticket/invoice # presence each reduce score by 0.04
- URL count >2 adds +0.05

### 6.3 Ensemble Fusion Logic

```
GPT + BERT available:
  score = GPT_score × 0.55 + BERT_prob × 0.45
  agreement = 1.0 − |GPT_score − BERT_prob|          (0=disagree → 1=perfect)
  confidence = GPT_conf × 0.70 + agreement × 0.30

Only GPT:    return GPT result directly
Only BERT:   blend = BERT_prob × 0.65 + heuristic_score × 0.35
Neither:     pure heuristic
```

### 6.4 Output Schema

```json
{
  "score": 0.87,
  "confidence": 0.91,
  "detected_tactics": [{"name": "Urgency", "mitre_id": "T1566.001", "confidence": 0.92}],
  "explanation": "This email uses extreme urgency...",
  "top_phrases": ["act now", "account suspended", "click below"],
  "phishing_intent": "Credential harvesting via fake login portal",
  "gpt_score": 0.91,
  "bert_score": 0.82,
  "source": "ensemble_gpt4o_mini_bert"
}
```

---

## 7. URL Analyzer — `models/url_analyzer.py`

### 7.1 Feature Extraction (150+ features, zero I/O)

`extract_features_sync(url)` runs synchronously in memory using `tldextract` and `urlparse`. Features are grouped:

**Lexical:** url_length, domain_length, path_length, query_length, num_dots/hyphens/underscores/slashes/at-symbols/percent, has_ip_address, url_entropy, domain_entropy (Shannon entropy)

**Domain structure:** subdomain_count, subdomain_length, tld_risk_high (checked against a curated set of 30 abused TLDs: `.tk`, `.ml`, `.ga`, `.cf`, `.xyz`, `.top`, etc.), tld_risk_medium

**Brand detection:** Checks 35 major brand keywords (Microsoft, Google, Apple, Amazon, PayPal, major banks, FedEx, DocuSign, etc.) against domain and URL path. Cross-references against a **legitimate host whitelist** (20 trusted CDN/platform domains) — if the URL is actually at `microsoft.com`, brand_in_domain doesn't trigger

**Typosquatting score:** For each brand keyword, if `|len(domain) − len(brand)| ≤ 2`: pads shorter string and counts character differences. If `0.70 < similarity < 1.0`, score = `similarity × 0.9`. Returns the best match across all 35 brands.

**Path/query:** Counts occurrences of 30 suspicious path keywords (login, verify, auth, billing, invoice, etc.) in both domain and path separately; has_exe_extension (`.exe`, `.php`, `.bat`, `.vbs`, etc.)

**Obfuscation:** hex_encoding (`%XX`), double_slash in path, `@` symbol in URL, redirect keywords in URL (`redirect=`, `url=`, `goto=`), excessive hyphens (>3 in domain)

### 7.2 Live Async Enrichment

Three lookups run in parallel for non-whitelisted domains:

```python
whois_data, dns_data, urlhaus_data = await asyncio.gather(
    get_whois_data(domain),   # python-whois, 5s timeout
    get_dns_data(domain),     # dnspython (A, MX, TXT/SPF, DMARC), 6s timeout
    check_urlhaus(domain),    # abuse.ch API POST, 4s timeout
)
```

**WHOIS enrichment effects:**
- Age < 7 days → `+0.20` (full newly_registered feature weight)
- Age 7–30 days → `+0.14`
- Age 30–90 days → `+0.06`
- Privacy-protected registrar → `+0.08`

**URLhaus hit:** `+0.50` added directly and confidence set to `0.99`

### 7.3 SHAP-Style Score Components

`compute_score_components(features, whois, dns, urlhaus)` returns a named dict of risk contributions. Known-legitimate hosts exit immediately with `{"__legitimate_host": -0.90}` causing the scorer to return `score=0.04, confidence=0.96`.

The raw URL score = sum of all component values, capped 0.04–0.99.

### 7.4 ML Blend

```python
rule_score = sum(components)
ml_score   = _ml_predict(url)   # XGBoost URL classifier
final_score = rule_score * 0.60 + ml_score * 0.40
```

The 60% rule-engine bias is intentional — the rule engine incorporates live WHOIS/DNS context that the static ML model trained on URL features alone cannot see at inference time.

---

## 8. Visual Engine — `models/visual_engine.py`

### 8.1 Four-Step Pipeline

```
URL
 │
 ▼
Apify Actor (FU5kPkREa2rdypuqb — Playwright)
 │ waitUntil: "domcontentloaded" (8s timeout, 1 retry)
 ▼
Screenshot bytes (JPEG/PNG)
 │
 ├──► Save to backend/data/screenshots/ → served as /screenshots/{filename}
 │
 └──► Replicate CLIP Model (75b33f25)
       │ Embedding vector (512-dim)
       ▼
      Cosine similarity vs 18 brand profiles
       ▼
      { score, matched_brand, similarity, screenshot_path }
```

### 8.2 Why `domcontentloaded` Not `networkidle0`

Phishing pages render instantly (no complex data loading). Using `networkidle0` causes the Apify actor to hang on legitimate complex apps (Google Docs, Teams) waiting for WebSocket/XHR traffic to settle. `domcontentloaded` captures the login redirect wall immediately — which is exactly what phishing clone pages show.

### 8.3 Screenshot Extraction Logic

The actor writes to its **dataset** (not a fixed output key). The engine exhaustively checks:
1. All dataset items for raw bytes (`bytes`/`bytearray` values with valid magic bytes)
2. All dataset items for `data:image/...;base64,...` strings (decoded and validated)
3. All HTTP URL values in dataset items (fetched with 15s timeout and magic-byte checked)
4. Key-value store keys: `OUTPUT`, `screenshot`, `screenshot.jpg`, `screenshot.jpeg`, `screenshot.png`

Magic-byte validation: JPEG = `\xFF\xD8\xFF`, PNG = `\x89PNG`.

### 8.4 Brand Profiles

18 entries covering: Microsoft, Google, PayPal, Apple, Amazon, Facebook, LinkedIn, Bank of America, Chase, Wells Fargo, Dropbox, DocuSign, Adobe, Office 365, Zoom, Slack, GitHub, plus generic `corporate_sso` and `hr_portal` profiles.

Each profile has a `domains` list (legitimate URLs to exclude from impersonation matching) and a `keywords` list for text-based matching.

### 8.5 URL Estimation Fallback

When Apify is unavailable, `estimate_visual_from_url(url, url_features)` keyword-matches the URL against all brand profiles and uses `brand_impersonation` and `typosquatting_score` from the URL analyzer as proxy for visual similarity. Confidence is 0.55 vs 0.82 for real screenshot analysis.

---

## 9. Header Analyzer — `models/header_analyzer.py`

Parses raw **SMTP email headers** and outputs structured authentication results. Key fields extracted:

| Field | Source Header | Risk Impact |
|---|---|---|
| SPF result | `Authentication-Results`, `Received-SPF` | `fail`/`softfail` → +score |
| DKIM result | `Authentication-Results` | `fail`/`none` → +score |
| DMARC result | `Authentication-Results` | `fail`/`none` → +score |
| Reply-To mismatch | `From` vs `Reply-To` domains | Flag `reply_to_mismatch` |
| Return-Path mismatch | `From` vs `Return-Path` domains | Flag `return_path_mismatch` |
| Missing Message-ID | Absence of `Message-ID` header | Flag `missing_message_id` |
| Missing Date | Absence of `Date` header | Flag `missing_date_header` |
| Excessive routing hops | Count of `Received:` headers > 7 | Flag `excessive_routing_hops` |
| Bulk mailer | `X-Mailer` or `List-Unsubscribe` present | Flag `bulk_mailer_detected` |

SPF/DKIM failures inject an `Email Spoofing` tactic tagged `T1566.002` into the detected tactics array. Reply-To manipulation injects `Reply-To Manipulation` tagged `T1656`.

---

## 10. LLM Fingerprint Detector — `models/llm_detector.py`

### 10.1 Why This Matters

Traditional phishing NLP classifiers were trained on human-written phishing emails. AI-generated phishing is structurally different: it's grammatically perfect, stylistically uniform, and uses formulaic structures. Standard classifiers often score it *lower* than human phishing because it lacks the obvious red flags of manual spam. SentinelAI adds a dedicated layer to catch AI-authored lures.

### 10.2 Prong 1 — Stylometric Analysis (pure Python, no API)

Five statistical signals computed on the text, weighted and fused:

| Signal | AI Signature | Human Signature | Weight |
|---|---|---|---|
| Sentence length std dev | < 3–4 words (uniform) | > 8 words (varies) | 20% |
| Type-Token Ratio (TTR) | < 0.50 (repetitive vocab) | > 0.60 (diverse vocab) | 20% |
| Template phrase density | > 0.04 matches/word | Low organic phrasing | 25% |
| Punctuation regularity | Near-zero messiness index | Occasional typos/quirks | 15% |
| Paragraph coherence | High overlap, low variance | Natural topic drift | 20% |

**Template phrases:** 20 formulaic patterns common in AI-generated phishing — e.g., `"we have detected"`, `"your account has been"`, `"within 24/48/72 hours"`, `"failure to comply will result"`.

**TTR computation:** Only first 200 words used (TTR is length-dependent). `unique_words / total_words`.

### 10.3 Prong 2 — BERT Perplexity Proxy

Uses the fine-tuned BERT phishing model to compute prediction entropy on the classifier output:

```python
probs = softmax(logits)
entropy = −Σ(p × log(p))
```

*Low entropy* = model is extremely confident = the text is highly predictable = **likely AI-authored**. Human text with mixed complexity produces higher entropy.

### 10.4 Prong 3 — Gemma-3-12B Meta-Analysis via OpenRouter

Sends the email to the Gemma-3-12B model with a forensic linguistics prompt. The model is asked to return a JSON with `is_ai_generated`, `ai_probability`, `confidence`, `reasoning`, and `key_indicators`. Temperature = 0.1 for determinism.

### 10.5 Ensemble Fusion

```
All three available:   Stylometric×0.30 + Perplexity×0.25 + Gemma×0.45
Stylometric + Gemma:   Stylometric×0.40 + Gemma×0.60
Stylometric + BERT:    Stylometric×0.50 + Perplexity×0.50
Stylometric only:      raw stylometric score
```

Confidence is boosted when methods agree: `confidence = 0.5 + agreement×0.4 + n_methods×0.05`

**Verdict thresholds:** `LIKELY_AI` ≥ 0.70, `POSSIBLY_AI` ≥ 0.45, `LIKELY_HUMAN` < 0.45

---

## 11. Fusion Engine — `models/fusion_engine.py`

### 11.1 Confidence-Weighted Ensemble

Each model contributes `score × confidence × weight` to the numerator. The denominator sums `confidence × weight` across all active models. This means a model with low confidence (e.g., visual engine when screenshot fails → confidence 0.40) contributes proportionally less than a high-confidence NLP result (0.91).

```python
raw_score = (nlp_score×nlp_conf×w_nlp + url_score×url_conf×w_url +
             visual_score×vis_conf×w_vis + header_score×hdr_conf×w_hdr)
           / (nlp_conf×w_nlp + url_conf×w_url + vis_conf×w_vis + hdr_conf×w_hdr)

raw_score = min(raw_score + threat_intel_boost, 0.99)
```

### 11.2 Per-Input-Type Weights

| Layer | Email Analysis | URL Analysis | Mixed |
|---|---|---|---|
| NLP | **35%** | 8% | 32% |
| URL | 28% | **55%** | 30% |
| Visual | 18% | **30%** | 20% |
| Header | **19%** | 7% | 18% |

For URL-only analysis, NLP is nearly weightless because there is no email text to analyze.

### 11.3 Verdict + Action Mapping

| Score Range | Verdict | Recommended Action |
|---|---|---|
| 0.00–0.25 | SAFE | monitor |
| 0.25–0.55 | SUSPICIOUS | flag_for_review |
| 0.55–0.80 | PHISHING | quarantine_and_block |
| 0.80–1.00 | CRITICAL | quarantine_block_and_alert |

### 11.4 Tactic Deduplication

All tactics from all layers are merged into one list and deduplicated by MITRE ID — so if both NLP and header layers detect spoofing, only one `Email Spoofing` tactic appears in the final result.

---

## 12. Kill Chain Engine — `engines/kill_chain.py`

Maps every phishing detection to a 4-stage MITRE ATT&CK attack progression:

| Stage | Phase | MITRE Technique | PS Coverage |
|---|---|---|---|
| 1 | Initial Access | T1566 — Phishing | PS-01 |
| 2 | Credential Access | T1078 — Valid Accounts | PS-02 |
| 3 | Financial Impact | T1657 — Financial Theft | PS-03 |
| 4 | Lateral Movement | T1534 — Internal Spearphishing | PS-02 |

**Stage activation logic:**
- Stage 2 active if: visual model matched a brand **OR** `"credential"` appears in detected tactics
- Stage 3 active if: financial keywords appear in NLP top_phrases (`bank`, `paypal`, `payment`, `wire`, `transfer`, `invoice`, `billing`)
- Stage 4 active if: overall threat score ≥ 0.70

**Per-stage risk score:**
- Stage 2: `base_score × 1.1` if credential, else `base_score × 0.6`
- Stage 3: `base_score × 1.2` if financial, else `base_score × 0.4`
- Stage 4: `base_score × 0.7` if threat active, else 0

**Color coding:** red (≥0.65), amber (≥0.35), slate (inactive)

**Financial impact estimate:**
- CRITICAL + financial + FIN7 attribution → `$12,000–$85,000`
- CRITICAL + financial + other actor → `$5,000–$45,000`
- HIGH + credential → `$2,500–$15,000`
- MEDIUM → `$500–$5,000`
- LOW → `$0`

**Containment steps** are tiered by threat score:
- ≥0.35: Quarantine email, block IOC domains/IPs
- ≥0.65: Force password reset, enable MFA, open incident ticket
- ≥0.85: Escalate to L3 SOC, preserve forensic evidence, notify business units

---

## 13. XGBoost Meta-Classifier — `models/sentinel_fusion_model.py`

### 13.1 Architecture

A **second-level classifier** trained on the *outputs of the full Sentinel pipeline* applied to 6,700 real emails from the **TREC-2007 spam corpus** (5,182 spam / 1,518 ham). It treats the multi-layer analysis result dict as its input — effectively learning a data-driven calibration of the heuristic ensemble.

**Train/val/test split:** 70% / 15% / 15% (stratified by label)

### 13.2 Feature Vector — 125 Features

Features are extracted from the full analysis result object:

- **Core scores:** threat_score, confidence, verdict_encoded, recommended_action_encoded  
- **NLP features (12):** nlp_score, nlp_weight, nlp_source_encoded, top_phrase_count, tactic_count, per-tactic confidence for each of 10 tactic types  
- **URL features (37):** url_score, url_weight, url_count, 21 SHAP component values (`shap_ip_as_host`, `shap_brand_impersonation`, `shap_newly_registered`, `shap_urlhaus_hit`, ...), 15 raw lexical features (lengths, counts, entropy, boolean flags)  
- **Header features (15):** header_score, header_weight, flag_count, SPF/DKIM/DMARC encoded results, 10 binary flag features  
- **Threat intel features (7):** has_known_campaign, actor_confidence, related_domains_count, malicious_domain_count, feed_source_count, global_reach_count, ioc_risk_boost  
- **Dark web features (5):** dark_web_risk encoded, breach_count, total_exposed, source_count  
- **Kill chain features (9):** active_stage_count, overall_risk, attack_vector_encoded, is_brand_impersonation, per-stage risk scores (4), impact_level_encoded

### 13.3 Isotonic Probability Calibration

Raw XGBoost probabilities are passed through a piecewise-linear calibration curve derived from validation set reliability analysis:

| Raw | Calibrated | Purpose |
|---|---|---|
| 0.00 | 0.02 | Floor — never claim 0% risk |
| 0.10 | 0.08 | Pull slight over-confidence down |
| 0.30 | 0.28 | Preserve low-risk range |
| 0.50 | 0.50 | Identity at decision boundary |
| 0.70 | 0.72 | Slight boost for high-confidence positives |
| 0.90 | 0.88 | Pull back extreme over-confidence |
| 1.00 | 0.98 | Ceiling — never claim 100% certainty |

---

## 14. Threat Knowledge Graph — `intelligence/knowledge_graph.py`

### 14.1 Graph Composition

A **NetworkX directed graph** (`DiGraph`) containing:
- **5 Threat Actor nodes:** FIN7 (RU, Financial), Lazarus Group (KP, Espionage+Financial), APT28 (RU, Espionage), Scattered Spider (US/UK, Financial), LAPSUS$ (BR/UK, Extortion)
- **50 Campaign nodes:** Each with status (active/monitoring/closed), risk_level, sector targets, IOC lists (domains, IPs, hashes), timeline events, attribution
- **200+ Domain nodes:** Extracted from campaign IOC lists; linked to their campaign and actor
- **100+ IP nodes:** With ASN, country, city, reputation, campaign memberships
- **20 MITRE Technique nodes:** Full ATT&CK technique metadata

**Edges:** `CONDUCTS` (actor→campaign) · `USES_DOMAIN` (campaign→domain) · `OWNS_INFRASTRUCTURE` (actor→domain) · `USES_IP` (campaign→ip) · `CONTROLS` (actor→ip) · `EMPLOYS` (actor→technique)

### 14.2 IOC Correlation

`correlate_iocs(domains, ips)` iterates all 50 campaigns and checks for domain/IP overlap with input indicators:

```python
domain_hits = [d for d in domains 
               if any(d == cd or d.endswith("."+cd) or cd.endswith("."+d) 
                      for cd in camp_domains)]
```

On a hit, returns the campaign, actor attribution, and a confidence of 0.92. Risk elevation is applied: +0.20 for critical campaigns, +0.12 for high, +0.06 for medium — capped at +0.30 total.

### 14.3 D3.js Graph Export

`get_graph_data(depth, entity_type, center_node)` supports:
- Full graph export (all nodes/edges)
- Entity-type filter (show only actors, or only campaigns, etc.)
- Subgraph BFS from a center node at configurable depth

Output is D3-compatible `{nodes, edges, links}` with color coding: actors=`#ef4444`, campaigns=`#f59e0b`, domains=`#3b82f6`, IPs=`#10b981`, techniques=`#8b5cf6`.

### 14.4 Live OSINT Feed Ingestion — `intelligence/feed_ingester.py`

On startup, three external threat intelligence feeds are fetched and merged into the knowledge graph:

- **ThreatFox (abuse.ch)** malicious IOC API
- **URLhaus (abuse.ch)** malicious URL list
- **PhishTank** community-reported phishing URLs

IOCs are normalized (domain extraction, deduplication) and injected as new domain/IP nodes linked to synthetic campaign entries. A background `feed_refresh_loop()` re-fetches every 6 hours.

---

## 15. Gmail Integration — `routers/gmail.py`

### 15.1 OAuth2 Flow (Real Mode)

1. `GET /api/v1/gmail/auth-url` → backend generates Google OAuth2 URL with scope `gmail.readonly`
2. User redirected to Google consent screen
3. Google redirects back with `?code=...` to `/api/v1/gmail/callback`
4. Backend POSTs to `https://oauth2.googleapis.com/token` to exchange code for `access_token` + `refresh_token`
5. Gmail API service built; user email fetched from `users.getProfile()`
6. Credentials persisted to `backend/data/gmail_token.json` and survive backend restarts

**Demo Mode:** When Google credentials are not configured, `GET /api/v1/gmail/demo-connect` activates 8 hardcoded pre-classified demo emails spanning all verdict tiers.

### 15.2 Inbox Fetch + Analysis Pipeline

`_fetch_real_inbox(session)` implements a **cache-first strategy**:

1. Lists current inbox message IDs (lightweight API call — no body fetched)
2. Identifies IDs not yet in `_gmail_cache` dictionary
3. Fetches full message objects for up to 3 new emails (controlled API cost)
4. Runs `_analyze_and_cache(msg, session)` in parallel via `asyncio.gather`
5. Returns all inbox emails in original order from cache

**`_analyze_and_cache()` per message:**
- Parses MIME structure recursively: extracts `From`/`Subject`/body (prefers `text/plain`, falls back to stripped `text/html`), attachment metadata
- Detects "image-heavy flyer" emails (< 200 chars body + image attachments): injects analyst note informing the LLM
- **PII Redaction:** `redact_pii(email_content)` strips real names, email addresses, phone numbers before sending to LLM
- Runs `_run_full_analysis(redacted_content, "email")` — the complete 5-layer pipeline
- Downloads attachment bytes for scannable file types (controlled by `_CONTENT_SCAN_EXTS` set)
- Runs `analyze_attachments_with_bytes()` for all attachments
- **Risk boost:** if `attachment_risk > 0.65`, the email's final `risk_score += 0.15`
- Writes finished entry to `_gmail_cache` and persists to disk as JSON

### 15.3 MIME Parsing Details

`_collect_body_parts(payload, plains, htmls)` recursively walks the MIME part tree. For `multipart/*` messages it dives into `parts[]`. Inline images (CID attachments) are captured as attachment metadata with `"inline": true`. `_decode_body()` prefers `text/plain` when ≥ 120 characters; falls back to stripped `text/html`.

RFC 2047 encoded header values (e.g., `=?UTF-8?B?...?=`) are decoded via Python's `email.header.decode_header()`.

---

## 16. URL Sandbox — `routers/sandbox.py`

Deep behavioral analysis running four probes in parallel:

### 16.1 Redirect Chain Unwinding

`_unwind_redirects(url)` uses `httpx` with `follow_redirects=False` to manually follow each hop. Tracks up to 10 intermediate URLs. Detects domain changes across the chain (a strong phishing signal — original link goes to `bitly.com`, ends at `paypal-verify.xyz`).

### 16.2 SSL Certificate Inspection

`_get_ssl_info(hostname)` connects to port 443 via raw socket + `ssl.create_default_context()`. Extracts: `issuer`, `subject`, `notAfter` expiry, Subject Alternative Names. `SSLCertVerificationError` is caught and flagged as "self-signed or expired."

### 16.3 DOM Scraping

`_scrape_page_info(url)` fetches HTML with a realistic browser User-Agent. Extracts:
- Page `<title>`
- Input elements of type `password`, `email`, `text` (password field = high-risk)
- External `<script src="...">` URLs from foreign domains
- `<iframe src="...">` count
- 15 hardcoded suspicious keywords scanned in the HTML body

**Credential harvesting detection:** `has_password_field AND len(suspicious_keywords) >= 2`

### 16.4 Risk Scoring

| Signal | Risk Added |
|---|---|
| ≥ 3 redirect hops | +0.25 |
| Invalid SSL cert | +0.20 |
| Password field present | +0.20 |
| Credential harvesting indicators | +0.15 |
| Domain changed across redirect chain | +0.15 |
| Suspicious keyword hits (×0.02 each) | up to +0.10 |
| > 2 iframes | +0.10 |

Verdict: PHISHING (≥0.65), SUSPICIOUS (≥0.35), CLEAN.

---

## 17. QR Quishing Module — `routers/quishing.py`

### 17.1 Why This Matters

QR code phishing ("Quishing") bypasses all standard email link scanners because the malicious URL is encoded in an image — no plain-text URL exists in the email body. Attack volume grew 587% in 2023-2025.

### 17.2 Decode Pipeline

```
Image upload (multipart or base64)
        │
        ├─► pyzbar.decode(PIL.Image)     ←── primary (fast, high accuracy)
        │
        └─► cv2.QRCodeDetector()         ←── fallback (OpenCV, no pyzbar needed)
```

If decoded content starts with `http`/`www` → forwarded to `_run_full_analysis(url, "url")` — the complete 5-layer pipeline runs on the embedded URL.

Non-URL QR content (vCards, plain text, WiFi credentials) is returned without analysis with `"is_url": false`.

### 17.3 Two Endpoints

- `POST /api/v1/quishing/decode` — accepts `multipart/form-data` image upload (max 10MB)
- `POST /api/v1/quishing/decode-base64` — accepts base64 data URL (from browser webcam canvas capture)

---

## 18. Dashboard — `routers/dashboard.py` + Frontend

### 18.1 Backend KPI Endpoint

`GET /api/v1/dashboard/metrics` combines:
- **Live session counters** from `_analysis_counter` (updated on every analysis)
- **Seeded historical baseline** (48,902 analyses, 1,284 threats) for a credible demo
- **Real AI accuracy** computed as average of XGBoost URL classifier + BERT phishing model evaluation metrics fetched live

### 18.2 Threat Feed

`GET /api/v1/dashboard/feed` cycles through 20 curated threat event templates (BEC interceptions, malware blocks, credential stuffing detections, wire fraud flags, etc.). Each call rotates the cursor by 1, randomizes timestamps within the past 120 minutes. Simulates a live SOC event stream.

### 18.3 Timeline Data

`GET /api/v1/dashboard/timeline` generates hourly threat counts for the past N hours with realistic patterns: business hours (9am–6pm) have higher baseline counts than off-hours.

### 18.4 Frontend Dashboard Page (`app/dashboard/page.tsx`)

Fetches 4 APIs in parallel on mount and refreshes every 30 seconds. Renders with **Framer Motion** staggered animations (0.1s delay between KPI cards).

**KPI Cards:** Threats Detected, Total Analyzed, Detection Speed, AI Accuracy — all from live backend data with Framer Motion entry animations.

**Quick Scan Widget:** Inline URL/email input → detects if input is a URL or text → calls appropriate endpoint → shows verdict badge inline without leaving the page.

**Model Performance Panel:** Conditionally rendered only when real evaluation metrics exist. Shows F1, AUC, Accuracy, Precision, Recall side-by-side for XGBoost URL classifier and BERT phishing detector.

**Threat Timeline** (`ThreatTimeline`): 24h stacked bar chart (phishing + suspicious) from `GET /api/v1/history/trends`.

**Risk Donut** (`RiskDonut`): Recharts donut chart of SAFE / SUSPICIOUS / PHISHING / CRITICAL breakdown from history stats.

**Threat Feed** (`ThreatFeed`): Scrolling event feed polling `/api/v1/dashboard/feed` every 30s.

---

## 19. WebSocket Streaming — `routers/stream.py`

`WS /api/v1/stream` maintains a set of active WebSocket connections. `emit_threat_event(data)` broadcasts a JSON payload to all connected clients.

The analyze pipeline emits events at each stage:

| Step | Event Type | Key Data |
|---|---|---|
| 0 | `pipeline_start` | input_type, status: running |
| 1 | `nlp` | score, confidence, detected tactics, phishing intent |
| 2 | `header` | SPF/DKIM/DMARC, flag list |
| 3 | `url` | risk score, domain age, blacklist hit, top features |
| 3 | `llm_fingerprint` | ai_probability, verdict |
| 4 | `visual` | brand match, similarity score, screenshot path |
| 5 | `intel` | IOC match count, risk boost, first-contact flag |
| Final | `analysis_complete` | full result object with all fields |

Frontend components subscribe on mount and update their state as each event arrives — creating a live "analysis in progress" experience with progressive result reveal.

---

## 20. SentinelChat — `chat/`

### RAG Pipeline (`chat/rag_pipeline.py`)

ChromaDB vector store pre-populated with cybersecurity knowledge documents. On each chat query:
1. Query is embedded
2. Top-k most similar document chunks retrieved
3. Retrieved context injected into the LLM system prompt

### Chat API (`routers/chat.py`)

`POST /api/v1/chat` handles multi-turn conversations. Uses `OPENROUTER_CHAT_MODEL` (currently `google/gemma-3-12b-it`). Conversation history maintained client-side and sent with each request to preserve context.

### Explanation Generator (`chat/sentinel_chat.py`)

`generate_explanation_narrative(result, content_preview)` constructs a structured prompt containing the verdict, threat score, top 3 tactics, threat actor attribution, and MITRE IDs, then asks the LLM to write a 2-3 sentence plain-English explanation. This text populates the `ExplanationCard` component in the analyze UI.

---

## 21. Analysis Frontend Components — `components/analyze/`

18 modular React components render the analysis result:

| Component | Purpose |
|---|---|
| `AnalysisInputSection` | Multi-tab input (Email · URL · Headers · File · QR Code), triggers analysis |
| `ThreatScoreCard` | Animated radial gauge showing `threat_score` with verdict badge |
| `AnalysisSummaryBanner` | Top-banner with "so what?" one-liner + recommended action button |
| `ColorCodedKillChain` | 4-stage kill chain with color-coded risk levels (red/amber/slate) |
| `ModelBreakdown` | Per-layer score bars (NLP, URL, Visual, Header) with weights |
| `EvidencePanel` | All detected tactics with MITRE IDs and confidence indicators |
| `EvidenceChainCard` | Evidence timeline cards linking each finding to its source layer |
| `ExplanationCard` | LLM-generated narrative explanation rendered as structured text |
| `LLMFingerprintCard` | AI authorship probability + stylometric component scores + verdict |
| `IntelCard` | Threat actor name, campaign ID, attribution confidence, IOC sources |
| `TacticsCard` | Compact MITRE ATT&CK tactic list with technique IDs |
| `ShapChart` | Recharts bar chart of SHAP URL feature importance values |
| `SenderFirstContactCard` | Domain novelty alert with first-seen timestamp |
| `DeepDivePanel` | Extended analysis controls (visual scan toggle, deep options) |
| `TransparencyPanel` | Full raw JSON result + all model layer outputs for audit |
| `InputPanel` | Displays the submitted content (email, URL, etc.) with preview |
| `ExecutionTraceCard` | For file uploads: step-by-step trace of what the file would do |
| `InputTypeCard` | Badge indicating which input type was used |

---

## 22. Behavioral Analysis Modules — `behavioral/`

### Bot Detector (`behavioral/bot_detector.py`) — PS-02

Detects automated credential stuffing attacks by analyzing:
- Request rate uniformity (bots are suspiciously regular; humans are not)
- Inter-request timing variance
- User-agent string consistency across requests
- IP geolocation spread (same credentials from 3 countries in 4 minutes)
- Failed authentication ratio

### Fraud Correlator (`behavioral/fraud_correlator.py`) — PS-03

Correlates phishing detections with downstream fraud signals:
- Wire transfer requests following credential theft events
- Payment method / bank account changes post-phishing
- Cross-account behavioral anomalies (access from new device/location after phishing)

---

## 23. Attachment Analyzer — `models/attachment_analyzer.py`

Performs **Tier-2 static content inspection** on uploaded files (max 20MB):

- **Office OOXML** (DOCX/XLSX/PPTX): ZIP archive inspection for VBA macro streams, embedded OLE objects, external data connections
- **PDF**: Checks for embedded JavaScript, `/Launch` actions, external payload URLs, encrypted streams
- **EXE/PE**: Reads PE header — checks for packed sections, suspicious import table entries
- **ZIP archives**: Inspects contents recursively for nested executables or scripts
- **HTML/SVG**: Scans for obfuscated scripts, data URIs, credential-form patterns

`generate_execution_trace(filename, findings, data)` constructs a step-by-step "if this file were opened" impact trace. `enrich_trace_with_live_probing()` then follows any URLs found in the file — checks SSL, follows redirects, detects credential form presence.

---

## 24. Technology Stack

| Layer | Technology |
|---|---|
| **API Framework** | FastAPI 0.110 + Uvicorn |
| **Primary LLM** | Gemma-3-12B-IT via OpenRouter |
| **BERT Model** | HuggingFace `transformers` — fine-tuned on ISCX-2016 |
| **URL ML** | XGBoost (scikit-learn API) — 31 URL features |
| **Meta-Classifier** | XGBoost — 125 features, trained on TREC-2007 pipeline outputs |
| **Screenshot** | Apify Actor FU5kPkREa2rdypuqb (Playwright headless browser) |
| **CLIP Vision** | Replicate API — model version 75b33f25 |
| **Threat Graph** | NetworkX DiGraph |
| **Vector Store** | ChromaDB (RAG pipeline) |
| **Dark Web** | HaveIBeenPwned API v3 |
| **OSINT Feeds** | ThreatFox · URLhaus · PhishTank (all free APIs) |
| **Gmail** | Google Gmail API v1 + OAuth2 (read-only scope) |
| **QR Decode** | pyzbar (primary) + OpenCV `QRCodeDetector` (fallback) |
| **DNS Lookup** | dnspython |
| **WHOIS** | python-whois |
| **HTTP Client** | httpx (async) + requests (sync wrappers in threads) |
| **Frontend** | Next.js 14 (App Router) + TypeScript |
| **UI Primitives** | shadcn/ui + Radix UI + Tailwind CSS |
| **Charts** | Recharts |
| **Animations** | Framer Motion |
| **Real-time** | WebSocket (FastAPI native) |

---

## 25. Data Flow — End to End

```
User Input
(Email text / URL string / QR image / File upload / Gmail inbox)
         │
         ▼
FastAPI Router (analyze.py / sandbox.py / quishing.py / gmail.py / bulk.py)
         │
         ├── [Layer 1, parallel] ──────────────────────────────────┐
         │    NLP Engine                                            │
         │     ├─ GPT-4o-mini (OpenRouter) ← structured prompt     │
         │     ├─ BERT Phishing Model ← ISCX-2016 fine-tuned       │
         │     └─ Heuristic fallback ← regex pattern matching       │
         │    Header Analyzer                                        │
         │     ├─ SPF/DKIM/DMARC parsing                           │
         │     └─ Routing + spoofing flags                          │
         │                                                           │ WebSocket
         ├── [Layer 2, parallel] ──────────────────────────────────┤ events
         │    URL Analyzer                                           │ emitted
         │     ├─ 150+ feature extraction (sync)                   │ at each
         │     ├─ WHOIS / DNS / URLhaus (async parallel)           │ step
         │     └─ XGBoost URL classifier                            │
         │    LLM Fingerprint Detector                               │
         │     ├─ Stylometric analysis (5 signals)                  │
         │     ├─ BERT perplexity proxy                             │
         │     └─ Gemma-3-12B meta-analysis                         │
         │                                                           │
         ├── [Layer 3, optional] ──────────────────────────────────┤
         │    Visual Engine                                          │
         │     ├─ Apify Playwright screenshot                        │
         │     ├─ Replicate CLIP embedding                          │
         │     └─ Cosine similarity vs 18 brand profiles            │
         │                                                           │
         ├── [Layer 4+] ───────────────────────────────────────────┤
         │    Threat Knowledge Graph IOC correlation                 │
         │    Live OSINT feed enrichment (URLhaus / PhishTank)      │
         │    Sender first-contact domain tracking                   │
         │    Dark web exposure check (HaveIBeenPwned)              │
         │                                                           │
         ▼                                                           │
    Fusion Engine (confidence-weighted ensemble)                    │
         │                                                           │
         ▼                                                           │
    Kill Chain Builder (4-stage MITRE ATT&CK mapping)              │
         │                                                           │
         ▼                                                           │
    LLM Explanation Generator (Gemma-3 narrative)                  │
         │                                                           │
         ▼                                                           │
    XGBoost Meta-Classifier (125 features → calibrated probability)│
         │                                                           │
         ▼                                                           ▼
    Final Result Object                                      WebSocket
    ─────────────────────                                  "analysis_complete"
    threat_score (0–1, calibrated)
    verdict (SAFE/SUSPICIOUS/PHISHING/CRITICAL)
    confidence + confidence_interval
    model_breakdown (per-layer scores + weights)
    detected_tactics (MITRE-tagged, deduplicated)
    kill_chain (4 stages + containment + impact)
    llm_fingerprint (AI authorship detection)
    threat_intelligence (actor, campaign, IOCs)
    dark_web_exposure (breach count, risk level)
    explanation_narrative (plain-English LLM text)
    so_what (one-liner verdict summary)
    inference_time_ms + inference_time_label
         │
         ├──► In-memory result cache (_result_cache, max 500 LRU)
         ├──► Analysis history (JSON, persistent)
         ├──► Dashboard counters (live KPIs)
         └──► WebSocket broadcast to all subscribed frontend clients
```

---

## 26. API Reference Summary

| Method | Endpoint | Description |
|---|---|---|
| POST | /api/v1/analyze/email | Full 5-layer email analysis |
| POST | /api/v1/analyze/url | Full 5-layer URL analysis |
| POST | /api/v1/analyze/headers | Email header forensics |
| POST | /api/v1/analyze/attachment | File upload inspection |
| POST | /api/v1/sandbox/analyze | Deep URL behavioral sandbox |
| POST | /api/v1/quishing/decode | QR code image → URL analysis |
| POST | /api/v1/quishing/decode-base64 | Base64 QR → URL analysis |
| POST | /api/v1/bulk/upload | CSV batch file analysis |
| GET | /api/v1/gmail/auth-url | Start Gmail OAuth2 flow |
| GET | /api/v1/gmail/callback | OAuth2 redirect handler |
| GET | /api/v1/gmail/demo-connect | Activate demo inbox mode |
| GET | /api/v1/gmail/inbox | Fetch + analyze Gmail inbox |
| POST | /api/v1/gmail/analyze/{id} | Analyze specific Gmail message |
| GET | /api/v1/dashboard/metrics | Live KPI metrics |
| GET | /api/v1/dashboard/feed | Live threat event feed |
| GET | /api/v1/dashboard/timeline | Hourly threat timeline |
| GET | /api/v1/history | Past analysis records |
| GET | /api/v1/history/stats | Aggregate statistics |
| GET | /api/v1/history/trends | Hourly trend data (24h) |
| GET | /api/v1/campaigns | Campaign intelligence list |
| GET | /api/v1/intelligence/graph | D3 knowledge graph data |
| POST | /api/v1/chat | SentinelChat conversational AI |
| POST | /api/v1/feedback | Analyst verdict feedback |
| POST | /api/v1/reports/generate | PDF/JSON incident report |
| WS | /api/v1/stream | Real-time pipeline events |
| GET | /health | System health + model status |

---

*SentinelAI Fusion v3.0.0 — Documentation generated April 2026*
