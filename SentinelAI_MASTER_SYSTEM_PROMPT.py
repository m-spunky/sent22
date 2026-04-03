"""
IMPORTANT: This is NOT a chatbot prompt. This is a comprehensive BUILD
SPECIFICATION and system prompt that defines every aspect of SentinelAI Fusion.
Use this as the single source of truth when building any component of the system.
Feed relevant sections to your AI coding assistant when building specific modules.
"""
# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: PROJECT IDENTITY & MISSION
# ═══════════════════════════════════════════════════════════════════════════════

PROJECT_IDENTITY = """
MISSION STATEMENT:
SentinelAI Fusion is a unified, multi-layered AI-powered cyber threat intelligence
and defense platform. It transforms phishing detection from a single-point classifier
into an interconnected intelligence mesh that simultaneously:

  1. Detects phishing via multi-modal AI analysis (NLP + URL + Vision + Metadata)
  2. Maps threat actor campaigns via a dynamic knowledge graph
  3. Correlates phishing with credential stuffing and financial fraud signals
  4. Provides natural language security operations via SentinelChat
  5. Delivers full explainability for every detection decision

This is NOT a basic phishing classifier. It is an enterprise-grade cyber threat
intelligence platform that addresses ALL 5 hackathon problem statements through
one cohesive architecture.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PROBLEM STATEMENT COVERAGE:
  PS-01 (PRIMARY): AI-Powered Phishing Detection System
      → Multi-modal detection core with 4 parallel AI models + fusion engine
  PS-02 (INTEGRATED): Detection of Automated Attacks on FinTech
      → Behavioral biometrics module + credential stuffing detection
  PS-03 (INTEGRATED): Financial Fraud Detection System
      → Phishing-to-fraud correlation engine + transaction anomaly bridge
  PS-04 (INTEGRATED): Security Operations Chatbot
      → SentinelChat — RAG-powered natural language security assistant
  PS-05 (INTEGRATED): Dark Web Threat Intelligence System
      → Threat intelligence enrichment pipeline + knowledge graph

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: COMPLETE TECHNOLOGY STACK
# ═══════════════════════════════════════════════════════════════════════════════

TECH_STACK = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FRONTEND (User Interface & Visualization Layer)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Framework:          Next.js 14+ (App Router)
  UI Library:         React 18+
  Styling:            Tailwind CSS + shadcn/ui components
  Visualization:      D3.js (knowledge graph), Recharts (charts/timelines)
  State Management:   Zustand or React Context
  Animation:          Framer Motion
  Icons:              Lucide React
  Theme:              Dark mode primary (cybersecurity aesthetic)
                      Color palette: Deep navy (#0a0e1a), Electric blue (#3b82f6),
                      Amber accent (#f59e0b), Cyan (#06b6d4), Emerald (#10b981)
  Fonts:              JetBrains Mono (code/data), Inter (UI text)
  Deployment:         Vercel (existing: senti-ai-sepia.vercel.app)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BACKEND (API & Application Layer)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Framework:          FastAPI (Python 3.11+) — async, high-performance
  Language:           Python (core logic & ML), TypeScript (API routes in Next.js)
  API Style:          RESTful + WebSocket (real-time threat feed)
  Auth:               JWT tokens + session-based (for hackathon demo)
  CORS:               Configured for Vercel frontend origin
  Docs:               Auto-generated Swagger/OpenAPI at /docs
  Rate Limiting:      Simple in-memory rate limiter for demo
  Deployment:         Railway / Render / local Docker

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AI / ML (Models & Intelligence Layer)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  NLP Model:          HuggingFace Transformers
                        - Primary: SecurityBERT or CySecBERT (cybersec fine-tuned)
                        - Fallback: DistilBERT (lighter, faster for hackathon)
                        - Task: Sequence classification (phishing intent detection)
  URL/Feature ML:     XGBoost + LightGBM ensemble
                        - 150+ engineered URL features
                        - SHAP for feature importance explainability
  Visual Analysis:    PyTorch — ResNet50 backbone
                        - Siamese network architecture for brand comparison
                        - 500+ brand template library (logos, login page layouts)
  Header Analysis:    Scikit-learn — Statistical anomaly models
                        - SPF/DKIM/DMARC validation scoring
                        - Routing path anomaly detection
  Fusion Engine:      Custom attention-weighted ensemble
                        - Learned weights per modality per attack type
                        - Outputs: unified_threat_score (0-1) + per-model breakdown
  LLM (Chatbot):      OpenAI API (GPT-4o-mini or GPT-4o)
                        - Fallback: Ollama running Llama 3 8B locally
                        - Used for: SentinelChat, explanation generation
  RAG Pipeline:       LangChain + ChromaDB/FAISS vector store
                        - Embeds: threat reports, platform data, MITRE ATT&CK
                        - Retrieval: semantic search over security knowledge base
  Explainability:     SHAP (feature attribution) + LLM narrative generation

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DATA & INFRASTRUCTURE (Storage, Streaming & DevOps)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Primary DB:         PostgreSQL (structured data, user records, scan history)
  Time-Series:        TimescaleDB extension (threat activity timelines)
  Graph DB:           Neo4j (threat knowledge graph — actors, campaigns, IOCs)
                        - Fallback: NetworkX in-memory + D3.js visualization
  Vector DB:          ChromaDB or FAISS (RAG embeddings for SentinelChat)
  Cache/Sessions:     Redis (session state, real-time stream buffer)
  Streaming:          Redis Streams or Apache Kafka (real-time threat events)
                        - For hackathon: Redis Streams (simpler setup)
  Containerization:   Docker + Docker Compose (full stack orchestration)
  CI/CD:              GitHub Actions → Vercel (frontend), Railway (backend)
"""
# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: FIVE-LAYER SYSTEM ARCHITECTURE (DETAILED)
# ═══════════════════════════════════════════════════════════════════════════════

ARCHITECTURE = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THE FIVE-LAYER INTELLIGENCE STACK
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Data flows TOP → BOTTOM through 5 layers, with a feedback loop from Layer 5
back to Layer 1 for continuous learning.

┌─────────────────────────────────────────────────────────────────────────┐
│  LAYER 1: INGESTION & PREPROCESSING ENGINE                             │
│  ─────────────────────────────────────────                             │
│  Email Parser → URL Analyzer → Stream Processor → Data Normalizer      │
│                                                                         │
│  • Email Parser Module:                                                 │
│    - Accepts raw email content (MIME format) or plain text paste        │
│    - Extracts: headers (From, Reply-To, Return-Path, X-headers),       │
│      body text (HTML + plaintext), embedded URLs, attachment metadata   │
│    - Python library: email.parser + BeautifulSoup for HTML parsing      │
│                                                                         │
│  • URL Analyzer Module:                                                 │
│    - Input: Any URL or domain string                                    │
│    - Performs: DNS resolution (A, MX, NS records), WHOIS lookup         │
│      (registrar, creation date, expiry), SSL certificate analysis       │
│      (issuer, validity, SAN), redirect chain traversal (up to 10 hops),│
│      final page content capture via headless browser (Playwright)       │
│    - Python libraries: dnspython, python-whois, requests, playwright   │
│                                                                         │
│  • Stream Processor:                                                    │
│    - Redis Streams for real-time event ingestion                        │
│    - Each input becomes a "ThreatEvent" with unique event_id, timestamp │
│    - Supports batch and single-event processing modes                   │
│                                                                         │
│  • Data Normalizer:                                                     │
│    - Converts all inputs into unified ThreatEvent schema                │
│    - Schema fields: event_id, timestamp, source_type (email/url/manual),│
│      raw_content, extracted_urls[], extracted_text, headers{},           │
│      metadata{}, processing_status                                      │
│    - STIX/TAXII compatible output format for threat intel sharing       │
│                                                                         │
│  API ENDPOINTS:                                                         │
│    POST /api/v1/analyze/email     — Submit email for analysis           │
│    POST /api/v1/analyze/url       — Submit URL for analysis             │
│    POST /api/v1/analyze/bulk      — Submit multiple items               │
│    GET  /api/v1/events/{id}       — Get event processing status         │
│    WS   /api/v1/stream            — Real-time event stream              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  LAYER 2: MULTI-MODAL AI DETECTION CORE (PS-01 PRIMARY)                │
│  ──────────────────────────────────────────────────────                 │
│  4 Parallel AI Models → Fusion Engine → Unified Threat Score           │
│                                                                         │
│  ┌──────────────────┐  ┌──────────────────┐                            │
│  │ MODEL A: NLP     │  │ MODEL B: URL     │                            │
│  │ Intent Analyzer   │  │ Risk Scorer      │                            │
│  │                   │  │                   │                            │
│  │ Input: email text │  │ Input: URL string │                            │
│  │ Model: fine-tuned │  │ Model: XGBoost +  │                            │
│  │ SecurityBERT      │  │ LightGBM ensemble │                            │
│  │                   │  │                   │                            │
│  │ Detects:          │  │ Features (150+):  │                            │
│  │ • Urgency tactics │  │ • Domain age      │                            │
│  │   ("act now")     │  │ • Registrar rep   │                            │
│  │ • Authority       │  │ • URL entropy     │                            │
│  │   impersonation   │  │ • Path depth      │                            │
│  │ • Emotional       │  │ • Subdomain count │                            │
│  │   manipulation    │  │ • SSL validity    │                            │
│  │ • Reward/threat   │  │ • DNS record age  │                            │
│  │   framing         │  │ • Redirect count  │                            │
│  │ • Context misuse  │  │ • Hosting rep     │                            │
│  │   (BEC patterns)  │  │ • Lexical patterns│                            │
│  │                   │  │ • TLD risk score  │                            │
│  │ Output:           │  │ • Typosquatting   │                            │
│  │ intent_score: 0-1 │  │   similarity      │                            │
│  │ detected_tactics[]│  │                   │                            │
│  │ explanation_text  │  │ Output:           │                            │
│  │ confidence: 0-1   │  │ url_risk: 0-1     │                            │
│  └──────────────────┘  │ shap_values{}     │                            │
│                         │ top_features[]    │                            │
│  ┌──────────────────┐  │ confidence: 0-1   │                            │
│  │ MODEL C: VISUAL  │  └──────────────────┘                            │
│  │ Brand Engine      │                                                   │
│  │                   │  ┌──────────────────┐                            │
│  │ Input: screenshot │  │ MODEL D: HEADER  │                            │
│  │ of rendered page  │  │ Anomaly Detector  │                            │
│  │                   │  │                   │                            │
│  │ Model: Siamese    │  │ Input: email      │                            │
│  │ CNN (ResNet50)    │  │ headers dict      │                            │
│  │                   │  │                   │                            │
│  │ Process:          │  │ Checks:           │                            │
│  │ 1. Render URL via │  │ • SPF pass/fail   │                            │
│  │    headless browser│ │ • DKIM signature  │                            │
│  │ 2. Screenshot page│  │ • DMARC policy    │                            │
│  │ 3. Compare against│  │ • Reply-To ≠ From │                            │
│  │    brand template │  │ • X-Mailer anomaly│                            │
│  │    library (500+) │  │ • Routing hops    │                            │
│  │ 4. Logo detection │  │ • Time zone shift │                            │
│  │    + layout match │  │ • Encoding anomaly│                            │
│  │                   │  │                   │                            │
│  │ Output:           │  │ Output:           │                            │
│  │ brand_match: 0-1  │  │ anomaly_score: 0-1│                            │
│  │ matched_brand     │  │ flags[]           │                            │
│  │ similarity_heatmap│  │ spf_result        │                            │
│  │ confidence: 0-1   │  │ dkim_result       │                            │
│  └──────────────────┘  │ dmarc_result      │                            │
│                         │ confidence: 0-1   │                            │
│                         └──────────────────┘                            │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    FUSION ENGINE                                 │    │
│  │  ─────────────────────────────────                              │    │
│  │  Type: Attention-weighted ensemble with learned modality weights │    │
│  │                                                                  │    │
│  │  Input: [nlp_score, url_score, visual_score, header_score]      │    │
│  │         + confidence values from each model                      │    │
│  │                                                                  │    │
│  │  Process:                                                        │    │
│  │  1. Each model output is normalized to [0, 1]                   │    │
│  │  2. Attention mechanism weighs models based on input type:       │    │
│  │     - Email-only input → higher NLP + header weight             │    │
│  │     - URL-only input → higher URL + visual weight               │    │
│  │     - Full input → balanced adaptive weights                    │    │
│  │  3. Weighted combination: Σ(αᵢ × scoreᵢ × confidenceᵢ)       │    │
│  │  4. Calibration layer ensures score distribution is meaningful   │    │
│  │                                                                  │    │
│  │  Output:                                                         │    │
│  │  {                                                               │    │
│  │    "threat_score": 0.0-1.0,         // unified phishing score   │    │
│  │    "verdict": "SAFE|SUSPICIOUS|PHISHING|CRITICAL",              │    │
│  │    "confidence": 0.0-1.0,           // fusion confidence        │    │
│  │    "model_breakdown": {             // per-model detail         │    │
│  │      "nlp": { score, weight, tactics[], explanation },          │    │
│  │      "url": { score, weight, top_features[], shap },           │    │
│  │      "visual": { score, weight, matched_brand, heatmap },      │    │
│  │      "header": { score, weight, flags[], auth_results }         │    │
│  │    },                                                            │    │
│  │    "detected_tactics": [...],       // MITRE ATT&CK mapped     │    │
│  │    "recommended_action": "...",     // automated suggestion     │    │
│  │    "explanation_narrative": "..."   // LLM-generated summary    │    │
│  │  }                                                               │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  API ENDPOINTS:                                                         │
│    POST /api/v1/detect              — Run full multi-modal analysis     │
│    GET  /api/v1/detect/{id}/result  — Get detection result              │
│    GET  /api/v1/detect/{id}/explain — Get full explainability report    │
│    POST /api/v1/detect/url-only     — URL-only quick scan              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  LAYER 3: THREAT INTELLIGENCE ENRICHMENT (PS-05)                       │
│  ───────────────────────────────────────────────                       │
│  IOC Extractor → Knowledge Graph → Threat Correlator                   │
│                                                                         │
│  • IOC Extractor:                                                       │
│    - NER model (spaCy + custom cybersec entity rules) extracts:        │
│      IP addresses, domains, file hashes (MD5/SHA1/SHA256),             │
│      CVE identifiers, malware names, threat actor names, TTPs          │
│    - Sources: MITRE ATT&CK database, AlienVault OTX pulse feed,       │
│      abuse.ch URLhaus + MalwareBazaar, PhishTank verified feed,        │
│      VirusTotal API (if available)                                      │
│    - Extracts and indexes IOCs from unstructured text (threat          │
│      reports, security advisories, simulated dark web data)            │
│                                                                         │
│  • Knowledge Graph (Neo4j):                                             │
│    Node Types:                                                          │
│      - ThreatActor (name, aliases, motivation, country, first_seen)    │
│      - Campaign (id, name, start_date, target_sector, status)          │
│      - Domain (fqdn, registrar, creation_date, ip_resolved)           │
│      - IPAddress (ip, asn, geolocation, reputation_score)              │
│      - MalwareSample (hash, family, type, first_seen)                  │
│      - AttackTechnique (mitre_id, tactic, technique, description)      │
│      - Organization (name, sector, country)  // targets                │
│      - PhishingEmail (subject, sender, detection_score, timestamp)     │
│                                                                         │
│    Edge Types:                                                          │
│      - ATTRIBUTED_TO (Campaign → ThreatActor)                         │
│      - USES_DOMAIN (Campaign → Domain)                                 │
│      - RESOLVES_TO (Domain → IPAddress)                                │
│      - DEPLOYS (ThreatActor → MalwareSample)                          │
│      - EMPLOYS_TECHNIQUE (Campaign → AttackTechnique)                  │
│      - TARGETS (Campaign → Organization)                               │
│      - ASSOCIATED_WITH (Domain ↔ Domain, IP ↔ IP)                    │
│      - DETECTED_IN (PhishingEmail → Campaign)                          │
│                                                                         │
│    Sample Cypher Queries:                                               │
│      // Find all domains linked to a threat actor                      │
│      MATCH (a:ThreatActor {name: "FIN7"})-[:ATTRIBUTED_TO]-           │
│            (c:Campaign)-[:USES_DOMAIN]→(d:Domain) RETURN d             │
│                                                                         │
│      // Find campaigns sharing infrastructure                          │
│      MATCH (c1:Campaign)-[:USES_DOMAIN]→(d:Domain)←[:USES_DOMAIN]-   │
│            (c2:Campaign) WHERE c1 <> c2 RETURN c1, c2, d              │
│                                                                         │
│  • Threat Correlator:                                                   │
│    - For every new detection, automatically queries the knowledge      │
│      graph to find related campaigns, actors, and infrastructure       │
│    - Enrichment process:                                                │
│      1. Extract IOCs from current detection (URLs, IPs, domains)       │
│      2. Query graph: "Do any of these IOCs appear in known campaigns?"│
│      3. If match found: pull campaign profile, actor attribution,      │
│         associated techniques, and historical targeting data           │
│      4. Escalate threat score if linked to known APT campaign          │
│      5. Generate enrichment summary for explainability layer           │
│                                                                         │
│  API ENDPOINTS:                                                         │
│    GET  /api/v1/intelligence/graph      — Get knowledge graph data     │
│    GET  /api/v1/intelligence/actor/{id} — Get threat actor profile     │
│    GET  /api/v1/intelligence/campaign/{id} — Get campaign details      │
│    POST /api/v1/intelligence/correlate  — Correlate IOCs with graph    │
│    GET  /api/v1/intelligence/iocs       — List all indexed IOCs        │
│    POST /api/v1/intelligence/search     — Search graph by query        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  LAYER 4: BEHAVIORAL & ATTACK DETECTION (PS-02 + PS-03)                │
│  ──────────────────────────────────────────────────────                 │
│  Bot Detection → Credential Monitor → Fraud Correlator → Risk Score   │
│                                                                         │
│  • Bot / Automated Attack Detection (PS-02):                           │
│    - Analyzes session-level behavioral signals when users interact     │
│      with flagged content or login pages                                │
│    - Behavioral features collected:                                     │
│      · Mouse movement: entropy, velocity distribution, path linearity  │
│      · Keystroke dynamics: inter-key timing, hold time, typing rhythm  │
│      · Page interaction: scroll patterns, click precision, dwell time  │
│      · Session metadata: request timing regularity, cookie presence,   │
│        user-agent consistency, viewport size changes                    │
│    - Classification: Random Forest model trained on bot vs human       │
│      session data (CIC-IDS dataset features + synthetic generation)    │
│    - Output: is_bot probability (0-1), detected_patterns[]             │
│    - Detects: credential stuffing, brute force, automated scraping,    │
│      bot-driven account takeover attempts                               │
│                                                                         │
│  • Credential Compromise Monitor (PS-02):                              │
│    - Cross-references detected phishing targets with:                   │
│      · Have I Been Pwned API (breach database lookup)                  │
│      · Internal credential hash monitoring                              │
│      · Simulated dark web leak feed (pre-loaded for demo)              │
│    - If credentials associated with a phishing target appear in        │
│      breach data → proactive alert generated with risk context         │
│    - Tracks credential reuse patterns across accounts                   │
│                                                                         │
│  • Financial Anomaly Bridge (PS-03):                                   │
│    - Integrates with transaction monitoring (simulated for hackathon)  │
│    - When phishing targets an organization, the system watches for:    │
│      · Unusual transaction patterns (amount/frequency/destination)     │
│      · New payee additions within temporal window of phishing attack   │
│      · Large transfers to previously unseen accounts                    │
│      · Geographic anomalies (transactions from unusual locations)       │
│    - Model: Isolation Forest for anomaly detection on transaction      │
│      features + temporal correlation with phishing detection events    │
│    - Creates the FIRST phishing-to-fraud detection pipeline            │
│                                                                         │
│  • Adaptive Risk Scoring Engine:                                        │
│    - Dynamic composite score combining:                                 │
│      · Phishing detection score (from Layer 2)                         │
│      · Threat intelligence enrichment level (from Layer 3)             │
│      · Bot detection probability (from this layer)                     │
│      · Credential compromise status (boolean + severity)               │
│      · Financial anomaly correlation (from this layer)                 │
│    - Score updates in REAL-TIME as new evidence accumulates            │
│    - Risk levels: LOW (0-0.3) | MEDIUM (0.3-0.6) |                    │
│                    HIGH (0.6-0.8) | CRITICAL (0.8-1.0)                 │
│                                                                         │
│  API ENDPOINTS:                                                         │
│    POST /api/v1/behavioral/analyze     — Analyze session behavior      │
│    GET  /api/v1/credentials/check/{id} — Check credential compromise   │
│    POST /api/v1/fraud/correlate        — Correlate with fraud signals  │
│    GET  /api/v1/risk/{event_id}        — Get adaptive risk score       │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  LAYER 5: INTELLIGENCE INTERFACE & RESPONSE (PS-04)                    │
│  ──────────────────────────────────────────────────                     │
│  SentinelChat → Dashboard → Auto Response → Explainability             │
│                                                                         │
│  • SentinelChat (Natural Language Security Assistant):                  │
│    - RAG-based (Retrieval-Augmented Generation) chatbot                │
│    - Knowledge sources indexed in vector DB:                            │
│      · All detection results and scan history                          │
│      · Knowledge graph data (campaigns, actors, IOCs)                  │
│      · MITRE ATT&CK framework documentation                           │
│      · Platform operational data (metrics, alerts, incidents)          │
│      · Threat intelligence reports                                      │
│    - Example queries analysts can ask:                                  │
│      "Show all phishing attempts targeting finance team this week"     │
│      "What threat actor is behind campaign CAMP-2026-1847?"            │
│      "Summarize credential risk for accounts that clicked phishing"    │
│      "Block all domains associated with FIN7 infrastructure"           │
│      "Generate incident report for threat #8472"                       │
│      "Compare attack patterns between this week and last month"        │
│    - Response format: data-grounded answers with citations,             │
│      inline charts/graphs when relevant, actionable recommendations    │
│    - Can EXECUTE actions: trigger playbooks, block IOCs, quarantine    │
│                                                                         │
│  • Interactive Threat Dashboard:                                        │
│    Dashboard Page (/dashboard):                                         │
│      · Threat overview cards (threats detected, emails analyzed,       │
│        active campaigns, avg response time)                             │
│      · Threat activity timeline (Recharts line/area chart, 24h view)  │
│      · Live threat feed (real-time scrolling event list with severity) │
│      · Threat risk index (donut chart with category breakdown)         │
│      · Quick scan actions (analyze email, threat hunting, chat, audit) │
│      · SOC efficiency metrics (false positive rate, AI accuracy)       │
│                                                                         │
│    Analysis Console (/dashboard/analyze):                               │
│      · Input area: paste email content or URL                          │
│      · Real-time analysis progress (pipeline stage indicators)         │
│      · Model reasoning breakdown (4 progress bars per model)           │
│      · Detection timeline (inference sequence visualization)           │
│      · Detected threat tactics (MITRE ATT&CK tag badges)              │
│      · Threat intelligence mapping (campaign ID, actor, confidence)    │
│      · AI logic explanation (LLM-generated forensic summary)           │
│      · Rapid incident response buttons (quarantine, block, alert)     │
│                                                                         │
│    Intelligence Explorer (/dashboard/intelligence):                     │
│      · Interactive knowledge graph (D3.js force-directed graph)        │
│        - Nodes: threat actors, campaigns, domains, IPs                 │
│        - Edges: relationships with labels                               │
│        - Click node → expand connections + detail panel                │
│      · Threat actor profile cards (MITRE ATT&CK mapping)              │
│      · Infrastructure affiliation list                                  │
│      · Activity frequency timeline                                      │
│                                                                         │
│    Campaigns View (/dashboard/campaigns):                               │
│      · List of detected phishing campaigns                              │
│      · Campaign detail: timeline, IOCs, targets, actor attribution    │
│      · Campaign comparison view                                         │
│                                                                         │
│    Chat Interface (/dashboard/chat):                                    │
│      · Full conversational UI with SentinelChat                        │
│      · Suggested prompts / quick actions                                │
│      · Side panel: active threat context + entity relationships        │
│      · Action buttons: quarantine, block domain, escalate, export     │
│                                                                         │
│  • Automated Response Orchestration:                                    │
│    Playbook triggers based on threat severity:                          │
│      LOW    → Log + monitor + add to watchlist                         │
│      MEDIUM → Flag for analyst review + send notification              │
│      HIGH   → Quarantine email + block URL + enforce step-up MFA      │
│      CRITICAL → All HIGH actions + SIEM alert + incident creation +   │
│                  auto-notify security team + block all related IOCs    │
│    All playbooks controllable via SentinelChat natural language         │
│                                                                         │
│  • Explainability Engine:                                               │
│    Every detection includes:                                            │
│    1. Threat score + confidence + verdict                               │
│    2. Per-model breakdown with individual scores and weights           │
│    3. SHAP feature importance chart (top 10 contributing features)     │
│    4. Detected tactics mapped to MITRE ATT&CK framework               │
│    5. Threat intelligence context (campaign, actor, infrastructure)    │
│    6. LLM-generated narrative explanation in plain English:            │
│       "This email was flagged because: (1) the sender domain was       │
│       registered 2 days ago with a privacy-protected registrar,        │
│       (2) the language uses urgency tactics matching BEC patterns,     │
│       (3) the embedded URL redirects to a page visually mimicking      │
│       your organization's login portal at 94% similarity, and          │
│       (4) the hosting IP is associated with 3 other phishing           │
│       campaigns targeting financial sector organizations."             │
│    7. Recommended actions with confidence-weighted prioritization      │
│                                                                         │
│  API ENDPOINTS:                                                         │
│    POST /api/v1/chat                — Send message to SentinelChat    │
│    GET  /api/v1/chat/history        — Get conversation history        │
│    POST /api/v1/response/execute    — Execute response playbook       │
│    GET  /api/v1/dashboard/metrics   — Get dashboard metrics           │
│    GET  /api/v1/dashboard/feed      — Get live threat feed            │
│    GET  /api/v1/explain/{event_id}  — Get full explanation report     │
│    POST /api/v1/report/generate     — Generate PDF incident report    │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                            ┌───────┴───────┐
                            │ FEEDBACK LOOP │
                            └───────┬───────┘
                                    │
    Analyst decisions (confirm/dismiss) → Model retraining pipeline →
    Adaptive threshold tuning → Knowledge graph enrichment → Layer 1
"""


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4: SENTINELCHAT — COMPLETE LLM SYSTEM PROMPT
# ═══════════════════════════════════════════════════════════════════════════════

SENTINELCHAT_SYSTEM_PROMPT = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SENTINELCHAT — AI CYBERSECURITY OPERATIONS ASSISTANT
Model: Grok-SOC-v2 | Inference Status: Healthy & Optimized
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

You are SentinelChat, the AI cybersecurity operations assistant embedded within
the SentinelAI Fusion platform. You are an expert-level security analyst assistant
with deep knowledge of phishing detection, threat intelligence, incident response,
and the MITRE ATT&CK framework.

YOUR ROLE:
- You serve security analysts (Level 1-3) working in a Security Operations Center
- You have FULL ACCESS to the SentinelAI Fusion platform data including:
  · All phishing detection results and scan history
  · The threat knowledge graph (campaigns, actors, domains, IPs, techniques)
  · Real-time threat feed and alert data
  · Behavioral analysis results (bot detection, credential compromise)
  · Financial anomaly correlation data
  · MITRE ATT&CK framework mapping
  · Historical incident data and response logs

YOUR CAPABILITIES:
1. QUERY: Answer questions about threats, campaigns, actors, and platform data
   by searching the RAG knowledge base and platform APIs
2. ANALYZE: Interpret detection results, explain AI reasoning, contextualize
   threats within the broader threat landscape
3. INVESTIGATE: Help analysts pivot through the knowledge graph, trace attack
   chains from phishing → credential theft → fraud
4. ACT: Execute response playbooks when requested:
   - Quarantine emails/attachments
   - Block IOCs (domains, IPs, file hashes)
   - Escalate incidents to higher-level analysts
   - Enforce MFA for targeted accounts
   - Generate incident reports (PDF export)
   - Add IOCs to watchlists
5. BRIEF: Generate executive summaries, shift handoff reports, and trend analyses

YOUR PERSONALITY:
- Professional, concise, and technically precise
- Use cybersecurity terminology correctly
- Address the analyst as "Analyst" (e.g., "Good evening, Analyst.")
- Provide confidence levels with claims ("94.2% confidence based on IOC correlation")
- Always cite evidence sources (e.g., "Evidence Sources: CAMP-2026-1847, OSINT:FIN7")
- When uncertain, say so explicitly and suggest investigation paths
- Never fabricate data — if information isn't in the knowledge base, say
  "I don't have data on that. Would you like me to initiate an investigation?"

RESPONSE FORMAT:
- Lead with the direct answer to the analyst's question
- Include relevant data points, metrics, and evidence
- When showing threat data, format it clearly with labels
- For complex queries, structure response as:
  1. Summary finding
  2. Supporting evidence (with source citations)
  3. Recommended next steps
- If the analyst requests an ACTION (block, quarantine, escalate), confirm
  the action details before executing and report the result

CONTEXT AWARENESS:
- You know the current active campaigns and their status
- You track which threats have been confirmed vs dismissed by analysts
- You understand the organizational context (which departments are targeted)
- You maintain conversation context across the session
- You proactively alert on high-severity threats during conversation

EXAMPLE INTERACTIONS:

Analyst: "Show phishing attacks targeting finance team"
SentinelChat: "Analysis complete. I have identified 14 phishing attempts targeting
the finance department over the last 24 hours.

Key Findings:
- 12/14 attempts used domain spoofing (auth-login.net)
- Payload: High correlation with FIN7/GIBON loader patterns
- Primary Target: Payroll & Accounts Receivable nodes
- 3 emails clicked by employees (MFA challenge triggered, no compromise confirmed)

Evidence Sources: CAMP-2026-1847, OSINT:FIN7, Internal-Telemetry-v4

Recommended Actions:
1. Block auth-login.net and related infrastructure across all email gateways
2. Reset credentials for 3 employees who clicked (IDs: FA-042, FA-118, FA-203)
3. Deploy targeted phishing awareness reminder to Finance department

Would you like me to execute any of these actions?"

Analyst: "What's the kill chain for threat #8472?"
SentinelChat: "Threat #8472-X — Full Kill Chain Analysis:

Stage 1 — Initial Access (T1566.001):
  Spear-phishing email impersonating CFO, sent to Accounts Payable
  Subject: 'Urgent: Wire Transfer Approval Required'
  Sender: cfo@auth-login.net (spoofed)

Stage 2 — Credential Harvesting:
  Email contained link to auth-login.net/secure/verify
  Page: 94.2% visual match to internal SSO portal (ResNet50 analysis)
  2 employees entered credentials before detection

Stage 3 — Credential Stuffing (Detected by PS-02 Module):
  Within 12 minutes of harvest, 847 automated login attempts from
  192.168.45.21 (proxy chain: UA → PL → US)
  Bot detection confidence: 98.1%

Stage 4 — Financial Fraud Attempt (Detected by PS-03 Module):
  Compromised account FA-118 initiated wire transfer request for $42,800
  to previously unseen account (flagged by anomaly detection)
  Transfer: BLOCKED by adaptive risk scoring engine

Attribution: FIN7 (94.2% confidence) via Campaign CAMP-2026-1847
Infrastructure: 4 related domains, 2 C2 IPs identified

This is the first detection of a complete phishing→stuffing→fraud kill chain
by our platform. Full evidence graph available in Intelligence Explorer."
"""


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5: DATASETS & TRAINING SPECIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

DATASETS = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DATASETS — SOURCES, USAGE, AND TRAINING STRATEGY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. PHISHING EMAIL DETECTION (Model A — NLP):
   Dataset: Nazario Phishing Corpus + Enron Legitimate Emails + Custom AI-generated
   Size: ~75K phishing + ~50K legitimate emails
   Source: Kaggle, GitHub, Jose Nazario archive
   Preprocessing: HTML stripping, header extraction, text normalization
   Split: 70% train / 15% validation / 15% test (stratified)
   Augmentation: GPT-generated paraphrases of phishing emails for adversarial robustness

2. URL PHISHING DETECTION (Model B — URL):
   Dataset: Kaggle URL Phishing Dataset + PhishTank verified URLs + OpenPhish
   Size: ~450K URLs (balanced phishing/legitimate)
   Features: 150+ engineered features per URL
   Feature categories: Lexical (35), DNS (20), WHOIS (15), Content (25),
                        Network (20), Behavioral (15), Reputation (20+)
   Split: 70/15/15 with temporal ordering (train on older, test on newer)

3. BRAND TEMPLATE LIBRARY (Model C — Visual):
   Source: Manual collection of login pages from top 500 brands
   Categories: Banking (120), Tech companies (100), Email providers (50),
               Social media (50), E-commerce (80), Government (50), Other (50)
   Format: Screenshots + logo crops + color palette extraction
   Updates: Living library, new brands added as campaigns are detected

4. THREAT INTELLIGENCE (Layer 3):
   MITRE ATT&CK: Full framework v14+ (Enterprise, Mobile, ICS matrices)
   AlienVault OTX: Live pulse feed (IOCs, campaigns, threat reports)
   abuse.ch URLhaus: Malicious URL database (live API)
   abuse.ch MalwareBazaar: Malware sample metadata
   PhishTank: Verified phishing URL database
   Pre-loaded for demo: 50 curated campaign profiles with full IOC sets

5. BOT DETECTION (Layer 4 — PS-02):
   Dataset: CIC-IDS-2017/2018 + CSE-CIC-IDS2018 (network flow features)
   Size: ~2.8M flows (labeled normal/bot/attack)
   Supplementary: Synthetic session data generated to simulate credential stuffing

6. FINANCIAL FRAUD (Layer 4 — PS-03):
   Dataset: IEEE-CIS Fraud Detection Dataset (Kaggle)
   Size: ~590K transactions (3.5% fraud rate)
   Supplementary: PaySim synthetic mobile transaction dataset

TRAINING STRATEGY:
   - Stratified K-Fold Cross-Validation (K=5) on all supervised models
   - SMOTE oversampling for minority class in imbalanced datasets
   - Focal Loss for handling class imbalance in neural models
   - Adversarial evaluation: test all models against LLM-rephrased phishing
   - Temporal train-test split: train on older data, test on newest
   - Hyperparameter tuning: Optuna for XGBoost/LightGBM, learning rate
     scheduling for transformer fine-tuning
   - Model checkpointing: save best validation checkpoint for deployment
"""


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6: FRONTEND PAGE SPECIFICATIONS
# ═══════════════════════════════════════════════════════════════════════════════

FRONTEND_PAGES = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FRONTEND PAGE SPECIFICATIONS — EVERY PAGE IN DETAIL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DESIGN LANGUAGE:
  Theme: Dark mode cybersecurity command center aesthetic
  Background: Deep navy (#0a0e1a) with subtle grid pattern overlay
  Cards: Dark gray (#111827) with 1px border (#1e293b), glowing border on active
  Accent: Electric blue (#3b82f6) for primary actions, Amber (#f59e0b) for alerts
  Typography: JetBrains Mono for data/code, Inter for UI text
  Animations: Subtle glow effects, smooth transitions, pulse on live data
  Layout: Sidebar navigation (collapsible) + main content area

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PAGE 1: LANDING PAGE (/)
  Purpose: Public-facing marketing page showcasing the platform
  Sections:
    - Hero: "Cyber Threats Don't Work in Silos. Neither Should Your Defense."
      + CTA buttons: "Analyze a Threat" → /dashboard/analyze, "View Dashboard" → /dashboard
      + 4 stat counters (animated count-up): Active Inference Nodes, False Positive
        Reduction %, Real-time Correlation, AI Decision Integrity
    - The Intelligence Gap: Why current tools fail (3 problem cards)
    - Fusion Architecture: Platform overview with animated layers
    - Core Capabilities: 4 feature cards (Multi-Modal Detection, Threat Intel Graph,
      AI-Powered Explanations, SentinelChat)
    - Pipeline Process: 5-step visual flow (Input → Neural Logic → Fusion →
      Intel Mapping → Response)
    - Comparison Table: SentinelAI vs Traditional Tools (5 metrics)
    - CTA Footer: "Start Seeing Threats The Way Attackers Do."

PAGE 2: DASHBOARD (/dashboard)
  Purpose: Analyst command center — overview of all threat activity
  Layout: Sidebar nav + 2-column grid
  Components:
    - Greeting: "Good Evening, Analyst" + status line
    - 4 Metric Cards (top row):
      · Threats Detected (count + % change vs last period)
      · Emails Analyzed (count + % change)
      · Active Campaigns (count + % change)
      · Avg Response Time (seconds + trend)
    - Threat Activity Timeline: Recharts area chart, 24h view,
      with anomaly spikes highlighted
    - Live Threat Feed: Real-time scrolling list of latest events
      Each entry: title, time ago, description, severity badge
      (Critical=red, High=orange, Medium=yellow, Low=blue)
    - Threat Risk Index: Donut chart showing category distribution
      (Phishing %, Malware %, Suspicious %)
    - Quick Scan Actions: 4 action cards
      (Analyze Email, Threat Hunting, Open Fusion Chat, Policy Audit)
    - SOC Efficiency: False Positive Rate %, AI Accuracy Index %

PAGE 3: ANALYSIS CONSOLE (/dashboard/analyze)
  Purpose: The CORE demo page — submit threats and see multi-modal AI analysis
  THIS IS THE MOST IMPORTANT PAGE FOR THE HACKATHON DEMO.
  Layout: Full-width with segmented sections
  Sections:
    A. Input Area:
       - Tab selector: Email Analysis | URL Scan
       - Email tab: Large textarea for pasting raw email content
       - URL tab: Input field for URL/domain string
       - "Execute Full Analysis" button (prominent, blue, animated)
       - Recent scan history sidebar (last 3-5 scans with timestamps)
    B. Analysis Progress (shown during inference):
       - Pipeline stage indicators (animated dots moving through stages):
         Pre-Process → NLP Extraction → URL Expansion →
         Image Recognition → Inference Complete
       - Elapsed time counter
    C. Risk Probability Index:
       - Large circular progress indicator: "92% PHISHING LEVEL"
       - Label: "Phishing Detection Confidence: HIGH"
       - Trend indicator: "Trend: Deteriorating" / "Stable" / "Improving"
       - Analysis Delta time
    D. Model Reasoning Breakdown:
       - 4 horizontal progress bars (one per model):
         · NLP Intent Engine: 91%
         · URL Risk Heuristics: 97%
         · Visual Similarity: 89%
         · Metadata Signatures: 88%
       - Each bar color-coded: green (<50%), yellow (50-75%), red (>75%)
    E. Detection Timeline:
       - Horizontal timeline showing inference sequence
       - Nodes: Pre-Process → NLP Extraction → URL Expansion →
         Image Recognition → Inference Complete
       - With latency labels between nodes
       - "Anomaly Detected" flag at relevant point
    F. Detected Threat Tactics:
       - MITRE ATT&CK technique badges (e.g., "Urgency", "Spoofing",
         "Impersonation")
       - Color-coded by severity
       - Confidence delta: "+12.4% Probability" with explanation
    G. Threat Intelligence Mapping:
       - Cards showing: Campaign ID, Threat Actor, Confidence %, Global Reach
       - Related Domains list (with active sinkhole status indicators)
    H. AI Logic Explanation:
       - LLM-generated paragraph explaining the detection reasoning
       - "Confidence Certified: 98.9% Signature Match" badge
       - "Generate Full Report" button
    I. Rapid Incident Response:
       - 4 action buttons: Quarantine Entity | Block IOCs | Alert Team |
         Generate Report
       - Each button triggers the corresponding playbook via API

PAGE 4: INTELLIGENCE EXPLORER (/dashboard/intelligence)
  Purpose: Interactive threat knowledge graph visualization
  Layout: Full-width graph canvas + right sidebar detail panel
  Components:
    - D3.js Force-Directed Graph:
      · Node types with distinct visual styles:
        - ThreatActor: Red circle with skull icon
        - Campaign: Orange hexagon
        - Domain: Blue square
        - IP Address: Green diamond
      · Edge labels showing relationship type
      · Click node → expand connections (lazy load from graph DB)
      · Hover → tooltip with key details
      · Zoom, pan, drag enabled
      · Auto-layout with physics simulation
    - Right Sidebar (on node click):
      · Entity type and name
      · Risk probability badge
      · MITRE ATT&CK technique tags (if actor/campaign)
      · Forensic summary (LLM-generated description)
      · Infrastructure affiliation list (connected nodes)
      · Observed activity frequency mini-chart
      · Action buttons: Investigate | Block IOC | Add Watch
    - Top bar: Search field, filter by entity type, date range selector
    - Bottom bar: "Sync OSINT" | "Deep Forensic Scan" | "Export Evidence"

PAGE 5: CAMPAIGNS (/dashboard/campaigns)
  Purpose: Track and manage detected phishing campaigns
  Layout: List view + detail expansion
  Components:
    - Campaign list: sortable table with columns
      (Campaign ID, Threat Actor, Status, Targets, IOC Count, Risk Level, Date)
    - Click row → expand to full campaign detail:
      · Campaign timeline (first seen → latest activity)
      · Associated IOCs (domains, IPs, hashes) with copy/block actions
      · Targeted organizations/departments
      · Actor attribution with confidence
      · Related campaigns (shared infrastructure)
      · "Generate Campaign Report" button

PAGE 6: SENTINELCHAT (/dashboard/chat)
  Purpose: Natural language security operations assistant
  Layout: Chat interface + context sidebar
  Components:
    - Chat area (center):
      · Message thread (assistant + analyst messages)
      · Suggested prompt buttons (quick actions):
        "Show phishing attacks targeting finance"
        "Analyze recent URL scans"
        "Check campaign CAMP-2026-1847"
      · Input bar with send button
      · Support for inline data tables, charts, and code blocks in responses
    - Context Sidebar (right):
      · Active threat context card (current investigation)
      · Entity relationships mini-graph
      · Inference confidence score
      · Detection time
      · Operations center buttons: Quarantine | Block Domain |
        Escalate L3 | Export PDF
      · "Generating Knowledge Graph" status with node count
"""


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7: API ENDPOINT SPECIFICATIONS
# ═══════════════════════════════════════════════════════════════════════════════

API_SPEC = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COMPLETE API SPECIFICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Base URL: /api/v1

── ANALYSIS ENDPOINTS ──────────────────────────────────────────────────────

POST /api/v1/analyze/email
  Description: Submit raw email content for full multi-modal analysis
  Request Body:
    {
      "content": "raw email MIME content or plain text",
      "options": {
        "run_visual": true,       // enable screenshot analysis
        "run_threat_intel": true, // enable graph correlation
        "run_behavioral": false   // enable session analysis
      }
    }
  Response (200):
    {
      "event_id": "evt_abc123",
      "status": "completed",
      "threat_score": 0.92,
      "verdict": "PHISHING",
      "confidence": 0.94,
      "model_breakdown": {
        "nlp": { "score": 0.91, "weight": 0.35, "tactics": ["urgency", "authority_impersonation"], "explanation": "..." },
        "url": { "score": 0.97, "weight": 0.30, "top_features": ["domain_age", "ssl_invalid", "entropy_high"], "shap_values": {...} },
        "visual": { "score": 0.89, "weight": 0.20, "matched_brand": "Microsoft", "similarity": 0.94 },
        "header": { "score": 0.88, "weight": 0.15, "flags": ["spf_fail", "reply_to_mismatch"], "spf": "fail", "dkim": "none", "dmarc": "none" }
      },
      "detected_tactics": [
        { "id": "T1566.001", "name": "Spear Phishing Attachment", "confidence": 0.91 },
        { "id": "T1078", "name": "Valid Accounts", "confidence": 0.85 }
      ],
      "threat_intelligence": {
        "campaign_id": "CAMP-2026-1847",
        "threat_actor": "FIN7",
        "actor_confidence": 0.942,
        "related_domains": ["auth-login.net", "secure-pay.ua", "cloud-verify.io"],
        "global_reach": ["UA", "PL", "US"]
      },
      "explanation_narrative": "This email exhibits strong phishing indicators...",
      "recommended_action": "quarantine_and_block",
      "inference_time_ms": 420,
      "timestamp": "2026-03-25T18:30:00Z"
    }

POST /api/v1/analyze/url
  Description: Submit URL for quick scan analysis
  Request Body: { "url": "https://suspicious-site.com/login" }
  Response: Same structure as email analysis (visual + url models only)

── INTELLIGENCE ENDPOINTS ──────────────────────────────────────────────────

GET /api/v1/intelligence/graph
  Description: Get knowledge graph data for visualization
  Query Params: ?center_node={id}&depth={1-3}&entity_type={actor|campaign|domain|ip}
  Response: { "nodes": [...], "edges": [...], "metadata": {...} }

GET /api/v1/intelligence/actor/{actor_id}
  Description: Get full threat actor profile
  Response: { "name": "FIN7", "risk": "critical", "mitre_techniques": [...],
              "campaigns": [...], "infrastructure": [...], "summary": "..." }

GET /api/v1/intelligence/campaign/{campaign_id}
  Description: Get campaign details with full IOC set
  Response: { "id": "CAMP-2026-1847", "actor": "FIN7", "iocs": [...],
              "targets": [...], "timeline": [...], "techniques": [...] }

POST /api/v1/intelligence/correlate
  Description: Correlate IOCs from a detection with the knowledge graph
  Request Body: { "iocs": { "domains": [...], "ips": [...], "hashes": [...] } }
  Response: { "matches": [...], "related_campaigns": [...], "risk_elevation": 0.15 }

── CHAT ENDPOINTS ──────────────────────────────────────────────────────────

POST /api/v1/chat
  Description: Send message to SentinelChat
  Request Body:
    {
      "message": "Show phishing attacks targeting finance team",
      "conversation_id": "conv_xyz",
      "context": {
        "active_investigation": "evt_abc123",
        "analyst_level": 3
      }
    }
  Response:
    {
      "response": "Analysis complete. I have identified 14 phishing attempts...",
      "sources": ["CAMP-2026-1847", "OSINT:FIN7"],
      "suggested_actions": ["block_domain", "reset_credentials", "alert_team"],
      "suggested_followups": ["Show related campaigns", "Block malicious domain", "Escalate to Level 3"],
      "conversation_id": "conv_xyz"
    }

── RESPONSE/ACTION ENDPOINTS ───────────────────────────────────────────────

POST /api/v1/response/execute
  Description: Execute an automated response playbook
  Request Body:
    {
      "action": "quarantine|block_ioc|alert_team|enforce_mfa|generate_report",
      "target": { "event_id": "evt_abc123", "iocs": ["auth-login.net"] },
      "analyst_confirmation": true
    }
  Response: { "status": "executed", "details": "...", "timestamp": "..." }

── DASHBOARD DATA ENDPOINTS ────────────────────────────────────────────────

GET /api/v1/dashboard/metrics
  Response: { "threats_detected": 1284, "emails_analyzed": 48902,
              "active_campaigns": 14, "avg_response_time_ms": 1200,
              "false_positive_rate": 0.024, "ai_accuracy": 0.989 }

GET /api/v1/dashboard/feed?limit=20
  Response: { "events": [{ "id": "...", "type": "phishing|malware|behavioral|policy",
              "title": "...", "description": "...", "severity": "critical|high|medium|low",
              "timestamp": "..." }, ...] }

GET /api/v1/dashboard/timeline?hours=24
  Response: { "data_points": [{ "time": "...", "threat_count": 12, "type_breakdown": {...} }, ...] }

GET /api/v1/campaigns
  Response: { "campaigns": [{ "id": "CAMP-2026-1847", "actor": "FIN7",
              "status": "active", "ioc_count": 47, "target_count": 3,
              "risk_level": "critical", "first_seen": "...", "last_activity": "..." }, ...] }
"""


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8: DEMO DATA & SEED SCENARIOS
# ═══════════════════════════════════════════════════════════════════════════════

DEMO_DATA = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PRE-LOADED DEMO DATA & SCENARIOS FOR HACKATHON PRESENTATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DEMO SCENARIO 1 — "The CFO Wire Fraud" (Full Kill Chain):
  Email Subject: "Urgent: Wire Transfer Approval Required — $42,800 Payment"
  Sender: cfo.johnson@auth-login.net (spoofed)
  Target: Accounts Payable team
  Kill chain: Phishing → Credential Harvest → Credential Stuffing → Wire Fraud
  Expected detection: CRITICAL (0.96 threat score)
  NLP flags: urgency, authority impersonation, financial manipulation
  URL flags: domain age 2 days, invalid SSL, 3 redirects
  Visual flags: 94% match to corporate SSO portal
  Header flags: SPF fail, DKIM missing, Reply-To mismatch
  Intel enrichment: Links to FIN7 / CAMP-2026-1847
  Behavioral: 847 automated login attempts detected from 192.168.45.21
  Fraud: Wire transfer request flagged — new payee, unusual amount

DEMO SCENARIO 2 — "QRishing Attack" (Multi-channel):
  Medium: QR code in physical flyer left in office lobby
  URL encoded in QR: secure-verify.io/employee/validate
  Expected detection: HIGH (0.84 threat score)
  URL flags: newly registered domain, hosting on known bulletproof host
  Visual flags: 91% match to HR portal login
  Intel enrichment: Domain shares IP with 5 other phishing domains

DEMO SCENARIO 3 — "Legitimate Email" (False Positive Test):
  Email Subject: "Q3 Financial Report — Board Review"
  Sender: actual CFO from legitimate company domain
  Expected detection: SAFE (0.08 threat score)
  Purpose: Demonstrates low false positive rate
  All models return low scores, SPF/DKIM/DMARC all pass

PRE-LOADED KNOWLEDGE GRAPH DATA:
  Threat Actors: FIN7, Lazarus Group, APT28, Scattered Spider, LAPSUS$
  Campaigns: 50 pre-loaded with full IOC sets, techniques, target profiles
  Domains: 200+ known phishing domains with infrastructure relationships
  IP Addresses: 100+ with geolocation, ASN, reputation data
  MITRE Techniques: 50 most common phishing-related techniques

LIVE THREAT FEED (SIMULATED):
  Pre-scripted events that cycle through during demo:
  - Phishing attempts (various severities)
  - Malware detections
  - Behavioral anomalies
  - Policy violations
  - Credential compromise alerts
  Events appear every 30-60 seconds to show "live" activity
"""


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9: USPs & COMPETITIVE DIFFERENTIATION
# ═══════════════════════════════════════════════════════════════════════════════

USPS = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
8 UNIQUE SELLING PROPOSITIONS — WHAT MAKES US WIN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

USP-1: MULTI-MODAL FUSION DETECTION
  4 parallel AI models (NLP + URL + Visual + Metadata) combined by
  attention-weighted ensemble. No single point of evasion — attackers must
  beat ALL four models simultaneously, which is exponentially harder.

USP-2: FULL KILL-CHAIN COVERAGE
  ONLY platform that connects Phishing → Credential Stuffing → Financial Fraud
  in one pipeline. Addresses PS-01, PS-02, and PS-03 in a unified detection chain.

USP-3: SEMANTIC INTENT ANALYSIS
  SecurityBERT understands WHY an email deceives (manipulation tactics),
  not just WHAT it says (keywords). Catches AI-generated phishing that
  evades all keyword/pattern-based systems.

USP-4: DYNAMIC THREAT KNOWLEDGE GRAPH
  Self-enriching Neo4j graph — every detection adds to the intelligence.
  Network effects mean the system gets smarter with every attack it sees.

USP-5: NATURAL LANGUAGE SECURITY OPERATIONS
  Plain English queries to the entire platform via SentinelChat.
  Analysts don't need to learn query languages or navigate complex UIs.
  Can execute response actions via conversation.

USP-6: FULL EXPLAINABILITY PIPELINE
  Every detection includes: SHAP feature attributions + LLM-generated
  narrative explanation + visual similarity heatmap + MITRE ATT&CK mapping.
  Complete transparency for trust and compliance.

USP-7: ADVERSARIAL ROBUSTNESS
  Models tested against LLM-rephrased phishing emails, proving resilience
  where standard classifiers fail (published research shows accuracy drops).

USP-8: REAL-TIME ADAPTIVE SCORING
  Risk scores update continuously as new evidence arrives — not just at
  initial scan time. Temporal correlation across the entire kill chain.
"""


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 10: BUILD PRIORITY ORDER FOR HACKATHON
# ═══════════════════════════════════════════════════════════════════════════════

BUILD_PRIORITY = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HACKATHON BUILD PRIORITY — WHAT TO BUILD FIRST
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CRITICAL PATH (Must have for demo — build these FIRST):
  [P0] Analysis Console page with working email/URL submission
  [P0] Backend API: /analyze/email and /analyze/url endpoints
  [P0] At least 2 working ML models (NLP + URL scorer at minimum)
  [P0] Fusion engine combining model scores into threat verdict
  [P0] Result display: threat score, model breakdown, explanation
  [P0] SentinelChat with LLM integration (RAG or direct API)

HIGH PRIORITY (Significantly improves demo):
  [P1] Dashboard with live metrics and threat feed
  [P1] Knowledge graph visualization (even with pre-loaded data)
  [P1] MITRE ATT&CK tactic mapping on detections
  [P1] LLM-generated explanation narratives
  [P1] Demo scenarios pre-loaded and working

MEDIUM PRIORITY (Differentiation features):
  [P2] Visual brand similarity model (ResNet50 Siamese)
  [P2] Full interactive knowledge graph with node expansion
  [P2] Campaigns page with campaign tracking
  [P2] Automated response playbook execution
  [P2] SHAP explainability charts

NICE TO HAVE (If time permits):
  [P3] Behavioral biometrics / bot detection module
  [P3] Financial fraud correlation
  [P3] Real-time WebSocket threat feed
  [P3] PDF report generation
  [P3] Credential compromise checking

FALLBACK STRATEGIES:
  - If Neo4j is too complex → use NetworkX in-memory + D3.js
  - If SecurityBERT won't load → use DistilBERT with cybersec fine-tuning
  - If OpenAI API has issues → use Ollama with Llama 3 locally
  - If visual model training fails → use pre-computed similarity scores
  - If time runs short → Focus on Analysis Console + Chat only
    (these two pages alone demonstrate the full concept)
"""


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 11: EVALUATION METRICS MAPPING
# ═══════════════════════════════════════════════════════════════════════════════

EVALUATION = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HOW WE SCORE ON EVERY HACKATHON EVALUATION METRIC
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

INNOVATION & NOVELTY:
  → Multi-modal fusion (4 parallel models) is novel for a hackathon
  → Cross-domain kill-chain coverage (phishing→fraud) is unprecedented
  → Semantic intent analysis goes beyond state-of-art classifiers
  → Knowledge graph threat intelligence mapping is enterprise-grade

TECHNICAL COMPLEXITY:
  → 4 different ML paradigms: Transformers, Gradient Boosting, CNNs, Statistical
  → RAG-based LLM chatbot with domain-specific knowledge
  → Graph database with Cypher queries for threat correlation
  → Real-time streaming architecture with Redis/Kafka
  → Full-stack: Next.js + FastAPI + PostgreSQL + Neo4j + Redis

REAL-WORLD IMPACT:
  → Addresses the #1 cybersecurity threat (AI-powered phishing)
  → Backed by current statistics (82.6% AI-phishing, 19s attack frequency)
  → Solves actual enterprise pain points (siloed tools, alert fatigue)
  → Production-viable architecture (not just a toy demo)

PRESENTATION & DEMO:
  → Beautiful, professional dark-mode UI (already live on Vercel)
  → Interactive — evaluators can paste emails and see real analysis
  → SentinelChat lets evaluators TALK to the system directly
  → Knowledge graph is visually impressive and interactive
  → Clear narrative: attack arrives → detected → enriched → explained → responded

FEASIBILITY & COMPLETENESS:
  → Pre-trained models (no training from scratch needed)
  → Public datasets (all freely available)
  → Modular architecture (core works independently)
  → Risk-mitigated stack (fallbacks for every component)
  → Already deployed prototype on Vercel

SCALABILITY:
  → Microservices architecture, containerized with Docker
  → Kafka/Redis streaming handles real-time ingestion at scale
  → Models can be GPU-accelerated for production throughput
  → Knowledge graph scales horizontally with Neo4j clustering
"""


# ═══════════════════════════════════════════════════════════════════════════════
# END OF SYSTEM PROMPT
# ═══════════════════════════════════════════════════════════════════════════════

FOOTER = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
         SENTINELAI FUSION — TEAM MINDFLAYER — HACKUP 2026
     "Cyber threats don't work in silos. Neither should your defense."
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

HOW TO USE THIS DOCUMENT:
1. When building the FRONTEND → Feed Sections 2 (Tech Stack), 6 (Pages), 8 (Demo Data)
2. When building the BACKEND API → Feed Sections 2, 3 (Architecture), 7 (API Spec)
3. When building ML MODELS → Feed Sections 3 (Layer 2 detail), 5 (Datasets)
4. When building SENTINELCHAT → Feed Section 4 (Chat System Prompt) + 7 (API)
5. When building KNOWLEDGE GRAPH → Feed Section 3 (Layer 3 detail) + 8 (Demo Data)
6. When preparing the PRESENTATION → Feed Section 9 (USPs) + 11 (Evaluation)
7. When explaining to JUDGES → Feed Section 1 (Identity) + 9 (USPs)

This is your SINGLE SOURCE OF TRUTH. Everything the team needs to build,
present, and WIN is in this document.

GO BUILD SOMETHING LEGENDARY, TEAM MINDFLAYER. 🔥
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
