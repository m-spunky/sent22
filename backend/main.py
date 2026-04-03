"""
SentinelAI Fusion — FastAPI Backend
PS-01: AI-powered phishing detection (email, URL, headers, QR code)
+ PS-02/03/04/05 bonus capabilities for maximum hackathon coverage.
"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager

from config import FRONTEND_URL, PORT
from routers import analyze, intelligence, chat, dashboard
from routers import stream, behavioral, campaigns, reports
from routers import history, feedback, sandbox, gmail, bulk, quishing


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-initialize knowledge graph
    from intelligence.knowledge_graph import get_graph
    graph = get_graph()
    print(f"[SentinelAI] Knowledge graph: {graph.G.number_of_nodes()} nodes, {graph.G.number_of_edges()} edges")
    # Pre-warm RAG pipeline
    try:
        from chat.rag_pipeline import get_rag
        rag = get_rag()
        rag._try_init_chromadb()
        print(f"[SentinelAI] RAG pipeline: {len(rag._docs)} documents")
    except Exception as e:
        print(f"[SentinelAI] RAG init: {e}")
    # Pre-train ML URL classifier
    try:
        from models.ml_url_classifier import get_evaluation_metrics, _model
        m = get_evaluation_metrics()
        if "error" not in m:
            print(f"[SentinelAI] XGBoost URL classifier: F1={m.get('f1_score')}, AUC={m.get('roc_auc')}, Acc={m.get('accuracy')}")
        else:
            print(f"[SentinelAI] XGBoost URL classifier: {m.get('error')}")
    except Exception as e:
        print(f"[SentinelAI] ML classifier init: {e}")
    # Pre-warm BERT phishing model (loads weights + runs evaluation)
    try:
        import asyncio as _asyncio
        from models.bert_phishing_model import get_evaluation_metrics as bert_eval
        m = bert_eval()  # triggers lazy load + evaluation
        if "error" not in m:
            print(f"[SentinelAI] BERT phishing model: F1={m.get('f1_score')}, AUC={m.get('roc_auc')}, Acc={m.get('accuracy')}")
        else:
            print(f"[SentinelAI] BERT model: {m.get('error')}")
    except Exception as e:
        print(f"[SentinelAI] BERT init: {e}")
    print("[SentinelAI] All systems operational.")
    yield
    print("[SentinelAI] Shutdown.")


app = FastAPI(
    title="SentinelAI Fusion — Phishing Detection API",
    description="PS-01 AI-powered phishing detector with Gmail integration, URL sandbox, QR quishing, bulk analysis, and multi-PS coverage.",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        FRONTEND_URL,
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
        "https://senti-ai-sepia.vercel.app",
        "https://*.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── PS-01 Core ────────────────────────────────────────────────────────────────
app.include_router(analyze.router)          # /api/v1/analyze/*, /api/v1/events/*, /api/v1/response/*
app.include_router(sandbox.router)          # /api/v1/sandbox/*
app.include_router(quishing.router)         # /api/v1/quishing/*
app.include_router(bulk.router)             # /api/v1/bulk/*
app.include_router(gmail.router)            # /api/v1/gmail/*

# ── History & Feedback ────────────────────────────────────────────────────────
app.include_router(history.router)          # /api/v1/history/*
app.include_router(feedback.router)         # /api/v1/feedback/*

# ── Dashboard & Streaming ─────────────────────────────────────────────────────
app.include_router(dashboard.router)        # /api/v1/dashboard/*
app.include_router(stream.router)           # /api/v1/stream (WebSocket)

# ── PS-02/03/04/05 Bonus ─────────────────────────────────────────────────────
app.include_router(behavioral.router)       # /api/v1/behavioral/*
app.include_router(intelligence.router)     # /api/v1/intelligence/*
app.include_router(campaigns.router)        # /api/v1/campaigns, /api/v1/actors
app.include_router(chat.router)             # /api/v1/chat
app.include_router(reports.router)          # /api/v1/reports/*

# ── Static: serve locally-saved screenshots ──────────────────────────────────
_ss_dir = os.path.join(os.path.dirname(__file__), "data", "screenshots")
os.makedirs(_ss_dir, exist_ok=True)
app.mount("/screenshots", StaticFiles(directory=_ss_dir), name="screenshots")


@app.get("/")
async def root():
    return {
        "service": "SentinelAI Fusion",
        "version": "3.0.0",
        "primary_ps": "PS-01 — AI-Powered Phishing Detection",
        "bonus_coverage": ["PS-02 Bot/Credential Stuffing", "PS-03 Fraud Detection", "PS-04 Security Chatbot", "PS-05 Dark Web Monitoring"],
        "core_endpoints": {
            "analyze_email": "POST /api/v1/analyze/email",
            "analyze_url": "POST /api/v1/analyze/url",
            "analyze_headers": "POST /api/v1/analyze/headers",
            "qr_decode_analyze": "POST /api/v1/quishing/decode",
            "bulk_upload": "POST /api/v1/bulk/upload",
            "sandbox": "POST /api/v1/sandbox/analyze",
            "gmail_connect": "GET /api/v1/gmail/demo-connect",
            "gmail_inbox": "GET /api/v1/gmail/inbox",
            "history": "GET /api/v1/history",
            "feedback": "POST /api/v1/feedback",
        },
        "docs": "/docs",
        "stream": "WS /api/v1/stream",
    }


@app.get("/health")
async def health():
    from intelligence.knowledge_graph import get_graph
    graph = get_graph()
    return {
        "status": "healthy",
        "version": "3.0.0",
        "ps1_detection": "5-layer ensemble (NLP+URL+Visual+Header+Intel)",
        "modules": {
            "nlp_engine": "openrouter/gpt-4o-mini",
            "url_analyzer": "whois+dns+urlhaus+phishtank",
            "visual_sandbox": "apify+replicate-clip",
            "header_analyzer": "spf+dkim+dmarc",
            "dark_web": "haveibeenpwned",
            "kill_chain": "ps02+ps03-correlator",
            "sentinelchat": "openrouter/gpt-4o+chromadb-rag",
            "gmail": "oauth2-demo-ready",
            "bulk": "csv-batch-processing",
            "quishing": "qr-code-decode+analyze",
            "knowledge_graph": f"{graph.G.number_of_nodes()} nodes",
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)
