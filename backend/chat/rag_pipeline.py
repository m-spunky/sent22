"""
RAG Pipeline — Retrieval-Augmented Generation for SentinelChat.
Uses ChromaDB vector store with sentence-transformers embeddings.
Falls back to keyword-based retrieval if ChromaDB unavailable.
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Documents to index ───────────────────────────────────────────────────────

def _build_knowledge_documents() -> list[dict]:
    """Build the knowledge base documents from platform data."""
    from intelligence.knowledge_graph import THREAT_ACTORS, CAMPAIGNS, MITRE_TECHNIQUES

    docs = []

    # Threat actor profiles
    for actor in THREAT_ACTORS:
        text = f"""
Threat Actor: {actor['name']}
Aliases: {', '.join(actor.get('aliases', []))}
Country: {actor.get('country', 'Unknown')}
Motivation: {actor.get('motivation', 'Unknown')}
Risk Level: {actor.get('risk', 'unknown').upper()}
MITRE Techniques: {', '.join(actor.get('mitre_techniques', []))}
Sectors Targeted: {', '.join(actor.get('sectors_targeted', []))}
Summary: {actor.get('summary', '')}
IOC Count: {actor.get('ioc_count', 0)}
        """.strip()
        docs.append({
            "id": f"actor_{actor['id']}",
            "text": text,
            "metadata": {"type": "actor", "name": actor["name"], "id": actor["id"]},
        })

    # Campaign profiles
    for camp in CAMPAIGNS[:30]:  # Top 30 campaigns
        ioc_domains = ', '.join(camp.get('iocs', {}).get('domains', [])[:5])
        text = f"""
Campaign: {camp['name']} (ID: {camp['id']})
Threat Actor: {camp['actor']}
Status: {camp['status'].upper()}
Risk Level: {camp['risk_level'].upper()}
Sectors: {', '.join(camp.get('sectors', []))}
Techniques: {', '.join(camp.get('techniques', []))}
Description: {camp.get('description', '')}
Known Domains: {ioc_domains}
Target Count: {camp.get('target_count', 0)}
IOC Count: {camp.get('ioc_count', 0)}
First Seen: {camp.get('first_seen', 'Unknown')}
Last Activity: {camp.get('last_activity', 'Unknown')}
        """.strip()
        docs.append({
            "id": f"campaign_{camp['id']}",
            "text": text,
            "metadata": {"type": "campaign", "id": camp["id"], "actor": camp["actor"]},
        })

    # MITRE techniques
    for tech in MITRE_TECHNIQUES[:20]:
        text = f"""
MITRE ATT&CK Technique: {tech['name']} ({tech['id']})
Tactic: {tech['tactic']}
        """.strip()
        docs.append({
            "id": f"tech_{tech['id']}",
            "text": text,
            "metadata": {"type": "technique", "id": tech["id"]},
        })

    # Platform knowledge
    platform_docs = [
        {
            "id": "platform_detection",
            "text": "SentinelAI Fusion uses 4 parallel AI models: NLP Intent Engine (OpenRouter GPT-4o-mini), URL Risk Analyzer (real WHOIS/DNS + 150+ features), Visual Brand Engine (Apify screenshots + Replicate CLIP), Header Anomaly Detector (SPF/DKIM/DMARC). These are combined via attention-weighted fusion engine.",
            "metadata": {"type": "platform", "topic": "detection"},
        },
        {
            "id": "platform_kill_chain",
            "text": "SentinelAI tracks the full attack kill chain: Phishing (PS-01) → Credential Stuffing (PS-02) → Financial Fraud (PS-03). The platform is the only solution connecting all three in one pipeline. Demo scenario: CFO Wire Fraud attack by FIN7 via CAMP-2026-1847.",
            "metadata": {"type": "platform", "topic": "kill_chain"},
        },
        {
            "id": "platform_threat_intel",
            "text": "Threat intelligence sources: AlienVault OTX (live pulse feed), abuse.ch URLhaus (malicious URL database), PhishTank (verified phishing URLs), NetworkX knowledge graph with 5 threat actors, 50 campaigns, 200+ domains, 100+ IPs. Graph correlates IOCs to campaigns and actors automatically.",
            "metadata": {"type": "platform", "topic": "threat_intel"},
        },
        {
            "id": "platform_sentinelchat",
            "text": "SentinelChat (PS-04) is the AI security operations assistant powered by OpenRouter GPT-4o. It has access to all platform data, can answer questions about threats, execute response playbooks, generate incident reports, and perform threat hunting. Powered by RAG over the knowledge base.",
            "metadata": {"type": "platform", "topic": "sentinelchat"},
        },
        {
            "id": "platform_behavioral",
            "text": "Behavioral analysis (PS-02): Bot detection analyzes session signals (request timing, user-agent consistency, click patterns). Credential compromise monitoring checks breached credential databases. Financial fraud correlation (PS-03) links phishing events to transaction anomalies using Isolation Forest.",
            "metadata": {"type": "platform", "topic": "behavioral"},
        },
        {
            "id": "platform_response",
            "text": "Automated response playbooks by severity: LOW=log+monitor, MEDIUM=flag+notify, HIGH=quarantine+block+MFA enforcement, CRITICAL=all HIGH actions + SIEM alert + incident creation + auto-notify security team + block all related IOCs. All playbooks executable via SentinelChat.",
            "metadata": {"type": "platform", "topic": "response"},
        },
        {
            "id": "demo_scenario_1",
            "text": "Demo Scenario 1 - CFO Wire Fraud: From cfo.johnson@auth-login.net, Subject 'Urgent: Wire Transfer Approval Required'. Detection: CRITICAL 96%+ threat score. FIN7 attribution (94.2% confidence). Campaign CAMP-2026-1847. NLP detects urgency+authority_impersonation+financial_lure. URL: auth-login.net registered 2 days ago. Visual: 94% match to corporate SSO. Header: SPF fail, DKIM missing, Reply-To mismatch.",
            "metadata": {"type": "demo", "scenario": "cfo_wire_fraud"},
        },
        {
            "id": "demo_scenario_2",
            "text": "Demo Scenario 2 - QRishing Attack: URL secure-verify.io/employee/validate encoded in QR code. Detection: HIGH 84% threat score. Scattered Spider suspected. Campaign CAMP-2026-0392. URL: newly registered on bulletproof hosting. Visual: 91% match to HR portal. Domain shares IP with 5 other phishing domains.",
            "metadata": {"type": "demo", "scenario": "qrishing"},
        },
        {
            "id": "demo_scenario_3",
            "text": "Demo Scenario 3 - Legitimate Email: From actual CFO cfo@legitimate-company.com, Subject Q3 Financial Report. Detection: SAFE 8% threat score. All models return low scores. SPF pass, DKIM pass, DMARC pass. No intelligence matches. False positive rate demonstrates platform accuracy.",
            "metadata": {"type": "demo", "scenario": "legitimate"},
        },
    ]
    docs.extend(platform_docs)
    return docs


class RAGPipeline:
    """Vector store for SentinelChat knowledge retrieval."""

    def __init__(self):
        self._collection = None
        self._docs = _build_knowledge_documents()
        self._initialized = False
        self._use_chromadb = False

    def _try_init_chromadb(self):
        """Try to initialize ChromaDB. Falls back to keyword search if unavailable."""
        try:
            import chromadb
            from chromadb.config import Settings

            client = chromadb.Client(Settings(
                is_persistent=False,
                anonymized_telemetry=False,
            ))
            self._collection = client.create_collection(
                name="sentinel_knowledge",
                metadata={"hnsw:space": "cosine"},
            )
            # Index all documents
            self._collection.add(
                ids=[d["id"] for d in self._docs],
                documents=[d["text"] for d in self._docs],
                metadatas=[d["metadata"] for d in self._docs],
            )
            self._use_chromadb = True
            logger.info(f"[RAG] ChromaDB initialized with {len(self._docs)} documents")
        except Exception as e:
            logger.warning(f"[RAG] ChromaDB unavailable ({e}), using keyword retrieval")
            self._use_chromadb = False
        self._initialized = True

    def _keyword_retrieve(self, query: str, k: int = 5) -> list[str]:
        """Simple keyword-based retrieval fallback."""
        query_words = set(query.lower().split())
        scored = []
        for doc in self._docs:
            doc_words = set(doc["text"].lower().split())
            score = len(query_words & doc_words) / max(len(query_words), 1)
            scored.append((score, doc["text"]))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [text for _, text in scored[:k] if text]

    async def retrieve(self, query: str, k: int = 5) -> str:
        """Retrieve relevant context for a query."""
        if not self._initialized:
            self._try_init_chromadb()

        if self._use_chromadb and self._collection:
            try:
                results = self._collection.query(
                    query_texts=[query],
                    n_results=min(k, len(self._docs)),
                )
                docs = results.get("documents", [[]])[0]
                return "\n\n---\n\n".join(docs[:k])
            except Exception as e:
                logger.debug(f"[RAG] ChromaDB query failed: {e}")

        # Keyword fallback
        docs = self._keyword_retrieve(query, k)
        return "\n\n---\n\n".join(docs)


# Singleton
_rag_instance: Optional[RAGPipeline] = None


def get_rag() -> RAGPipeline:
    global _rag_instance
    if _rag_instance is None:
        _rag_instance = RAGPipeline()
    return _rag_instance
