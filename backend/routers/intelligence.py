"""
Threat Intelligence endpoints — knowledge graph queries.
"""
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional

from intelligence.knowledge_graph import get_graph

router = APIRouter(prefix="/api/v1/intelligence", tags=["intelligence"])


class CorrelateRequest(BaseModel):
    iocs: dict  # { "domains": [...], "ips": [...], "hashes": [...] }


class SearchRequest(BaseModel):
    query: str


@router.get("/graph")
async def get_graph_data(
    depth: int = Query(2, ge=1, le=3),
    entity_type: Optional[str] = Query(None),
):
    """Get knowledge graph data for D3.js visualization."""
    graph = get_graph()
    return graph.get_graph_data(depth=depth, entity_type=entity_type)


@router.get("/actor/{actor_id}")
async def get_actor(actor_id: str):
    """Get full threat actor profile."""
    graph = get_graph()
    actor = graph.get_actor(actor_id)
    if not actor:
        raise HTTPException(status_code=404, detail=f"Threat actor '{actor_id}' not found.")
    return actor


@router.get("/campaign/{campaign_id}")
async def get_campaign(campaign_id: str):
    """Get campaign details with full IOC set."""
    graph = get_graph()
    campaign = graph.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found.")
    return campaign


@router.post("/correlate")
async def correlate_iocs(request: CorrelateRequest):
    """Correlate IOCs from a detection with the knowledge graph."""
    graph = get_graph()
    result = graph.correlate_iocs(
        domains=request.iocs.get("domains", []),
        ips=request.iocs.get("ips", []),
        hashes=request.iocs.get("hashes", []),
    )
    return result


@router.get("/iocs")
async def list_iocs():
    """List all indexed IOCs."""
    from intelligence.knowledge_graph import CAMPAIGNS, DOMAINS, IPS
    all_iocs = {
        "domains": [d["fqdn"] for d in DOMAINS],
        "ips": [i["ip"] for i in IPS],
        "total_count": len(DOMAINS) + len(IPS),
    }
    return all_iocs


@router.post("/search")
async def search_graph(request: SearchRequest):
    """Search the knowledge graph by text query."""
    if not request.query or len(request.query.strip()) < 2:
        raise HTTPException(status_code=400, detail="Query must be at least 2 characters.")
    graph = get_graph()
    return graph.search(request.query)
