"""
Campaign management endpoints — list, filter, detail, and IOC lookup.
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional

from intelligence.knowledge_graph import get_graph, CAMPAIGNS, THREAT_ACTORS

router = APIRouter(prefix="/api/v1", tags=["campaigns"])


@router.get("/campaigns")
async def list_campaigns(
    actor: Optional[str] = Query(None, description="Filter by threat actor ID"),
    status: Optional[str] = Query(None, description="Filter by status (active/monitoring/archived)"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level (critical/high/medium/low)"),
    search: Optional[str] = Query(None, description="Text search in name/description"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """List all tracked threat campaigns with optional filtering."""
    campaigns = list(CAMPAIGNS)

    # Apply filters
    if actor:
        campaigns = [c for c in campaigns if c.get("actor_id") == actor or c.get("actor", "").lower() == actor.lower()]

    if status:
        campaigns = [c for c in campaigns if c.get("status", "").lower() == status.lower()]

    if risk_level:
        campaigns = [c for c in campaigns if c.get("risk_level", "").lower() == risk_level.lower()]

    if search:
        search_lower = search.lower()
        campaigns = [
            c for c in campaigns
            if search_lower in c.get("name", "").lower()
            or search_lower in c.get("description", "").lower()
            or search_lower in c.get("actor", "").lower()
            or any(search_lower in t.lower() for t in c.get("techniques", []))
            or any(search_lower in s.lower() for s in c.get("sectors", []))
        ]

    total = len(campaigns)
    paginated = campaigns[offset: offset + limit]

    # Summarize (strip heavy IOC lists for listing)
    summary = []
    for c in paginated:
        ioc_count = (
            len(c.get("iocs", {}).get("domains", []))
            + len(c.get("iocs", {}).get("ips", []))
        )
        summary.append({
            "id": c["id"],
            "name": c["name"],
            "actor": c["actor"],
            "actor_id": c.get("actor_id", ""),
            "status": c["status"],
            "risk_level": c["risk_level"],
            "sectors": c.get("sectors", []),
            "techniques": c.get("techniques", [])[:5],
            "target_count": c.get("target_count", 0),
            "ioc_count": ioc_count,
            "first_seen": c.get("first_seen"),
            "last_activity": c.get("last_activity"),
            "description": c.get("description", ""),
        })

    return {
        "campaigns": summary,
        "total": total,
        "limit": limit,
        "offset": offset,
        "filters_applied": {
            "actor": actor,
            "status": status,
            "risk_level": risk_level,
            "search": search,
        },
    }


@router.get("/campaigns/{campaign_id}")
async def get_campaign_detail(campaign_id: str):
    """Get full campaign details including all IOCs."""
    graph = get_graph()
    campaign = graph.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found.")
    return campaign


@router.get("/campaigns/{campaign_id}/iocs")
async def get_campaign_iocs(campaign_id: str):
    """Get all IOCs for a specific campaign."""
    graph = get_graph()
    campaign = graph.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found.")
    return {
        "campaign_id": campaign_id,
        "campaign_name": campaign.get("name"),
        "iocs": campaign.get("iocs", {}),
        "total_domains": len(campaign.get("iocs", {}).get("domains", [])),
        "total_ips": len(campaign.get("iocs", {}).get("ips", [])),
        "total_hashes": len(campaign.get("iocs", {}).get("hashes", [])),
    }


@router.get("/actors")
async def list_actors():
    """List all tracked threat actors."""
    actors = []
    for a in THREAT_ACTORS:
        actors.append({
            "id": a["id"],
            "name": a["name"],
            "aliases": a.get("aliases", []),
            "country": a.get("country", "Unknown"),
            "motivation": a.get("motivation", "Unknown"),
            "risk": a.get("risk", "unknown"),
            "sectors_targeted": a.get("sectors_targeted", []),
            "mitre_techniques": a.get("mitre_techniques", []),
            "ioc_count": a.get("ioc_count", 0),
            "summary": a.get("summary", ""),
        })
    return {"actors": actors, "total": len(actors)}


@router.get("/actors/{actor_id}")
async def get_actor_detail(actor_id: str):
    """Get full threat actor profile."""
    graph = get_graph()
    actor = graph.get_actor(actor_id)
    if not actor:
        raise HTTPException(status_code=404, detail=f"Threat actor '{actor_id}' not found.")

    # Also attach actor's campaigns
    actor_campaigns = [
        {"id": c["id"], "name": c["name"], "status": c["status"], "risk_level": c["risk_level"]}
        for c in CAMPAIGNS
        if c.get("actor_id") == actor_id or c.get("actor", "").lower() == actor.get("name", "").lower()
    ]
    return {**actor, "campaigns": actor_campaigns, "campaign_count": len(actor_campaigns)}
