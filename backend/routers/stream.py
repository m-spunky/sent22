"""
WebSocket streaming endpoint — real-time threat event feed.
Clients connect to /api/v1/stream and receive live threat events as JSON.
"""
import asyncio
import json
import logging
from datetime import datetime
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["stream"])

# Active WebSocket connections
_connections: list[WebSocket] = []


async def emit_threat_event(event: dict):
    """Broadcast a threat event to all connected WebSocket clients."""
    if not _connections:
        return
    payload = json.dumps(event)
    dead = []
    for ws in list(_connections):
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in _connections:
            _connections.remove(ws)


@router.websocket("/stream")
async def websocket_stream(websocket: WebSocket):
    """WebSocket endpoint for real-time threat event streaming."""
    await websocket.accept()
    _connections.append(websocket)
    logger.info(f"[Stream] Client connected. Total: {len(_connections)}")

    # Send connection acknowledgment
    await websocket.send_text(json.dumps({
        "type": "connected",
        "message": "SentinelAI real-time stream active",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }))

    try:
        while True:
            # Keep connection alive — wait for any incoming message (ping/pong)
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if data == "ping":
                    await websocket.send_text(json.dumps({"type": "pong", "timestamp": datetime.utcnow().isoformat() + "Z"}))
            except asyncio.TimeoutError:
                # Send keepalive heartbeat
                await websocket.send_text(json.dumps({"type": "heartbeat", "timestamp": datetime.utcnow().isoformat() + "Z"}))
    except WebSocketDisconnect:
        logger.info("[Stream] Client disconnected.")
    except Exception as e:
        logger.debug(f"[Stream] Connection error: {e}")
    finally:
        if websocket in _connections:
            _connections.remove(websocket)
        logger.info(f"[Stream] Active connections: {len(_connections)}")


@router.get("/stream/status")
async def stream_status():
    """Get WebSocket stream status."""
    return {
        "active_connections": len(_connections),
        "status": "active",
        "endpoint": "ws://localhost:8001/api/v1/stream",
    }
