"""
SentinelChat endpoint.
"""
import uuid
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

from chat.sentinel_chat import chat as sentinel_chat

router = APIRouter(prefix="/api/v1", tags=["chat"])

# In-memory conversation store (resets on restart — fine for hackathon)
_conversations: dict = {}


class ChatRequest(BaseModel):
    message: str
    conversation_id: Optional[str] = None
    context: Optional[dict] = None


class ChatHistoryRequest(BaseModel):
    conversation_id: str


@router.post("/chat")
async def chat_endpoint(request: ChatRequest):
    """Send a message to SentinelChat."""
    conversation_id = request.conversation_id or f"conv_{uuid.uuid4().hex[:8]}"

    # Retrieve existing history
    history = _conversations.get(conversation_id, [])

    # Get context
    ctx = request.context or {}
    active_investigation = ctx.get("active_investigation")
    analyst_level = ctx.get("analyst_level", 2)

    result = await sentinel_chat(
        message=request.message,
        conversation_history=history,
        conversation_id=conversation_id,
        active_investigation=active_investigation,
        analyst_level=analyst_level,
    )

    # Store conversation
    history.append({"role": "user", "content": request.message})
    history.append({"role": "assistant", "content": result["response"]})
    _conversations[conversation_id] = history[-20:]  # Keep last 20 turns

    return result


@router.get("/chat/history")
async def get_chat_history(conversation_id: str):
    """Get conversation history."""
    history = _conversations.get(conversation_id, [])
    return {"conversation_id": conversation_id, "messages": history, "turn_count": len(history) // 2}
