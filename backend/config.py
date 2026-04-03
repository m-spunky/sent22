import os
from dotenv import load_dotenv

load_dotenv()

# OpenRouter (GPT-4o / LLM inference)
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

# Replicate (CLIP visual model)
REPLICATE_API_TOKEN = os.getenv("REPLICATE_API_TOKEN", "")

# Apify (screenshots, WHOIS, web scraping)
APIFY_API_TOKEN = os.getenv("APIFY_API_TOKEN", "")

# Server
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
PORT = int(os.getenv("PORT", 8001))

# OpenRouter model IDs
OPENROUTER_CHAT_MODEL = "openai/gpt-4o"
OPENROUTER_FAST_MODEL = "google/gemma-3-12b-it"

# Google OAuth2 (Gmail integration)
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8001/api/v1/gmail/callback")

# HaveIBeenPwned (dark web credential exposure)
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")

# Feature flags
VISUAL_ANALYSIS_ENABLED = bool(APIFY_API_TOKEN and REPLICATE_API_TOKEN)
LIVE_IOC_FEEDS_ENABLED = True
RAG_ENABLED = True
GMAIL_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)
