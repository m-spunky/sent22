import os
import httpx
import asyncio
from dotenv import load_dotenv


load_dotenv()
key = os.getenv("OPENROUTER_API_KEY", "").strip()
import requests
import json

response = requests.post(
  url="https://openrouter.ai/api/v1/chat/completions",
  headers={
    "Authorization": f"Bearer {key}",
    "Content-Type": "application/json",
    "HTTP-Referer": "<YOUR_SITE_URL>", # Optional. Site URL for rankings on openrouter.ai.
    "X-OpenRouter-Title": "<YOUR_SITE_NAME>", # Optional. Site title for rankings on openrouter.ai.
  },
  data=json.dumps({
    "model": "openai/gpt-4o",
    "messages": [
      {
        "role": "user",
        "content": [
          {
            "type": "text",
            "text": "What is in this image?"
          },
          {
            "type": "image_url",
            "image_url": {
              "url": "https://live.staticflickr.com/3851/14825276609_098cac593d_b.jpg"
            }
          }
        ]
      }
    ]
  })
)

print(response.json())
