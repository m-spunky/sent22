# SentinelAI Gmail Extension

Real-time phishing detection overlay for Gmail.  
Scores every email in your inbox. Detailed analysis on click. URL sandbox. Full Sentinel platform integration.

---

## What It Does

| Feature | Detail |
|---------|--------|
| **Inbox score badges** | Colored pill on every email row (green/amber/red/pulsing-red) |
| **Phase 1 quick scan** | Sender domain + subject heuristics — result in < 800ms |
| **Phase 2 full scan** | Complete 5-layer NLP+URL+Header+Intel pipeline (2–5s, background) |
| **Hover tooltip** | Mini threat card: score, top flags, quick actions |
| **Side panel** | Score ring · Layer bars · Detected threats · Attachments (VT) · All extracted URLs |
| **Inline URL sandbox** | Click any URL in the panel → instant sandbox: redirects, SSL, credential forms |
| **Screenshot sandbox** | Click "📸 + Screenshot" → Apify visual screenshot of any URL |
| **Warning banner** | Auto-injected inside email body for SUSPICIOUS/PHISHING/CRITICAL |
| **Sentinel deep-link** | "View Full Report" → opens Sentinel platform with that email's event_id |
| **Sentinel Chat** | "Ask Sentinel Chat" → pre-fills chat with email context |
| **History persistence** | All analyses saved in Sentinel with `source: "gmail_extension"` tag |

---

## Install (Developer Mode)

1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select this folder: `d:\Projects\sent2\sentinel-extension`
5. The extension icon will appear in the Chrome toolbar

---

## Requirements

- **Sentinel backend must be running** on `http://localhost:8001`
  ```bash
  cd d:\Projects\sent2\backend
  uvicorn main:app --port 8001 --reload
  ```
- **Add VirusTotal API key** to `backend/.env`:
  ```
  VIRUSTOTAL_API_KEY=your_key_here
  ```
  Get a free key at: https://www.virustotal.com/gui/my-apikey

---

## File Structure

```
sentinel-extension/
├── manifest.json           Chrome MV3 manifest
├── background/
│   └── background.js       Service worker: cache + API routing
├── content/
│   ├── gmail_content.js    Gmail DOM observer + badge + banner
│   └── content.css         Badge, tooltip, banner styles
├── sidepanel/
│   ├── sidepanel.html      Detail panel shell
│   ├── sidepanel.js        Full analysis render + URL sandbox
│   └── sidepanel.css       Dark panel styles
├── popup/
│   ├── popup.html          Toolbar popup
│   └── popup.js            Health check + stats
├── shared/
│   ├── utils.js            Score/verdict helpers
│   └── api.js              API client
└── icons/
    └── icon*.png           Extension icons
```

---

## API Endpoints Used

| Endpoint | Purpose |
|----------|---------|
| `POST /api/v1/analyze/quick` | Phase 1 inbox badge (< 800ms) |
| `POST /api/v1/analyze/email` | Phase 2 full 5-layer analysis |
| `POST /api/v1/sandbox/analyze` | URL sandbox (standard + visual) |
| `GET  /api/v1/history` | Retrieve past analyses |
| `GET  /api/v1/history/event/{id}` | Get analysis by event_id |

---

## Score Badge Color Guide

| Badge | Score | Meaning |
|-------|-------|---------|
| 🟢 Green | 0–30 | SAFE |
| 🟡 Amber | 30–60 | SUSPICIOUS |
| 🔴 Red | 60–85 | PHISHING |
| 🚨 Pulsing Red | 85–100 | CRITICAL |
