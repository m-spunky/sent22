// SentinelAI Extension — API Client (content script context)

const SENTINEL_API_BASE = 'http://localhost:8001/api/v1';

window.SentinelAPI = {

  async quickAnalyze({ subject, sender, snippet, gmailMessageId }) {
    try {
      const res = await fetch(`${SENTINEL_API_BASE}/analyze/quick`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject: subject || '',
          sender: sender || '',
          snippet: snippet || '',
          gmail_message_id: gmailMessageId || null,
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      console.warn('[SentinelAI] Quick analyze failed:', e.message);
      return null;
    }
  },

  async fullAnalyze({ content, gmailMessageId, gmailSubject, gmailSender, attachmentsScanned }) {
    try {
      const res = await fetch(`${SENTINEL_API_BASE}/analyze/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content,
          options: {
            source: 'gmail_extension',
            gmail_message_id: gmailMessageId || null,
            gmail_subject: gmailSubject || null,
            gmail_sender: gmailSender || null,
            attachments_scanned: attachmentsScanned || [],
            run_threat_intel: true,
            run_visual: false,
          },
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      console.warn('[SentinelAI] Full analyze failed:', e.message);
      return null;
    }
  },

  async sandboxUrl(url, deep = false) {
    try {
      const res = await fetch(`${SENTINEL_API_BASE}/sandbox/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, depth: deep ? 'deep' : 'standard' }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      console.warn('[SentinelAI] Sandbox failed:', e.message);
      return null;
    }
  },

  async getHistory(source = 'gmail_extension', limit = 50) {
    try {
      const res = await fetch(
        `${SENTINEL_API_BASE}/history?source=${source}&limit=${limit}`
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      console.warn('[SentinelAI] History fetch failed:', e.message);
      return null;
    }
  },

  getPlatformUrl(eventId) {
    return `http://localhost:3000/dashboard/analyze?event_id=${eventId}`;
  },

  getChatUrl(eventId, subject) {
    const prompt = encodeURIComponent(
      `Analyze the email with event ID ${eventId}: "${subject}"`
    );
    return `http://localhost:3000/dashboard/chat?q=${prompt}`;
  },
};
