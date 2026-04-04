// SentinelAI — Background Service Worker
// Persistent cache in chrome.storage.local — survives page refresh + Gmail nav

const CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes
const CACHE_KEY_PREFIX = 'sentinel_cache_';
const SENTINEL_API = 'http://localhost:8001/api/v1';

// ── Client-side request queue ─────────────────────────────────────────────────
// Prevents hammering the backend with 5+ concurrent full analyses.
// Full pipeline: max 1 at a time.   LLM-only: max 2 at a time.
let _fullRunning = 0;
let _llmRunning  = 0;
const _fullQueue = [];   // [{ fn, resolve, reject }]
const _llmQueue  = [];

const FULL_CONCURRENCY = 1;
const LLM_CONCURRENCY  = 2;

function _drainQueue(queue, maxConcurrent, getRunning, setRunning) {
  while (queue.length > 0 && getRunning() < maxConcurrent) {
    const job = queue.shift();
    setRunning(getRunning() + 1);
    job.fn()
      .then(job.resolve)
      .catch(job.reject)
      .finally(() => {
        setRunning(getRunning() - 1);
        _drainQueue(queue, maxConcurrent, getRunning, setRunning);
      });
  }
}

function enqueueFullAnalysis(fn) {
  return new Promise((resolve, reject) => {
    _fullQueue.push({ fn, resolve, reject });
    _drainQueue(_fullQueue, FULL_CONCURRENCY,
      () => _fullRunning, (n) => { _fullRunning = n; });
  });
}

function enqueueLlmAnalysis(fn) {
  return new Promise((resolve, reject) => {
    _llmQueue.push({ fn, resolve, reject });
    _drainQueue(_llmQueue, LLM_CONCURRENCY,
      () => _llmRunning, (n) => { _llmRunning = n; });
  });
}


// ── Persistent cache helpers (chrome.storage.local) ───────────────────────────

async function cacheGet(msgId) {
  const key = CACHE_KEY_PREFIX + msgId;
  const result = await chrome.storage.local.get(key);
  const entry = result[key];
  if (!entry) return null;
  // TTL check
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
    await chrome.storage.local.remove(key);
    return null;
  }
  return entry;
}

async function cacheSet(msgId, data) {
  const key = CACHE_KEY_PREFIX + msgId;
  const result = await chrome.storage.local.get(key);
  const existing = result[key] || {};
  await chrome.storage.local.set({
    [key]: { ...existing, ...data, timestamp: Date.now() },
  });
}

// Periodically purge expired cache entries (every 30 minutes)
async function purgeStaleCacheEntries() {
  const all = await chrome.storage.local.get(null);
  const keysToRemove = [];
  for (const [key, entry] of Object.entries(all)) {
    if (key.startsWith(CACHE_KEY_PREFIX)) {
      if (Date.now() - (entry.timestamp || 0) > CACHE_TTL_MS) {
        keysToRemove.push(key);
      }
    }
  }
  if (keysToRemove.length) {
    await chrome.storage.local.remove(keysToRemove);
    console.log(`[SentinelAI] Purged ${keysToRemove.length} stale cache entries`);
  }
}

// ── API helpers ────────────────────────────────────────────────────────────────

async function quickAnalyze({ subject, sender, snippet, gmailMessageId }) {
  const res = await fetch(`${SENTINEL_API}/analyze/quick`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject, sender, snippet, gmail_message_id: gmailMessageId }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function fullAnalyze({ content, gmailMessageId, gmailSubject, gmailSender, attachmentNames }) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 28000); // 28s — backend hard caps at 25s
  try {
    const res = await fetch(`${SENTINEL_API}/analyze/email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        content,
        options: {
          source: 'gmail_extension',
          gmail_message_id: gmailMessageId,
          gmail_subject: gmailSubject,
          gmail_sender: gmailSender,
          run_threat_intel: true,
          run_visual: false,
          llm_only: false,
          attachment_names: attachmentNames || [],
          has_attachments: (attachmentNames || []).length > 0,
        },
      }),
    });
    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status}${errText ? ': ' + errText.slice(0, 120) : ''}`);
    }
    return res.json();
  } catch (err) {
    if (err.name === 'AbortError') throw new Error('Analysis timed out (28s). Backend may be busy.');
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

// Tier 2 analysis: NLP + LLM only (no live URL/DNS/IOC). Targets ~3–6s.
async function llmAnalyze({ content, gmailMessageId, gmailSubject, gmailSender }) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 20000); // 20s — plenty for llm_only mode
  try {
    const res = await fetch(`${SENTINEL_API}/analyze/email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        content,
        options: {
          source: 'gmail_extension',
          gmail_message_id: gmailMessageId,
          gmail_subject: gmailSubject,
          gmail_sender: gmailSender,
          run_threat_intel: false,
          run_visual: false,
          llm_only: true,       // skips headers, URL live lookup, IOC feeds
        },
      }),
    });
    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status}${errText ? ': ' + errText.slice(0, 120) : ''}`);
    }
    return res.json();
  } catch (err) {
    if (err.name === 'AbortError') throw new Error('Analysis timed out (20s).');
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function sandboxUrl(url, deep = false) {
  const res = await fetch(`${SENTINEL_API}/sandbox/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, depth: deep ? 'deep' : 'standard' }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ── Message handlers ───────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const { action } = message;

  // ── Quick analyze ────────────────────────────────────────────────────────
  if (action === 'quick_analyze') {
    (async () => {
      try {
        const cached = await cacheGet(message.gmailMessageId);
        if (cached?.phase1) {
          sendResponse({ success: true, result: cached.phase1, cached: true });
          return;
        }
        const result = await quickAnalyze(message);
        await cacheSet(message.gmailMessageId, { phase1: result });
        sendResponse({ success: true, result, cached: false });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  // ── Full analyze ─────────────────────────────────────────────────────────
  if (action === 'full_analyze') {
    (async () => {
      try {
        const cached = await cacheGet(message.gmailMessageId);
        if (cached?.phase2) {
          sendResponse({ success: true, result: cached.phase2, cached: true });
          return;
        }
        // Serialize: only 1 full analysis runs at a time (protects BERT)
        const result = await enqueueFullAnalysis(() => fullAnalyze({
          ...message,
          attachmentNames: message.attachmentNames || [],
        }));
        await cacheSet(message.gmailMessageId, { phase2: result });
        sendResponse({ success: true, result, cached: false });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  // ── LLM-only analyze (Tier 2: NLP+LLM, no live URL/DNS/IOC) ─────────────
  if (action === 'llm_analyze') {
    (async () => {
      try {
        const cached = await cacheGet(message.gmailMessageId);
        if (cached?.phase2 || cached?.llm_phase) {
          sendResponse({ success: true, result: cached.phase2 || cached.llm_phase, cached: true });
          return;
        }
        // Allow 2 LLM analyses concurrently (faster than full)
        const result = await enqueueLlmAnalysis(() => llmAnalyze(message));
        await cacheSet(message.gmailMessageId, { llm_phase: result });
        sendResponse({ success: true, result, cached: false });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  // ── Sandbox ──────────────────────────────────────────────────────────────
  if (action === 'sandbox_url') {
    (async () => {
      try {
        const result = await sandboxUrl(message.url, message.deep || false);
        sendResponse({ success: true, result });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  // ── Get cache ────────────────────────────────────────────────────────────
  if (action === 'get_cache') {
    (async () => {
      const cached = await cacheGet(message.gmailMessageId);
      sendResponse({ success: true, result: cached });
    })();
    return true;
  }

  // ── Check cache exists (fast path, no API) ───────────────────────────────
  if (action === 'check_cached') {
    (async () => {
      const cached = await cacheGet(message.gmailMessageId);
      sendResponse({
        success: true,
        hasCached: !!cached,
        hasPhase1: !!(cached?.phase1),
        hasPhase2: !!(cached?.phase2),
        result: cached,
      });
    })();
    return true;
  }

  // ── Open side panel ──────────────────────────────────────────────────────
  if (action === 'open_sidepanel') {
    chrome.sidePanel.open({ tabId: sender.tab.id }).catch(() => {});
    chrome.storage.session.set({ sidepanel_context: message.context });
    sendResponse({ success: true });
    return false;
  }

  // ── Get full count from session (how many phase2 ran this session) ────────
  if (action === 'get_full_count') {
    chrome.storage.session.get('full_analysis_count', (res) => {
      sendResponse({ count: res.full_analysis_count || 0 });
    });
    return true;
  }

  if (action === 'increment_full_count') {
    chrome.storage.session.get('full_analysis_count', (res) => {
      const next = (res.full_analysis_count || 0) + 1;
      chrome.storage.session.set({ full_analysis_count: next });
      sendResponse({ count: next });
    });
    return true;
  }

  if (action === 'reset_full_count') {
    chrome.storage.session.set({ full_analysis_count: 0 });
    sendResponse({ success: true });
    return false;
  }

  if (action === 'clear_all_cache') {
    (async () => {
      const all = await chrome.storage.local.get(null);
      const keys = Object.keys(all).filter(k => k.startsWith(CACHE_KEY_PREFIX));
      if (keys.length) await chrome.storage.local.remove(keys);
      await chrome.storage.session.set({ full_analysis_count: 0 });
      try {
        await fetch(`${SENTINEL_API}/history/clear`, { method: 'DELETE' });
      } catch (e) {
        console.warn('Failed to clear backend history:', e);
      }
      sendResponse({ success: true, cleared: keys.length });
    })();
    return true;
  }

  if (action === 'ping') {
    sendResponse({ success: true, status: 'background_alive' });
    return false;
  }

  // ── Safe sender list ─────────────────────────────────────────────────────
  function _normalizeSender(raw) {
    // Extract email from "Name <email>" or just "email"
    const m = (raw || '').match(/<([^>]+)>/);
    return (m ? m[1] : raw).toLowerCase().trim();
  }

  if (action === 'mark_safe') {
    (async () => {
      const { sentinel_safe_senders = [] } = await chrome.storage.local.get('sentinel_safe_senders');
      const normalized = _normalizeSender(message.sender);
      if (normalized && !sentinel_safe_senders.includes(normalized)) {
        sentinel_safe_senders.push(normalized);
        await chrome.storage.local.set({ sentinel_safe_senders });
      }
      sendResponse({ success: true, count: sentinel_safe_senders.length });
    })();
    return true;
  }

  if (action === 'check_safe') {
    (async () => {
      const { sentinel_safe_senders = [] } = await chrome.storage.local.get('sentinel_safe_senders');
      const normalized = _normalizeSender(message.sender);
      sendResponse({ success: true, isSafe: !!normalized && sentinel_safe_senders.includes(normalized) });
    })();
    return true;
  }

  if (action === 'unmark_safe') {
    (async () => {
      const { sentinel_safe_senders = [] } = await chrome.storage.local.get('sentinel_safe_senders');
      const normalized = _normalizeSender(message.sender);
      const updated = sentinel_safe_senders.filter(s => s !== normalized);
      await chrome.storage.local.set({ sentinel_safe_senders: updated });
      sendResponse({ success: true });
    })();
    return true;
  }
});

// ── Startup + periodic purge ──────────────────────────────────────────────────
purgeStaleCacheEntries();
setInterval(purgeStaleCacheEntries, 30 * 60 * 1000);
console.log('[SentinelAI] Background service worker started (persistent cache)');
