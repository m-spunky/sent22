// SentinelAI Popup Script

const SENTINEL_API = 'http://localhost:8001';

// ── API health check ───────────────────────────────────────────────────────────
async function checkApiHealth() {
  const dot      = document.getElementById('status-dot');
  const statusEl = document.getElementById('api-status');
  try {
    const res = await fetch(`${SENTINEL_API}/health`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      statusEl.textContent  = 'Connected ✓';
      statusEl.className    = 'status-val status-val--ok';
      dot.className         = 'status-dot';
    } else {
      throw new Error(`HTTP ${res.status}`);
    }
  } catch {
    statusEl.textContent = 'Offline ✗';
    statusEl.className   = 'status-val status-val--err';
    dot.className        = 'status-dot status-dot--off';
  }
}

// ── Detect current tab's mail platform ────────────────────────────────────────
function detectPlatform(url) {
  if (!url) return 'none';
  if (url.includes('mail.google.com')) return 'gmail';
  if (url.includes('outlook.com') || url.includes('outlook.live.com') ||
      url.includes('outlook.office.com') || url.includes('outlook.office365.com')) return 'outlook';
  return 'none';
}

async function updatePlatformChips() {
  let platform = 'none';
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    platform = detectPlatform(tab?.url || '');
  } catch { /* tabs permission may not be granted yet */ }

  const chipGmail   = document.getElementById('chip-gmail');
  const chipOutlook = document.getElementById('chip-outlook');
  const brandSub    = document.getElementById('brand-sub');

  chipGmail.className   = 'chip' + (platform === 'gmail'   ? ' chip--active-gmail'   : '');
  chipOutlook.className = 'chip' + (platform === 'outlook' ? ' chip--active-outlook' : '');

  if (platform === 'gmail') {
    brandSub.textContent = 'Active on Gmail';
  } else if (platform === 'outlook') {
    brandSub.textContent = 'Active on Outlook';
  } else {
    brandSub.textContent = 'Phishing Guard';
  }
}

// ── Session stats ──────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const res = await fetch(`${SENTINEL_API}/api/v1/history?source=gmail_extension&limit=200`);
    if (!res.ok) return;
    const data  = await res.json();
    const items = data.items || [];
    document.getElementById('stat-scanned').textContent    = items.length;
    document.getElementById('stat-threats').textContent    =
      items.filter(i => ['PHISHING', 'CONFIRMED_THREAT', 'CRITICAL'].includes(i.verdict)).length;
    document.getElementById('stat-suspicious').textContent =
      items.filter(i => i.verdict === 'SUSPICIOUS').length;
  } catch { /* api down */ }
}

// ── Settings persistence ───────────────────────────────────────────────────────
async function loadSettings() {
  const { autoScan = true, outlookScan = true, showBanner = true } =
    await chrome.storage.sync.get(['autoScan', 'outlookScan', 'showBanner']);
  document.getElementById('toggle-gmail').checked   = autoScan;
  document.getElementById('toggle-outlook').checked = outlookScan;
  document.getElementById('toggle-banner').checked  = showBanner;
}

document.getElementById('toggle-gmail').addEventListener('change', (e) => {
  chrome.storage.sync.set({ autoScan: e.target.checked });
});
document.getElementById('toggle-outlook').addEventListener('change', (e) => {
  chrome.storage.sync.set({ outlookScan: e.target.checked });
});
document.getElementById('toggle-banner').addEventListener('change', (e) => {
  chrome.storage.sync.set({ showBanner: e.target.checked });
});

// ── Cache clear ────────────────────────────────────────────────────────────────
document.getElementById('btn-clear-cache')?.addEventListener('click', () => {
  const btn = document.getElementById('btn-clear-cache');
  btn.textContent = '⏳ Clearing…';
  btn.disabled    = true;
  chrome.runtime.sendMessage({ action: 'clear_all_cache' }, (resp) => {
    btn.textContent = `✅ Cleared ${resp?.cleared || 0} entries`;
    setTimeout(() => {
      btn.textContent = '🗑 Reset Cached Scores';
      btn.disabled    = false;
      loadStats();
    }, 2000);
  });
});

// ── Init ───────────────────────────────────────────────────────────────────────
checkApiHealth();
loadStats();
loadSettings();
updatePlatformChips();
