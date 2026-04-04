// SentinelAI Popup Script

const SENTINEL_API = 'http://localhost:8001';

async function checkApiHealth() {
  const dot = document.getElementById('status-dot');
  const statusEl = document.getElementById('api-status');
  try {
    const res = await fetch(`${SENTINEL_API}/health`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      statusEl.textContent = 'Connected ✓';
      statusEl.className = 'status-val status-val--ok';
      dot.className = 'status-dot';
    } else {
      throw new Error(`HTTP ${res.status}`);
    }
  } catch {
    statusEl.textContent = 'Offline ✗';
    statusEl.className = 'status-val status-val--err';
    dot.className = 'status-dot status-dot--off';
  }
}

async function loadStats() {
  try {
    const res = await fetch(`${SENTINEL_API}/api/v1/history?source=gmail_extension&limit=200`);
    if (!res.ok) return;
    const data = await res.json();
    const items = data.items || [];
    document.getElementById('stat-scanned').textContent = items.length;
    document.getElementById('stat-threats').textContent =
      items.filter(i => ['PHISHING','CONFIRMED_THREAT','CRITICAL'].includes(i.verdict)).length;
    document.getElementById('stat-suspicious').textContent =
      items.filter(i => i.verdict === 'SUSPICIOUS').length;
  } catch { /* api down */ }
}

// Settings persistence
async function loadSettings() {
  const { autoScan = true, showBanner = true } = await chrome.storage.sync.get(['autoScan', 'showBanner']);
  document.getElementById('toggle-auto').checked = autoScan;
  document.getElementById('toggle-banner').checked = showBanner;
}

document.getElementById('toggle-auto').addEventListener('change', (e) => {
  chrome.storage.sync.set({ autoScan: e.target.checked });
});
document.getElementById('toggle-banner').addEventListener('change', (e) => {
  chrome.storage.sync.set({ showBanner: e.target.checked });
});

document.getElementById('btn-clear-cache')?.addEventListener('click', () => {
  const btn = document.getElementById('btn-clear-cache');
  btn.textContent = '⏳ Clearing…';
  btn.disabled = true;
  chrome.runtime.sendMessage({ action: 'clear_all_cache' }, (resp) => {
    btn.textContent = `✅ Cleared ${resp?.cleared || 0} entries`;
    setTimeout(() => {
      btn.textContent = '🗑 Reset Cached Scores';
      btn.disabled = false;
      loadStats();
    }, 2000);
  });
});


// Init
checkApiHealth();
loadStats();
loadSettings();
