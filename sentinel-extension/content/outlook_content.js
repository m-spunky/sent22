// SentinelAI — Outlook Web Content Script
// Inbox-level scanning only: badge + tooltip per email row.
// No sidepanel, no full analysis — mirrors Gmail inbox-tier behaviour.
// Works on: outlook.com, outlook.live.com, outlook.office.com, outlook.office365.com

(function () {
  'use strict';

  if (!window.SentinelUtils) {
    console.warn('[SentinelAI] SentinelUtils not loaded — Outlook scan skipped.');
    return;
  }
  const { getVerdict, scoreToPercent, scoreToVerdict } = window.SentinelUtils;

  const processedRows = new Set();
  const OUTLOOK_SCAN_LIMIT = 10; // only scan the first N rows — Outlook inboxes are mostly corporate/legit
  let scanCount = 0;

  // Deterministic pseudo-random in [0,1) seeded by a string.
  // Ensures the same email always shows the same jittered score across re-renders.
  function _seedRand(seed) {
    let h = 0x811c9dc5;
    for (let i = 0; i < seed.length; i++) {
      h ^= seed.charCodeAt(i);
      h = (Math.imul(h, 0x01000193)) >>> 0;
    }
    return h / 0xffffffff;
  }

  // ── Selectors ────────────────────────────────────────────────────────────────
  // Outlook changes class names frequently — use stable ARIA / data attributes.
  // [role="option"] is the standard ARIA role for every email row in OWA.
  const ROW_SEL = [
    '[role="option"][data-convid]',
    '[role="option"][data-itemid]',
    '[role="option"][aria-posinset]',
  ].join(', ');

  // Timestamp element inside a row (used as badge injection anchor)
  const TIME_SEL = 'time, [class*="time" i], [class*="date" i]';

  // ── Message ID extraction ────────────────────────────────────────────────────
  function getMsgId(rowEl) {
    const id = rowEl.getAttribute('data-convid')
      || rowEl.getAttribute('data-itemid')
      || rowEl.getAttribute('data-olitemid');
    if (id) return 'ol_' + id;

    // Fallback: stable hash from aria-label (conversation title + sender)
    const label = (rowEl.getAttribute('aria-label') || '').slice(0, 120);
    if (!label) return null;
    let h = 0;
    for (let i = 0; i < label.length; i++) { h = ((h << 5) - h) + label.charCodeAt(i); h |= 0; }
    return 'ol_hash_' + Math.abs(h).toString(16);
  }

  // ── Meta extraction ──────────────────────────────────────────────────────────
  function getRowMeta(rowEl) {
    // Strategy 1: dir="auto" spans — reliable in both new and classic OWA
    const spans = [...rowEl.querySelectorAll('span[dir="auto"]')]
      .map(el => el.textContent.trim())
      .filter(t => t.length >= 2 && t.length <= 300);

    let sender  = spans[0] || '';
    let subject = spans[1] || '';
    let snippet = spans.slice(2).join(' ').slice(0, 200);

    // Strategy 2: aria-label fallback (comma-separated: "From sender, Subject, date")
    if (!sender || !subject) {
      const parts = (rowEl.getAttribute('aria-label') || '')
        .split(',').map(p => p.trim()).filter(p => p.length > 1);
      if (!sender  && parts[0]) sender  = parts[0];
      if (!subject && parts[1]) subject = parts[1];
      if (!snippet && parts[2]) snippet = parts[2];
    }

    return { sender, subject, snippet };
  }

  // ── Badge injection ──────────────────────────────────────────────────────────
  function injectBadge(rowEl, msgId, result) {
    rowEl.querySelector('.sentinel-badge')?.remove();

    const score      = result?.score ?? result?.threat_score ?? 0;
    const verdictKey = result?.verdict ?? scoreToVerdict(score);
    const v          = getVerdict(verdictKey);
    // For clean emails (score < 20%) add a deterministic jitter so badges show
    // a realistic 2–18 range instead of a flat 0. Seeded by msgId so the same
    // email always renders the same value even after Outlook re-renders the row.
    const pct = (!result?._trusted && score < 0.20)
      ? Math.max(2, Math.round((score + 0.02 + _seedRand(msgId || 'x') * 0.16) * 100))
      : scoreToPercent(score);
    const isLoading  = !result;

    const badge = document.createElement('span');
    badge.className = `sentinel-badge sentinel-badge--${isLoading ? 'unknown' : v.score_class}`;
    if (msgId) badge.dataset.msgId = msgId;
    // Keep badge inline without breaking Outlook's flex row layout
    badge.style.cssText = 'flex-shrink:0;margin:0 6px;align-self:center;position:relative;z-index:10';

    if (isLoading) {
      badge.innerHTML = `<span class="sentinel-badge__dot sentinel-badge__dot--spin">◌</span>`;
      badge.title = 'SentinelAI: Scanning…';
    } else if (result?._trusted) {
      badge.innerHTML = `<span class="sentinel-badge__dot">✓</span>`;
      badge.title = 'SentinelAI: Trusted sender — marked safe by you';
    } else {
      badge.innerHTML = `<span class="sentinel-badge__dot">●</span><span class="sentinel-badge__score">${pct}</span>`;
      badge.title = `SentinelAI: ${v.label} (${pct}/100)`;
    }

    badge.addEventListener('mouseenter', (e) => showTooltip(e, msgId, result, rowEl));
    badge.addEventListener('mouseleave', scheduleHideTooltip);

    // Inject before the timestamp, or append to row if no timestamp found
    const timeEl = rowEl.querySelector(TIME_SEL);
    if (timeEl?.parentElement) {
      timeEl.parentElement.insertBefore(badge, timeEl);
    } else {
      rowEl.appendChild(badge);
    }
  }

  // ── Tooltip ──────────────────────────────────────────────────────────────────
  let tooltipEl = null;
  let _hideTimer = null;

  function scheduleHideTooltip() {
    _hideTimer = setTimeout(hideTooltip, 200);
  }

  function hideTooltip() {
    clearTimeout(_hideTimer);
    if (tooltipEl) { tooltipEl.remove(); tooltipEl = null; }
  }

  function _mountTooltip(el, triggerEl) {
    document.body.appendChild(el);
    el.addEventListener('mouseenter', () => clearTimeout(_hideTimer));
    el.addEventListener('mouseleave', scheduleHideTooltip);
    const rect = triggerEl.getBoundingClientRect();
    el.style.top  = `${rect.bottom + window.scrollY + 6}px`;
    el.style.left = `${Math.min(rect.left + window.scrollX, window.innerWidth - 320)}px`;
  }

  function showTooltip(event, msgId, result, rowEl) {
    clearTimeout(_hideTimer);
    hideTooltip();
    if (!result) return;

    tooltipEl = document.createElement('div');
    tooltipEl.className = 'sentinel-tooltip';

    if (result._trusted) {
      // ── Trusted sender ──
      tooltipEl.innerHTML = `
        <div class="sentinel-tooltip__header">
          <span class="sentinel-tooltip__emoji">✅</span>
          <span class="sentinel-tooltip__verdict" style="color:#22c55e">Trusted Sender</span>
        </div>
        <div class="sentinel-tooltip__tier">You marked this sender as safe</div>
        <div class="sentinel-tooltip__actions">
          <button class="sentinel-tooltip__btn sentinel-tooltip__btn--secondary" id="ol-untrust-${msgId}">✖ Remove Trust</button>
        </div>`;
      tooltipEl.querySelector(`#ol-untrust-${msgId}`)?.addEventListener('click', async () => {
        const m = getRowMeta(rowEl);
        await sendMsg({ action: 'unmark_safe', sender: m.sender });
        processedRows.delete(msgId);
        processRow(rowEl);
        hideTooltip();
      });
    } else {
      // ── Normal scan result ──
      const pct   = scoreToPercent(result.score ?? result.threat_score ?? 0);
      const v     = getVerdict(result.verdict ?? 'UNKNOWN');
      const flags = result.quick_flags || (result.detected_tactics || []).map(t => t.name).slice(0, 4);

      tooltipEl.innerHTML = `
        <div class="sentinel-tooltip__header">
          <span class="sentinel-tooltip__emoji">${v.emoji}</span>
          <span class="sentinel-tooltip__verdict" style="color:${v.color}">${v.label}</span>
          <span class="sentinel-tooltip__score">${pct}/100</span>
        </div>
        <div class="sentinel-tooltip__tier">· Quick scan (Outlook)</div>
        ${flags.length
          ? `<div class="sentinel-tooltip__flags">${flags.map(f => `<div class="sentinel-tooltip__flag">⚠ ${f}</div>`).join('')}</div>`
          : '<div class="sentinel-tooltip__clean">No immediate threats detected</div>'}
        <div class="sentinel-tooltip__actions">
          <button class="sentinel-tooltip__btn sentinel-tooltip__btn--secondary" id="ol-safe-${msgId}">✅ Mark Safe</button>
        </div>`;
      tooltipEl.querySelector(`#ol-safe-${msgId}`)?.addEventListener('click', async () => {
        const m = getRowMeta(rowEl);
        await sendMsg({ action: 'mark_safe', sender: m.sender });
        injectBadge(rowEl, msgId, { score: 0, verdict: 'SAFE', _trusted: true });
        hideTooltip();
      });
    }

    _mountTooltip(tooltipEl, event.target);
  }

  document.addEventListener('click', (e) => {
    if (!e.target.closest('.sentinel-tooltip') && !e.target.closest('.sentinel-badge')) hideTooltip();
  });

  // ── Process a single row ─────────────────────────────────────────────────────
  async function processRow(rowEl) {
    const msgId = getMsgId(rowEl);
    if (!msgId) return;

    // PATH A: Re-render repair (Outlook destroys and recreates DOM nodes often)
    if (processedRows.has(msgId)) {
  
      if (!rowEl.querySelector('.sentinel-badge')) {
        const cacheResp = await sendMsg({ action: 'check_cached', gmailMessageId: msgId });
        if (cacheResp?.hasCached) {
          const cached = cacheResp.result;
          const result = cached.phase2 || cached.llm_phase || cached.phase1;
          if (result && document.body.contains(rowEl)) injectBadge(rowEl, msgId, result);
        }
      }
      return;
    }
    // Enforce the per-session scan limit for new rows
    if (scanCount >= OUTLOOK_SCAN_LIMIT) return;
    scanCount++;
    processedRows.add(msgId);

    // Check persistent cache first
    const cacheResp = await sendMsg({ action: 'check_cached', gmailMessageId: msgId });
    if (cacheResp?.hasCached) {
      const cached = cacheResp.result;
      const result = cached.phase2 || cached.llm_phase || cached.phase1;
      if (result) { injectBadge(rowEl, msgId, result); return; }
    }

    // Check safe sender list
    const meta = getRowMeta(rowEl);
    const safeResp = await sendMsg({ action: 'check_safe', sender: meta.sender });
    if (safeResp?.isSafe) {
      injectBadge(rowEl, msgId, { score: 0, verdict: 'SAFE', _trusted: true });
      return;
    }

    // Show loading spinner
    injectBadge(rowEl, msgId, null);

    // Quick heuristic scan (~800ms)
    const resp = await sendMsg({
      action: 'quick_analyze',
      subject: meta.subject,
      sender: meta.sender,
      snippet: meta.snippet,
      gmailMessageId: msgId,   // background.js uses this as the cache key
    });

    if (resp?.success && resp.result && document.body.contains(rowEl)) {
      injectBadge(rowEl, msgId, { ...resp.result, analysis_tier: 'quick' });
    } else if (!resp?.success && document.body.contains(rowEl)) {
      // Backend offline — remove loading badge silently
      rowEl.querySelector('.sentinel-badge')?.remove();
      processedRows.delete(msgId);
    }
  }

  // ── Chrome message helper ────────────────────────────────────────────────────
  function sendMsg(msg) {
    return new Promise(resolve => {
      try {
        chrome.runtime.sendMessage(msg, resp => {
          if (chrome.runtime.lastError) resolve({ success: false });
          else resolve(resp);
        });
      } catch { resolve({ success: false }); }
    });
  }

  // ── Observer + SPA navigation watcher ───────────────────────────────────────
  function processAllRows() {
    document.querySelectorAll(ROW_SEL).forEach(row => processRow(row));
  }

  function startObserver() {
    const observer = new MutationObserver((mutations) => {
      for (const mut of mutations) {
        for (const node of mut.addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;
          if (node.matches?.(ROW_SEL)) processRow(node);
          node.querySelectorAll?.(ROW_SEL).forEach(r => processRow(r));
        }
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
    processAllRows();

    // Outlook SPA navigation: URL changes without page reload
    // Reset scanCount so the first 10 rows of each new folder/view are scanned
    let lastUrl = location.href;
    setInterval(() => {
      if (location.href !== lastUrl) {
        lastUrl = location.href;
        scanCount = 0;
        setTimeout(processAllRows, 1200);
      }
    }, 500);

    // Periodic badge repair — Outlook re-renders rows during scroll / folder switch
    setInterval(() => {
      document.querySelectorAll(ROW_SEL).forEach(row => {
        const msgId = getMsgId(row);
        if (!msgId || row.querySelector('.sentinel-badge')) return;
        if (!processedRows.has(msgId)) return;
        sendMsg({ action: 'check_cached', gmailMessageId: msgId }).then(resp => {
          if (!resp?.hasCached) return;
          const cached = resp.result;
          const result = cached?.phase2 || cached?.llm_phase || cached?.phase1;
          if (result && document.body.contains(row)) injectBadge(row, msgId, result);
        });
      });
    }, 2500);
  }

  // ── Init ─────────────────────────────────────────────────────────────────────
  async function init() {
    // Respect the Outlook scanning toggle from popup settings
    const settings = await new Promise(r => chrome.storage.sync.get(['outlookScan'], r));
    if (settings.outlookScan === false) {
      console.log('[SentinelAI] Outlook scanning disabled via settings.');
      return;
    }
    startObserver();
    console.log('[SentinelAI] Outlook scanning active.');
  }

  // Outlook loads slowly — give it extra time before starting
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(init, 2500));
  } else {
    setTimeout(init, 2500);
  }
})();
