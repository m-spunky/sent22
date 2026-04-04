// SentinelAI Gmail Content Script
// Tier A (count 0–4):   Full 5-layer pipeline   (~2–5s)
// Tier B (count 5–14):  LLM + NLP only           (~1–2s)
// Tier C (count >= 15): Quick heuristic only
//
// KEY: processedRows tracks API calls (no re-calls).
//      Badge injection always re-runs if Gmail destroys the badge node.

(function () {
  'use strict';

  const { getVerdict, scoreToPercent, scoreToVerdict, extractUrlsFromText, truncate } = window.SentinelUtils;

  // ── State ─────────────────────────────────────────────────────────────────
  // msgIds whose API call is done / in-flight — prevents duplicate API calls
  const processedRows = new Set();
  let bannerInjected = false;

  const FULL_LIMIT = 5;    // count 0–4  → full pipeline
  const LLM_LIMIT = 15;   // count 5–14 → LLM+NLP only
  // count >= 15 → quick only

  const SELECTORS = {
    inboxContainer: '.AO',
    emailRow: '.zA',
    openedBody: '.a3s.aiL',
  };

  // ── Message ID extraction ─────────────────────────────────────────────────
  function getMsgId(rowEl) {
    const id = rowEl.getAttribute('data-legacy-message-id');
    if (id) return id;
    const link = rowEl.querySelector('a[href*="#inbox/"], a[href*="#all/"], a[href*="#sent/"]');
    if (link) {
      const m = link.href.match(/#(?:inbox|all|sent)\/([a-f0-9]+)/i);
      if (m) return m[1];
    }
    const subject = rowEl.querySelector('.bog, .bqe');
    const sender = rowEl.querySelector('.yW span[name]');
    if (subject && sender) {

      const text = `${sender.textContent}|${subject.textContent}`;
      let hash = 0;
      for (let i = 0; i < text.length; i++) {
        hash = ((hash << 5) - hash) + text.charCodeAt(i);
        hash |= 0;
      }
      return 'hash_' + Math.abs(hash).toString(16);
    }
    return null;
  }

  function getRowMeta(rowEl) {
    const subjectEl = rowEl.querySelector('.bog, .bqe, .y6 span');
    const fromEl = rowEl.querySelector('.yW span[name]') || rowEl.querySelector('.yX span');
    const snippetEl = rowEl.querySelector('.y2');
    return {
      subject: subjectEl?.textContent.trim() || '',
      sender: fromEl?.getAttribute('email') || fromEl?.textContent.trim() || '',
      snippet: snippetEl?.textContent.trim() || '',
    };
  }

  // ── Badge injection ───────────────────────────────────────────────────────
  function injectBadge(rowEl, msgId, result) {
    // Remove stale badge if present
    rowEl.querySelector('.sentinel-badge')?.remove();

    const score = result?.score ?? result?.threat_score ?? 0;
    const verdictKey = result?.verdict ?? scoreToVerdict(score);
    const pct = scoreToPercent(score);
    const v = getVerdict(verdictKey);
    const isLoading = !result;

    const badge = document.createElement('span');
    badge.className = `sentinel-badge sentinel-badge--${isLoading ? 'unknown' : v.score_class}`;
    badge.dataset.msgId = msgId;

    if (isLoading) {
      badge.innerHTML = `<span class="sentinel-badge__dot sentinel-badge__dot--spin">◌</span>`;
      badge.title = 'SentinelAI: Scanning…';
    } else {
      const tierDot = result?.analysis_tier === 'full' ? '★'
        : result?.analysis_tier === 'llm' ? '◆' : '●';
      badge.innerHTML = `<span class="sentinel-badge__dot">${tierDot}</span><span class="sentinel-badge__score">${pct}</span>`;
      badge.title = `SentinelAI: ${v.label} (${pct}/100)`;
    }

    badge.addEventListener('click', (e) => {
      e.stopPropagation(); e.preventDefault();
      openSidePanel(msgId, result, getRowMeta(rowEl));
    });
    badge.addEventListener('mouseenter', (e) => showTooltip(e, msgId, result, rowEl));
    badge.addEventListener('mouseleave', hideTooltip);

    // Insert before date cell — most reliable anchor in Gmail
    const dateEl = rowEl.querySelector('.xW.xY, .xW, .xY');
    if (dateEl) dateEl.parentElement?.insertBefore(badge, dateEl);
    else rowEl.appendChild(badge);
  }

  // ── Tooltip ───────────────────────────────────────────────────────────────
  let tooltipEl = null;
  function showTooltip(event, msgId, result, rowEl) {
    hideTooltip();
    if (!result) return;
    const pct = scoreToPercent(result.score ?? result.threat_score ?? 0);
    const v = getVerdict(result.verdict ?? 'UNKNOWN');
    const flags = result.quick_flags || (result.detected_tactics || []).map(t => t.name).slice(0, 4) || [];
    const tierLabel = result.analysis_tier === 'full' ? '★ Full analysis'
      : result.analysis_tier === 'llm' ? '◆ LLM analysis' : '· Quick scan';

    tooltipEl = document.createElement('div');
    tooltipEl.className = 'sentinel-tooltip';
    tooltipEl.innerHTML = `
      <div class="sentinel-tooltip__header">
        <span class="sentinel-tooltip__emoji">${v.emoji}</span>
        <span class="sentinel-tooltip__verdict" style="color:${v.color}">${v.label}</span>
        <span class="sentinel-tooltip__score">${pct}/100</span>
      </div>
      <div class="sentinel-tooltip__tier">${tierLabel}</div>
      ${flags.length
        ? `<div class="sentinel-tooltip__flags">${flags.map(f => `<div class="sentinel-tooltip__flag">⚠ ${f}</div>`).join('')}</div>`
        : '<div class="sentinel-tooltip__clean">No immediate threats detected</div>'}
      <div class="sentinel-tooltip__actions">
        <button class="sentinel-tooltip__btn sentinel-tooltip__btn--primary" id="tip-detail-${msgId}">📊 Detailed Analysis</button>
        <button class="sentinel-tooltip__btn sentinel-tooltip__btn--secondary">✅ Mark Safe</button>
      </div>`;
    tooltipEl.querySelector(`#tip-detail-${msgId}`)?.addEventListener('click', () => {
      openSidePanel(msgId, result, getRowMeta(rowEl));
      hideTooltip();
    });
    document.body.appendChild(tooltipEl);
    const rect = event.target.getBoundingClientRect();
    tooltipEl.style.top = `${rect.bottom + window.scrollY + 6}px`;
    tooltipEl.style.left = `${Math.min(rect.left + window.scrollX, window.innerWidth - 320)}px`;
  }

  function hideTooltip() {
    if (tooltipEl) { tooltipEl.remove(); tooltipEl = null; }
  }
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.sentinel-tooltip') && !e.target.closest('.sentinel-badge')) hideTooltip();
  });

  // ── Extract full email content when email is open ─────────────────────────
  function extractOpenEmailContent() {
    const bodyEl = document.querySelector(SELECTORS.openedBody); // .a3s.aiL
    if (!bodyEl) return null;
    const bodyText = (bodyEl.innerText || bodyEl.textContent || '').trim();
    if (!bodyText || bodyText.length < 20) return null;

    // Attachment filenames from Gmail attachment chips (names only — bytes not accessible)
    const attachmentNames = [];
    const seen = new Set();
    // Try multiple selectors — Gmail changes these periodically
    document.querySelectorAll(
      '.aZo .aV3, .brc .aV3, .aQy .aV3, .aQH span[data-tooltip], .aQH .aV3'
    ).forEach(el => {
      const t = el.textContent?.trim();
      if (t && t.includes('.') && !seen.has(t)) { seen.add(t); attachmentNames.push(t); }
    });
    // Fallback: attachment icon siblings
    document.querySelectorAll('.aQH .aZo').forEach(el => {
      const t = el.querySelector('span')?.textContent?.trim();
      if (t && t.includes('.') && !seen.has(t)) { seen.add(t); attachmentNames.push(t); }
    });

    // Visible To / Date from open-email header area
    const toEl = document.querySelector('.hb .g2 span[email], .ajy span[email]');
    const dateEl = document.querySelector('.g3 .gK span, .g3 span[title]');

    return {
      bodyText: bodyText.slice(0, 12000),
      attachmentNames,
      hasAttachments: attachmentNames.length > 0,
      to: toEl?.getAttribute('email') || toEl?.textContent?.trim() || '',
      date: dateEl?.getAttribute('title') || dateEl?.textContent?.trim() || '',
    };
  }

  function openSidePanel(msgId, result, meta) {
    const emailContent = extractOpenEmailContent(); // null if email not open
    chrome.runtime.sendMessage({
      action: 'open_sidepanel',
      context: { msgId, quickResult: result, meta, emailContent },
    });
  }

  // ── Session counter helpers ───────────────────────────────────────────────
  function getFullCount() {
    return new Promise(r => chrome.runtime.sendMessage({ action: 'get_full_count' }, resp => r(resp?.count || 0)));
  }
  function incrementFullCount() {
    return new Promise(r => chrome.runtime.sendMessage({ action: 'increment_full_count' }, resp => r(resp?.count || 1)));
  }

  // ── CORE: Process a row ───────────────────────────────────────────────────
  //
  // TWO separate paths:
  //   A) Row has no badge AND msgId in processedRows  → silent re-inject from cache
  //   B) Row is brand new (not in processedRows)      → full API flow
  //
  async function processRow(rowEl) {
    const msgId = getMsgId(rowEl);
    if (!msgId) return;

    const hasBadge = !!rowEl.querySelector('.sentinel-badge');

    // ── PATH A: Already processed, badge was destroyed by Gmail re-render ──
    if (processedRows.has(msgId)) {
      if (!hasBadge) {
        // Silent re-inject from cache — no API call
        const cacheResp = await sendMsg({ action: 'check_cached', gmailMessageId: msgId });
        if (cacheResp?.hasCached) {
          const cached = cacheResp.result;
          const result = cached.phase2 || cached.llm_phase || cached.phase1;
          if (result) injectBadge(rowEl, msgId, result);
          else injectBadge(rowEl, msgId, null); // restore loading state
        }
      }
      return; // Never re-trigger API for an already-processed row
    }

    // ── PATH B: New row — mark as processing immediately ──────────────────
    processedRows.add(msgId);

    // STEP 1: Check persistent storage cache
    const cacheResp = await sendMsg({ action: 'check_cached', gmailMessageId: msgId });
    if (cacheResp?.hasCached) {
      const cached = cacheResp.result;
      const result = cached.phase2 || cached.llm_phase || cached.phase1;
      if (result) { injectBadge(rowEl, msgId, result); return; }
    }

    // STEP 2: Inject loading spinner
    injectBadge(rowEl, msgId, null);
    const meta = getRowMeta(rowEl);

    // STEP 3: Quick heuristic (always, ~800ms)
    const q1Resp = await sendMsg({
      action: 'quick_analyze',
      subject: meta.subject,
      sender: meta.sender,
      snippet: meta.snippet,
      gmailMessageId: msgId,
    });
    if (!q1Resp?.success || !q1Resp.result) return;

    // Only inject if row still in DOM and badge still ours
    if (document.body.contains(rowEl)) {
      injectBadge(rowEl, msgId, { ...q1Resp.result, analysis_tier: 'quick' });
    }

    // STEP 4: Deep analysis tier selection
    const count = await getFullCount();
    if (count < FULL_LIMIT) {
      await incrementFullCount();
      runDeepAnalysis(rowEl, msgId, meta, 'full');
    } else if (count < LLM_LIMIT) {
      await incrementFullCount();
      runDeepAnalysis(rowEl, msgId, meta, 'llm');
    }
    // count >= 15: keep quick score
  }

  async function runDeepAnalysis(rowEl, msgId, meta, tier) {
    const content = `From: ${meta.sender}\nSubject: ${meta.subject}\n\n${meta.snippet}`;
    const resp = await sendMsg({
      action: tier === 'full' ? 'full_analyze' : 'llm_analyze',
      content,
      gmailMessageId: msgId,
      gmailSubject: meta.subject,
      gmailSender: meta.sender,
    });
    if (resp?.success && resp.result) {
      const r = resp.result;
      const badgeData = {
        score: r.threat_score,
        threat_score: r.threat_score,
        verdict: r.verdict,
        quick_flags: (r.detected_tactics || []).map(t => t.name).slice(0, 4),
        confidence: r.confidence,
        full_result: r,
        analysis_tier: tier,
      };
      // Re-find the row in case Gmail re-rendered it to a new element
      const liveRow = findRowByMsgId(msgId) || rowEl;
      if (document.body.contains(liveRow)) {
        injectBadge(liveRow, msgId, badgeData);
      }
    }
  }

  // Find the current DOM element for a msgId (Gmail may replace the node)
  function findRowByMsgId(msgId) {
    return document.querySelector(`.zA[data-legacy-message-id="${msgId}"]`)
      || [...document.querySelectorAll('.zA')].find(row => getMsgId(row) === msgId);
  }

  // ── Periodic re-scan: restore any badges Gmail silently destroyed ─────────
  function startPeriodicReinject() {
    setInterval(() => {
      document.querySelectorAll(SELECTORS.emailRow).forEach(row => {
        const msgId = getMsgId(row);
        if (!msgId) return;
        if (processedRows.has(msgId) && !row.querySelector('.sentinel-badge')) {
          // Badge was destroyed — restore silently
          sendMsg({ action: 'check_cached', gmailMessageId: msgId }).then(resp => {
            if (!resp?.hasCached) return;
            const cached = resp.result;
            const result = cached?.phase2 || cached?.llm_phase || cached?.phase1;
            if (result && document.body.contains(row)) injectBadge(row, msgId, result);
          });
        }
      });
    }, 2000); // every 2 seconds
  }

  // ── Watch for opened email — inject warning banner ────────────────────────
  function watchOpenedEmail() {
    let lastBodyEl = null;
    const observer = new MutationObserver(() => {
      const bodyEl = document.querySelector(SELECTORS.openedBody);
      if (!bodyEl) { bannerInjected = false; lastBodyEl = null; return; }
      if (bodyEl === lastBodyEl || bannerInjected) return;
      lastBodyEl = bodyEl;

      const m = location.hash.match(/#(?:inbox|sent|all)\/?([a-f0-9]+)/i);
      const msgId = m ? m[1] : null;
      if (msgId) {
        sendMsg({ action: 'get_cache', gmailMessageId: msgId }).then(resp => {
          const cached = resp?.result;
          const result = cached?.phase2 || cached?.llm_phase || cached?.phase1;
          injectEmailBanner(bodyEl, msgId, result);
        });
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  // ── Warning banner ────────────────────────────────────────────────────────
  function injectEmailBanner(bodyEl, msgId, result) {
    const score = result?.threat_score ?? result?.score ?? 0;
    const verdictKey = result?.verdict ?? scoreToVerdict(score);
    if (['SAFE', 'LOW_RISK', 'UNKNOWN'].includes(verdictKey)) { bannerInjected = true; return; }
    if (document.querySelector('.sentinel-email-banner')) return;

    const pct = scoreToPercent(score);
    const v = getVerdict(verdictKey);
    const tactics = result?.detected_tactics || [];
    const flags = result?.quick_flags || tactics.map(t => t.name) || [];
    const urls = result?.urls_analyzed || extractUrlsFromText(bodyEl.textContent);
    const eventId = result?.event_id || '';

    const banner = document.createElement('div');
    banner.className = `sentinel-email-banner sentinel-email-banner--${v.score_class}`;
    banner.innerHTML = `
      <div class="sentinel-banner__header">
        <div class="sentinel-banner__title">
          <span>${v.emoji}</span>
          <span>SentinelAI — <strong>${v.label}</strong> DETECTED</span>
        </div>
        <div class="sentinel-banner__meta">Score: <strong>${pct}/100</strong> &nbsp;|&nbsp; Confidence: <strong>${Math.round((result?.confidence || 0) * 100)}%</strong></div>
        <button class="sentinel-banner__close">✕</button>
      </div>
      <div class="sentinel-banner__body">
        <div class="sentinel-banner__flags">
          ${flags.length
        ? flags.slice(0, 4).map(f => {
          const name = typeof f === 'string' ? f : f.name;
          const desc = typeof f === 'object' ? (f.description || '') : '';
          return `<div class="sentinel-banner__flag">⚠ <strong>${name}</strong>${desc ? ` — ${desc}` : ''}</div>`;
        }).join('')
        : '<div class="sentinel-banner__flag">⚠ Suspicious patterns detected</div>'}
        </div>
        ${urls.length ? `<div class="sentinel-banner__urls">
          <div class="sentinel-banner__section-title">🔗 Extracted Links</div>
          ${urls.slice(0, 3).map(u => `<div class="sentinel-banner__url">${truncate(u, 70)}</div>`).join('')}
        </div>` : ''}
      </div>
      <div class="sentinel-banner__actions">
        ${eventId
        ? `<a href="http://localhost:3002/dashboard/analyze?event_id=${eventId}" target="_blank" class="sentinel-banner__btn sentinel-banner__btn--primary">📊 View Full Report</a>`
        : `<button class="sentinel-banner__btn sentinel-banner__btn--primary" id="sentinel-banner-panel-${msgId}">📊 Detailed Analysis</button>`}
        ${eventId ? `<a href="http://localhost:3002/dashboard/chat?q=${encodeURIComponent(`Analyze email event ${eventId}`)}" target="_blank" class="sentinel-banner__btn sentinel-banner__btn--secondary">💬 Sentinel Chat</a>` : ''}
        <button class="sentinel-banner__btn sentinel-banner__btn--ghost">🚩 Report</button>
        <button class="sentinel-banner__btn sentinel-banner__btn--ghost sentinel-banner__close-btn">✅ Mark Safe</button>
      </div>`;

    banner.querySelector('.sentinel-banner__close')?.addEventListener('click', () => banner.remove());
    banner.querySelector('.sentinel-banner__close-btn')?.addEventListener('click', () => banner.remove());
    banner.querySelector(`#sentinel-banner-panel-${msgId}`)?.addEventListener('click', () => openSidePanel(msgId, result, {}));
    bodyEl.parentElement?.insertBefore(banner, bodyEl);
    bannerInjected = true;
  }

  // ── Chrome message helper ─────────────────────────────────────────────────
  function sendMsg(msg) {
    return new Promise(resolve => {
      try {
        chrome.runtime.sendMessage(msg, resp => {
          if (chrome.runtime.lastError) resolve({ success: false, error: chrome.runtime.lastError.message });
          else resolve(resp);
        });
      } catch (e) {
        resolve({ success: false, error: e.message });
      }
    });
  }

  // ── MutationObserver ──────────────────────────────────────────────────────
  function startObserver() {
    const processAllRows = () =>
      document.querySelectorAll(SELECTORS.emailRow).forEach(row => processRow(row));

    // Watch both the inbox container AND document body for Gmail re-renders
    const rowObserver = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;
          if (node.matches?.(SELECTORS.emailRow)) processRow(node);
          node.querySelectorAll?.(SELECTORS.emailRow).forEach(row => processRow(row));
        }
      }
    });

    function attachObserver() {
      const container = document.querySelector(SELECTORS.inboxContainer);
      if (container) {
        rowObserver.observe(container, { childList: true, subtree: true });
        processAllRows();
        return true;
      }
      return false;
    }

    if (!attachObserver()) {
      // Gmail not loaded yet — wait
      const waitObserver = new MutationObserver(() => {
        if (attachObserver()) waitObserver.disconnect();
      });
      waitObserver.observe(document.body, { childList: true, subtree: true });
    }

    // Re-scan on Gmail hash navigation (#inbox, #sent, etc.)
    let lastHash = location.hash;
    setInterval(() => {
      if (location.hash !== lastHash) {
        lastHash = location.hash;
        bannerInjected = false;
        setTimeout(processAllRows, 800);
      }
    }, 400);
  }

  // ── Init ──────────────────────────────────────────────────────────────────
  function init() {
    startObserver();
    watchOpenedEmail();
    startPeriodicReinject();   // ← repair badges Gmail destroys every 2s
    console.log(`[SentinelAI] Ready. Tiers: full<${FULL_LIMIT} | llm<${LLM_LIMIT} | quick>=15`);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(init, 1500));
  } else {
    setTimeout(init, 1500);
  }
})();
