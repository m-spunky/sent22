// SentinelAI — Side Panel Logic

const SENTINEL_API = 'http://localhost:8001/api/v1';

// ── State ──────────────────────────────────────────────────────────────────────
let currentContext = null; // { msgId, quickResult, meta }
let fullResult = null;

// ── DOM refs ───────────────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const loadingEl = $('loading-state');
const mainEl = $('main-content');
const errorEl = $('error-state');

// ── Utils (loaded from shared/utils.js attached to window) ────────────────────
// getVerdict, scoreToPercent, VERDICTS, etc. are already in global scope from utils.js

// ── Init: read context from session storage ────────────────────────────────────
async function init() {
  showLoading();

  // Get context passed from content script via background
  const stored = await chrome.storage.session.get('sidepanel_context');
  currentContext = stored?.sidepanel_context || null;

  if (!currentContext?.msgId) {
    showError('Open a Gmail email and click the SentinelAI badge to analyze it.');
    return;
  }

  // Check cache first
  const cachedResp = await sendMsg({ action: 'get_cache', gmailMessageId: currentContext.msgId });
  const cached = cachedResp?.result;

  if (cached?.phase2) {
    fullResult = cached.phase2;
    renderFull(fullResult);
    return;
  }

  // Show quick result while full runs
  if (cached?.phase1 || currentContext.quickResult) {
    const quick = cached?.phase1 || currentContext.quickResult;
    renderQuick(quick);
  }

  // Run full analysis
  runFullAnalysis();
}

async function runFullAnalysis() {
  const meta = currentContext.meta || {};
  const emailContent = currentContext.emailContent; // set when email is open in Gmail

  let content, action, attachmentNames = [];

  if (emailContent?.bodyText && emailContent.bodyText.length > 50) {
    // ── Full email body available (user had email open) ──────────────────────
    // Build a structured content string with headers + body for all 5 layers
    const headerLines = [
      `From: ${meta.sender || ''}`,
      `Subject: ${meta.subject || ''}`,
    ];
    if (emailContent.to) headerLines.push(`To: ${emailContent.to}`);
    if (emailContent.date) headerLines.push(`Date: ${emailContent.date}`);
    if (emailContent.attachmentNames?.length) {
      attachmentNames = emailContent.attachmentNames;
      headerLines.push(`X-Attachments: ${attachmentNames.join(', ')}`);
    }
    content = headerLines.join('\n') + '\n\n' + emailContent.bodyText;
    action = 'full_analyze'; // full 5-layer: NLP + URL live + headers + IOC + dark web

    if ($('layer-bars')) {
      const attNote = attachmentNames.length
        ? ` · ${attachmentNames.length} attachment(s) detected`
        : '';
      $('layer-bars').innerHTML =
        `<div class="layer-bars__scanning">Running full 5-layer analysis…${attNote}</div>`;
    }
  } else {
    // ── Snippet only (email not open) ─────────────────────────────────────────
    content = `From: ${meta.sender || ''}\nSubject: ${meta.subject || ''}\n\n${meta.snippet || ''}`;
    action = 'llm_analyze'; // llm_only: faster, appropriate for snippet

    if ($('layer-bars')) {
      $('layer-bars').innerHTML =
        '<div class="layer-bars__scanning">Running AI analysis… (open the email for full 5-layer scan)</div>';
    }
  }

  const resp = await sendMsg({
    action,
    content,
    gmailMessageId: currentContext.msgId,
    gmailSubject: meta.subject,
    gmailSender: meta.sender,
    attachmentNames,
  });

  if (resp?.success && resp.result) {
    fullResult = resp.result;
    renderFull(fullResult);
  } else {
    const isAlreadyShowingResult = !mainEl.classList.contains('hidden');
    if (isAlreadyShowingResult) {
      if ($('layer-bars')) {
        $('layer-bars').innerHTML = `<div class="layer-bars__error" style="color:#ef4444;font-size:12px;padding:8px 0">
          ⚠ Analysis failed: ${resp?.error || 'Backend timeout'}. Quick scan result shown above.
          <button id="retry-full-btn" style="margin-left:8px;padding:2px 8px;font-size:11px;cursor:pointer">Retry</button>
        </div>`;
        document.getElementById('retry-full-btn')?.addEventListener('click', runFullAnalysis);
      }
    } else {
      showError(resp?.error || 'Analysis failed. Is the Sentinel backend running?');
    }
  }
}

// ── Render: Quick (Phase 1) ────────────────────────────────────────────────────
function renderQuick(quick) {
  showMain();
  const score = quick.score || 0;
  const pct = scoreToPercent(score);
  const v = getVerdict(quick.verdict || 'UNKNOWN');

  setScoreCircle(pct, v);
  $('score-verdict').textContent = v.label;
  $('score-verdict').style.color = v.color;
  $('score-conf').textContent = `Confidence: ${Math.round((quick.confidence || 0) * 100)}% (quick scan)`;
  $('score-time').textContent = quick.inference_time_ms ? `⚡ ${quick.inference_time_ms}ms` : '';
  $('header-verdict').textContent = v.label;
  $('header-verdict').className = `header__verdict header__verdict--${v.score_class}`;

  // Quick flags
  const flags = quick.quick_flags || [];
  $('threats-list').innerHTML = flags.length
    ? flags.map(f => `<div class="threat-item threat-item--medium"><span class="threat-icon">⚠</span><div><div class="threat-name">${f}</div></div></div>`).join('')
    : '<div class="no-threats">No immediate threats (quick scan). Full analysis running…</div>';

  $('layer-bars').innerHTML = '<div class="layer-bars__scanning">Running full analysis…</div>';
  renderUrlsFromMeta();
}

// ── Render: Full (Phase 2) ─────────────────────────────────────────────────────
function renderFull(result) {
  showMain();
  const score = result.threat_score || 0;
  const pct = scoreToPercent(score);
  const verdict = result.verdict || 'UNKNOWN';
  const v = getVerdict(verdict);

  setScoreCircle(pct, v);
  $('score-verdict').textContent = v.label;
  $('score-verdict').style.color = v.color;
  $('score-conf').textContent = `Confidence: ${Math.round((result.confidence || 0) * 100)}%`;
  $('score-time').textContent = result.inference_time_ms
    ? `⚡ Full analysis: ${result.inference_time_ms}ms` : '';
  $('header-verdict').textContent = v.label;
  $('header-verdict').className = `header__verdict header__verdict--${v.score_class}`;

  renderLayerBars(result);
  renderThreats(result);
  renderAttachments(result);
  renderUrls(result);
  renderActions(result);
}

// ── Score ring ─────────────────────────────────────────────────────────────────
function setScoreCircle(pct, v) {
  $('score-num').textContent = pct;
  $('score-num').style.color = v.color;
  const circumference = 213.6;
  const offset = circumference - (pct / 100) * circumference;
  $('score-ring-progress').style.strokeDashoffset = offset;
  $('score-ring-progress').style.stroke = v.color;
}

// ── Layer bars ─────────────────────────────────────────────────────────────────
function renderLayerBars(result) {
  const mb = result.model_breakdown || {};
  const layers = [
    { key: 'nlp', label: 'NLP Content', icon: '🧠', score: mb.nlp?.score },
    { key: 'header', label: 'Email Headers', icon: '📋', score: mb.header?.score },
    { key: 'url', label: 'URL Analysis', icon: '🔗', score: mb.url?.score },
    { key: 'visual', label: 'Visual Sandbox', icon: '🖼', score: mb.visual?.score },
  ];

  $('layer-bars').innerHTML = layers.map(l => {
    if (l.score === undefined || l.score === null) return '';
    const pct = Math.round((l.score || 0) * 100);
    const color = pct >= 60 ? '#ef4444' : pct >= 35 ? '#f59e0b' : '#22c55e';
    return `
      <div class="layer-bar">
        <div class="layer-bar__label">
          <span>${l.icon} ${l.label}</span>
          <span style="color:${color}">${pct}%</span>
        </div>
        <div class="layer-bar__track">
          <div class="layer-bar__fill" style="width:${pct}%;background:${color}"></div>
        </div>
      </div>`;
  }).join('');
}

// ── Threats ────────────────────────────────────────────────────────────────────
function renderThreats(result) {
  const tactics = result.detected_tactics || [];
  if (!tactics.length) {
    $('threats-list').innerHTML = '<div class="no-threats">✅ No phishing tactics detected</div>';
    return;
  }
  $('threats-list').innerHTML = tactics.map(t => {
    const sev = t.severity || 'medium';
    const colors = { high: '#ef4444', critical: '#b91c1c', medium: '#f59e0b', low: '#6b7280' };
    const color = colors[sev] || colors.medium;
    return `
      <div class="threat-item">
        <div class="threat-sev-dot" style="background:${color}"></div>
        <div class="threat-content">
          <div class="threat-name">${t.name || 'Unknown Tactic'}</div>
          ${t.mitre_id ? `<div class="threat-mitre">MITRE: ${t.mitre_id}</div>` : ''}
          ${t.description ? `<div class="threat-desc">${t.description}</div>` : ''}
        </div>
        <div class="threat-sev-badge" style="color:${color};border-color:${color}44">${sev.toUpperCase()}</div>
      </div>`;
  }).join('');
}

// ── Attachments ────────────────────────────────────────────────────────────────
function renderAttachments(result) {
  const attCard = $('attachments-card');
  const attList = $('attachments-list');

  // Priority 1: full Gmail API + VT results
  const gmailAtts = result.attachment_analysis?.results || [];
  // Priority 2: legacy VT blob (single file upload from dashboard)
  const legacyVt = result.virustotal;
  // Priority 3: names-only from DOM extraction
  const attSummary = result.attachment_summary;

  const hasData = gmailAtts.length > 0 || legacyVt || (attSummary?.total > 0);
  if (!hasData) { attCard.classList.add('hidden'); return; }

  attCard.classList.remove('hidden');

  // ── Priority 1: Per-file Gmail API + VT results ───────────────────────────
  if (gmailAtts.length > 0) {
    attList.innerHTML = gmailAtts.map(a => {
      const vt = a.virustotal || {};
      const riskColors = { CRITICAL: '#b91c1c', HIGH: '#ef4444', MEDIUM: '#f59e0b', LOW: '#22c55e', UNKNOWN: '#6b7280' };
      const color = riskColors[a.risk_level] || riskColors.UNKNOWN;
      const vtBadge = vt.available
        ? `<a href="${vt.permalink}" target="_blank"
             style="font-size:11px;font-weight:700;color:${color};border:1px solid ${color}44;
                    padding:2px 6px;border-radius:4px;text-decoration:none">
             VT: ${vt.detection_ratio}
           </a>`
        : `<span style="font-size:11px;color:#6b7280;border:1px solid #33333344;padding:2px 6px;border-radius:4px">
             ${vt.reason === 'no_api_key' ? 'VT: no key' : vt.reason === 'timeout' ? 'VT: timeout' : 'VT: pending'}
           </span>`;

      const sizeKb = a.size_bytes > 0 ? `${(a.size_bytes / 1024).toFixed(0)} KB` : '';

      return `
        <div class="att-item">
          <div class="att-header">
            <div class="att-name">📎 ${a.filename} <span style="color:#6b7280;font-size:11px">${sizeKb}</span></div>
            ${vtBadge}
          </div>
          ${vt.malware_families?.length ? `<div class="att-families">🦠 ${vt.malware_families.join(', ')}</div>` : ''}
          ${vt.malicious_engines?.length ? `
            <div class="att-engines">
              <div class="att-engines-label">Detected by:</div>
              <div class="att-engines-list">${vt.malicious_engines.slice(0, 6).join(', ')}</div>
            </div>` : ''}
          <div class="att-findings">
            ${(a.findings || []).slice(0, 3).map(f => `<div class="att-finding">⚠ ${f}</div>`).join('')}
          </div>
          ${vt.permalink ? `<a href="${vt.permalink}" target="_blank" class="btn btn--ghost btn--sm" style="margin-top:6px">🔗 View on VirusTotal</a>` : ''}
        </div>`;
    }).join('');
    return;
  }

  // ── Priority 2: legacy single-file VT (dashboard upload) ─────────────────
  if (legacyVt?.available) {
    const color = legacyVt.risk_level === 'CRITICAL' ? '#b91c1c'
      : legacyVt.risk_level === 'HIGH' ? '#ef4444'
        : legacyVt.risk_level === 'MEDIUM' ? '#f59e0b' : '#22c55e';
    attList.innerHTML = `
      <div class="att-item">
        <div class="att-header">
          <div class="att-name">📎 Attachment</div>
          <a href="${legacyVt.permalink}" target="_blank" class="att-vt-badge" style="border-color:${color}44;color:${color}">
            VT: ${legacyVt.detection_ratio}
          </a>
        </div>
        ${legacyVt.malware_families?.length ? `<div class="att-families">🦠 ${legacyVt.malware_families.join(', ')}</div>` : ''}
        ${legacyVt.malicious_engines?.length ? `
          <div class="att-engines">
            <div class="att-engines-label">Detected by:</div>
            <div class="att-engines-list">${legacyVt.malicious_engines.slice(0, 6).join(', ')}</div>
          </div>` : ''}
        <a href="${legacyVt.permalink}" target="_blank" class="btn btn--ghost btn--sm" style="margin-top:8px">🔗 View on VirusTotal</a>
      </div>`;
    return;
  }

  // ── Priority 3: names only (email not open / OAuth not connected) ─────────
  if (attSummary?.total > 0) {
    attList.innerHTML = attSummary.names.map(name => {
      const isRisky = attSummary.risky?.includes(name);
      const color = isRisky ? '#ef4444' : '#6b7280';
      const ext = name.split('.').pop().toUpperCase();
      return `
        <div class="att-item">
          <div class="att-header">
            <div class="att-name">📎 ${name}</div>
            <span style="color:${color};font-size:11px;font-weight:600">${isRisky ? '⚠ RISKY EXT' : ext}</span>
          </div>
          ${isRisky ? `<div class="att-findings"><div class="att-finding">⚠ ${ext} can execute malicious code — verify before opening</div></div>` : ''}
          <div style="font-size:11px;color:#6b7280;margin-top:4px">Connect Gmail OAuth for VirusTotal scan</div>
        </div>`;
    }).join('');
  }
}

// ── URLs ───────────────────────────────────────────────────────────────────────
function renderUrls(result) {
  const urls = result.urls_analyzed || [];
  if (!urls.length) {
    $('urls-list').innerHTML = '<div class="no-urls">No URLs found in this email.</div>';
    return;
  }
  $('urls-list').innerHTML = urls.map((url, i) => {
    const short = url.length > 55 ? url.slice(0, 55) + '…' : url;
    return `
      <div class="url-item" id="url-item-${i}">
        <div class="url-text" title="${url}">${short}</div>
        <div class="url-actions">
          <button class="btn btn--ghost btn--xs sandbox-btn" data-url="${url}" data-idx="${i}">
            🔍 Sandbox
          </button>
          <button class="btn btn--ghost btn--xs sandbox-visual-btn" data-url="${url}" data-idx="${i}">
            📸 + Screenshot
          </button>
        </div>
        <div class="url-sandbox-result hidden" id="sandbox-inline-${i}"></div>
      </div>`;
  }).join('');

  // Attach sandbox button listeners
  document.querySelectorAll('.sandbox-btn').forEach(btn => {
    btn.addEventListener('click', () => runInlineSandbox(btn.dataset.url, btn.dataset.idx, false));
  });
  document.querySelectorAll('.sandbox-visual-btn').forEach(btn => {
    btn.addEventListener('click', () => runInlineSandbox(btn.dataset.url, btn.dataset.idx, true));
  });
}

function renderUrlsFromMeta() {
  const meta = currentContext?.meta || {};
  const text = `${meta.subject || ''} ${meta.snippet || ''}`;
  const urls = window.SentinelUtils.extractUrlsFromText(text);
  if (!urls.length) {
    $('urls-list').innerHTML = '<div class="no-urls">Open the email to extract URLs.</div>';
    return;
  }
  // Render simplified without sandbox (quick mode)
  $('urls-list').innerHTML = urls.map(u =>
    `<div class="url-item"><div class="url-text">${u.length > 60 ? u.slice(0, 60) + '…' : u}</div></div>`
  ).join('');
}

// ── Inline URL Sandbox ─────────────────────────────────────────────────────────
async function runInlineSandbox(url, idx, withScreenshot) {
  const resultEl = $(`sandbox-inline-${idx}`);
  resultEl.classList.remove('hidden');
  resultEl.innerHTML = `<div class="sandbox-loading">🔍 Sandboxing <span class="mono">${url.slice(0, 40)}…</span></div>`;

  const resp = await sendMsg({ action: 'sandbox_url', url, deep: withScreenshot });
  if (!resp?.success) {
    resultEl.innerHTML = `<div class="sandbox-error">❌ Sandbox failed: ${resp?.error || 'Unknown error'}</div>`;
    return;
  }

  const r = resp.result;
  const score = r.sandbox_risk_score || 0;
  const pct = Math.round(score * 100);
  const vKey = r.sandbox_verdict || (score >= 0.65 ? 'PHISHING' : score >= 0.35 ? 'SUSPICIOUS' : 'SAFE');
  const v = getVerdict(vKey);

  const redirectHtml = (r.redirect_chain?.length > 1)
    ? `<div class="sandbox-row">🔀 Redirects: <span class="sandbox-chain">${r.redirect_chain.join(' → ')}</span></div>`
    : '';

  const sslIcon = r.ssl_info?.valid === false ? '🔴 Invalid SSL' : '🟢 SSL Valid';

  resultEl.innerHTML = `
    <div class="sandbox-result">
      <div class="sandbox-result__header" style="border-color:${v.color}44">
        <span style="color:${v.color}">${v.emoji} ${v.label}</span>
        <span class="sandbox-score" style="color:${v.color}">${pct}/100</span>
      </div>
      ${r.page_info?.title ? `<div class="sandbox-row">📄 Page title: <strong>${r.page_info.title}</strong></div>` : ''}
      ${redirectHtml}
      <div class="sandbox-row">${sslIcon} — ${r.hostname}</div>
      ${r.page_info?.has_password_field ? `<div class="sandbox-row warning">⚠ Password field detected — credential harvesting form</div>` : ''}
      ${(r.sandbox_flags || []).slice(0, 3).map(f => `<div class="sandbox-flag">• ${f}</div>`).join('')}
      ${r.screenshot_url ? `<img src="${r.screenshot_url}" class="sandbox-screenshot" alt="Page screenshot" />` : !withScreenshot ? `<div class="sandbox-hint">Click "📸 + Screenshot" for visual sandbox</div>` : '<div class="sandbox-loading">📸 Screenshot loading…</div>'}
      <a href="http://localhost:3002/dashboard/sandbox?url=${encodeURIComponent(url)}" target="_blank" class="btn btn--ghost btn--sm" style="margin-top:8px">
        🔗 Open Full Sandbox Report
      </a>
    </div>`;
}

// ── Actions bar ────────────────────────────────────────────────────────────────
function renderActions(result) {
  const eventId = result.event_id || '';
  const meta = currentContext?.meta || {};
  if (eventId) {
    $('btn-platform').href = `http://localhost:3002/dashboard/analyze?event_id=${eventId}`;
    const chatQ = encodeURIComponent(`Analyze email event ${eventId}: "${meta.subject || ''}"`);
    $('btn-chat').href = `http://localhost:3002/dashboard/chat?q=${chatQ}`;
  }
}

// ── UI state helpers ───────────────────────────────────────────────────────────
function showLoading() {
  loadingEl.classList.remove('hidden');
  mainEl.classList.add('hidden');
  errorEl.classList.add('hidden');
}
function showMain() {
  loadingEl.classList.add('hidden');
  mainEl.classList.remove('hidden');
  errorEl.classList.add('hidden');
}
function showError(msg) {
  loadingEl.classList.add('hidden');
  mainEl.classList.add('hidden');
  errorEl.classList.remove('hidden');
  $('error-msg').textContent = msg;
}

// ── Chrome message helper ──────────────────────────────────────────────────────
function sendMsg(msg) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(msg, (resp) => {
        if (chrome.runtime.lastError) resolve({ success: false, error: chrome.runtime.lastError.message });
        else resolve(resp);
      });
    } catch (e) {
      resolve({ success: false, error: e.message });
    }
  });
}

// ── Event listeners ────────────────────────────────────────────────────────────
$('btn-retry')?.addEventListener('click', init);

// ── Start ──────────────────────────────────────────────────────────────────────
init();
