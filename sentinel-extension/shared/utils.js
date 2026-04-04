// SentinelAI Extension — Shared Utilities

const VERDICTS = {
  SAFE: { label: 'SAFE', color: '#22c55e', bg: '#14532d', emoji: '✅', score_class: 'safe' },
  LOW_RISK: { label: 'LOW RISK', color: '#86efac', bg: '#166534', emoji: '🟢', score_class: 'low' },
  SUSPICIOUS: { label: 'SUSPICIOUS', color: '#f59e0b', bg: '#78350f', emoji: '⚠️', score_class: 'suspicious' },
  PHISHING: { label: 'PHISHING', color: '#ef4444', bg: '#7f1d1d', emoji: '🔴', score_class: 'phishing' },
  CONFIRMED_THREAT: { label: 'CRITICAL', color: '#b91c1c', bg: '#450a0a', emoji: '🚨', score_class: 'critical' },
  CRITICAL: { label: 'CRITICAL', color: '#b91c1c', bg: '#450a0a', emoji: '🚨', score_class: 'critical' },
  UNKNOWN: { label: 'SCANNING', color: '#6b7280', bg: '#1f2937', emoji: '🔍', score_class: 'unknown' },
};

function getVerdict(verdictKey) {
  return VERDICTS[verdictKey] || VERDICTS.UNKNOWN;
}

function scoreToPercent(score) {
  return Math.round((score || 0) * 100);
}

function scoreToVerdict(score) {
  if (score >= 0.85) return 'CRITICAL';
  if (score >= 0.60) return 'PHISHING';
  if (score >= 0.35) return 'SUSPICIOUS';
  if (score >= 0.15) return 'LOW_RISK';
  return 'SAFE';
}

function extractUrlsFromText(text) {
  const re = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/g;
  const found = [];
  const seen = new Set();
  let match;
  while ((match = re.exec(text)) !== null) {
    const url = match[0].replace(/[.,;:!?)]+$/, '');
    if (!seen.has(url)) {
      seen.add(url);
      found.push(url);
    }
  }
  return found.slice(0, 20);
}

function formatMs(ms) {
  if (!ms) return '';
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function truncate(str, len = 60) {
  if (!str) return '';
  return str.length > len ? str.slice(0, len) + '…' : str;
}

// Export for content scripts (non-module context — attach to window)
if (typeof window !== 'undefined') {
  window.SentinelUtils = {
    getVerdict, scoreToPercent, scoreToVerdict,
    extractUrlsFromText, formatMs, truncate, VERDICTS,
  };
}
