'use strict';

const API = `http://${window.location.hostname}:8000/api/v1`;

// ── State ─────────────────────────────────────────────────────────────────────
const S = {
  page: 'scan',       // 'scan' | 'loading' | 'results'
  result: null,
  scanId: null,
  online: false,
  collapsed: false,
  expanded: new Set(),
  loadingDomain: '',
  loadingDone: [],
  loadingProgress: 0,
  loadingStep: '',
  chatOpen: true,
  chatMsgs: [],
  chatStreaming: false,
};

// ── SVG icons ─────────────────────────────────────────────────────────────────
const IC = {
  search:    `<svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>`,
  download:  `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`,
  refresh:   `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>`,
  shield:    `<svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  alert:     `<svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  check:     `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>`,
  chevDown:  `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg>`,
  chevLeft:  `<svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><polyline points="15 18 9 12 15 6"/></svg>`,
  chevRight: `<svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg>`,
  dot:       `<svg width="8" height="8" viewBox="0 0 8 8"><circle cx="4" cy="4" r="4" fill="currentColor"/></svg>`,
  xCircle:   `<svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
  modules:   `<svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>`,
};

// ── Severity / score helpers ──────────────────────────────────────────────────
const SEV_MAP = {
  critical: { color: '#dc2626', bg: 'rgba(220,38,38,.12)',  label: 'CRITIQUE', emoji: '🔴' },
  high:     { color: '#ea580c', bg: 'rgba(234,88,12,.12)',  label: 'ÉLEVÉ',    emoji: '🟠' },
  medium:   { color: '#d97706', bg: 'rgba(217,119,6,.12)', label: 'MOYEN',    emoji: '🟡' },
  low:      { color: '#2563eb', bg: 'rgba(37,99,235,.12)', label: 'FAIBLE',   emoji: '🔵' },
  info:     { color: '#71717a', bg: 'rgba(113,113,122,.12)', label: 'INFO',    emoji: '⚪' },
};

function sv(s)    { return SEV_MAP[s] || SEV_MAP.info; }

function scoreInfo(n) {
  if (n < 40) return { label: 'CRITIQUE',  color: '#dc2626' };
  if (n < 60) return { label: 'ÉLEVÉ',     color: '#ea580c' };
  if (n < 75) return { label: 'MOYEN',     color: '#d97706' };
  if (n < 85) return { label: 'BON',       color: '#2563eb' };
  return             { label: 'EXCELLENT', color: '#16a34a' };
}

function fmtDate(iso) {
  const d = new Date(iso);
  return d.toLocaleDateString('fr-FR', { day: '2-digit', month: 'short', year: 'numeric' })
       + ' · ' + d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
}

function capFirst(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : '—'; }

function h(str) {
  return String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function fmtVal(v) {
  if (v === null || v === undefined) return '—';
  if (Array.isArray(v)) return v.length ? v.join(', ') : '—';
  if (typeof v === 'object') return JSON.stringify(v).slice(0, 120);
  if (typeof v === 'boolean') return v ? 'Oui' : 'Non';
  return String(v);
}

// ── API calls ─────────────────────────────────────────────────────────────────
async function apiHealth() {
  try {
    const r = await fetch(`http://${window.location.hostname}:8000/health`,
                         { signal: AbortSignal.timeout(3000) });
    S.online = r.ok;
  } catch { S.online = false; }
  const dot = document.getElementById('s-dot');
  const lbl = document.getElementById('s-lbl');
  if (dot) dot.style.color = S.online ? '#4ade80' : '#f87171';
  if (lbl) lbl.textContent  = S.online ? 'En ligne' : 'Hors ligne';
}

async function apiScan(domain, sub) {
  const r = await fetch(`${API}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, include_subdomains: sub }),
  });
  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    const msg = (e.detail?.[0]?.msg || e.detail || 'Erreur serveur').replace(/^Value error,\s*/i, '');
    throw new Error(msg);
  }
  return r.json();
}


async function downloadPDF() {
  if (!S.scanId) return;
  const btn = document.getElementById('btn-pdf');
  if (btn) { btn.disabled = true; btn.innerHTML = `${IC.download} Génération...`; }
  try {
    const r = await fetch(`${API}/scan/${S.scanId}/pdf`);
    if (!r.ok) throw new Error('Erreur génération PDF');
    const blob = await r.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    const cd = r.headers.get('Content-Disposition') || '';
    a.download = (cd.match(/filename="(.+?)"/) || [])[1] || `rapport-eon-${S.result?.domain}.pdf`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  } catch (e) { showError(e.message); }
  finally {
    if (btn) { btn.disabled = false; btn.innerHTML = `${IC.download} Télécharger le rapport`; }
  }
}

// ── Error banner ──────────────────────────────────────────────────────────────
function showError(msg) {
  document.getElementById('err-slot')?.remove();
  const el = document.createElement('div');
  el.id = 'err-slot'; el.className = 'error-banner';
  el.innerHTML = `${IC.xCircle} <span>${h(msg)}</span>
    <button class="error-close" onclick="this.parentElement.remove()">✕</button>`;
  document.querySelector('.main-content')?.prepend(el);
}

// ── Module names for loading animation ────────────────────────────────────────
const MOD_NAMES = [
  'DNS Security', 'SSL/TLS Security', 'Security Headers',
  'Email Security', 'Subdomain Takeover', 'Domain Expiration', 'OSINT Breaches',
];

// ── HTML builders ─────────────────────────────────────────────────────────────
function buildSidebar() {
  const c = S.collapsed;
  const nav = (id, icon, label, href) => {
    const active = S.page === id || (S.page === 'results' && id === 'scan');
    if (href) return `<a href="${href}" target="_blank" class="nav-item">${icon}${c ? '' : `<span>${label}</span>`}</a>`;
    return `<button class="nav-item ${active ? 'active' : ''}" data-nav="${id}">${icon}${c ? '' : `<span>${label}</span>`}</button>`;
  };
  return `
  <aside class="sidebar ${c ? 'collapsed' : ''}">
    <div class="sb-logo">
      <img src="logo.svg" class="logo-img" alt="ÉON">
      ${c ? '' : '<span class="logo-text">ÉON</span>'}
    </div>
    <nav class="sb-nav">
      ${nav('scan',    IC.search,  'Nouveau scan')}
    </nav>
    <div class="sb-footer">
      <div class="status-row">
        <span id="s-dot" class="status-dot" style="color:${S.online ? '#4ade80' : '#f87171'}">${IC.dot}</span>
        ${c ? '' : `<span id="s-lbl" class="status-label">${S.online ? 'En ligne' : 'Hors ligne'}</span>`}
      </div>
      ${c ? '' : '<p class="esgi-label">ESGI M1 · 2025-2026</p>'}
      <button class="collapse-btn" data-action="sidebar">${c ? IC.chevRight : IC.chevLeft}</button>
    </div>
  </aside>`;
}

function buildScan() {
  return `
  <div class="scan-wrap">
    <p class="scan-hero-title">Audit de sécurité</p>
    <div class="scan-form-wrap">
      <form id="scan-form">
        <div class="search-row">
          <span class="search-icon">${IC.search}</span>
          <input id="domain-inp" class="domain-input" type="text"
                 placeholder="exemple.com" autocomplete="off" spellcheck="false" required>
          <button type="submit" class="search-submit">Analyser →</button>
        </div>
      </form>
      <div class="toggle-wrap">
        <input type="checkbox" class="toggle" id="sub-tog" checked>
        <label class="toggle-track" for="sub-tog"><div class="toggle-thumb"></div></label>
        <label class="toggle-label" for="sub-tog">Inclure les sous-domaines</label>
      </div>
      <p class="search-hint">7 modules · analyse passive · 100% légal</p>
    </div>
  </div>`;
}

function buildLoading() {
  const done = S.loadingDone;
  const pct  = Math.round((S.loadingProgress / MOD_NAMES.length) * 100);
  return `
  <div class="page-header">
    <div>
      <h1 class="page-title">Analyse en cours…</h1>
      <p class="page-subtitle mono">${h(S.loadingDomain)}</p>
    </div>
  </div>
  <div class="loading-wrap">
    <div class="loading-card">
      <div class="scan-progress-wrap">
        <div class="scan-progress-bar">
          <div class="scan-progress-fill" style="width:${pct}%"></div>
        </div>
        <div class="scan-progress-info">
          <span class="scan-progress-step">${h(S.loadingStep || 'Validation du domaine…')}</span>
          <span class="scan-progress-pct">${pct}%</span>
        </div>
      </div>
      <div class="mod-loading">
        ${MOD_NAMES.map((name, i) => {
          const isDone   = done.includes(i);
          const isActive = !isDone && done.length === i;
          return `<div class="mod-row ${isDone ? 'done' : isActive ? 'active' : ''}">
            <span class="mod-icon">${isDone ? IC.check : isActive ? '<span class="spin-sm">⟳</span>' : '·'}</span>
            <span>${h(name)}</span>
          </div>`;
        }).join('')}
      </div>
    </div>
  </div>`;
}

function buildResults() {
  const r  = S.result;
  const si = scoreInfo(r.overall_score);
  const cnt = { critical: 0, high: 0, medium: 0, low: 0 };
  r.modules.forEach(m => { if (cnt[m.severity] !== undefined) cnt[m.severity]++; });

  const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const allRecs = r.modules
    .flatMap(m => m.recommendations.map(rec => ({ mod: m.module_name, sev: m.severity, rec })))
    .sort((a, b) => sevOrder.indexOf(a.sev) - sevOrder.indexOf(b.sev));

  return `
  <div class="page-header results-hdr">
    <div class="res-title">
      <h1 class="page-title mono">${h(r.domain)}</h1>
      <span class="plat-badge">${h(capFirst(r.platform))}</span>
    </div>
    <div class="res-actions">
      <span class="ts-text">${h(fmtDate(r.timestamp))}</span>
      <button id="btn-pdf" class="btn btn-primary" data-action="pdf">
        ${IC.download} Télécharger le rapport
      </button>
      <button class="btn btn-ghost" data-nav="scan">
        ${IC.refresh} Nouveau scan
      </button>
    </div>
  </div>

  <div class="stat-cards">
    <div class="stat-card">
      <p class="stat-lbl">Score global</p>
      <p class="stat-val" style="color:${si.color}">${r.overall_score}<span class="stat-sub">/100</span></p>
      <span class="stat-tag" style="background:${si.color}18;color:${si.color}">${si.label}</span>
    </div>
    <div class="stat-card">
      <p class="stat-lbl">Critiques</p>
      <p class="stat-val" style="color:#f87171">${cnt.critical}</p>
      <p class="stat-hint">modules critiques</p>
    </div>
    <div class="stat-card">
      <p class="stat-lbl">Élevés</p>
      <p class="stat-val" style="color:#fb923c">${cnt.high}</p>
      <p class="stat-hint">modules à risque élevé</p>
    </div>
    <div class="stat-card">
      <p class="stat-lbl">Modules</p>
      <p class="stat-val" style="color:var(--text)">${r.modules.length}<span class="stat-sub">/7</span></p>
      <p class="stat-hint">modules analysés</p>
    </div>
  </div>

  <div class="res-cols">
    <!-- Left: modules -->
    <div>
      <p class="sec-title">Modules de sécurité</p>
      <div class="mod-list">
        ${r.modules.map((m, i) => {
          const s      = sv(m.severity);
          const isOpen = S.expanded.has(i);
          const det    = Object.entries(m.details || {});
          return `
          <div class="mod-card ${isOpen ? 'open' : ''}">
            <button class="mod-btn" data-action="toggle" data-i="${i}">
              <div class="mod-left">
                <span class="sev-dot" style="color:${s.color}">${IC.dot}</span>
                <span class="mod-name">${h(m.module_name)}</span>
              </div>
              <div class="mod-right">
                <div class="prog-wrap">
                  <div class="prog-bar">
                    <div class="prog-fill" style="width:${m.score}%;background:${s.color}"></div>
                  </div>
                </div>
                <span class="mod-score" style="color:${s.color}">${m.score}/100</span>
                <span class="sev-badge" style="background:${s.bg};color:${s.color}">${s.label}</span>
                <span class="chevron">${IC.chevDown}</span>
              </div>
            </button>
            ${isOpen ? `
            <div class="mod-detail">
              ${det.length ? `
              <div class="det-grid">
                ${det.map(([k, v]) => `
                  <div class="det-key">${h(k.replace(/_/g,' '))}</div>
                  <div class="det-val">${h(fmtVal(v))}</div>`).join('')}
              </div>` : ''}
              ${m.recommendations?.length ? `
              <p class="rec-section-title">Recommandations</p>
              ${m.recommendations.map(r => `
                <div class="rec-row">
                  <span class="rec-arrow" style="color:${s.color}">→</span>
                  <span>${h(r)}</span>
                </div>`).join('')}` : ''}
            </div>` : ''}
          </div>`;
        }).join('')}
      </div>
    </div>

    <!-- Right: action plan -->
    <div>
      <p class="sec-title">Actions prioritaires</p>
      <div class="actions-card">
        ${allRecs.length === 0
          ? `<p class="no-actions">Aucune action requise ✓</p>`
          : allRecs.map(({ mod, sev: sevKey, rec }) => {
            const s = sv(sevKey);
            return `
            <div class="action-item">
              <div class="action-header">
                <span class="action-emoji">${s.emoji}</span>
                <span class="action-module">${h(mod)}</span>
                <span class="action-badge" style="background:${s.bg};color:${s.color}">${s.label}</span>
              </div>
              <p class="action-text">${h(rec)}</p>
            </div>`;
          }).join('')}
      </div>
      <div class="support-card">
        <p class="support-title">Besoin d'aide ?</p>
        <p class="support-text">Notre équipe peut vous accompagner dans la mise en conformité de votre domaine.</p>
        <a href="mailto:support@eon-audit.com" class="support-link">support@eon-audit.com</a>
      </div>
    </div>
  </div>

`;
}

const IC_CHAT  = `<svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>`;
const IC_CLOSE = `<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;

function buildChatWidget() {
  const domain = S.result?.domain || '';
  const msgs   = S.chatMsgs;
  return `
  <div class="chat-widget">
    ${S.chatOpen ? `
    <div class="chat-panel">
      <div class="chat-panel-hdr">
        <div>
          <p class="chat-panel-title">Assistant ÉON</p>
          <p class="chat-panel-sub">${h(domain)}</p>
        </div>
        <button class="chat-panel-close" data-action="chat-toggle">${IC_CLOSE}</button>
      </div>
      <div class="chat-msgs" id="chat-msgs">
        ${msgs.length === 0
          ? `<div class="chat-empty">Posez-moi vos questions sur les résultats de sécurité de <strong>${h(domain)}</strong>.</div>`
          : msgs.map((msg, i) => {
              const isLast = i === msgs.length - 1 && msg.role === 'assistant';
              return `
              <div class="chat-msg ${msg.role}">
                <span class="chat-role">${msg.role === 'user' ? 'Vous' : 'ÉON'}</span>
                <p class="chat-content"${isLast ? ' id="chat-last"' : ''}>${h(msg.content)}</p>
              </div>`;
            }).join('')
        }
        ${S.chatStreaming && (msgs.length === 0 || msgs[msgs.length-1].role === 'user')
          ? `<div class="chat-typing"><span></span><span></span><span></span></div>` : ''}
      </div>
      <form id="chat-form" class="chat-form">
        <input id="chat-inp" class="chat-inp" type="text"
               placeholder="Posez votre question…"
               autocomplete="off" spellcheck="false"
               ${S.chatStreaming ? 'disabled' : ''}>
        <button type="submit" class="chat-send" ${S.chatStreaming ? 'disabled' : ''}>→</button>
      </form>
    </div>` : ''}
    <button class="chat-fab" data-action="chat-toggle" title="Assistant ÉON">
      ${S.chatOpen ? IC_CLOSE : IC_CHAT}
    </button>
  </div>`;
}


// ── Chat ──────────────────────────────────────────────────────────────────────
async function sendChat(message) {
  if (!S.scanId || S.chatStreaming) return;
  const history = [...S.chatMsgs];
  S.chatMsgs.push({ role: 'user', content: message });
  S.chatMsgs.push({ role: 'assistant', content: '' });
  S.chatStreaming = true;
  render();

  try {
    const resp = await fetch(`${API}/chat/${S.scanId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, history }),
    });
    if (!resp.ok) {
      const e = await resp.json().catch(() => ({}));
      throw new Error(e.detail || 'Erreur serveur');
    }

    const reader = resp.body.getReader();
    const dec    = new TextDecoder();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      for (const line of dec.decode(value).split('\n')) {
        if (!line.startsWith('data: ')) continue;
        const raw = line.slice(6).trim();
        if (raw === '[DONE]') break;
        try {
          const parsed = JSON.parse(raw);
          if (parsed.error) throw new Error(parsed.error);
          S.chatMsgs[S.chatMsgs.length - 1].content += parsed.text;
          const el = document.getElementById('chat-last');
          if (el) el.textContent = S.chatMsgs[S.chatMsgs.length - 1].content;
          const box = document.getElementById('chat-msgs');
          if (box) box.scrollTop = box.scrollHeight;
        } catch {}
      }
    }
  } catch (err) {
    S.chatMsgs.pop();
    showError(err.message);
  }

  S.chatStreaming = false;
  render();
  setTimeout(() => {
    const box = document.getElementById('chat-msgs');
    if (box) box.scrollTop = box.scrollHeight;
  }, 50);
}

async function onChatSubmit(e) {
  e.preventDefault();
  const inp = document.getElementById('chat-inp');
  const msg = inp?.value.trim();
  if (!msg || S.chatStreaming) return;
  inp.value = '';
  await sendChat(msg);
}

// ── Render ────────────────────────────────────────────────────────────────────
function render() {
  let pageHtml = '';
  switch (S.page) {
    case 'scan':    pageHtml = buildScan();    break;
    case 'loading': pageHtml = buildLoading(); break;
    case 'results': pageHtml = buildResults(); break;
  }

  document.getElementById('app').innerHTML = `
    ${buildSidebar()}
    <div class="main${S.collapsed ? ' collapsed' : ''}">
      <div class="main-content">${pageHtml}</div>
    </div>
    ${S.page === 'results' ? buildChatWidget() : ''}`;

  // Re-attach form listeners
  document.getElementById('scan-form')?.addEventListener('submit', onScanSubmit);
  document.getElementById('chat-form')?.addEventListener('submit', onChatSubmit);
}

// ── Handlers ──────────────────────────────────────────────────────────────────
async function onScanSubmit(e) {
  e.preventDefault();
  const domain = document.getElementById('domain-inp')?.value.trim();
  const sub    = document.getElementById('sub-tog')?.checked ?? true;
  if (!domain) return;

  S.page = 'loading'; S.loadingDomain = domain;
  S.loadingDone = []; S.loadingProgress = 0; S.loadingStep = '';
  render();

  try {
    const resp = await fetch(`${API}/scan/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, include_subdomains: sub }),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      const msg = (err.detail?.[0]?.msg || err.detail || 'Erreur serveur').replace(/^Value error,\s*/i, '');
      throw new Error(msg);
    }

    const reader = resp.body.getReader();
    const dec    = new TextDecoder();

    outer: while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      for (const line of dec.decode(value).split('\n')) {
        if (!line.startsWith('data: ')) continue;
        const raw = line.slice(6).trim();
        let evt;
        try { evt = JSON.parse(raw); } catch { continue; }

        if (evt.error) throw new Error(evt.error);
        if (evt.done) {
          S.result = evt.result; S.scanId = evt.scan_id;
          S.page = 'results'; S.expanded = new Set(); S.chatMsgs = [];
          render();
          break outer;
        }
        if (evt.step !== undefined) {
          S.loadingStep = evt.step;
          S.loadingProgress = evt.progress;
          S.loadingDone = [...Array(evt.progress).keys()];
          render();
        }
      }
    }
  } catch (err) {
    S.page = 'scan'; render();
    showError(err.message);
  }
}

// Global delegation
document.addEventListener('click', async (e) => {
  const el = e.target.closest('[data-action],[data-nav]');
  if (!el) return;

  const action = el.dataset.action;
  const nav    = el.dataset.nav;

  if (nav) {
    S.page = nav; S.expanded = new Set();
    render();
    return;
  }

  switch (action) {
    case 'chat-toggle':
      S.chatOpen = !S.chatOpen; render(); break;

    case 'sidebar':
      S.collapsed = !S.collapsed; render(); break;

    case 'toggle': {
      const i = parseInt(el.dataset.i, 10);
      S.expanded.has(i) ? S.expanded.delete(i) : S.expanded.add(i);
      render(); break;
    }

    case 'pdf':
      await downloadPDF(); break;

  }
});

// ── Boot ──────────────────────────────────────────────────────────────────────
render();
apiHealth();
setInterval(apiHealth, 30_000);
