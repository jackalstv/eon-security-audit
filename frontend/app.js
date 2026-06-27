'use strict';

const API = `http://${window.location.hostname}:8000/api/v1`;

// ── State ─────────────────────────────────────────────────────────────────────
const S = {
  page: 'scan',       // 'scan' | 'loading' | 'results' | 'history'
  result: null,
  scanId: null,
  online: false,
  collapsed: false,
  expanded: new Set(),
  loadingDomain: '',
  loadingDone: [],
  loadingTimer: null,
  history: null,
};

// ── SVG icons ─────────────────────────────────────────────────────────────────
const IC = {
  search:    `<svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>`,
  clock:     `<svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
  extLink:   `<svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>`,
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

async function apiHistory() {
  try {
    const r = await fetch(`${API}/history?limit=30`);
    if (!r.ok) return [];
    const d = await r.json();
    return d.scans || [];
  } catch { return []; }
}

async function apiLoadScan(scanId) {
  const r = await fetch(`${API}/scan/${scanId}`);
  if (!r.ok) throw new Error('Scan introuvable');
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
      <div class="logo-mark">É</div>
      ${c ? '' : '<span class="logo-text">ÉON</span>'}
    </div>
    <nav class="sb-nav">
      ${nav('scan',    IC.search,  'Nouveau scan')}
      ${nav('history', IC.clock,   'Historique')}
      ${nav('api',     IC.extLink, 'API Docs', `http://${window.location.hostname}:8000/api/docs`)}
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
    <p class="scan-hero-title">Audit de sécurité <span>d'un domaine</span></p>
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
  return `
  <div class="page-header">
    <div>
      <h1 class="page-title">Analyse en cours…</h1>
      <p class="page-subtitle mono">${h(S.loadingDomain)}</p>
    </div>
  </div>
  <div class="loading-wrap">
    <div class="loading-card">
      <div class="spinner"></div>
      <p class="loading-domain">${h(S.loadingDomain)}</p>
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
    </div>
  </div>`;
}

function buildHistory() {
  const scans = S.history;
  if (!scans) return `
    <div class="page-header"><div><h1 class="page-title">Historique</h1></div></div>
    <div class="loading-wrap"><div class="spinner"></div></div>`;

  if (scans.length === 0) return `
    <div class="page-header"><div><h1 class="page-title">Historique</h1><p class="page-subtitle">Aucun scan enregistré</p></div></div>
    <div class="empty-state">
      <p>Lancez votre premier audit</p>
      <button class="btn btn-primary" data-nav="scan">${IC.search} Nouveau scan</button>
    </div>`;

  return `
  <div class="page-header">
    <div>
      <h1 class="page-title">Historique</h1>
      <p class="page-subtitle">${scans.length} scan${scans.length > 1 ? 's' : ''} enregistré${scans.length > 1 ? 's' : ''}</p>
    </div>
  </div>
  <div class="history-list">
    ${scans.map(sc => {
      const si = scoreInfo(sc.overall_score);
      return `
      <div class="hist-row" data-action="open-scan" data-id="${h(sc.scan_id)}">
        <div class="hist-left">
          <span class="hist-domain">${h(sc.domain)}</span>
          <span class="hist-date">${h(fmtDate(sc.timestamp))}</span>
        </div>
        <div class="hist-right">
          <span class="hist-plat">${h(capFirst(sc.platform))}</span>
          <span class="hist-score" style="color:${si.color}">${sc.overall_score}/100</span>
          <span class="sev-badge" style="background:${si.color}20;color:${si.color}">${si.label}</span>
        </div>
      </div>`;
    }).join('')}
  </div>`;
}

// ── Render ────────────────────────────────────────────────────────────────────
function render() {
  let pageHtml = '';
  switch (S.page) {
    case 'scan':    pageHtml = buildScan();    break;
    case 'loading': pageHtml = buildLoading(); break;
    case 'results': pageHtml = buildResults(); break;
    case 'history': pageHtml = buildHistory(); break;
  }

  document.getElementById('app').innerHTML = `
    ${buildSidebar()}
    <div class="main${S.collapsed ? ' collapsed' : ''}">
      <div class="main-content">${pageHtml}</div>
    </div>`;

  // Re-attach scan form submit
  document.getElementById('scan-form')?.addEventListener('submit', onScanSubmit);
}

// ── Handlers ──────────────────────────────────────────────────────────────────
async function onScanSubmit(e) {
  e.preventDefault();
  const domain = document.getElementById('domain-inp')?.value.trim();
  const sub    = document.getElementById('sub-tog')?.checked ?? true;
  if (!domain) return;

  S.page = 'loading'; S.loadingDomain = domain; S.loadingDone = [];
  render();

  // Animate module indicators
  let idx = 0;
  S.loadingTimer = setInterval(() => {
    S.loadingDone = [...Array(++idx).keys()];
    const rows = document.querySelectorAll('.mod-row');
    rows.forEach((row, i) => {
      if (i < idx) {
        row.className = 'mod-row done';
        row.querySelector('.mod-icon').innerHTML = IC.check;
      } else if (i === idx) {
        row.className = 'mod-row active';
        row.querySelector('.mod-icon').innerHTML = '<span class="spin-sm">⟳</span>';
      }
    });
    if (idx >= MOD_NAMES.length) clearInterval(S.loadingTimer);
  }, 1300);

  try {
    const data = await apiScan(domain, sub);
    clearInterval(S.loadingTimer);
    if (data.success) {
      S.result = data.result; S.scanId = data.scan_id;
      S.page = 'results'; S.expanded = new Set();
      render();
    }
  } catch (err) {
    clearInterval(S.loadingTimer);
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
    clearInterval(S.loadingTimer);
    S.page = nav; S.expanded = new Set();
    if (nav === 'history') { S.history = null; render(); S.history = await apiHistory(); }
    render();
    return;
  }

  switch (action) {
    case 'sidebar':
      S.collapsed = !S.collapsed; render(); break;

    case 'toggle': {
      const i = parseInt(el.dataset.i, 10);
      S.expanded.has(i) ? S.expanded.delete(i) : S.expanded.add(i);
      render(); break;
    }

    case 'pdf':
      await downloadPDF(); break;

    case 'open-scan': {
      try {
        const data = await apiLoadScan(el.dataset.id);
        if (data.success) {
          S.result = data.result; S.scanId = el.dataset.id;
          S.page = 'results'; S.expanded = new Set(); render();
        }
      } catch (err) { showError(err.message); }
      break;
    }
  }
});

// ── Boot ──────────────────────────────────────────────────────────────────────
render();
apiHealth();
setInterval(apiHealth, 30_000);
