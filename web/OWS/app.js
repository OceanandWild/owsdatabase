// OWS Dashboard — Client Logic
// Uses same backend & token as Ocean Pay for seamless SSO

// Backend REAL: siempre server.js en Render (producción).
// No usar localhost: todas las peticiones van a la DB real de owsdatabase.onrender.com.
// Si abres index.html con doble clic (file://), window.location.origin es "null"
// y antes resolvía a file:///ocean-pay/login -> CORS/ERR_FAILED. Ahora siempre Render.
const OWS_DEFAULT_API = 'https://owsdatabase.onrender.com';

function resolveOwsApiBase() {
  // Solo se permite override explícito: ?api=https://... o localStorage ows_api_base
  try {
    const params = new URLSearchParams(window.location.search || '');
    const override = (params.get('api') || localStorage.getItem('ows_api_base') || '').trim();
    if (override && /^https?:\/\//i.test(override)) return override.replace(/\/+$/, '');
  } catch (_) {}

  return OWS_DEFAULT_API;
}

const API_BASE = resolveOwsApiBase();
console.log('[OWS] API_BASE (REAL):', API_BASE, '| protocol:', window.location.protocol);
if (window.location.protocol === 'file:') {
  console.info('[OWS] Abierto como archivo local (file://). Para desarrollo, sirve la carpeta por HTTP. API: ' + API_BASE);
}

// Same token keys as Ocean Pay — SSO via shared localStorage
const TOKEN_KEY = 'ocean_pay_token';
const USER_KEY  = 'ocean_pay_user';

let currentUser = null;

// ═══════════════════════════════════════════════
// STAR FIELD — Canvas animation
// ═══════════════════════════════════════════════

function initStars() {
  const canvas = document.getElementById('stars-canvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  let W = canvas.width  = window.innerWidth;
  let H = canvas.height = window.innerHeight;

  const STAR_COUNT   = 220;
  const SHOOT_CHANCE = 0.003; // probability each frame to spawn a shooting star

  // Generate static stars
  const stars = Array.from({ length: STAR_COUNT }, () => ({
    x:    Math.random() * W,
    y:    Math.random() * H,
    r:    Math.random() * 1.4 + 0.3,
    base: Math.random() * 0.6 + 0.3,   // base opacity
    amp:  Math.random() * 0.35,          // twinkle amplitude
    spd:  Math.random() * 0.012 + 0.004, // twinkle speed
    t:    Math.random() * Math.PI * 2,   // phase offset
    // color: mix warm white & amber
    warm: Math.random() < 0.25,
  }));

  // Shooting stars pool
  const shooters = [];

  function spawnShooter() {
    const angle = Math.random() * 0.4 + 0.15; // slight downward angle
    shooters.push({
      x:    Math.random() * W,
      y:    Math.random() * H * 0.5,
      vx:   Math.cos(angle) * (6 + Math.random() * 5),
      vy:   Math.sin(angle) * (4 + Math.random() * 3),
      len:  80 + Math.random() * 120,
      life: 1.0,
      fade: 0.025 + Math.random() * 0.02,
    });
  }

  function drawFrame() {
    ctx.clearRect(0, 0, W, H);

    // ── Static stars ──
    stars.forEach(s => {
      s.t += s.spd;
      const opacity = s.base + Math.sin(s.t) * s.amp;

      ctx.beginPath();
      ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
      if (s.warm) {
        ctx.fillStyle = `rgba(255, 220, 130, ${opacity})`;
      } else {
        ctx.fillStyle = `rgba(245, 240, 255, ${opacity})`;
      }
      ctx.fill();
    });

    // ── Shooting stars ──
    if (Math.random() < SHOOT_CHANCE) spawnShooter();

    for (let i = shooters.length - 1; i >= 0; i--) {
      const sh = shooters[i];
      sh.x    += sh.vx;
      sh.y    += sh.vy;
      sh.life -= sh.fade;

      if (sh.life <= 0) { shooters.splice(i, 1); continue; }

      const tailX = sh.x - sh.vx / sh.fade * sh.life * 0.6;
      const tailY = sh.y - sh.vy / sh.fade * sh.life * 0.6;

      const grad = ctx.createLinearGradient(tailX, tailY, sh.x, sh.y);
      grad.addColorStop(0, `rgba(255, 200, 80, 0)`);
      grad.addColorStop(1, `rgba(255, 230, 140, ${sh.life * 0.9})`);

      ctx.beginPath();
      ctx.moveTo(tailX, tailY);
      ctx.lineTo(sh.x, sh.y);
      ctx.strokeStyle = grad;
      ctx.lineWidth   = 1.5;
      ctx.stroke();

      // head glow
      ctx.beginPath();
      ctx.arc(sh.x, sh.y, 2, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(255, 240, 180, ${sh.life})`;
      ctx.fill();
    }

    requestAnimationFrame(drawFrame);
  }

  drawFrame();

  window.addEventListener('resize', () => {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
    // Reposition stars within new bounds
    stars.forEach(s => {
      s.x = Math.random() * W;
      s.y = Math.random() * H;
    });
  });
}

// ═══════════════════════════════════════════════
// EVENTS — binding centralizado (sin inline handlers:
// el WebView de Tauri no compila atributos onclick/*)
// ═══════════════════════════════════════════════

function bindStaticEvents() {
  // Tabs auth
  document.querySelectorAll('[data-tab]').forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.getAttribute('data-tab')));
  });

  // Forms auth
  const loginForm = document.getElementById('login-form');
  if (loginForm) loginForm.addEventListener('submit', handleLogin);
  const regForm = document.getElementById('register-form');
  if (regForm) regForm.addEventListener('submit', handleRegister);

  // Logout único: icono del user-card (el botón "Salir" duplicado fue eliminado)
  const logoutIcon = document.getElementById('btn-logout-icon');
  if (logoutIcon) logoutIcon.addEventListener('click', handleLogout);

  // ── Menú lateral v2: colapsar / drawer / buscador / scrollspy ──
  initSideNav();

  // Tarjetas de módulos (click + Enter/Espacio)
  document.querySelectorAll('[data-module]').forEach((card) => {
    const mod = card.getAttribute('data-module');
    card.addEventListener('click', () => goToModule(mod));
    card.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); goToModule(mod); }
    });
  });

  // Modales: cerrar al click en overlay o botón [data-close]
  ['event-modal', 'release-modal', 'announce-modal', 'news-modal'].forEach((id) => {
    const overlay = document.getElementById(id);
    if (!overlay) return;
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay || (id === 'news-modal' && e.target.classList && e.target.classList.contains('news-modal'))) {
        if (id === 'event-modal') closeEventModal();
        else if (id === 'release-modal') closeReleaseModal();
        else if (id === 'news-modal') closeNewsModal();
        else closeAnnounceModal();
      }
    });
  });
  document.querySelectorAll('[data-close]').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.getAttribute('data-close');
      if (id === 'event-modal') closeEventModal();
      else if (id === 'release-modal') closeReleaseModal();
      else if (id === 'news-modal') closeNewsModal();
      else if (id === 'hub-changelog-modal') closeHubChangelogModal();
      else closeAnnounceModal();
    });
  });

  // Barra de progreso de scroll del modal de lanzamiento
  const rdCard = document.querySelector('#release-modal .release-modal-card');
  const rdBar = document.querySelector('#release-modal .rd-progress i');
  if (rdCard && rdBar) {
    rdCard.addEventListener('scroll', () => {
      const max = rdCard.scrollHeight - rdCard.clientHeight;
      rdBar.style.width = max > 6 ? ((rdCard.scrollTop / max) * 100).toFixed(1) + '%' : '0%';
    }, { passive: true });
  }

  // Grillas: delegación (sobrevive a re-renders)
  const eventsGrid = document.getElementById('events-grid');
  if (eventsGrid) {
    const openFromCard = (card) => {
      const idx = Number(card.getAttribute('data-ev-idx'));
      const ev = eventsCache[idx];
      if (ev) openEventModal(ev);
    };
    eventsGrid.addEventListener('click', (e) => {
      const card = e.target.closest('[data-ev-idx]');
      if (card) openFromCard(card);
    });
    eventsGrid.addEventListener('keydown', (e) => {
      if ((e.key === 'Enter' || e.key === ' ') && e.target.closest('[data-ev-idx]')) {
        e.preventDefault();
        openFromCard(e.target.closest('[data-ev-idx]'));
      }
    });
  }
  // Noticias: delegación en la grilla (sobrevive a re-renders)
  const newsGrid = document.getElementById('news-table-body');
  if (newsGrid && !newsGrid.dataset.bound) {
    newsGrid.dataset.bound = '1';
    const openNewsFromCard = (card) => {
      const item = newsFeedCache[Number(card.getAttribute('data-news-idx'))];
      if (item) openNewsModal(item);
    };
    newsGrid.addEventListener('click', (e) => {
      const card = e.target.closest('[data-news-idx]');
      if (card) openNewsFromCard(card);
    });
    newsGrid.addEventListener('keydown', (e) => {
      if ((e.key === 'Enter' || e.key === ' ') && e.target.closest('[data-news-idx]')) {
        e.preventDefault();
        openNewsFromCard(e.target.closest('[data-news-idx]'));
      }
    });
  }
  const releasesGrid = document.getElementById('releases-grid');
  if (releasesGrid) {
    // Dock de iconos: 1 clic = preview abajo del icono + spotlight · 2 clics = modal con banner
    let relClickTimer = null;
    const findProject = (slug) => releasesCache.find((x) => String(x.slug) === String(slug));
    const toggleDockItem = (item) => {
      if (!item) return;
      const wasOpen = item.classList.contains('is-open');
      releasesGrid.querySelectorAll('.release-dock-item.is-open').forEach((x) => {
        x.classList.remove('is-open');
        x.setAttribute('aria-expanded', 'false');
        const info = x.querySelector('.dock-info');
        if (info) info.setAttribute('aria-hidden', 'true');
      });
      if (!wasOpen) {
        item.classList.add('is-open');
        item.setAttribute('aria-expanded', 'true');
        const info = item.querySelector('.dock-info');
        if (info) info.setAttribute('aria-hidden', 'false');
      }
      syncReleasesSpotlight();
    };
    // Clic en el overlay oscuro = cerrar preview y quitar highlight
    const spotlight = document.getElementById('releases-spotlight');
    if (spotlight && !spotlight.dataset.bound) {
      spotlight.dataset.bound = '1';
      spotlight.addEventListener('click', () => closeReleasesDock());
    }
    releasesGrid.addEventListener('click', (e) => {
      const retry = e.target.closest('[data-releases-retry]');
      if (retry) { e.preventDefault(); loadDashboardReleases(); return; }
      const item = e.target.closest('[data-slug]');
      if (!item) return;
      // Doble clic llega como 2 clicks seguidos: el 2º abre el modal directamente
      if (relClickTimer) {
        try { clearTimeout(relClickTimer); } catch (_) {}
        relClickTimer = null;
        if (!item.classList.contains('is-open')) toggleDockItem(item);
        const p = findProject(item.getAttribute('data-slug'));
        if (p) openReleaseModal(p);
        return;
      }
      relClickTimer = setTimeout(() => {
        relClickTimer = null;
        toggleDockItem(item);
      }, 260);
    });
    // Evita zoom/selección en doble clic y cubre ratones que disparan dblclick sin 2º click
    releasesGrid.addEventListener('dblclick', (e) => {
      const item = e.target.closest('[data-slug]');
      if (!item) return;
      e.preventDefault();
      try { if (relClickTimer) { clearTimeout(relClickTimer); relClickTimer = null; } } catch (_) {}
      if (!item.classList.contains('is-open')) toggleDockItem(item);
      const p = findProject(item.getAttribute('data-slug'));
      if (p) openReleaseModal(p);
    });
    releasesGrid.addEventListener('keydown', (e) => {
      const item = e.target.closest ? e.target.closest('[data-slug]') : null;
      if (!item) return;
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        // Enter simple = preview · con Ctrl/Cmd+Enter = modal directo (accesible sin ratón)
        if ((e.ctrlKey || e.metaKey)) {
          const p = findProject(item.getAttribute('data-slug'));
          if (p) openReleaseModal(p);
        } else {
          toggleDockItem(item);
        }
      }
    });
  }

  // Gestor de Descargas: delegación (cancelar / reintentar / ver)
  const dlList = document.getElementById('downloads-list');
  if (dlList) {
    dlList.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-dl-action]');
      if (!btn) return;
      const id = btn.getAttribute('data-dl-id') || '';
      const action = btn.getAttribute('data-dl-action') || '';
      if (action === 'cancel') cancelDownload(id);
      else if (action === 'retry') retryDownload(id);
      else if (action === 'goto') scrollToDownloads();
      else if (action === 'dismiss') dismissDownload(id);
      else if (action === 'uninstall') uninstallFromManager(btn, id);
    });
  }
  const btnClearDl = document.getElementById('btn-clear-downloads');
  if (btnClearDl) btnClearDl.addEventListener('click', clearCompletedDownloads);
  const btnGotoRel = document.getElementById('btn-goto-releases');
  if (btnGotoRel) btnGotoRel.addEventListener('click', (e) => {
    if (e && e.preventDefault) e.preventDefault();
    showOwsSection('sec-lanzamientos', { smooth: true });
  });
  const toastDl = document.getElementById('toast-dl');
  if (toastDl) toastDl.addEventListener('click', () => scrollToDownloads());
  bindDlToaster();

  // Imágenes rotas: fallback global (capture, cubre renders futuros)
  document.addEventListener('error', (e) => {
    const t = e.target;
    if (!t || t.tagName !== 'IMG') return;
    if (t.classList.contains('event-card-img')) {
      t.style.display = 'none';
      const media = t.closest('.event-card-media');
      if (media) media.classList.add('ev-img-fallback');
    } else if (t.classList.contains('release-banner')) {
      const media = t.closest('.release-media');
      if (media) media.classList.add('release-media-empty');
      t.remove();
    } else if (t.classList.contains('release-icon') || t.classList.contains('modal-icon') || t.classList.contains('modal-banner')) {
      t.remove();
    }
  }, true);
}

// ═══════════════════════════════════════════════
// SIDE-NAV v2 — colapsar / drawer móvil / buscador / scrollspy
// ═══════════════════════════════════════════════

const NAV_COLLAPSE_KEY = 'ows_nav_collapsed';

function initSideNav() {
  const nav = document.getElementById('side-nav');
  if (!nav) return;

  // Arranca siempre arriba: evita que un link o la promo nazcan "cortados"
  const scroller = nav.querySelector('.nav-scroll');
  if (scroller) scroller.scrollTop = 0;

  // Año real del footer (nunca se queda desfasado)
  try {
    const y = document.getElementById('ows-year');
    if (y) y.textContent = String(new Date().getFullYear());
  } catch (_) {}

  // Tooltips para el modo colapsado (cuando solo se ven iconos)
  nav.querySelectorAll('.nav-link').forEach((a) => {
    if (!a.getAttribute('title')) {
      const t = a.querySelector('.nav-txt');
      if (t && t.textContent.trim()) a.setAttribute('title', t.textContent.trim());
    }
  });

  // Si se vuelve a desktop con el drawer abierto, se cierra solo
  let _navResizeT = null;
  window.addEventListener('resize', () => {
    if (_navResizeT) clearTimeout(_navResizeT);
    _navResizeT = setTimeout(() => { if (window.innerWidth > 900) closeNavDrawer(); }, 150);
  });

  // Estado colapsado persistido (solo desktop)
  try {
    if (localStorage.getItem(NAV_COLLAPSE_KEY) === '1' && window.innerWidth > 900) {
      nav.classList.add('collapsed');
      syncCollapseBtn();
    }
  } catch (_) {}

  const collapseBtn = document.getElementById('btn-collapse');
  if (collapseBtn) collapseBtn.addEventListener('click', () => {
    nav.classList.toggle('collapsed');
    try { localStorage.setItem(NAV_COLLAPSE_KEY, nav.classList.contains('collapsed') ? '1' : '0'); } catch (_) {}
    syncCollapseBtn();
  });

  // Drawer móvil
  const menuBtn = document.getElementById('btn-menu-mobile');
  const overlay = document.getElementById('nav-overlay');
  if (menuBtn) menuBtn.addEventListener('click', () => openNavDrawer());
  if (overlay) overlay.addEventListener('click', () => closeNavDrawer());
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeNavDrawer();
    // "/" enfoca el buscador (si no se está escribiendo en un input)
    if (e.key === '/' && !/INPUT|TEXTAREA/.test(String(document.activeElement && document.activeElement.tagName || ''))) {
      const s = document.getElementById('nav-search-input');
      if (s && !document.getElementById('dashboard-section').classList.contains('hidden')) {
        e.preventDefault();
        s.focus();
      }
    }
  });

  // Buscador filtra por texto + data-keys
  const search = document.getElementById('nav-search-input');
  if (search) {
    search.addEventListener('input', () => filterSideNav(search.value));
    search.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const first = nav.querySelector('.nav-link:not(.no-match)');
        if (first) first.click();
      }
    });
  }

  // Click en links: ABRE la vista correspondiente (no scroll)
  nav.querySelectorAll('.nav-link[data-view]').forEach((a) => {
    a.addEventListener('click', (e) => {
      e.preventDefault();
      const view = a.getAttribute('data-view');
      showOwsSection(view);
      closeNavDrawer();
    });
  });

  // Delegación global: cualquier [data-goto-view] abre su vista
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-goto-view]');
    if (!btn) return;
    // Si es un <a> externo real, no interferir
    if (btn.tagName === 'A' && !btn.hasAttribute('data-goto-view')) return;
    e.preventDefault();
    showOwsSection(btn.getAttribute('data-goto-view'));
    closeNavDrawer();
  });

  initOwsRouter();
}

function syncCollapseBtn() {
  const nav = document.getElementById('side-nav');
  const btn = document.getElementById('btn-collapse');
  if (!nav || !btn) return;
  const c = nav.classList.contains('collapsed');
  btn.textContent = c ? '›' : '‹';
  btn.title = c ? 'Expandir menú' : 'Contraer menú';
}

function openNavDrawer() {
  const nav = document.getElementById('side-nav');
  const overlay = document.getElementById('nav-overlay');
  if (!nav) return;
  nav.classList.add('open');
  if (overlay) overlay.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeNavDrawer() {
  const nav = document.getElementById('side-nav');
  const overlay = document.getElementById('nav-overlay');
  if (!nav || !nav.classList.contains('open')) return;
  nav.classList.remove('open');
  if (overlay) overlay.classList.add('hidden');
  // No pisar el overflow de los modales
  const newsModal = document.getElementById('news-modal');
  if (document.getElementById('event-modal').classList.contains('hidden') &&
      document.getElementById('release-modal').classList.contains('hidden') &&
      (!newsModal || newsModal.classList.contains('hidden'))) {
    document.body.style.overflow = '';
  }
}

function setActiveNavLink(link) {
  document.querySelectorAll('#side-nav .nav-link').forEach((x) => x.classList.remove('is-active'));
  if (link) link.classList.add('is-active');
}

function filterSideNav(q) {
  const query = String(q || '').trim().toLowerCase();
  const nav = document.getElementById('side-nav');
  if (!nav) return;
  nav.querySelectorAll('.nav-link').forEach((a) => {
    if (!query) { a.classList.remove('no-match'); return; }
    const hay = ((a.textContent || '') + ' ' + (a.getAttribute('data-keys') || '')).toLowerCase();
    a.classList.toggle('no-match', !hay.includes(query));
  });
  // Oculta etiquetas de grupo sin resultados visibles
  nav.querySelectorAll('.nav-group-label').forEach((label) => {
    let el = label.nextElementSibling;
    let visible = false;
    while (el && !el.classList.contains('nav-group-label') && !el.classList.contains('nav-promo')) {
      if (el.classList.contains('nav-links')) {
        if (el.querySelector('.nav-link:not(.no-match)')) visible = true;
      }
      el = el.nextElementSibling;
    }
    label.style.display = visible || !query ? '' : 'none';
  });
  // La promo de Ocean Pay también responde al buscador
  const promo = nav.querySelector('.nav-promo');
  if (promo) {
    if (!query) promo.style.display = '';
    else {
      const hayPromo = ((promo.textContent || '') + ' ocean pay billetera wallet dinero pagos').toLowerCase();
      promo.style.display = hayPromo.includes(query) ? '' : 'none';
    }
  }
}

// ── Router de vistas: una sección visible a la vez ──
const OWS_VIEWS = ['view-inicio', 'sec-modulos', 'sec-noticias', 'sec-lanzamientos', 'sec-eventos', 'sec-descargas', 'sec-actualizaciones'];
const OWS_VIEW_ROUTES = {
  'inicio': 'view-inicio',
  'modulos': 'sec-modulos',
  'noticias': 'sec-noticias',
  'lanzamientos': 'sec-lanzamientos',
  'eventos': 'sec-eventos',
  'descargas': 'sec-descargas',
  'actualizaciones': 'sec-actualizaciones',
  // compat con hashes viejos (#sec-modulos, #top, ...)
  'view-inicio': 'view-inicio',
  'sec-modulos': 'sec-modulos',
  'sec-noticias': 'sec-noticias',
  'sec-lanzamientos': 'sec-lanzamientos',
  'sec-eventos': 'sec-eventos',
  'sec-descargas': 'sec-descargas',
  'sec-actualizaciones': 'sec-actualizaciones',
  'updates': 'sec-actualizaciones',
  'top': 'view-inicio',
};
const OWS_VIEW_TITLES = {
  'view-inicio': 'Inicio',
  'sec-modulos': 'Módulos',
  'sec-noticias': 'Noticias',
  'sec-lanzamientos': 'Lanzamientos',
  'sec-eventos': 'Eventos',
  'sec-descargas': 'Descargas',
  'sec-actualizaciones': 'Actualizaciones',
};
const OWS_VIEW_KEY = 'ows_last_view';
let owsCurrentView = 'view-inicio';

function resolveOwsView(input) {
  const raw = String(input || '').trim().replace(/^#\/?/, '');
  if (!raw) return null;
  if (OWS_VIEW_ROUTES[raw]) return OWS_VIEW_ROUTES[raw];
  return null;
}

function showOwsSection(viewId, opts) {
  const target = OWS_VIEW_ROUTES[String(viewId || '').trim()] || null;
  if (!target || OWS_VIEWS.indexOf(target) === -1) return false;
  owsCurrentView = target;

  // Muestra solo la vista pedida
  OWS_VIEWS.forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('is-active', id === target);
  });

  // Limpia el buscador para no dejar links ocultos tras navegar
  try {
    const si = document.getElementById('nav-search-input');
    if (si && si.value) { si.value = ''; filterSideNav(''); }
  } catch (_) {}

  // Marca el link activo del menú
  const link = document.querySelector('#side-nav .nav-link[data-view="' + target + '"]');
  setActiveNavLink(link || null);

  // Título en topbar móvil
  const mt = document.getElementById('mobile-view-title');
  if (mt) mt.textContent = OWS_VIEW_TITLES[target] || 'Inicio';

  // Persiste + refleja en el hash (sin disparar scroll del navegador)
  try { localStorage.setItem(OWS_VIEW_KEY, target); } catch (_) {}
  const route = Object.keys(OWS_VIEW_ROUTES).find((k) => OWS_VIEW_ROUTES[k] === target && !k.startsWith('sec-') && !k.startsWith('view-') && k !== 'top') || target;
  const wantHash = '#/' + route;
  if (window.location.hash !== wantHash && !(opts && opts.replace === false)) {
    try { history.replaceState(null, '', wantHash); } catch (_) { window.location.hash = wantHash; }
  }

  // Al salir de Lanzamientos se cierra el preview y se quita el spotlight
  try { if (target !== 'sec-lanzamientos') closeReleasesDock(); } catch (_) {}

  // Si se entra a Lanzamientos sin datos (nunca cargó o falló), reintenta:
  // el servidor en plan gratuito puede tardar y quedarse en blanco.
  if (target === 'sec-lanzamientos' && !releasesLoading && releasesLoadState !== 'ready') {
    try { loadDashboardReleases(); } catch (_) {}
  }

  // El Gestor de Actualizaciones es la única vista que necesita saber qué hay
  // instalado: si nunca se consultó (o hace rato), se pide al entrar.
  if (target === 'sec-actualizaciones') {
    try { ensureUpdatesManager(); } catch (_) {}
  }

  // Sube al inicio del contenido (las vistas ya no hacen scroll entre sí)
  try {
    const sync = opts && opts.smooth === true;
    window.scrollTo({ top: 0, behavior: sync ? 'smooth' : 'auto' });
    const main = document.querySelector('.main-col');
    if (main && typeof main.scrollIntoView === 'function' && sync) main.scrollIntoView({ block: 'start' });
  } catch (_) { try { window.scrollTo(0, 0); } catch (_) {} }

  // Destello opcional (Gestor de Descargas)
  if (opts && opts.flash) {
    try {
      const el = document.querySelector('#sec-descargas #dl-summary')
        || document.querySelector('#sec-descargas #downloads-list')
        || document.querySelector('#sec-descargas');
      if (el) {
        el.classList.remove('dl-flash');
        void el.offsetWidth;
        el.classList.add('dl-flash');
        setTimeout(() => el.classList.remove('dl-flash'), 1600);
      }
    } catch (_) {}
  }
  // El toaster de descargas solo vive si NO estás en el Gestor
  try { syncDlToaster(); } catch (_) {}
  return true;
}

function initOwsRouter() {
  // Hash inicial (deep-link) o última vista guardada; por defecto Inicio
  let initial = 'view-inicio';
  try {
    const fromHash = resolveOwsView(window.location.hash);
    const fromStore = (() => { try { return localStorage.getItem(OWS_VIEW_KEY); } catch (_) { return null; } })();
    if (fromHash) initial = fromHash;
    else if (fromStore && OWS_VIEWS.indexOf(fromStore) !== -1) initial = fromStore;
  } catch (_) {}
  showOwsSection(initial, { replace: true });

  window.addEventListener('hashchange', () => {
    const v = resolveOwsView(window.location.hash);
    if (v && v !== owsCurrentView) showOwsSection(v, { replace: true });
  });
}

function syncNavProfile() {
  const name = currentUser ? (currentUser.username || currentUser.id || 'Jugador') : 'Jugador';
  const avatar = document.getElementById('nav-avatar');
  if (avatar) avatar.textContent = String(name || 'J').trim().charAt(0).toUpperCase() || 'J';
  const role = document.getElementById('nav-role');
  if (role) role.textContent = isOwsOwnerUser() ? 'Owner · Admin' : 'Explorador';
}

function syncNavBadges(newsCount, eventsList) {
  const newsBadge = document.getElementById('nav-news-count');
  if (newsBadge) {
    const n = Number(newsCount || 0);
    newsBadge.textContent = n > 99 ? '99+' : String(n);
    newsBadge.classList.toggle('hidden', !(n > 0));
  }
  const evDot = document.getElementById('nav-ev-dot');
  if (evDot) {
    const hasActive = Array.isArray(eventsList) && eventsList.some((e) => e.phase === 'active');
    evDot.classList.toggle('hidden', !hasActive);
  }
}

// ═══════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', function () {
  initStars();
  bindStaticEvents();
  initDownloadsManager();
  initOwsSettings();
  initOwsHubPanel();
  bindSetupWizard();
  bindIntroButtons();
  // Rework 3.3.0: modales de reinicio/novedades + changelog de la versión
  // recién instalada. Va acá (y no dentro del bloque de sesión) para que
  // las novedades aparezcan siempre, haya sesión o no.
  try { bindHubUpdateFlow(); } catch (_) {}
  // Si venimos de una actualización: pantalla completa al arrancar (idempotente).
  try { hubFullscreenAfterUpdate(); } catch (_) {}

  const token = localStorage.getItem(TOKEN_KEY);
  const storedUser = localStorage.getItem(USER_KEY);

  if (storedUser) {
    try { currentUser = JSON.parse(storedUser); } catch (_) {}
  }

  if (token && currentUser) {
    // Sesión activa: entra directo (sin intro) salvo ?intro=1
    const wantIntro = /[?&]intro=1/.test(window.location.search || '');
    if (wantIntro && !isSetupDone()) {
      runIntroSequence();
    } else {
      hideIntroInstant();
      showDashboard();
      // Si nunca hizo setup, se abre el asistente automáticamente encima del panel
      if (!isSetupDone()) {
        setTimeout(() => showSetup('dashboard'), 900);
      }
    }
    loadDashboardNews();
    loadDashboardEvents();
    loadDashboardReleases();
    checkOwsPopups();
    updateAdminVisibility();
    // Gestor de Actualizaciones: se consulta al entrar para tener el badge
    // del menú listo. No bloquea nada: si falla, la vista avisa al abrirla.
    bindUpdatesManager();
    loadUpdatesManager();
  } else {
    // Sin sesión: intro cinemática → setup (si falta) → auth
    runIntroSequence();
  }
});

// ═══════════════════════════════════════════════
// AUTH — Show / Hide
// ═══════════════════════════════════════════════

function showAuth(opts) {
  hideIntroInstant();
  hideSetup();
  document.getElementById('auth-section').classList.remove('hidden');
  document.getElementById('dashboard-section').classList.add('hidden');
  runAuthWelcomeSequence(opts && opts.fromSetup);
}

// ── Secuencia de bienvenida GSAP ──
// 1) "Bienvenido" entra letra por letra → 2) desaparece →
// 3) "OWS Hub" aparece en el centro → 4) sube → 5) fade-in del panel login
let owsAuthWelcomeTl = null;

function killAuthWelcome() {
  try { if (owsAuthWelcomeTl) { owsAuthWelcomeTl.kill(); owsAuthWelcomeTl = null; } } catch (_) {}
  try { if (window.gsap) gsap.killTweensOf('#auth-welcome, #aw-bienvenido, #aw-hub, #auth-card'); } catch (_) {}
}

function splitHubWord(el) {
  if (!el || el.dataset.split === '1') return;
  const text = el.textContent || '';
  el.dataset.split = '1';
  el.setAttribute('aria-label', text);
  el.textContent = '';
  [...text].forEach((ch) => {
    const span = document.createElement('span');
    span.className = 'ch';
    span.textContent = ch === ' ' ? '\u00A0' : ch;
    el.appendChild(span);
  });
}

function skipAuthWelcome() {
  try {
    if (owsAuthWelcomeTl) { owsAuthWelcomeTl.progress(1); return; }
  } catch (_) {}
  finishAuthWelcome(true);
}

function finishAuthWelcome(instant) {
  killAuthWelcome();
  const welcome = document.getElementById('auth-welcome');
  const card = document.getElementById('auth-card');
  if (welcome) welcome.classList.add('hidden');
  if (card) {
    card.classList.remove('auth-pre');
    if (instant && !window.gsap) { card.style.opacity = '1'; return; }
  }
  revealAuthCard(false);
}

function runAuthWelcomeSequence(fromSetup) {
  killAuthWelcome();
  const welcome = document.getElementById('auth-welcome');
  const card = document.getElementById('auth-card');
  const bienvenido = document.getElementById('aw-bienvenido');
  const hub = document.getElementById('aw-hub');
  const kicker = document.getElementById('aw-kicker');
  const sub = document.getElementById('aw-sub');
  const ring = document.getElementById('aw-ring');
  const glow = document.querySelector('#auth-welcome .aw-glow');
  const fill = document.getElementById('aw-bar-fill');

  // Click en el overlay = saltar
  if (welcome) welcome.onclick = () => skipAuthWelcome();

  const reduced = (() => {
    try { return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (_) { return false; }
  })();

  // Fallback: sin GSAP o movimiento reducido → directo al panel
  if (!window.gsap || reduced || !welcome || !card || !bienvenido || !hub) {
    if (welcome) welcome.classList.add('hidden');
    if (card) card.classList.remove('auth-pre');
    revealAuthCard(fromSetup);
    return;
  }

  // Prepara letras (reutiliza splitChars; el Hub se parte por palabras para no romper el gradiente)
  try {
    splitChars(bienvenido);
    splitHubWord(hub.querySelector('.aw-hub-ows'));
    splitHubWord(hub.querySelector('.aw-hub-hub'));
  } catch (_) {}

  welcome.classList.remove('hidden');
  welcome.setAttribute('aria-hidden', 'false');
  card.classList.add('auth-pre');
  try { gsap.set(card, { opacity: 0 }); } catch (_) {}

  const tl = gsap.timeline({
    defaults: { ease: 'power3.out' },
    onUpdate: () => {
      if (fill) {
        try { fill.style.width = Math.round((tl.progress() || 0) * 100) + '%'; } catch (_) {}
      }
    },
    onComplete: () => {
      welcome.classList.add('hidden');
      welcome.setAttribute('aria-hidden', 'true');
      card.classList.remove('auth-pre');
      owsAuthWelcomeTl = null;
      revealAuthCard(fromSetup);
    },
  });
  owsAuthWelcomeTl = tl;

  // ── Estado inicial ──
  tl.set(kicker, { opacity: 0, y: 14 })
    .set('#aw-bienvenido .ch', { opacity: 0, y: 70, rotateX: -80, filter: 'blur(6px)' })
    .set(bienvenido, { opacity: 1 })
    .set('#aw-hub .ch', { opacity: 0, y: 44, rotateX: -70, scale: 0.8 })
    .set(hub, { opacity: 0, xPercent: -50, yPercent: -50, y: 0, scale: 1 })
    .set(sub, { opacity: 0, y: 12 })
    .set(ring, { opacity: 0, scale: 0.6, xPercent: -50, yPercent: -50 })
    .set(glow, { opacity: 0.6, scale: 0.9 }, 0)
    // ── 1) "Bienvenido": kicker + letras con rebote ──
    .to(kicker, { opacity: 1, y: 0, duration: 0.45 }, 0.1)
    .fromTo(kicker, { letterSpacing: '0.55em' }, { letterSpacing: '0.34em', duration: 0.9 }, '<')
    .to('#aw-bienvenido .ch', { opacity: 1, y: 0, rotateX: 0, filter: 'blur(0px)', duration: 0.65, stagger: 0.055, ease: 'back.out(1.7)' }, 0.25)
    .to(ring, { opacity: 0.9, scale: 1, duration: 0.9, ease: 'power2.out' }, 0.35)
    .to(glow, { opacity: 1, scale: 1.06, duration: 0.9, ease: 'sine.inOut' }, 0.35)
    .to(sub, { opacity: 1, y: 0, duration: 0.5 }, 0.9)
    // respiro
    .to({}, { duration: 0.55 })
    // ── 2) "Bienvenido" desaparece hacia arriba con blur ──
    .to('#aw-bienvenido .ch', { opacity: 0, y: -46, filter: 'blur(8px)', duration: 0.4, stagger: 0.03, ease: 'power3.in' }, 'bye')
    .to([kicker, sub], { opacity: 0, y: -18, duration: 0.35, ease: 'power2.in' }, 'bye')
    .to(ring, { opacity: 0, scale: 1.25, duration: 0.45, ease: 'power2.in' }, 'bye')
    // ── 3) "OWS Hub" aparece en el centro ──
    .to(hub, { opacity: 1, duration: 0.25 }, 'bye+=0.3')
    .to('#aw-hub .ch', { opacity: 1, y: 0, rotateX: 0, scale: 1, duration: 0.6, stagger: 0.05, ease: 'back.out(1.9)' }, 'bye+=0.32')
    .to(glow, { opacity: 0.9, scale: 1, duration: 0.6, ease: 'sine.out' }, 'bye+=0.3')
    // latido de presencia
    .to(hub, { scale: 1.04, duration: 0.28, ease: 'sine.inOut', yoyo: true, repeat: 1 }, '+=0.15')
    .to({}, { duration: 0.35 })
    // ── 4) "OWS Hub" sube ──
    .to(hub, { y: -160, scale: 0.82, opacity: 0, duration: 0.65, ease: 'power3.inOut' }, 'rise')
    .to(glow, { opacity: 0, scale: 0.8, duration: 0.6, ease: 'power2.in' }, 'rise')
    // ── 5) el overlay cede y entra el panel (revealAuthCard lo remata) ──
    .to(welcome, { opacity: 0, duration: 0.4, ease: 'power2.inOut' }, 'rise+=0.35')
    .set(welcome, { opacity: 1 });
}

function revealAuthCard(fromSetup) {
  const card = document.getElementById('auth-card');
  if (!card) return;
  // Sin GSAP: aparición simple
  if (!window.gsap) {
    card.style.opacity = '1';
    return;
  }
  try {
    gsap.killTweensOf(card);
    gsap.killTweensOf('.auth-brand > *');
    gsap.killTweensOf('.auth-forms > *');
    gsap.fromTo(card,
      { opacity: 0, y: fromSetup ? 46 : 34, scale: 0.97 },
      { opacity: 1, y: 0, scale: 1, duration: fromSetup ? 0.9 : 0.7, ease: 'power3.out' });
    gsap.fromTo('.auth-brand > *',
      { opacity: 0, x: -22 },
      { opacity: 1, x: 0, duration: 0.55, stagger: 0.08, ease: 'power3.out', delay: 0.1 });
    gsap.fromTo('.auth-forms > *',
      { opacity: 0, y: 16 },
      { opacity: 1, y: 0, duration: 0.5, stagger: 0.07, ease: 'power3.out', delay: 0.18 });
  } catch (_) {}
}

// Mantener el nombre viejo como alias por compatibilidad
function animateAuthEntrance(fromSetup) { revealAuthCard(fromSetup); }

function authShake() {
  const card = document.getElementById('auth-card');
  if (!card) return;
  if (window.gsap) {
    try {
      gsap.fromTo(card, { x: 0 }, { keyframes: [{ x: -10 }, { x: 9 }, { x: -6 }, { x: 4 }, { x: 0 }], duration: 0.45, ease: 'power1.inOut' });
      return;
    } catch (_) {}
  }
  card.classList.remove('auth-shake');
  void card.offsetWidth;
  card.classList.add('auth-shake');
}

function authSuccessFlash(msg) {
  const card = document.getElementById('auth-card');
  if (!card || !window.gsap) return;
  try {
    let flash = card.querySelector('.auth-success-flash');
    if (!flash) {
      flash = document.createElement('div');
      flash.className = 'auth-success-flash';
      card.appendChild(flash);
    }
    gsap.fromTo(flash, { opacity: 0 }, { opacity: 1, duration: 0.25, yoyo: true, repeat: 1, ease: 'power1.inOut' });
    gsap.to(card, { scale: 1.015, duration: 0.22, yoyo: true, repeat: 1, ease: 'power2.inOut' });
  } catch (_) {}
  if (msg) showToast(msg);
}

function showDashboard() {
  try { hideIntroInstant(); } catch (_) {}
  try { hideSetup(); } catch (_) {}
  try { killAuthWelcome(); } catch (_) {}
  try {
    const w = document.getElementById('auth-welcome');
    if (w) w.classList.add('hidden');
    const c = document.getElementById('auth-card');
    if (c) c.classList.remove('auth-pre');
  } catch (_) {}
  document.getElementById('auth-section').classList.add('hidden');
  document.getElementById('dashboard-section').classList.remove('hidden');

  const name = currentUser ? (currentUser.username || currentUser.id || 'Jugador') : 'Jugador';
  const navName  = document.getElementById('nav-username');
  const welcome  = document.getElementById('welcome-name');
  if (navName)  navName.textContent  = name;
  if (welcome)  welcome.textContent  = name;
  try { syncNavProfile(); } catch (_) {}
  // Re-aplica la vista actual al entrar (deep-link / última vista / Inicio)
  try {
    const fromHash = resolveOwsView(window.location.hash);
    showOwsSection(fromHash || owsCurrentView || 'view-inicio', { replace: true });
  } catch (_) {}
}

// ═══════════════════════════════════════════════
// AUTH — Tabs
// ═══════════════════════════════════════════════

function switchTab(tab) {
  const loginForm = document.getElementById('login-form');
  const regForm   = document.getElementById('register-form');
  const loginBtn  = document.getElementById('tab-login-btn');
  const regBtn    = document.getElementById('tab-register-btn');
  hideAlert('auth-alert');

  const showEl = tab === 'login' ? loginForm : regForm;
  const hideEl = tab === 'login' ? regForm : loginForm;

  if (tab === 'login') {
    loginBtn.classList.add('active');
    regBtn.classList.remove('active');
  } else {
    loginBtn.classList.remove('active');
    regBtn.classList.add('active');
  }

  if (hideEl === showEl || !window.gsap) {
    loginForm.classList.toggle('hidden', tab !== 'login');
    regForm.classList.toggle('hidden', tab !== 'register');
    return;
  }
  try {
    gsap.to(hideEl, { opacity: 0, x: tab === 'login' ? 18 : -18, duration: 0.18, ease: 'power2.in', onComplete: () => {
      hideEl.classList.add('hidden');
      gsap.set(hideEl, { clearProps: 'all' });
      showEl.classList.remove('hidden');
      gsap.fromTo(showEl, { opacity: 0, x: tab === 'login' ? -18 : 18 }, { opacity: 1, x: 0, duration: 0.32, ease: 'power3.out' });
    }});
  } catch (_) {
    loginForm.classList.toggle('hidden', tab !== 'login');
    regForm.classList.toggle('hidden', tab !== 'register');
  }
}

function setBtnLoading(btn, loading, loadingText) {
  if (!btn) return;
  if (loading) {
    if (!btn.dataset.origHtml) btn.dataset.origHtml = btn.innerHTML;
    btn.disabled = true;
    btn.classList.add('btn-loading');
    btn.innerHTML = '<span class="btn-spinner"></span> ' + (loadingText || 'Conectando…');
  } else {
    btn.disabled = false;
    btn.classList.remove('btn-loading');
    if (btn.dataset.origHtml) {
      btn.innerHTML = btn.dataset.origHtml;
      delete btn.dataset.origHtml;
    }
  }
}

// ═══════════════════════════════════════════════
// AUTH — Login
// ═══════════════════════════════════════════════

async function handleLogin(e) {
  if (e && e.preventDefault) e.preventDefault();
  hideAlert('auth-alert');

  const username = document.getElementById('login-user').value.trim();
  const password = document.getElementById('login-pass').value.trim();
  const btn      = document.getElementById('btn-login');

  if (!username || !password) {
    showAlert('auth-alert', 'Por favor ingresa tu usuario y contraseña.', 'error');
    authShake();
    return;
  }

  setBtnLoading(btn, true, 'Conectando con OWS…');

  try {
    const res  = await fetch(API_BASE + '/ocean-pay/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password }),
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) throw new Error(data.error || `Error del servidor (${res.status})`);
    if (!data.token) throw new Error('No se recibió token de acceso');

    currentUser = data.user || { id: data.id, username };
    localStorage.setItem(TOKEN_KEY, data.token);
    localStorage.setItem(USER_KEY, JSON.stringify(currentUser));
    // Guarda nick del setup si existe y el login no trae username
    try { applySetupNickToUser(); } catch (_) {}

    authSuccessFlash();
    showToast(`¡Bienvenido a OWS Hub, ${username}! 🌟`);
    // Pequeña pausa para que se vea el flash de éxito
    setTimeout(() => {
      showDashboard();
      updateAdminVisibility();
      loadDashboardNews();
      loadDashboardEvents();
      loadDashboardReleases();
      checkOwsPopups();
    }, 450);
  } catch (err) {
    console.error('[OWS] Login error:', err, '| API_BASE:', API_BASE);
    let msg = err.message || 'Error de conexión con el servidor.';
    if (String(err.message || '').includes('Failed to fetch') || err instanceof TypeError) {
      msg = `No se pudo conectar con el servidor (${API_BASE}). Revisa tu internet o que el backend esté en línea.`;
    }
    showAlert('auth-alert', msg, 'error');
    authShake();
  } finally {
    setBtnLoading(btn, false);
    if (!btn.dataset.origHtml) btn.innerHTML = '<span class="btn-icon">🚀</span> Iniciar sesión';
  }
}

// ═══════════════════════════════════════════════
// AUTH — Register
// ═══════════════════════════════════════════════
async function handleRegister(e) {
  if (e && e.preventDefault) e.preventDefault();
  hideAlert('auth-alert');

  const username = document.getElementById('reg-user').value.trim();
  const password = document.getElementById('reg-pass').value.trim();
  const btn      = document.getElementById('btn-register');

  if (!username || !password) {
    showAlert('auth-alert', 'Completa todos los campos.', 'error');
    authShake();
    return;
  }

  if (password.length < 6) {
    showAlert('auth-alert', 'La contraseña debe tener al menos 6 caracteres.', 'error');
    authShake();
    return;
  }

  setBtnLoading(btn, true, 'Creando cuenta…');

  try {
    const res  = await fetch(API_BASE + '/ocean-pay/register', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password }),
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) throw new Error(data.error || 'No se pudo crear la cuenta');

    showAlert('auth-alert', '¡Cuenta creada con éxito! Ya puedes iniciar sesión.', 'success');
    authSuccessFlash();
    switchTab('login');
    document.getElementById('login-user').value = username;
  } catch (err) {
    console.error('[OWS] Register error:', err);
    showAlert('auth-alert', err.message || 'Error al crear la cuenta.', 'error');
    authShake();
  } finally {
    setBtnLoading(btn, false);
    if (!btn.dataset.origHtml) btn.innerHTML = '<span class="btn-icon">✨</span> Crear Cuenta OWS';
  }
}

// ═══════════════════════════════════════════════
// AUTH — Logout
// ═══════════════════════════════════════════════

function handleLogout() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  currentUser = null;
  updateAdminVisibility(); // oculta la tarjeta admin al cerrar sesión
  showToast('Sesión cerrada. ¡Hasta pronto!');
  setTimeout(() => showAuth(), 800);
}

// ═══════════════════════════════════════════════
// MODULES — Navigation
// ═══════════════════════════════════════════════

function goToModule(moduleId) {
  if (moduleId === 'ocean-pay') {
    window.location.href = './Ocean Pay/index.html';
  } else if (moduleId === 'admin-panel') {
    window.location.href = './admin/index.html';
  }
}

// ═══════════════════════════════════════════════
// ADMIN PANEL — visibilidad solo para OceanandWild
// ═══════════════════════════════════════════════

const OWS_ADMIN_USERNAME = 'oceanandwild';

function isOwsOwnerUser() {
  if (!currentUser) return false;
  return String(currentUser.username || '').trim().toLowerCase() === OWS_ADMIN_USERNAME;
}

function updateAdminVisibility() {
  const card = document.getElementById('admin-module-card');
  const statModules = document.getElementById('stat-modules');
  const isAdmin = isOwsOwnerUser();
  if (statModules) statModules.textContent = isAdmin ? '2' : '1';
  const navModCount = document.getElementById('nav-mod-count');
  if (navModCount) navModCount.textContent = isAdmin ? '2' : '1';
  const navAdmin = document.getElementById('nav-admin-link');
  if (navAdmin) navAdmin.classList.toggle('hidden', !isAdmin);
  // Sin menciones a Admin para no-admins: subtítulo y buscador del link Módulos
  const quickSub = document.getElementById('quick-modulos-sub');
  if (quickSub) quickSub.textContent = isAdmin ? 'Ocean Pay y Admin' : 'Ocean Pay';
  const navModLink = document.getElementById('nav-modulos-link');
  if (navModLink) navModLink.setAttribute('data-keys', isAdmin ? 'modulos apps juegos ocean pay admin' : 'modulos apps juegos ocean pay');
  try { syncNavProfile(); } catch (_) {}
  if (!card) return;
  if (isAdmin) {
    card.classList.remove('hidden');
    card.classList.add('admin-visible-pop');
  } else {
    card.classList.add('hidden');
    card.classList.remove('admin-visible-pop');
  }
}

// ═══════════════════════════════════════════════
// EVENTOS — seccion calendario (estilo Roblox/Steam)
// ═══════════════════════════════════════════════

const EVENT_CATEGORY_META = {
  update:       { label: 'Actualización', icon: '⬆️', cls: 'ev-cat-update' },
  launch:       { label: 'Lanzamiento',   icon: '🚀', cls: 'ev-cat-launch' },
  release:      { label: 'Release',       icon: '📦', cls: 'ev-cat-release' },
  event:        { label: 'Evento',        icon: '🎉', cls: 'ev-cat-event' },
  announcement: { label: 'Anuncio',       icon: '📢', cls: 'ev-cat-announcement' },
  maintenance:  { label: 'Mantenimiento', icon: '🛠️', cls: 'ev-cat-maintenance' }
};

function eventCategoryMeta(category) {
  return EVENT_CATEGORY_META[String(category || '').trim().toLowerCase()] || EVENT_CATEGORY_META.update;
}

function formatEventRange(startIso, endIso) {
  const s = startIso ? new Date(startIso) : null;
  const e = endIso ? new Date(endIso) : null;
  if (!s || Number.isNaN(s.getTime())) return 'Fechas por confirmar';
  const sameDay = e && s.toDateString() === e.toDateString();
  if (e && !Number.isNaN(e.getTime()) && !sameDay) {
    return `${s.toLocaleDateString('es-ES', { day: 'numeric', month: 'short' })} — ${e.toLocaleDateString('es-ES', { day: 'numeric', month: 'short', year: 'numeric' })}`;
  }
  const opts = { day: 'numeric', month: 'short', year: 'numeric' };
  let text = s.toLocaleDateString('es-ES', opts);
  if (e && !Number.isNaN(e.getTime()) && sameDay) {
    text += ` · ${s.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' })} – ${e.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' })}`;
  }
  return text;
}

function eventCountdown(targetIso, phase) {
  if (!targetIso || phase === 'ended') return '';
  const diff = new Date(targetIso).getTime() - Date.now();
  if (Number.isNaN(diff) || diff <= 0) return '';
  const mins = Math.floor(diff / 60000);
  const days = Math.floor(mins / 1440);
  const hours = Math.floor((mins % 1440) / 60);
  const minutes = mins % 60;
  if (days > 0) return `Empieza en ${days}d ${hours}h`;
  if (hours > 0) return `Empieza en ${hours}h ${minutes}m`;
  return `Empieza en ${Math.max(1, minutes)}m`;
}

function renderEvents(eventsList) {
  const grid = document.getElementById('events-grid');
  const empty = document.getElementById('events-empty');
  const statEvents = document.getElementById('stat-events');
  if (!grid || !empty) return;

  const items = Array.isArray(eventsList) ? eventsList.slice() : [];
  if (statEvents) statEvents.textContent = items.length;
  // Orden: activos primero, luego próximos, luego terminados; por prioridad y fecha
  const phaseRank = { active: 0, upcoming: 1, ended: 2 };
  items.sort((a, b) => {
    const pr = (phaseRank[a.phase] ?? 1) - (phaseRank[b.phase] ?? 1);
    if (pr !== 0) return pr;
    const prio = Number(b.priority || 0) - Number(a.priority || 0);
    if (prio !== 0) return prio;
    return new Date(b.starts_at || b.created_at || 0) - new Date(a.starts_at || a.created_at || 0);
  });

  try {
    const newsEl = document.getElementById('stat-news');
    syncNavBadges(newsEl ? newsEl.textContent : 0, items);
  } catch (_) {}
  if (items.length === 0) {
    grid.innerHTML = '';
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');

  eventsCache = items;
  grid.innerHTML = items.map((ev, evIdx) => {
    const meta = eventCategoryMeta(ev.category);
    const hasImg = Boolean(ev.image_url || ev.cover_url);
    const img = escapeHtml(ev.image_url || ev.cover_url || '');
    const phaseClass = ev.phase === 'active' ? 'ev-active' : ev.phase === 'ended' ? 'ev-ended' : 'ev-upcoming';
    const phaseBadge = ev.phase === 'active'
      ? '<span class="ev-badge ev-badge-live">● En curso</span>'
      : ev.phase === 'ended'
        ? '<span class="ev-badge ev-badge-ended">Finalizado</span>'
        : `<span class="ev-badge ev-badge-soon">${escapeHtml(eventCountdown(ev.starts_at, ev.phase)) || 'Próximamente'}</span>`;
    const dateRange = escapeHtml(formatEventRange(ev.starts_at, ev.ends_at));
    return `
      <article class="event-card glass-card ${phaseClass} ${hasImg ? '' : 'ev-noimg'}" data-ev-idx="${evIdx}" role="button" tabindex="0">
        <div class="event-card-media">
          ${hasImg
            ? `<img src="${img}" alt="${escapeHtml(ev.title)}" class="event-card-img" loading="lazy" />`
            : `<div class="event-card-img-fallback"><span>${meta.icon}</span></div>`}
          <div class="event-card-gradient"></div>
          <span class="ev-badge ev-badge-cat ${meta.cls}">${meta.icon} ${meta.label}</span>
          ${phaseBadge}
        </div>
        <div class="event-card-body">
          <span class="event-card-project">${escapeHtml(ev.project_name || 'OWS')}</span>
          <h4 class="event-card-title">${escapeHtml(ev.title)}</h4>
          ${ev.description ? `<p class="event-card-desc">${escapeHtml(ev.description)}</p>` : ''}
          <span class="event-card-date">📅 ${dateRange}</span>
        </div>
      </article>
    `;
  }).join('');
}

async function loadDashboardEvents() {
  const empty = document.getElementById('events-empty');
  try {
    const res = await fetch(API_BASE + '/ows-dashboard/events?limit=30');
    if (!res.ok) throw new Error(`Error del servidor (${res.status})`);
    const data = await res.json();
    renderEvents(data.events || []);
  } catch (err) {
    console.error('[OWS] No se pudieron cargar los eventos:', err);
    renderEvents([]);
    if (empty) {
      const note = document.createElement('p');
      note.className = 'news-error';
      note.textContent = 'No se pudieron cargar los eventos. Revisa tu conexión.';
      empty.appendChild(note);
    }
  }
}

function openEventModal(ev) {
  const modal = document.getElementById('event-modal');
  const body = document.getElementById('event-modal-body');
  if (!modal || !body || !ev) return;
  const meta = eventCategoryMeta(ev.category);
  const hasImg = Boolean(ev.image_url || ev.cover_url);
  body.innerHTML = `
    ${hasImg ? `<img src="${escapeHtml(ev.image_url || ev.cover_url || '')}" alt="${escapeHtml(ev.title)}" class="modal-banner" />` : ''}
    <div class="modal-head">
      <div class="modal-head-info">
        <span class="ev-badge ev-badge-cat ${meta.cls}" style="align-self:flex-start">${meta.icon} ${meta.label}</span>
        <h3 class="modal-title">${escapeHtml(ev.title)}</h3>
        <p class="modal-tagline">${escapeHtml(ev.project_name || 'OWS')} · ${escapeHtml(formatEventRange(ev.starts_at, ev.ends_at))}</p>
      </div>
    </div>
    ${ev.description ? `<div class="modal-about"><p class="modal-about-text">${escapeHtml(ev.description)}</p></div>` : ''}
    <dl class="modal-data">
      <div class="data-row"><dt>Inicio</dt><dd>${escapeHtml(ev.starts_at ? new Date(ev.starts_at).toLocaleString('es-ES') : '—')}</dd></div>
      <div class="data-row"><dt>Fin</dt><dd>${escapeHtml(ev.ends_at ? new Date(ev.ends_at).toLocaleString('es-ES') : '—')}</dd></div>
      <div class="data-row"><dt>Estado</dt><dd>${ev.phase === 'active' ? 'En curso' : ev.phase === 'ended' ? 'Finalizado' : 'Próximamente'}</dd></div>
    </dl>
    ${ev.link_url || ev.linkUrl ? `<div style="padding:0 28px 28px"><a class="btn btn-primary btn-block" href="${escapeHtml(ev.link_url || ev.linkUrl)}" target="_blank" rel="noopener" style="text-align:center;text-decoration:none;display:block">Ver más detalles ↗</a></div>` : ''}
  `;
  modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeEventModal() {
  const modal = document.getElementById('event-modal');
  if (modal) {
    modal.classList.add('hidden');
    document.body.style.overflow = '';
  }
}

// ═══════════════════════════════════════════════
// ANUNCIOS EMERGENTES — modales de Eventos (admin)
// Aparecen UNA sola vez por usuario: al cerrar se guarda el
// show_token visto. Si el admin pulsa Re-mostrar (token nuevo),
// el modal vuelve a aparecer sin recrear nada.
// ═══════════════════════════════════════════════

const SEEN_POPUPS_KEY = 'ows_seen_popups';

function getSeenPopups() {
  try { return JSON.parse(localStorage.getItem(SEEN_POPUPS_KEY) || '{}') || {}; }
  catch (_) { return {}; }
}

function markPopupSeen(id, token) {
  try {
    const seen = getSeenPopups();
    seen[String(id)] = Number(token || 1);
    localStorage.setItem(SEEN_POPUPS_KEY, JSON.stringify(seen));
  } catch (_) {}
}

async function checkOwsPopups() {
  try {
    const res = await fetch(API_BASE + '/ows-dashboard/popups/active?limit=10');
    if (!res.ok) return;
    const data = await res.json().catch(() => ({}));
    const popups = Array.isArray(data.popups) ? data.popups : [];
    if (!popups.length) return;
    const seen = getSeenPopups();
    const pending = popups.find((p) => seen[String(p.id)] !== Number(p.show_token || p.showToken || 1));
    if (!pending) return;
    // Da tiempo al panel y evita pisar otros modales o el setup
    setTimeout(() => {
      if (document.getElementById('dashboard-section').classList.contains('hidden')) return;
      if (!document.getElementById('event-modal').classList.contains('hidden')) return;
      if (!document.getElementById('release-modal').classList.contains('hidden')) return;
      const setup = document.getElementById('setup-screen');
      if (setup && !setup.classList.contains('hidden')) return;
      openAnnounceModal(pending);
    }, 1800);
  } catch (_) {}
}

function announceTextOn(hex) {
  // Texto legible sobre el color del toast (amarillo → negro, oscuro → blanco)
  try {
    let h = String(hex || '').replace('#', '');
    if (h.length === 3) h = h.split('').map((c) => c + c).join('');
    const r = parseInt(h.slice(0, 2), 16);
    const g = parseInt(h.slice(2, 4), 16);
    const b = parseInt(h.slice(4, 6), 16);
    const lum = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
    return lum > 0.6 ? '#1a0a00' : '#ffffff';
  } catch (_) { return '#1a0a00'; }
}

function showAnnounceToast(p) {
  const zone = document.getElementById('announce-toasts');
  if (!zone || !p) return;
  const token = Number(p.show_token || p.showToken || 1);
  const color = p.toast_color || p.toastColor || '#f59e0b';
  const pos = (p.toast_position || p.toastPosition || 'top') === 'bottom' ? 'bottom' : 'top';
  const dur = Math.max(2000, Math.min(30000, Number(p.duration_ms || p.durationMs || 6000)));
  const link = p.link_url || p.linkUrl || '';
  zone.dataset.pos = pos;
  zone.innerHTML = '';
  const el = document.createElement('div');
  el.className = 'announce-toast';
  el.style.background = color;
  el.style.color = announceTextOn(color);
  el.setAttribute('role', 'status');
  el.innerHTML = `
    <span class="announce-toast-ico">📢</span>
    <span class="announce-toast-main">
      <b>${escapeHtml(p.title)}</b>
      ${p.body ? `<small>${escapeHtml(p.body)}</small>` : ''}
    </span>
    ${link ? `<a class="announce-toast-link" href="${escapeHtml(link)}" target="_blank" rel="noopener">Abrir ↗</a>` : ''}
    <button class="announce-toast-x" type="button" aria-label="Cerrar">✕</button>
  `;
  let gone = false;
  const hide = (mark) => {
    if (gone) return;
    gone = true;
    el.classList.add('announce-toast-hide');
    setTimeout(() => el.remove(), 320);
    if (mark !== false) markPopupSeen(p.id, token);
  };
  el.querySelector('.announce-toast-x').addEventListener('click', (e) => { e.stopPropagation(); hide(true); });
  el.addEventListener('click', () => hide(true));
  zone.appendChild(el);
  setTimeout(() => hide(true), dur);
}

function openAnnounceModal(p) {
  // Los toast no abren ventana: barrita corta arriba (o abajo)
  if (String((p && p.kind) || '').toLowerCase() === 'toast') { showAnnounceToast(p); return; }
  const modal = document.getElementById('announce-modal');
  const body = document.getElementById('announce-modal-body');
  if (!modal || !body || !p) return;
  const token = Number(p.show_token || p.showToken || 1);
  const img = p.image_url || p.imageUrl || '';
  const link = p.link_url || p.linkUrl || '';
  const linkLabel = p.link_label || p.linkLabel || 'Ver más detalles ↗';
  body.innerHTML = `
    ${img ? `<img src="${escapeHtml(img)}" alt="${escapeHtml(p.title)}" class="modal-banner" />` : ''}
    <div class="modal-head">
      <div class="modal-head-info">
        <span class="announce-badge">📢 Anuncio OWS</span>
        <h3 class="modal-title">${escapeHtml(p.title)}</h3>
      </div>
    </div>
    ${p.body ? `<div class="modal-about"><p class="modal-about-text announce-text">${escapeHtml(p.body)}</p></div>` : ''}
    <div class="announce-actions">
      ${link ? `<a class="btn btn-primary btn-block announce-btn" href="${escapeHtml(link)}" target="_blank" rel="noopener" style="text-align:center;text-decoration:none;display:block">${escapeHtml(linkLabel)}</a>` : ''}
      <button class="btn btn-ghost btn-block announce-btn" id="announce-ok" type="button">Entendido ✓</button>
    </div>
  `;
  const ok = document.getElementById('announce-ok');
  if (ok) ok.addEventListener('click', () => closeAnnounceModal());
  modal.dataset.popupId = String(p.id);
  modal.dataset.popupToken = String(token);
  modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeAnnounceModal() {
  const modal = document.getElementById('announce-modal');
  if (!modal || modal.classList.contains('hidden')) return;
  // Cerrar = visto: no vuelve a salir salvo Re-mostrar del admin
  if (modal.dataset.popupId) markPopupSeen(modal.dataset.popupId, modal.dataset.popupToken);
  modal.classList.add('hidden');
  const newsModal = document.getElementById('news-modal');
  if (document.getElementById('event-modal').classList.contains('hidden') &&
      document.getElementById('release-modal').classList.contains('hidden') &&
      (!newsModal || newsModal.classList.contains('hidden'))) {
    document.body.style.overflow = '';
  }
}

// ═══════════════════════════════════════════════
// ULTIMAS NOTICIAS — tabla del dashboard
// ═══════════════════════════════════════════════

function formatNewsDate(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString('es-ES', { day: 'numeric', month: 'short', year: 'numeric' });
}

function escapeHtml(text) {
  return String(text || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

let newsFeedCache = [];

function renderNewsTable(newsList) {
  const list = document.getElementById('news-table-body');
  const empty = document.getElementById('news-empty');
  const count = document.getElementById('news-count');
  const statNews = document.getElementById('stat-news');
  if (!list || !empty) return;

  const items = Array.isArray(newsList) ? newsList : [];
  newsFeedCache = items;

  if (count) {
    count.textContent = items.length > 0
      ? `${items.length} ${items.length === 1 ? 'noticia' : 'noticias'}`
      : 'Sin noticias';
  }
  if (statNews) statNews.textContent = items.length;
  try { syncNavBadges(items.length, eventsCache); } catch (_) {}

  if (items.length === 0) {
    list.innerHTML = '';
    empty.classList.remove('hidden');
    return;
  }

  empty.classList.add('hidden');
  list.innerHTML = items.map((item, idx) => {
    const raw = item.published_at || item.created_at;
    const d = raw ? new Date(raw) : null;
    const valid = d && !Number.isNaN(d.getTime());
    const day = valid ? d.getDate() : '•';
    const mon = valid ? d.toLocaleDateString('es-ES', { month: 'short' }).replace('.', '') : '—';
    const year = valid ? d.getFullYear() : '';
    const media = String(item.image_url || '').trim();
    const title = escapeHtml(item.title);
    const visual = media
      ? `<img src="${escapeHtml(media)}" alt="" loading="lazy" />`
      : `<span class="news-card-fallback" aria-hidden="true">📰</span>`;
    return `
    <article class="news-card${idx === 0 ? ' is-featured' : ''}" data-news-idx="${idx}" role="button" tabindex="0" aria-label="Leer noticia: ${title}">
      <div class="news-card-media">
        ${visual}
        <span class="news-card-date"><b>${day}</b><span>${escapeHtml(mon)}</span>${year ? `<i>${year}</i>` : ''}</span>
        <span class="news-card-project">${escapeHtml(item.project_name || 'OWS')}</span>
      </div>
      <div class="news-card-body">
        ${idx === 0 ? '<span class="news-card-kicker">Última noticia</span>' : ''}
        <h4 class="news-card-title">${title}</h4>
        ${item.description ? `<p class="news-card-desc">${escapeHtml(item.description)}</p>` : ''}
        <span class="news-card-cta">Leer noticia →</span>
      </div>
    </article>
  `;
  }).join('');
}

// ── Modal de noticia completa (pantalla completa) ──
// Sin imagen / imagen horizontal → banner arriba + contenido debajo.
// Imagen vertical → el modal se redistribuye: contenido a la izquierda
// y la imagen a la derecha (sticky, alto completo).
const NEWS_MODAL_SIBLINGS = ['event-modal', 'release-modal', 'announce-modal', 'updates-modal', 'hub-changelog-modal', 'hub-restart-modal'];

function newsModalIsAloneOpen() {
  return NEWS_MODAL_SIBLINGS.some((id) => {
    const el = document.getElementById(id);
    return el && !el.classList.contains('hidden');
  });
}

function openNewsModal(item) {
  const modal = document.getElementById('news-modal');
  const body = document.getElementById('news-modal-body');
  if (!modal || !body || !item) return;

  const media = String(item.image_url || '').trim();
  const raw = item.published_at || item.created_at;
  const d = raw ? new Date(raw) : null;
  const valid = d && !Number.isNaN(d.getTime());
  const longDate = valid ? d.toLocaleDateString('es-ES', { day: 'numeric', month: 'long', year: 'numeric' }) : '';
  const footDate = valid ? d.toLocaleDateString('es-ES', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';
  const text = String(item.description || '').trim();
  const paragraphs = text
    ? text.split(/\n{2,}/).map((p) => `<p>${escapeHtml(p)}</p>`).join('')
    : '<p>Esta noticia no tiene contenido adicional.</p>';

  body.innerHTML = `
    <div class="nm-media${media ? '' : ' is-hidden'}">
      ${media ? `<img src="${escapeHtml(media)}" alt="${escapeHtml(item.title)}" />` : ''}
    </div>
    <div class="nm-content">
      <div class="nm-meta">
        ${longDate ? `<span class="nm-date">📅 ${escapeHtml(longDate)}</span>` : ''}
        <span class="nm-project">${escapeHtml(item.project_name || 'OWS')}</span>
      </div>
      <h2 class="nm-title">${escapeHtml(item.title)}</h2>
      <hr class="nm-rule" />
      <div class="nm-text">${paragraphs}</div>
      <div class="nm-foot">
        <span>OWS Hub · Últimas Noticias</span>
        <span>${escapeHtml(footDate)}</span>
      </div>
    </div>`;

  modal.classList.remove('hidden', 'is-vertical', 'is-noimg');
  document.body.style.overflow = 'hidden';
  const scroller = modal.querySelector('.news-modal');
  if (scroller) scroller.scrollTop = 0;

  if (!media) {
    modal.classList.add('is-noimg');
    return;
  }
  // Orientación de la imagen: vertical = alto > ancho
  const probe = new Image();
  probe.onload = () => {
    if (modal.classList.contains('hidden')) return;
    modal.classList.toggle('is-vertical', probe.naturalHeight > probe.naturalWidth);
  };
  probe.onerror = () => {
    if (modal.classList.contains('hidden')) return;
    modal.classList.add('is-noimg');
    const m = body.querySelector('.nm-media');
    if (m) m.classList.add('is-hidden');
  };
  probe.src = media;
}

function closeNewsModal() {
  const modal = document.getElementById('news-modal');
  if (!modal || modal.classList.contains('hidden')) return;
  modal.classList.add('hidden');
  modal.classList.remove('is-vertical', 'is-noimg');
  if (!newsModalIsAloneOpen()) document.body.style.overflow = '';
}

async function loadDashboardNews() {
  const empty = document.getElementById('news-empty');
  try {
    const res = await fetch(API_BASE + '/ows-dashboard/news?limit=20');
    if (!res.ok) throw new Error(`Error del servidor (${res.status})`);
    const data = await res.json();
    renderNewsTable(data.news || []);
  } catch (err) {
    console.error('[OWS] No se pudieron cargar las noticias:', err);
    // La tabla se mantiene vacia; se muestra el estado vacio con nota de error
    if (empty) {
      renderNewsTable([]);
      const note = document.createElement('p');
      note.className = 'news-error';
      note.textContent = 'No se pudieron cargar las noticias. Revisa tu conexión.';
      empty.appendChild(note);
    }
  }
}

// ═══════════════════════════════════════════════
// LANZAMIENTOS — proyectos OWS (ows-launch-projects)
// ═══════════════════════════════════════════════

const RELEASE_STATUS_META = {
  development: { label: 'En desarrollo', cls: 'release-status-dev' },
  soon:        { label: 'Próximamente',  cls: 'release-status-soon' },
  launched:    { label: '¡Disponible ya!', cls: 'release-status-launched' },
  cancelled:   { label: 'Cancelado',     cls: 'release-status-cancelled' }
};

function releaseMediaMarkup(p) {
  const banner = p.banner_url || '';
  const icon = p.icon_url || '';
  const alt = `${p.name} — Banner`;
  // Sin banner propio, el icono hace de portada; encuadre bajo para mostrar
  // la zona del titulo del arte (el icono es 1:1, el recorte es inevitable).
  const hero = banner ? '' : ' release-banner-hero';
  if (banner) {
    return `<div class="release-media">
      <img src="${escapeHtml(banner)}" alt="${escapeHtml(alt)}" class="release-banner" loading="lazy" />
    </div>`;
  }
  if (icon) {
    return `<div class="release-media">
      <img src="${escapeHtml(icon)}" alt="${escapeHtml(alt)}" class="release-banner${hero}" loading="lazy" />
    </div>`;
  }
  return '<div class="release-media release-media-empty"></div>';
}

function releaseBodyMarkup(p) {
  const icon = p.icon_url
    ? `<img src="${escapeHtml(p.icon_url)}" alt="${escapeHtml(p.name)}" class="release-icon" loading="lazy" />`
    : '<div class="release-icon"></div>';
  const itchUrl = p.itch_url || p.itchUrl || p.link_url || p.linkUrl || '';
  const itchVersion = p.itch_version || p.itchVersion || '';
  const versionBadge = itchVersion
    ? `<span class="release-version">v${escapeHtml(itchVersion)}</span>`
    : (itchUrl ? `<span class="release-version release-version-itch">itch.io</span>` : '');
  return `
    <div class="release-body">
      <div class="release-title-row">
        ${icon}
        <h4 class="release-name">${escapeHtml(p.name)}</h4>
        ${versionBadge}
      </div>
      ${p.genre ? `<p class="release-genre">${escapeHtml(p.genre)}</p>` : ''}
      ${p.description ? `<p class="release-desc">${escapeHtml(p.description)}</p>` : ''}
      <div class="release-foot">
        <span>${escapeHtml((p.platforms || []).map((x) => String(x).charAt(0).toUpperCase() + String(x).slice(1)).join(' · ') || 'Plataforma por confirmar')}</span>
        <span>Ver detalles →</span>
      </div>
    </div>
  `;
}

// Fallback offline (mismas imágenes locales de siempre) si la API no responde
const RELEASES_FALLBACK = [
  {
    id: 0,
    slug: 'wilder-gambit',
    name: 'Wilder Gambit',
    description: 'Ajedrez de alto riesgo. Cada movimiento cuenta.',
    status: 'development',
    genre: 'Ajedrez · Estrategia por turnos',
    platforms: ['windows'],
    icon_url: 'img/wilder-gambit-icon.jpeg',
    banner_url: 'img/wilder-gambit-banner.jpeg',
    expected_date: null,
    confirmed_date: null,
    link_url: 'https://oceanandwildstudios.itch.io/wilder-gambit',
    itch_url: 'https://oceanandwildstudios.itch.io/wilder-gambit',
    itch_version: ''
  }
];

let releasesCache = [];
let eventsCache = [];
// Estados de carga: sin esto la grilla quedaba vacía mientras Render
// despertaba (free tier tarda 20-60s en el primer request) y parecía rota.
let releasesLoadState = 'idle'; // idle | loading | ready | error
let releasesLoading = false;

function releaseStatusMeta(status) {
  return RELEASE_STATUS_META[String(status || '').trim().toLowerCase()] || RELEASE_STATUS_META.development;
}

// Fetch con timeout: si el servidor no contesta, se corta y se cae al
// siguiente fuente en vez de dejar la vista en blanco para siempre.
function fetchWithTimeout(url, ms) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  return fetch(url, { signal: ctrl.signal }).finally(() => clearTimeout(timer));
}

function renderReleasesLoading() {
  const grid = document.getElementById('releases-grid');
  if (!grid) return;
  grid.innerHTML = `
    <div class="releases-placeholder" role="status" aria-live="polite">
      <span class="releases-spinner" aria-hidden="true"></span>
      <p class="releases-placeholder-title">Cargando lanzamientos…</p>
      <p class="releases-placeholder-sub">La primera carga puede tardar si el servidor está despertando.</p>
    </div>`;
  try { syncReleasesSpotlight(); } catch (_) {}
}

// ── Spotlight Lanzamientos ──────────────────────────────────
// Al abrir 1 icono se oscurece todo (menos el menú lateral) y el
// item activo queda por encima del overlay para highlight total.
function syncReleasesSpotlight() {
  const grid = document.getElementById('releases-grid');
  const sp = document.getElementById('releases-spotlight');
  if (!grid || !sp) return;
  const anyOpen = !!grid.querySelector('.release-dock-item.is-open');
  sp.classList.toggle('hidden', !anyOpen);
  try { document.body.classList.toggle('releases-focus', anyOpen); } catch (_) {}
  try { sp.setAttribute('aria-hidden', anyOpen ? 'false' : 'true'); } catch (_) {}
}

function closeReleasesDock() {
  const grid = document.getElementById('releases-grid');
  if (grid) {
    grid.querySelectorAll('.release-dock-item.is-open').forEach((x) => {
      x.classList.remove('is-open');
      x.setAttribute('aria-expanded', 'false');
      const info = x.querySelector('.dock-info');
      if (info) info.setAttribute('aria-hidden', 'true');
    });
  }
  syncReleasesSpotlight();
}

function formatReleaseDate(value) {
  if (!value) return null;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleDateString('es-ES', { day: 'numeric', month: 'short', year: 'numeric' });
}

function renderReleases(projects) {
  const grid = document.getElementById('releases-grid');
  if (!grid) return;
  const items = Array.isArray(projects) ? projects : [];
  if (!items.length) {
    grid.innerHTML = '<p class="loading-note" style="color:var(--text-muted);font-size:0.85rem">Todavía no hay lanzamientos anunciados. ¡Volvé pronto! ✨</p>';
    releasesLoadState = 'ready';
    try { syncReleasesSpotlight(); } catch (_) {}
    return;
  }
  // Conserva el icono expandido si el enrich re-renderiza al llegar la versión de itch.io
  let openSlug = '';
  try {
    const prev = grid.querySelector('.release-dock-item.is-open');
    if (prev) openSlug = prev.getAttribute('data-slug') || '';
  } catch (_) {}
  releasesCache = items;
  grid.innerHTML = items.map((p) => {
    try {
    const meta = releaseStatusMeta(p.status);
    const icon = p.icon_url || '';
    const itchVersion = p.itch_version || p.itchVersion || '';
    const itchUrl = p.itch_url || p.itchUrl || p.link_url || p.linkUrl || '';
    const versionBadge = itchVersion
      ? `<span class="dock-ver">v${escapeHtml(itchVersion)}</span>`
      : (itchUrl ? `<span class="dock-ver dock-ver-itch">itch.io</span>` : '');
    const platforms = Array.isArray(p.platforms) && p.platforms.length
      ? p.platforms.map((x) => String(x).charAt(0).toUpperCase() + String(x).slice(1)).join(' · ')
      : 'PC · Windows';
    const isOpen = openSlug && String(p.slug) === String(openSlug) ? ' is-open' : '';
    const iconHtml = icon
      ? `<img src="${escapeHtml(icon)}" alt="${escapeHtml(p.name)}" class="release-dock-icon" loading="lazy" draggable="false" />`
      : `<span class="release-dock-icon release-dock-fallback">🎮</span>`;
    return `
      <div class="release-dock-item${isOpen}" data-slug="${escapeHtml(p.slug)}" role="button" tabindex="0" aria-expanded="${isOpen ? 'true' : 'false'}" aria-label="${escapeHtml(p.name)} — clic para info, doble clic para detalles">
        <div class="release-dock-icon-wrap">
          ${iconHtml}
          <span class="release-dock-ring" aria-hidden="true"></span>
          <span class="release-dock-dot ${meta.cls}" title="${escapeHtml(meta.label)}"></span>
          <span class="dock-tip">${escapeHtml(p.name)}</span>
        </div>
        <div class="dock-info" aria-hidden="${isOpen ? 'false' : 'true'}">
          <div class="dock-info-card">
            <div class="dock-info-head">
              <h4 class="dock-info-name">${escapeHtml(p.name)}</h4>
              ${versionBadge}
            </div>
            ${p.genre ? `<p class="dock-info-genre">${escapeHtml(p.genre)}</p>` : ''}
            ${p.description ? `<p class="dock-info-desc">${escapeHtml(p.description)}</p>` : ''}
            <div class="dock-info-foot">
              <span class="dock-status ${meta.cls}">${escapeHtml(meta.label)}</span>
              <span class="dock-plats">${escapeHtml(platforms)}</span>
            </div>
            <p class="dock-hint">doble clic para detalles →</p>
          </div>
        </div>
      </div>
    `;
    } catch (err) {
      // Un proyecto roto no puede vaciar la grilla entera
      console.error('[OWS] Proyecto de lanzamiento inválido, se omite:', err, p);
      return '';
    }
  }).join('');
  releasesLoadState = 'ready';
  try { syncReleasesSpotlight(); } catch (_) {}
}

// Aviso + reintento manual cuando se pintó la lista local por falta de servidor.
function appendReleasesRetryNote() {
  const grid = document.getElementById('releases-grid');
  if (!grid) return;
  grid.insertAdjacentHTML('beforeend', `
    <div class="releases-retry-note">
      <span>Sin respuesta del servidor: se muestra la lista local.</span>
      <button type="button" class="btn btn-ghost btn-sm" data-releases-retry>Reintentar</button>
    </div>`);
}

const RELEASES_FETCH_TIMEOUT_MS = 12000;

async function loadDashboardReleases() {
  // Hub Epic-style: 1 request (/ows-hub/summary) en vez de 3.
  // Fallback a /ows-launch-projects si el hub aún no está desplegado.
  // Si nada responde se pintan los datos locales en vez de dejar la vista vacía.
  if (releasesLoading) return;
  releasesLoading = true;
  releasesLoadState = 'loading';
  renderReleasesLoading();
  let lastErr = null;
  try {
    try {
      const hubRes = await fetchWithTimeout(API_BASE + '/ows-hub/summary', RELEASES_FETCH_TIMEOUT_MS);
      if (hubRes.ok) {
        const hub = await hubRes.json();
        if (Array.isArray(hub.projects)) {
          renderReleases(hub.projects);
          releasesLoading = false;
          enrichReleasesWithItch(hub.projects);
          return;
        }
      }
      throw new Error(`Hub no disponible (${hubRes.status})`);
    } catch (hubErr) {
      lastErr = hubErr;
      try {
        const res = await fetchWithTimeout(API_BASE + '/ows-launch-projects', RELEASES_FETCH_TIMEOUT_MS);
        if (!res.ok) throw new Error(`Error del servidor (${res.status})`);
        const data = await res.json();
        const projects = Array.isArray(data.projects) ? data.projects : [];
        renderReleases(projects);
        releasesLoading = false;
        enrichReleasesWithItch(projects);
        return;
      } catch (err) {
        lastErr = err;
      }
    }
    console.error('[OWS] No se pudieron cargar los lanzamientos, usando fallback local:', lastErr);
    renderReleases(RELEASES_FALLBACK);
    appendReleasesRetryNote();
    // 'error' (no 'ready') para que al volver a entrar en la vista reintente solo.
    releasesLoadState = 'error';
  } finally {
    releasesLoading = false;
  }
}

// Enriquece las tarjetas con la versión real de itch.io (cache 6h en server)
// y con el artefacto real de descarga (ZIP). No bloquea el primer paint:
// actualiza badge + modal cache en background.
async function enrichReleasesWithItch(projects) {
  const items = Array.isArray(projects) ? projects : [];
  await Promise.all(items.map(async (p) => {
    const slug = String(p.slug || '').trim();
    if (!slug) return;
    // Si ya trae versión Y qué archivo se baja, no hace falta pedirla
    if ((p.itch_version || p.itchVersion) && p.download) return;
    try {
      const res = await fetch(API_BASE + '/ows-launch-projects/' + encodeURIComponent(slug) + '/version');
      if (!res.ok) return;
      const v = await res.json();
      const idx = releasesCache.findIndex((x) => String(x.slug) === slug);
      if (idx >= 0) {
        releasesCache[idx] = {
          ...releasesCache[idx],
          itch_url: v.itch_url || releasesCache[idx].itch_url || releasesCache[idx].link_url || '',
          itch_version: releasesCache[idx].itch_version || v.version || '',
          itch_file: v.file || releasesCache[idx].itch_file || '',
          itch_size: v.size || releasesCache[idx].itch_size || '',
          // Qué se descarga de verdad: ZIP con el juego (el .exe va dentro)
          download: v.download || releasesCache[idx].download || null,
          download_type: v.download_type || (releasesCache[idx].download && releasesCache[idx].download.type) || '',
          download_file: v.download_file || releasesCache[idx].download_file || '',
          download_size: v.download_size || releasesCache[idx].download_size || '',
          download_size_bytes: Number(v.download_size_bytes || releasesCache[idx].download_size_bytes || 0),
          exe_file: v.exe_file || releasesCache[idx].exe_file || '',
          installer_url: v.installer_url || releasesCache[idx].installer_url || ''
        };
        // Re-render ligero solo si llegó versión nueva
        if (v.version && releasesLoadState === 'ready') renderReleases(releasesCache);
      }
    } catch (_) { /* badge queda como itch.io sin versión */ }
  }));
}

let rdCloseTimer = 0;

function openReleaseModal(project) {
  const modal = document.getElementById('release-modal');
  const body = document.getElementById('release-modal-body');
  if (!modal || !body || !project) return;

  const p = releasesCache.find((x) => String(x.slug) === String(project.slug)) || project;
  const slug = String(p.slug || '').trim();
  const meta = releaseStatusMeta(p.status);
  const banner = p.banner_url || p.bannerUrl || '';
  const icon = p.icon_url || p.iconUrl || '';
  const token = slug + '_' + Date.now().toString(36);
  body.dataset.rmSlug = slug;
  body.dataset.rmToken = token;

  body.innerHTML = `
    <header class="rd-hero">
      ${banner
        ? `<img src="${escapeHtml(banner)}" alt="${escapeHtml(p.name)} — Banner" class="rd-hero-img" />`
        : `<div class="rm-notice" style="position:absolute;inset:auto 26px 90px;max-width:520px"><span class="rm-notice-ico">🎮</span><div class="rm-notice-main"><b>${escapeHtml(p.name)}</b><p>Vista previa del lanzamiento.</p></div></div>`}
      <div class="rd-hero-shade" aria-hidden="true"></div>
      <div class="rd-hero-inner">
        ${icon ? `<img src="${escapeHtml(icon)}" alt="${escapeHtml(p.name)}" class="rd-hero-icon" />` : ''}
        <div class="rd-hero-titles">
          <div class="rd-chips">
            <span class="release-soon ${meta.cls}">${meta.label}</span>
            ${releaseVersionChipHtml(p) || ''}
          </div>
          <h3 class="rd-title">${escapeHtml(p.name)}</h3>
          ${p.genre ? `<p class="rd-tagline">${escapeHtml(p.genre)}</p>` : ''}
        </div>
      </div>
    </header>

    <div class="rd-body">
      <div class="rd-main">
        ${p.description ? `
        <section>
          <h4 class="rd-sec-title">Acerca del juego</h4>
          <p class="rd-about">${escapeHtml(p.description)}</p>
        </section>` : ''}

        <section>
          <h4 class="rd-sec-title">Descarga y versiones</h4>
          <div id="rm-versions" class="rd-versions" aria-live="polite">
            ${releaseVersionsHtml(p, null)}
          </div>
        </section>

        <section>
          <h4 class="rd-sec-title">Detalles</h4>
          <dl class="modal-data" style="margin:0">
            <div class="data-row"><dt>Motor</dt><dd>Unity</dd></div>
            ${p.genre ? `<div class="data-row"><dt>Género</dt><dd>${escapeHtml(p.genre)}</dd></div>` : ''}
            <div class="data-row"><dt>Desarrollador</dt><dd>Ocean &amp; Wild Studios</dd></div>
            <div class="data-row"><dt>Plataformas</dt><dd>${escapeHtml(releasePlatformsLabel(p))}</dd></div>
            <div class="data-row"><dt>Peso de descarga</dt><dd id="rm-dl-size" class="data-na">Calculando…</dd></div>
            <div class="data-row"><dt>Estado</dt><dd>${meta.label}</dd></div>
            ${releaseDateRowHtml('Fecha esperada', p.expected_date || p.expectedDate)}
            ${releaseDateRowHtml('Fecha confirmada', p.confirmed_date || p.confirmedDate)}
            <div class="data-row"><dt>Precio</dt><dd class="data-na">N/A</dd></div>
          </dl>
        </section>
      </div>

      <aside class="rd-side">
        <div class="rd-facts">
          <h4 class="rd-sec-title" style="border:none;margin:0 0 8px;padding:0">Ficha</h4>
          <div class="rd-fact"><span>Estado</span><b class="release-soon ${meta.cls}" style="text-transform:uppercase;font-size:0.62rem">${meta.label}</b></div>
          <div class="rd-fact"><span>Versión</span><b id="rm-fact-version">${escapeHtml(releaseEffectiveVersion(p) ? 'v' + releaseEffectiveVersion(p) : '—')}</b></div>
          <div class="rd-fact"><span>Motor</span><b>Unity</b></div>
          <div class="rd-fact"><span>Plataformas</span><b>${escapeHtml(releasePlatformsLabel(p))}</b></div>
        </div>
        ${releaseLinksHtml(p) ? `<div>
          <h4 class="rd-sec-title">Enlaces</h4>
          ${releaseLinksHtml(p)}
        </div>` : ''}
        ${p.status_feedback || p.statusFeedback ? `<div>
          <h4 class="rd-sec-title">Estado del desarrollo</h4>
          <p class="rd-notes">${escapeHtml(p.status_feedback || p.statusFeedback)}</p>
        </div>` : ''}
      </aside>
    </div>
  `;
  bindReleaseModalActions(body);
  if (rdCloseTimer) { clearTimeout(rdCloseTimer); rdCloseTimer = 0; }
  modal.classList.remove('is-closing', 'hidden');
  const rdc = modal.querySelector('.release-modal-card');
  if (rdc) rdc.scrollTop = 0;
  const rdb = modal.querySelector('.rd-progress i');
  if (rdb) rdb.style.width = '0%';
  document.body.style.overflow = 'hidden';
  loadReleaseModalVersions(slug, token);
  // Tamaño en disco del juego instalado (solo desktop): va bajo "Desinstalar".
  paintUninstallSize(slug);
  // Peso del archivo a descargar: se calcula solo (dato del server o HEAD).
  paintDownloadSize(slug, token);
  // App Android: botón de APK (o aviso "solo PC") dentro del modal.
  if (owsEnvironment() === 'android') paintAndroidApkSlot(slug, token);
  // Si aún no sabemos qué archivo se baja (ZIP real vs .exe), se consulta
  // en background y la ficha de descarga se repinta al llegar.
  if (!p.download) enrichReleasesWithItch([p]).then(refreshReleaseModalArtifact);
}

// Repinta solo el bloque "Descarga y versiones" cuando llega el artefacto real.
function refreshReleaseModalArtifact() {
  try {
    const body = document.getElementById('release-modal-body');
    const modal = document.getElementById('release-modal');
    if (!body || !modal || modal.classList.contains('hidden')) return;
    const slug = String(body.dataset.rmSlug || '').trim();
    if (!slug) return;
    const p = getDownloadProject(slug);
    const box = document.getElementById('rm-versions');
    if (box && p && p.download) {
      box.innerHTML = releaseVersionsHtml(p, null);
      bindReleaseModalActions(box);
    }
    // El tamaño real llega con la misma resolución: se repinta la ficha.
    paintDownloadSize(slug);
    if (owsEnvironment() === 'android') paintAndroidApkSlot(slug);
  } catch (_) {}
}

// ── Helpers del modal fullscreen ──

function releasePlatformsLabel(p) {
  if (Array.isArray(p.platforms) && p.platforms.length) {
    return p.platforms.map((x) => String(x).charAt(0).toUpperCase() + String(x).slice(1)).join(' · ');
  }
  return 'Por confirmar';
}

function releaseLatestOf(p) {
  return p.latest_release || p.latestRelease || null;
}

function releaseEffectiveVersion(p) {
  const rel = releaseLatestOf(p);
  if (rel && rel.version) return String(rel.version).trim();
  return String(p.itch_version || p.itchVersion || '').trim();
}

function releaseHasBuild(p) {
  const rel = releaseLatestOf(p);
  if (rel && rel.id) return true;
  if (String(p.itch_version || p.itchVersion || '').trim()) return true;
  if (String(p.installer_url || p.installerUrl || '').trim()) return true;
  return false;
}

function releaseVersionChipHtml(p) {
  const ver = releaseEffectiveVersion(p);
  if (ver) return `<span class="rd-ver-chip">v${escapeHtml(ver)}</span>`;
  const itch = p.itch_url || p.itchUrl || p.link_url || p.linkUrl || '';
  if (itch) return `<span class="rd-ver-chip rd-ver-itch">itch.io</span>`;
  return '';
}

// ── Artefacto de descarga: lo que se baja es el ZIP, no el .exe ──
// itch.io guarda el juego dentro de un ZIP (exe + _Data) y el Hub sirve ese
// ZIP. La ficha mostraba "Wilder Gambit.exe · 652 kB" (datos del scrape de
// itch) mientras la descarga real eran ~400 MB de ZIP: ahora se dice claro.
function releaseArtifact(p, rel) {
  const src = p || {};
  const d = src.download && typeof src.download === 'object' ? src.download : null;
  const itchFile = String(src.itch_file || src.itchFile || '').trim();
  const relFile = String((rel && (rel.file_label || rel.fileLabel)) || '').trim();
  const file = String((d && d.file) || src.download_file || '').trim()
    || (/\.zip$/i.test(itchFile) ? itchFile : '')
    || (/\.zip$/i.test(relFile) ? relFile : '');
  let type = String((d && d.type) || src.download_type || '').trim().toLowerCase();
  if (!type) type = file ? (/\.zip$/i.test(file) ? 'zip' : 'exe') : 'zip';
  // El tamaño del .exe NO es el de la descarga: solo se usa el tamaño que
  // resolvió el server para el artefacto real, o itch_size si itch_file
  // ya es un ZIP. Sin dato no se inventa ninguno.
  let size = String((d && d.size) || src.download_size || '').trim();
  if (!size && /\.zip$/i.test(itchFile)) size = String(src.itch_size || src.itchSize || '').trim();
  // Ejecutable jugable: dentro del ZIP (o el propio archivo si es .exe suelto)
  const exe = String((d && d.exe) || src.exe_file || '').trim()
    || (type === 'zip' ? (/\.exe$/i.test(itchFile) ? itchFile : '') : (type === 'exe' ? file : ''));
  return { type, file, size, exe, isZip: type !== 'exe' };
}

function releaseArtifactLineHtml(art) {
  const label = art.file || (art.isZip ? 'ZIP para Windows' : 'Build');
  const size = art.size ? ` · ${escapeHtml(art.size)}` : '';
  const exeLine = (art.isZip && art.exe)
    ? `<p class="rm-rel-exe">El ZIP incluye el ejecutable <b>${escapeHtml(art.exe)}</b> (se extrae al instalar)</p>`
    : '';
  return `
    <p class="rm-rel-file">📦 ${escapeHtml(label)}${size}</p>
    ${exeLine}`;
}

function releaseDateRowHtml(label, value) {
  const f = formatReleaseDate(value);
  if (f) return `<div class="data-row"><dt>${escapeHtml(label)}</dt><dd class="data-ok">${escapeHtml(f)}</dd></div>`;
  return `<div class="data-row"><dt>${escapeHtml(label)}</dt><dd class="data-na">N/A</dd></div>`;
}

function releaseLinksHtml(p) {
  const itch = p.itch_url || p.itchUrl || '';
  const link = p.link_url || p.linkUrl || '';
  const page = itch || link;
  if (!page) return '';
  const isItch = /itch\.io/i.test(page);
  return `
    <a class="btn btn-ghost btn-block rd-link-btn" href="${escapeHtml(page)}" target="_blank" rel="noopener">${isItch ? 'Ver en itch.io ↗' : 'Página oficial ↗'}</a>`;
}

// Mensaje cuando NO hay build, según el estado real del proyecto.
function releaseNoBuildNoticeHtml(p) {
  const status = String(p.status || 'development').trim().toLowerCase();
  const expected = formatReleaseDate(p.expected_date || p.expectedDate);
  const when = expected ? ` Fecha estimada: <b>${escapeHtml(expected)}</b>.` : '';
  const copy = {
    development: ['🚧', 'En desarrollo', 'Todavía no hay versión descargable. El equipo está construyendo el juego y las builds aparecerán aquí en cuanto se publiquen.'],
    soon: ['🔜', 'Próximamente', 'Aún no hay descarga disponible. Falta poco: cuando salga la primera build la verás aquí.'],
    launched: ['📦', 'Lanzado', 'La descarga se está preparando y aparecerá aquí en breve.'],
    cancelled: ['⛔', 'Cancelado', 'Este proyecto fue cancelado y no tiene descargas disponibles.'],
    discontinued: ['⛔', 'Descontinuado', 'Este proyecto fue descontinuado y no tiene descargas disponibles.']
  }[status] || ['ℹ️', 'Sin versión', 'Este proyecto aún no tiene versión descargable.'];
  return `
    <div class="rm-notice rm-notice-${status}">
      <span class="rm-notice-ico">${copy[0]}</span>
      <div class="rm-notice-main">
        <b>${escapeHtml(copy[1])} — sin descarga por ahora</b>
        <p>${copy[2]}${when}</p>
      </div>
    </div>`;
}

// Bloque de versiones/descarga. `releases` = lista fresca del servidor
// (null = aún cargando / usar solo caché).
function releaseVersionsHtml(p, releases) {
  const slug = String(p.slug || '').trim();
  const safeSlug = escapeHtml(slug);
  // Entorno real (Tauri/WebView2 o navegador). La regla del Hub es: en navegador
  // NO hay descargas, así que ambos caminos deben usar la misma detección.
  const inDesktop = owsEnvironment() === 'desktop';
  const installed = (window.OWSHubLibrary && window.OWSHubLibrary.installed(slug)) || null;
  const effVer = releaseEffectiveVersion(p);
  const list = Array.isArray(releases) ? releases : null;
  const latest = (list && list.length ? list[0] : null) || releaseLatestOf(p);
  const hasBuild = releaseHasBuild(p) || !!(latest && latest.id);

  let html = '';

  if (list === null && !releaseHasBuild(p)) {
    // Primera pintura sin build en caché: skeleton breve (luego llega el fetch)
    html += `<div class="rd-loading"><span class="btn-spinner"></span> Consultando versiones…</div>`;
  }

  const art = releaseArtifact(p, latest);

  if (hasBuild && latest && latest.id) {
    const relDate = latest.released_at ? formatReleaseDate(latest.released_at) : '';
    html += `
      <div class="rm-rel-card">
        <div class="rm-rel-top">
          <span class="rm-rel-ver">v${escapeHtml(latest.version || effVer || '?')}</span>
          <span class="rm-rel-channel">${escapeHtml(latest.channel || 'stable')}</span>
          ${relDate ? `<span class="rm-rel-date">${escapeHtml(relDate)}</span>` : ''}
        </div>
        ${releaseArtifactLineHtml(art)}
        ${latest.notes ? `<p class="rm-rel-notes">${escapeHtml(latest.notes)}</p>` : ''}
      </div>`;
    if (list && list.length > 1) {
      html += `<div class="rm-rel-history">` + list.slice(1, 5).map((r) => `
        <div class="rm-rel-old"><span>v${escapeHtml(r.version || '?')}</span><span>${escapeHtml(r.channel || '')}</span><span>${r.released_at ? escapeHtml(formatReleaseDate(r.released_at) || '') : ''}</span></div>
      `).join('') + `</div>`;
    }
  } else if (hasBuild) {
    // Build heredada de itch.io (sin fila en la tabla de releases)
    html += `
      <div class="rm-rel-card">
        <div class="rm-rel-top">
          <span class="rm-rel-ver">v${escapeHtml(effVer || '?')}</span>
          <span class="rm-rel-channel">itch.io</span>
        </div>
        ${releaseArtifactLineHtml(art)}
      </div>`;
  }

  const progressMarkup = `
    <div class="owshub-progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
      <div class="owshub-progress-fill" id="owshub-install-bar" style="width:0%"></div>
    </div>
    <p class="loading-note" id="owshub-install-note" style="text-align:center"></p>
    <p class="loading-note owshub-pct" id="owshub-install-pct" style="text-align:center"></p>`;

  if (hasBuild) {
    html += `<div class="rm-actions">`;
    if (inDesktop) {
      if (installed && installed.exePath) {
        const upd = window.OWSHubLibrary.needsUpdate(slug, effVer);
        html += `<button class="btn btn-primary btn-block" data-hub-action="launch" data-slug="${safeSlug}">▶ Jugar${effVer ? ` (v${escapeHtml(installed.version || effVer)})` : ''}</button>`;
        if (upd) {
          html += `<button class="btn btn-ghost btn-block" style="margin-top:0" data-hub-action="install" data-slug="${safeSlug}">⬇ Actualizar y jugar (v${escapeHtml(effVer)})</button>`;
        }
        html += `<p class="loading-note" id="owshub-install-note" style="text-align:center">Instalado ✓ — pulsa Jugar para abrirlo</p>`;
        html += `<p class="loading-note owshub-pct" id="owshub-install-pct" style="text-align:center"></p>`;
        html += `<button class="btn btn-danger btn-block" style="margin-top:12px" data-hub-action="uninstall" data-slug="${safeSlug}">🗑 Desinstalar</button>`;
        html += `<p class="loading-note owshub-uninstall-size" data-uninstall-size="${safeSlug}" style="text-align:center;font-size:0.76rem"></p>`;
      } else {
        html += `<button class="btn btn-primary btn-block" data-hub-action="install" data-slug="${safeSlug}">⬇ Instalar y jugar automáticamente${effVer ? ` (v${escapeHtml(effVer)})` : ''}</button>`;
        const dlSize = art.size ? ` (${escapeHtml(art.size)})` : '';
        html += `<p class="loading-note" style="text-align:center;font-size:0.78rem">Descarga el ZIP oficial${dlSize}, lo extrae y ejecuta el juego sin que hagas nada más.</p>`;
        html += progressMarkup;
      }
    } else if (hubIsRequired()) {
      // Navegador: sin OWS Hub no hay descargas. Se muestra el aviso obligatorio.
      html += hubRequiredNoticeHtml();
    } else if (owsEnvironment() === 'android') {
      // App Android: el slot lo rellena paintAndroidApkSlot con el APK
      // publicado (o con el aviso "se juega en PC" si no existe).
      html += `<div id="rm-apk-slot" data-apk-slug="${safeSlug}"><p class="loading-note"><span class="btn-spinner"></span> Buscando APK para Android…</p></div>`;
      html += progressMarkup;
    } else {
      const direct = `${API_BASE}/ows-launch-projects/${encodeURIComponent(slug)}/download`;
      html += `<a class="btn btn-primary btn-block rm-dl-btn" href="${escapeHtml(direct)}" download="${escapeHtml(art.file && /\.zip$/i.test(art.file) ? art.file : safeSlug + '.zip')}" data-hub-action="download-browser" data-slug="${safeSlug}" style="text-align:center;text-decoration:none;display:block">⬇ Descargar ${art.isZip ? 'ZIP' : 'build'}${effVer ? ` (v${escapeHtml(effVer)})` : ''}</a>`;
      const sizeHint = art.size ? ` de ${escapeHtml(art.size)}` : '';
      html += `<p class="loading-note" style="text-align:center;font-size:0.78rem">ZIP oficial de Windows${sizeHint}: trae el juego completo, así que la descarga puede tardar varios minutos. No cierres esta ventana.</p>`;
      html += progressMarkup;
    }
    html += `</div>`;
  } else if (list !== null) {
    // Confirmado por el servidor: no hay builds → aviso por estado
    html += releaseNoBuildNoticeHtml(p);
  }

  return html || `<div class="rd-loading"><span class="btn-spinner"></span> Consultando versiones…</div>`;
}

// Refresca la sección Descarga con las releases reales del servidor y
// las fusiona al caché para que instalación/badges usen la versión oficial.
async function loadReleaseModalVersions(slug, token) {
  const body = document.getElementById('release-modal-body');
  const modal = document.getElementById('release-modal');
  if (!body || !modal || modal.classList.contains('hidden')) return;
  if (!slug) return;
  try {
    const res = await fetch(API_BASE + '/ows-project-releases?slug=' + encodeURIComponent(slug));
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json().catch(() => ({}));
    const releases = Array.isArray(data.releases) ? data.releases : [];
    // ¿Sigue abierto el mismo modal? Si no, se descarta la respuesta.
    if (body.dataset.rmToken !== token || body.dataset.rmSlug !== slug) return;
    if (modal.classList.contains('hidden')) return;
    const idx = releasesCache.findIndex((x) => String(x.slug) === String(slug));
    const latest = releases.length ? releases[0] : null;
    if (idx >= 0) {
      releasesCache[idx] = {
        ...releasesCache[idx],
        has_release: !!latest,
        hasRelease: !!latest,
        latest_release: latest,
        latestRelease: latest,
        // La release oficial manda como versión visible si itch no trae nada
        itch_version: releasesCache[idx].itch_version || releasesCache[idx].itchVersion || (latest ? latest.version : ''),
        itchVersion: releasesCache[idx].itchVersion || releasesCache[idx].itch_version || (latest ? latest.version : '')
      };
    }
    const p = (idx >= 0 ? releasesCache[idx] : getDownloadProject(slug));
    const box = document.getElementById('rm-versions');
    if (box && p) {
      box.innerHTML = releaseVersionsHtml(p, releases);
      bindReleaseModalActions(box);
      if (owsEnvironment() === 'android') paintAndroidApkSlot(slug, token);
    }
    const factVer = document.getElementById('rm-fact-version');
    if (factVer && p) {
      const v = releaseEffectiveVersion(p);
      factVer.textContent = v ? 'v' + v : '—';
    }
  } catch (_) {
    // Sin red: si ya había build en caché se queda; si no, aviso por estado
    try {
      if (body.dataset.rmToken !== token) return;
      const box = document.getElementById('rm-versions');
      const p = getDownloadProject(slug);
      if (box && p && !releaseHasBuild(p) && !box.querySelector('.rm-notice')) {
        box.innerHTML = releaseVersionsHtml(p, []);
        bindReleaseModalActions(box);
      }
    } catch (_) {}
  }
}

function getDownloadProject(slug) {
  const s = String(slug || '').trim();
  if (!s) return null;
  const fromCache = (releasesCache || []).find((x) => String(x.slug) === s);
  if (fromCache) return fromCache;
  const fromFallback = (RELEASES_FALLBACK || []).find((x) => String(x.slug) === s);
  return fromFallback || { slug: s, name: s, icon_url: '', banner_url: '' };
}

function bindReleaseModalActions(root) {
  if (!root || !window.OWSHubLibrary) return;
  root.querySelectorAll('[data-hub-action]').forEach((btn) => {
    btn.addEventListener('click', (ev) => {
      const action = btn.getAttribute('data-hub-action');
      const slug = btn.getAttribute('data-slug') || '';
      const proj = getDownloadProject(slug);
      const displayName = (proj && proj.name) || slug || 'juego';
      if (action === 'launch') {
        btn.disabled = true;
        window.OWSHubLibrary.launch(slug)
          .then(() => { showToast('¡Que lo disfrutes! 🎮'); })
          .catch((err) => {
            showToast('No se pudo lanzar: ' + (err && err.message ? err.message : err));
          })
          .finally(() => { btn.disabled = false; });
      } else if (action === 'download-browser') {
        // Navegador: cierra el modal al instante, toast de inicio y Gestor visible.
        if (ev && ev.preventDefault) ev.preventDefault();
        closeReleaseModal();
        showDownloadToastStarted(displayName);
        startBrowserDownloadManaged(slug);
      } else if (action === 'install') {
        // Desktop (Tauri): mismo UX — cerrar, toast y seguir en el Gestor.
        const ver = (proj && (proj.itch_version || proj.itchVersion)) || '';
        closeReleaseModal();
        showDownloadToastStarted(displayName);
        startDesktopInstallManaged(slug, ver, displayName);
      } else if (action === 'install-apk') {
        // App Android: descarga interna con progreso + instalación del APK.
        if (ev && ev.preventDefault) ev.preventDefault();
        startAndroidApkInstall(slug, displayName);
      } else if (action === 'uninstall') {
        ev.preventDefault();
        runUninstall(btn, slug, displayName);
      }
    });
  });
}

// Tamaño en disco del juego instalado (se pinta bajo el botón Desinstalar).
async function paintUninstallSize(slug) {
  const box = document.querySelector(`[data-uninstall-size="${String(slug).replace(/"/g, '')}"]`);
  if (!box || !window.OWSHubLibrary) return;
  try {
    const bytes = await window.OWSHubLibrary.installedSizeBytes(slug);
    if (!bytes) { box.textContent = ''; return; }
    box.textContent = `Ocupa ${formatMB(bytes)} en tu biblioteca`;
  } catch (_) { box.textContent = ''; }
}

// ── Peso del archivo a descargar (fila "Peso de descarga" en Detalles) ──
// Se calcula solo: primero con lo que ya resolvió el server para el artefacto
// real (API de itch, cache 6h) y, si no hay dato, con un HEAD al endpoint de
// descarga que devuelve el Content-Length del ZIP.
function parseSizeToBytes(text) {
  const m = String(text || '').trim().match(/^([\d.,]+)\s*(b|kb?|mb?|gb?|tb?|kib|mib|gib|tib)?$/i);
  if (!m) return 0;
  const n = parseFloat(m[1].replace(',', '.'));
  if (!Number.isFinite(n) || n <= 0) return 0;
  const u = (m[2] || 'b').toLowerCase();
  const mult = ({
    b: 1,
    k: 1024, kb: 1024, kib: 1024,
    m: 1048576, mb: 1048576, mib: 1048576,
    g: 1073741824, gb: 1073741824, gib: 1073741824,
    t: 1099511627776, tb: 1099511627776, tib: 1099511627776
  })[u] || 1;
  return Math.round(n * mult);
}

function downloadBytesOf(p) {
  if (!p) return 0;
  const direct = Number(p.download_size_bytes || 0);
  if (direct > 0) return direct;
  const d = p.download && typeof p.download === 'object' ? p.download : null;
  const human = String((d && d.size) || p.download_size || '').trim();
  return parseSizeToBytes(human) || parseSizeToBytes(releaseArtifact(p, null).size);
}

async function paintDownloadSize(slug, token) {
  const modal = document.getElementById('release-modal');
  const body = document.getElementById('release-modal-body');
  const s = String(slug || '').trim();
  if (!s || !modal || !body || modal.classList.contains('hidden')) return;
  if (String(body.dataset.rmSlug || '') !== s) return;
  if (!document.getElementById('rm-dl-size')) return;
  // El modal puede cambiar de proyecto o cerrarse mientras calculamos.
  const isCurrent = () => !modal.classList.contains('hidden')
    && String(body.dataset.rmSlug || '') === s
    && (!token || body.dataset.rmToken === token);
  const put = (text, ok) => {
    if (!isCurrent()) return;
    const el = document.getElementById('rm-dl-size');
    if (!el) return;
    el.textContent = text;
    el.className = ok ? 'data-ok' : 'data-na';
  };

  const known = downloadBytesOf(getDownloadProject(s));
  if (known > 0) { put(formatMB(known), true); return; }
  // Sin build publicada no hay archivo que pesar: sin pedidos inútiles.
  if (!releaseHasBuild(getDownloadProject(s))) { put('N/D', false); return; }

  // 1) El server resuelve el artefacto real (ZIP) contra la API de itch.io.
  try {
    const res = await fetch(API_BASE + '/ows-launch-projects/' + encodeURIComponent(s) + '/version');
    if (res.ok) {
      const v = await res.json();
      const idx = (releasesCache || []).findIndex((x) => String(x.slug) === s);
      if (idx >= 0) {
        releasesCache[idx] = {
          ...releasesCache[idx],
          download: v.download || releasesCache[idx].download || null,
          download_size: v.download_size || releasesCache[idx].download_size || '',
          download_size_bytes: Number(v.download_size_bytes || releasesCache[idx].download_size_bytes || 0)
        };
      }
      const bytes = downloadBytesOf(v) || downloadBytesOf(getDownloadProject(s));
      if (bytes > 0) { put(formatMB(bytes), true); return; }
    }
  } catch (_) { /* sigue con HEAD */ }

  // 2) HEAD al endpoint de descarga: Content-Length del ZIP real.
  try {
    const res = await fetch(API_BASE + '/ows-launch-projects/' + encodeURIComponent(s) + '/download', { method: 'HEAD' });
    const len = Number(res.headers.get('Content-Length') || 0);
    if (res.ok && len > 0) { put(formatMB(len), true); return; }
  } catch (_) { /* sin dato */ }

  put('N/D', false);
}

// ── Android: slot de APK en el modal + descarga e instalación nativa ──
// Pinta el botón "Descargar e instalar APK" (o el aviso "solo PC") dentro
// de #rm-apk-slot con la release publicada en ows_android_releases.
async function paintAndroidApkSlot(slug, token) {
  const modal = document.getElementById('release-modal');
  const body = document.getElementById('release-modal-body');
  const s = String(slug || '').trim();
  if (!s || !modal || !body || modal.classList.contains('hidden')) return;
  if (String(body.dataset.rmSlug || '') !== s) return;
  if (token && body.dataset.rmToken && body.dataset.rmToken !== token) return;
  if (!document.getElementById('rm-apk-slot')) return;
  const rel = await fetchAndroidRelease(s);
  // El usuario pudo cambiar de proyecto o cerrar el modal mientras consultamos.
  if (modal.classList.contains('hidden') || String(body.dataset.rmSlug || '') !== s) return;
  const slot = document.getElementById('rm-apk-slot');
  if (!slot) return;
  if (!rel || !rel.apk_url) {
    slot.innerHTML = `
      <div class="rm-notice rm-notice-pc">
        <span class="rm-notice-ico">🖥️</span>
        <div class="rm-notice-main">
          <b>Se juega en PC — todavía no hay APK</b>
          <p>Esta versión es de Windows: instalala con <b>OWS Hub</b> en tu computadora y jugá desde ahí.</p>
        </div>
      </div>`;
    return;
  }
  const size = Number(rel.size_bytes || 0);
  const sizeLabel = size ? ` · ${formatMB(size)}` : '';
  const verLabel = rel.version_name ? `v${escapeHtml(String(rel.version_name))}` : 'última versión';
  slot.innerHTML = `
    <button class="btn btn-primary btn-block rm-apk-btn" data-hub-action="install-apk" data-slug="${escapeHtml(s)}">⬇ Descargar e instalar APK (${verLabel}${sizeLabel})</button>
    <p class="loading-note" style="text-align:center;font-size:0.78rem">Se guarda en tu teléfono y Android te pide instalarlo. Si aparece un aviso de seguridad, elegí "permitir".</p>`;
  bindReleaseModalActions(slot);
}

function nativeFilePath(uri) {
  let p = String(uri || '').replace(/^file:\/\//, '');
  try { p = decodeURIComponent(p); } catch (_) {}
  return p;
}

function describeNativeError(err) {
  if (err == null) return 'error desconocido';
  if (typeof err === 'string') return err;
  const parts = [];
  const msg = err.message || err.errorMessage || err.error;
  if (msg) parts.push(String(msg));
  if (err.code) parts.push('código ' + err.code);
  const d = err.data && typeof err.data === 'object' ? err.data : {};
  if (d.httpStatus) parts.push('HTTP ' + d.httpStatus);
  if (d.exception && d.exception !== msg) parts.push(String(d.exception));
  if (d.target) parts.push('destino ' + d.target);
  if (!parts.length) {
    try { parts.push(JSON.stringify(err)); } catch (_) { parts.push(String(err)); }
  }
  return parts.join(' · ');
}

// Cuadro de error persistente: el toast es corto y en móvil no deja leer
// el detalle, así que los fallos de instalación se muestran acá (con copiar).
function showErrorDialog(title, summary, detail, action) {
  try {
    const prev = document.getElementById('ows-error-dialog');
    if (prev) prev.remove();
    const wrap = document.createElement('div');
    wrap.id = 'ows-error-dialog';
    wrap.setAttribute('role', 'alertdialog');
    wrap.style.cssText = 'position:fixed;inset:0;z-index:99999;background:rgba(0,0,0,.72);display:flex;align-items:center;justify-content:center;padding:16px;';
    const box = document.createElement('div');
    box.style.cssText = 'background:#0b1422;color:#e8f0ff;border:1px solid #2a3b57;border-radius:14px;max-width:520px;width:100%;max-height:85vh;overflow:auto;padding:16px;font-size:14px;line-height:1.4;';
    const h = document.createElement('b');
    h.textContent = '⚠️ ' + title;
    h.style.cssText = 'display:block;font-size:16px;margin-bottom:8px;';
    const p = document.createElement('p');
    p.textContent = summary || '';
    p.style.cssText = 'margin:0 0 10px;';
    const pre = document.createElement('pre');
    pre.textContent = detail || '';
    pre.style.cssText = 'white-space:pre-wrap;word-break:break-all;user-select:text;-webkit-user-select:text;background:#050a12;border-radius:8px;padding:10px;font-size:12px;margin:0 0 12px;max-height:40vh;overflow:auto;';
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;';
    const mk = (label, fn, primary) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'btn ' + (primary ? 'btn-primary' : 'btn-ghost');
      b.textContent = label;
      b.addEventListener('click', fn);
      row.appendChild(b);
    };
    if (action && action.run) mk(action.label || 'Reintentar', () => { wrap.remove(); try { action.run(); } catch (_) {} }, true);
    mk('Copiar detalle', () => {
      const text = `${title}\n${summary || ''}\n${detail || ''}`;
      try { navigator.clipboard.writeText(text); showToast('Detalle copiado'); } catch (_) {}
    }, false);
    mk('Cerrar', () => wrap.remove(), false);
    box.append(h, p);
    if (detail) box.appendChild(pre);
    box.appendChild(row);
    wrap.appendChild(box);
    document.body.appendChild(wrap);
  } catch (_) {
    try { alert(title + '\n' + (summary || '') + '\n' + (detail || '')); } catch (__) {}
  }
}

// Último recurso: el navegador del sistema descarga el APK y Android lo instala.
function openApkInBrowser(url) {
  const u = String(url || '');
  if (!u) return;
  try { window.location.href = u; } catch (_) {}
}

// Descarga el APK a la caché de la app (con % en el Gestor) y abre el
// instalador del sistema. Toda la transferencia ocurre dentro de la app.
async function startAndroidApkInstall(slug, displayName) {
  const s = String(slug || '').trim();
  const proj = getDownloadProject(s);
  const name = displayName || (proj && proj.name) || s;
  const rel = androidReleaseCache[s] || await fetchAndroidRelease(s);
  if (!rel || !rel.apk_url) {
    showToast('Este proyecto todavía no tiene APK para Android');
    return null;
  }
  let native = null;
  try { native = await loadOwsNative(); } catch (_) { native = null; }
  if (!native) {
    showToast('No se pudo cargar el módulo nativo de descargas');
    return null;
  }

  closeReleaseModal();
  showDownloadToastStarted(name);
  const id = createDownloadEntry({
    slug: s, name,
    icon: (proj && proj.icon_url) || '',
    version: rel.version_name || '',
    mode: 'android',
    fileLabel: `APK · ${name}${rel.version_name ? ' v' + rel.version_name : ''}`,
    url: rel.apk_url,
    filename: `ows-${s}.apk`,
  });

  let handle = null;
  try {
    updateDownload(id, { status: 'downloading', note: 'Preparando descarga…' });
    handle = await native.FileTransfer.addListener('progress', (p) => {
      if (!p || p.type !== 'download') return;
      updateDownload(id, {
        status: 'downloading',
        downloaded: Number(p.bytes || 0),
        total: Number(p.contentLength || 0),
        note: 'Descargando APK…',
      });
    });
    const fname = `ows-${s}-${String(rel.version_name || 'latest').replace(/[^\w.-]+/g, '_')}.apk`;
    const diag = [];
    let savedPath = '';
    const roots = [['Cache', native.Directory.Cache], ['Data', native.Directory.Data]];
    for (let r = 0; r < roots.length && !savedPath; r++) {
      const rootName = roots[r][0];
      const rootDir = roots[r][1];
      let fileUri = '';
      try {
        try { await native.Filesystem.mkdir({ path: 'owshub-apk', directory: rootDir, recursive: true }); } catch (_) {}
        const uriRes = await native.Filesystem.getUri({ directory: rootDir, path: 'owshub-apk/' + fname });
        fileUri = String((uriRes && uriRes.uri) || '');
        if (!fileUri) throw new Error('no se pudo resolver la ruta de descarga');
      } catch (pathErr) {
        diag.push(`[${rootName}] ruta: ${describeNativeError(pathErr)}`);
        continue;
      }
      const plain = nativeFilePath(fileUri);
      const forms = [fileUri, plain].filter((v, i, a) => v && a.indexOf(v) === i);
      for (let f = 0; f < forms.length && !savedPath; f++) {
        try {
          await native.Filesystem.deleteFile({ path: 'owshub-apk/' + fname, directory: rootDir });
        } catch (_) {}
        try {
          updateDownload(id, { status: 'downloading', downloaded: 0, note: 'Descargando APK…' });
          await native.FileTransfer.downloadFile({ url: rel.apk_url, path: forms[f], progress: true });
          savedPath = plain;
        } catch (dlErr) {
          diag.push(`[${rootName} ${forms[f] === fileUri ? 'uri' : 'ruta'}] descarga: ${describeNativeError(dlErr)}`);
        }
      }
    }
    if (!savedPath) {
      const detail = diag.join('\n');
      throw Object.assign(new Error('no se pudo guardar el APK'), { owsDetail: detail });
    }

    updateDownload(id, { status: 'completed', pct: 100, completedAt: new Date().toISOString(), note: 'APK listo · abriendo instalador' });
    const openDiag = [];
    let opened = false;
    const openForms = [savedPath, 'file://' + savedPath];
    for (let o = 0; o < openForms.length && !opened; o++) {
      try {
        await native.FileOpener.open({
          filePath: openForms[o],
          contentType: 'application/vnd.android.package-archive',
          openWithDefault: true,
        });
        opened = true;
      } catch (openErr) {
        openDiag.push(`[abrir ${o === 0 ? 'ruta' : 'uri'}] ${describeNativeError(openErr)}`);
      }
    }
    if (opened) {
      showToast(`APK de ${name} listo · confirmá la instalación 📲`);
    } else {
      const detail = openDiag.join('\n') + '\n' + savedPath;
      updateDownload(id, { note: 'APK descargado, pero no se pudo abrir el instalador' });
      showErrorDialog('No se pudo abrir el instalador', 'El APK se descargó pero Android no permitió abrirlo desde la app.', detail, {
        label: 'Descargar desde el navegador',
        run: () => openApkInBrowser(rel.apk_url),
      });
    }
  } catch (err) {
    const base = String((err && (err.message || err.error)) || err);
    const detail = (err && err.owsDetail) || describeNativeError(err);
    updateDownload(id, { status: 'error', error: base + (detail ? ' · ' + detail.split('\n')[0] : '') });
    showToast('Falló la descarga del APK · mirá el detalle en pantalla');
    showErrorDialog('Falló la descarga del APK', base, detail, {
      label: 'Descargar desde el navegador',
      run: () => openApkInBrowser(rel.apk_url),
    });
  } finally {
    try { if (handle && typeof handle.remove === 'function') await handle.remove(); } catch (_) {}
  }
  return id;
}

// Desinstalar desde la propia OWS Hub: borra la carpeta del juego de la
// biblioteca y lo quita del registro local. Confirmación en dos toques para no
// perder nada por un clic de más (borrar no tiene vuelta atrás).
async function runUninstall(btn, slug, displayName) {
  if (!window.OWSHubLibrary || owsEnvironment() !== 'desktop') {
    showToast('Desinstalar solo está disponible en la app OWS Hub 🖥');
    return;
  }
  const name = displayName || slug;

  if (btn.dataset.uninstallArmed !== '1') {
    // Estado "fuerza" (tras un fallo previo): el siguiente clic borra ya sin preguntar.
    if (btn.dataset.uninstallArmed === 'force' && typeof btn._uninstallForce === 'function') {
      btn._uninstallForce();
      return;
    }
    btn.dataset.uninstallArmed = '1';
    btn.textContent = '⚠ ¿Seguro? Se borrará del disco';
    btn.classList.add('is-armed');
    clearTimeout(btn._uninstallTimer);
    btn._uninstallTimer = setTimeout(() => {
      btn.dataset.uninstallArmed = '0';
      btn.classList.remove('is-armed');
      btn.textContent = '🗑 Desinstalar';
    }, 5000);
    return;
  }

  clearTimeout(btn._uninstallTimer);
  btn.dataset.uninstallArmed = '0';
  btn.classList.remove('is-armed');
  btn.disabled = true;
  btn.textContent = '🗑 Borrando…';

  try {
    const res = await window.OWSHubLibrary.uninstall(slug, (e) => {
      if (e && e.type === 'error') showToast('No se pudo desinstalar: ' + e.error);
    });
    const freed = Number(res && res.bytes) || 0;
    const parked = res && res.deleted === false;
    showToast(parked
      ? `${name} desinstalado${freed ? ` · ${formatMB(freed)}` : ''} · la carpeta se borrará al reiniciar el Hub 🗑`
      : `${name} desinstalado${freed ? ` · ${formatMB(freed)} liberados` : ''} 🗑`);
    // El modal ya no tiene sentido: se cierra y el Gestor se repinta.
    closeReleaseModal();
    renderDownloads();
  } catch (err) {
    const msg = String((err && err.message) || err);
    showToast('No se pudo desinstalar: ' + msg);
    btn.disabled = false;
    btn.textContent = '🧹 Desinstalar igual (solo quitar de la biblioteca)';
    btn.classList.add('is-armed');
    btn.dataset.uninstallArmed = 'force';
    btn._uninstallForce = async () => {
      clearTimeout(btn._uninstallTimer);
      btn._uninstallForce = null;
      btn.disabled = true;
      btn.textContent = '🗑 Borrando…';
      try {
        const res = await window.OWSHubLibrary.forget(slug);
        showToast(`${name} quitado de la biblioteca${res ? ' · carpeta borrada' : ''} 🧹`);
        closeReleaseModal();
        renderDownloads();
      } catch (err2) {
        showToast(String((err2 && err2.message) || err2));
        btn.disabled = false;
        btn.textContent = '🗑 Desinstalar';
        btn.classList.remove('is-armed');
      }
    };
  }
}

// Desktop (Tauri): instalar con progreso reflejado en el Gestor de Descargas.
async function startDesktopInstallManaged(slug, remoteVersion, displayName) {
  const proj = getDownloadProject(slug);
  const name = displayName || (proj && proj.name) || slug;
  const id = createDownloadEntry({
    slug, name,
    icon: (proj && proj.icon_url) || '',
    version: remoteVersion || (proj && (proj.itch_version || proj.itchVersion)) || '',
    mode: 'desktop',
  });
  // No se cambia de sección a la fuerza: si el usuario está en otra vista
  // ve el toaster de arriba con el progreso; el badge del menú marca el curso.
  const onEvent = (e) => {
    try { window.OWSHubInstallProgress && window.OWSHubInstallProgress(e); } catch (_) {}
    pushHubEventToManager(id, e);
    if (e && e.type === 'done' && !e.fallback) {
      showToast(`¡${name} instalado y en ejecución! 🎮`);
      // La versión local cambió: el Gestor de Actualizaciones y su badge
      // tienen que volver a calcular si queda algo pendiente.
      try { loadUpdatesManager({ force: true }); } catch (_) {}
    } else if (e && e.type === 'error') {
      showToast('Falló la instalación: ' + (e.error || 'error desconocido'));
    }
  };
  try {
    // opts.version: el Gestor de Actualizaciones ya sabe cuál es la versión
    // oficial publicada; se pasa explícita para que el registro local no
    // quede en la versión vieja de itch.io (eso hacía que el juego pidiera
    // actualizarse para siempre).
    await window.OWSHubLibrary.downloadAndInstall(slug, onEvent, { version });
  } catch (_) { /* error ya reflejado en el Gestor */ }
}

// Descarga el ZIP real en el navegador mostrando % y MB en el Gestor.
// Al terminar dispara el "Guardar como" sin salir de la página.
async function downloadBrowserWithProgress(btn, slug) {
  // Compat: si algún botón viejo lo llama directo, delega al Gestor.
  const proj = getDownloadProject(slug);
  closeReleaseModal();
  showDownloadToastStarted((proj && proj.name) || slug);
  return startBrowserDownloadManaged(slug);
}

async function startBrowserDownloadManaged(slug, opts) {
  // Regla del ecosistema: en el navegador NO se pueden continuar las descargas.
  // Hay que instalar OWS Hub (el panel del menú lateral ofrece el instalador).
  if (hubIsRequired()) {
    showToast('Instala OWS Hub para poder descargar ⬇ (panel del menú lateral)');
    showOwsSection('sec-descargas', { smooth: true });
    return null;
  }
  const proj = getDownloadProject(slug);
  const s = String(slug || '').trim() || 'juego';
  const name = (proj && proj.name) || s;
  const url = (opts && opts.url) || `${API_BASE}/ows-launch-projects/${encodeURIComponent(s)}/download`;
  // Lo que se baja es el ZIP (el .exe va dentro): el nombre real lo manda
  // el servidor, acá solo se usa de suggestion si no hay dato.
  const projArt = releaseArtifact(proj, null);
  const filename = (opts && opts.filename)
    || (projArt.file && projArt.isZip ? projArt.file : `${s}.zip`);
  const id = (opts && opts.reuseId) || createDownloadEntry({
    slug: s, name,
    icon: (proj && proj.icon_url) || '',
    version: (proj && (proj.itch_version || proj.itchVersion)) || '',
    fileLabel: (projArt.file || (proj && (proj.itch_file || proj.itchFile)) || `${s}.zip`),
    url, filename, mode: 'browser',
  });
  const ctrl = new AbortController();
  dlControllers.set(id, ctrl);
  updateDownload(id, { status: 'downloading', downloaded: 0, total: 0, pct: 0, error: '' });
  const emit = (e) => {
    try { window.OWSHubInstallProgress && window.OWSHubInstallProgress(e); } catch (_) {}
    pushHubEventToManager(id, e);
  };
  try {
    emit({ type: 'status', phase: 'downloading' });
    const res = await fetch(url, { method: 'GET', signal: ctrl.signal });
    if (!res.ok) throw new Error(`servidor respondió ${res.status}`);
    if (!res.body || typeof res.body.getReader !== 'function') {
      window.open(url, '_blank', 'noopener');
      updateDownload(id, { status: 'completed', pct: 100, completedAt: new Date().toISOString(), note: 'Abierta en pestaña nueva' });
      emit({ type: 'done', fallback: true });
      showToast('Descarga abierta en pestaña nueva ⬇');
      return id;
    }
    const total = Number(res.headers.get('Content-Length') || 0) || 0;
    updateDownload(id, { total });
    const reader = res.body.getReader();
    const chunks = [];
    let downloaded = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        chunks.push(value);
        downloaded += value.length || value.byteLength || 0;
        updateDownload(id, { downloaded, total, pct: total > 0 ? Math.round((downloaded / total) * 100) : 0 });
        emit({ type: 'progress', phase: 'downloading', downloaded, total });
      }
    }
    const blob = new Blob(chunks, { type: 'application/zip' });
    const blobUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = blobUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { try { a.remove(); } catch (_) {} }, 1000);
    setTimeout(() => { try { URL.revokeObjectURL(blobUrl); } catch (_) {} }, 60000);
    updateDownload(id, {
      status: 'completed', pct: 100, downloaded: downloaded || blob.size || downloaded,
      total: total || blob.size || total, completedAt: new Date().toISOString(),
    });
    emit({ type: 'done', browserDownload: true, filename });
    showToast(`¡${name} descargado! Extrae el ZIP y abre el .exe 🎮`);
    try { persistDownloadsHistory(); } catch (_) {}
  } catch (err) {
    const isAbort = err && (err.name === 'AbortError' || /abort/i.test(String(err.message || '')));
    if (isAbort) {
      updateDownload(id, { status: 'cancelled', error: 'Cancelada por el usuario' });
    } else {
      const msg = String((err && err.message) || err || 'descarga fallida');
      updateDownload(id, { status: 'error', error: msg });
      emit({ type: 'error', error: msg });
      showToast('No se pudo descargar: ' + msg);
    }
  } finally {
    dlControllers.delete(id);
  }
  return id;
}

function closeReleaseModal() {
  const modal = document.getElementById('release-modal');
  if (!modal || modal.classList.contains('hidden') || modal.classList.contains('is-closing')) return;
  modal.classList.add('is-closing');
  rdCloseTimer = window.setTimeout(() => {
    rdCloseTimer = 0;
    modal.classList.add('hidden');
    modal.classList.remove('is-closing');
    document.body.style.overflow = '';
    const card = modal.querySelector('.release-modal-card');
    if (card) card.scrollTop = 0;
  }, 200);
}

// ═══════════════════════════════════════════════
// GESTOR DE DESCARGAS — estado + render + historial
// ═══════════════════════════════════════════════

const DL_HISTORY_KEY = 'ows_downloads_history_v1';
let downloadsState = []; // [{id, slug, name, icon, version, fileLabel, url, filename, mode, status, downloaded, total, pct, speed, error, note, startedAt, completedAt}]
const dlControllers = new Map();
const DL_ACTIVE_STATUSES = ['downloading', 'extracting', 'searching', 'launching'];
let dlListSig = '';

function dlIsActive(d) {
  return !!d && DL_ACTIVE_STATUSES.includes(d.status);
}

function dlId() {
  return 'dl_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 7);
}

function formatMB(bytes) {
  const n = Number(bytes || 0);
  if (!n || n <= 0) return '0 MB';
  if (n < 1048576) return `${Math.max(1, Math.round(n / 1024))} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(n >= 104857600 ? 0 : 1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}

// Velocidad media móvil (bytes/s) para la barra y el toaster.
function formatSpeed(bytesPerSecond) {
  const n = Number(bytesPerSecond || 0);
  if (!Number.isFinite(n) || n <= 0) return '';
  return `${formatMB(n)}/s`;
}

// Tiempo restante estimado: null si no hay velocidad o total.
function dlEta(d) {
  const speed = Number(d && d.speed || 0);
  const total = Number(d && d.total || 0);
  const got = Number(d && d.downloaded || 0);
  if (speed <= 0 || total <= 0 || got >= total) return null;
  const secs = Math.round((total - got) / speed);
  if (!Number.isFinite(secs) || secs <= 0) return null;
  if (secs < 60) return `faltan ~${secs} s`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `faltan ~${mins} min`;
  return `faltan ~${Math.round(mins / 60)} h`;
}

function formatDlTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleString('es-ES', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
}

function initDownloadsManager() {
  try {
    const raw = localStorage.getItem(DL_HISTORY_KEY);
    const hist = raw ? JSON.parse(raw) : [];
    if (Array.isArray(hist)) {
      // El historial guardado siempre entra como completado/error (nunca "downloading" fantasma)
      downloadsState = hist.slice(0, 12).map((h) => ({
        ...h,
        status: h.status === 'downloading' ? 'cancelled' : h.status,
        error: h.status === 'downloading' ? 'Interrumpida (sesión anterior)' : (h.error || ''),
        speed: 0,
      }));
    }
  } catch (_) { downloadsState = []; }
  renderDownloads();
}

function persistDownloadsHistory() {
  try {
    const hist = downloadsState
      .filter((d) => ['completed', 'error', 'cancelled'].includes(d.status))
      .slice(0, 12);
    localStorage.setItem(DL_HISTORY_KEY, JSON.stringify(hist));
  } catch (_) {}
}

function createDownloadEntry(meta) {
  const entry = {
    id: dlId(),
    slug: meta.slug || 'juego',
    name: meta.name || meta.slug || 'Juego',
    icon: meta.icon || '',
    version: meta.version || '',
    fileLabel: meta.fileLabel || '',
    url: meta.url || '',
    filename: meta.filename || `${meta.slug || 'juego'}.zip`,
    mode: meta.mode || 'browser',
    status: 'downloading',
    downloaded: 0, total: 0, pct: 0, speed: 0,
    error: '', note: '',
    startedAt: new Date().toISOString(), completedAt: '',
    _t: 0, _b: 0, _etaAt: 0, _etaTxt: '',
  };
  downloadsState.unshift(entry);
  downloadsState = downloadsState.slice(0, 20);
  renderDownloads();
  return entry.id;
}

function updateDownload(id, patch) {
  const idx = downloadsState.findIndex((d) => String(d.id) === String(id));
  if (idx < 0) return;
  const prev = downloadsState[idx];
  const next = { ...prev, ...(patch || {}) };

  // Velocidad: media móvil entre ticks (suaviza los picos de la red)
  if (patch && Number.isFinite(Number(patch.downloaded))) {
    const bytes = Number(patch.downloaded) || 0;
    const now = Date.now();
    const lastT = Number(prev._t || 0);
    const lastB = Number(prev._b || 0);
    if (lastT && now > lastT) {
      const inst = ((bytes - lastB) * 1000) / (now - lastT);
      if (inst > 0) next.speed = prev.speed > 0 ? (prev.speed * 0.65 + inst * 0.35) : inst;
    }
    next._t = now;
    next._b = bytes;
    // Sin Content-Length: el % no se puede calcular hasta el final
    if (Number(next.total || 0) > 0) next.pct = Math.max(0, Math.min(100, Math.round((bytes / next.total) * 100)));
  }
  // Fase nueva (extraer/localizar/abrir) o fin: la velocidad deja de aplicar
  if (patch && patch.status && patch.status !== 'downloading') next.speed = 0;

  downloadsState[idx] = next;
  renderDownloads();
  if (['completed', 'error', 'cancelled'].includes(next.status)) {
    try { persistDownloadsHistory(); } catch (_) {}
  }
}

function pushHubEventToManager(id, e) {
  if (!e || !id) return;
  if (e.type === 'status') {
    if (e.phase === 'downloading') updateDownload(id, { status: 'downloading' });
    else if (e.phase === 'extracting') updateDownload(id, { status: 'extracting', pct: 100 });
    else if (e.phase === 'searching') updateDownload(id, { status: 'searching', pct: 100 });
    else if (e.phase === 'launching') updateDownload(id, { status: 'launching', pct: 100 });
  } else if (e.type === 'progress') {
    const dl = Number(e.downloaded || 0), tot = Number(e.total || 0);
    updateDownload(id, { status: 'downloading', downloaded: dl, total: tot, pct: tot > 0 ? Math.round((dl / tot) * 100) : 0 });
  } else if (e.type === 'done') {
    if (e.fallback || e.browserDownload) return; // el flujo browser ya marcó completed
    updateDownload(id, { status: 'completed', pct: 100, completedAt: new Date().toISOString() });
  } else if (e.type === 'error') {
    updateDownload(id, { status: 'error', error: String(e.error || 'error desconocido') });
  }
}

function dlStatusMeta(status) {
  if (status === 'downloading') return { label: 'Descargando', cls: 'dl-badge-downloading', icon: '⬇' };
  if (status === 'extracting') return { label: 'Extrayendo', cls: 'dl-badge-working', icon: '📦' };
  if (status === 'searching') return { label: 'Localizando juego', cls: 'dl-badge-working', icon: '🔍' };
  if (status === 'launching') return { label: 'Abriendo juego', cls: 'dl-badge-working', icon: '🚀' };
  if (status === 'completed') return { label: 'Completada', cls: 'dl-badge-done', icon: '✓' };
  if (status === 'cancelled') return { label: 'Cancelada', cls: 'dl-badge-cancelled', icon: '✕' };
  return { label: 'Error', cls: 'dl-badge-error', icon: '⚠' };
}

// Fases del install del Hub (desktop): descarga → extrae → busca → abre.
const DL_STEPS = [
  { key: 'downloading', label: 'Descarga' },
  { key: 'extracting', label: 'Extraer' },
  { key: 'searching', label: 'Localizar' },
  { key: 'launching', label: 'Abrir' },
];

function dlStepsHtml(d) {
  // Solo en desktop: el navegador no extrae ni busca el .exe.
  if (d.mode !== 'desktop') return '';
  const at = DL_STEPS.findIndex((s) => s.key === d.status);
  if (at < 0) {
    // Ya terminó: todos los pasos quedan hechos
    if (d.status === 'completed') {
      return `<ol class="dl-steps">` + DL_STEPS.map((s) => `<li class="dl-step is-done"><i>✓</i>${escapeHtml(s.label)}</li>`).join('') + `</ol>`;
    }
    return '';
  }
  return `<ol class="dl-steps">` + DL_STEPS.map((s, i) => {
    const cls = i < at ? 'is-done' : (i === at ? 'is-now' : '');
    const mark = i < at ? '✓' : (i === at ? '●' : String(i + 1));
    return `<li class="dl-step ${cls}"><i>${mark}</i>${escapeHtml(s.label)}</li>`;
  }).join('') + `</ol>`;
}

// Anillo de progreso alrededor del icono (solo mientras está en curso).
function dlRingHtml(d, pct) {
  if (!dlIsActive(d)) return '';
  const r = 45;
  const c = 2 * Math.PI * r;
  const off = c * (1 - Math.max(0, Math.min(100, pct)) / 100);
  return `
    <svg class="dl-ring" viewBox="0 0 100 100" aria-hidden="true">
      <circle class="dl-ring-bg" cx="50" cy="50" r="${r}"></circle>
      <circle class="dl-ring-fg" cx="50" cy="50" r="${r}" style="stroke-dasharray:${c.toFixed(1)};stroke-dashoffset:${off.toFixed(1)}"></circle>
    </svg>`;
}

// ETA: se recalcula en cada tick, pero SOLO se pinta cada pocos segundos.
// Si no, "faltan ~1 min" alterna con "faltan ~59 s" en cada chunk y el
// texto tiembla al ritmo de los bytes.
const DL_ETA_MIN_INTERVAL_MS = 5000;
function dlEtaText(d) {
  const txt = dlEta(d);
  const lastTxt = String(d._etaTxt || '');
  if (txt === lastTxt) return txt;
  const now = Date.now();
  const last = Number(d._etaAt || 0);
  if (last && now - last < DL_ETA_MIN_INTERVAL_MS) return lastTxt;
  d._etaAt = now;
  d._etaTxt = txt;
  return txt;
}

function dlMetaHtml(d) {
  const isFinished = ['completed', 'error', 'cancelled'].includes(d.status);
  const size = d.total > 0
    ? `${escapeHtml(formatMB(d.downloaded))} / ${escapeHtml(formatMB(d.total))}`
    : (d.downloaded > 0 ? `${escapeHtml(formatMB(d.downloaded))} descargados` : '');
  const speed = (!isFinished && d.speed > 0) ? escapeHtml(formatSpeed(d.speed)) : '';
  const eta = (!isFinished && d.total > 0) ? escapeHtml(dlEtaText(d)) : '';
  // Cada dato va en su propio span con ancho reservado: si no, el número
  // que cambia empuja al de al lado y la línea "vibra" en cada chunk.
  return `
    <span class="dl-meta">
      <span class="dl-meta-when">${escapeHtml(formatDlTime(d.completedAt || d.startedAt))}</span>
      <span class="dl-meta-size">${isFinished || d.total > 0 ? size : ''}</span>
      <span class="dl-meta-speed">${speed}</span>
      <span class="dl-meta-eta">${eta}</span>
    </span>`;
}

// Refresco en sitio: si la estructura no cambió (mismo id/status/orden),
// solo se tocan los números. Evita repintar toda la tarjeta en cada chunk
// (era lo que hacía temblar el texto y perder el foco/hover).
const dlWritten = new Map(); // id -> { size, speed, eta, pct, sub }
function patchDownloadsDom(items) {
  const r = 45;
  const circ = 2 * Math.PI * r;
  items.forEach((d) => {
    const card = document.querySelector(`[data-dl-card="${String(d.id).replace(/"/g, '\\"')}"]`);
    if (!card) return;
    const isActive = dlIsActive(d);
    const pct = d.status === 'completed' ? 100 : Math.max(0, Math.min(100, Number(d.pct || 0)));
    const isFinished = ['completed', 'error', 'cancelled'].includes(d.status);
    const size = d.total > 0
      ? `${formatMB(d.downloaded)} / ${formatMB(d.total)}`
      : (d.downloaded > 0 ? `${formatMB(d.downloaded)} descargados` : '');
    const speed = (!isFinished && d.speed > 0) ? formatSpeed(d.speed) : '';
    const eta = (!isFinished && d.total > 0) ? dlEtaText(d) : '';
    const prev = dlWritten.get(d.id) || {};
    const next = { size, speed, eta, pct };
    const changed = prev.size !== size || prev.speed !== speed || prev.eta !== eta || prev.pct !== pct;
    if (changed) dlWritten.set(d.id, next);

    if (prev.pct !== pct) {
      const fill = card.querySelector('[data-dl-fill]');
      if (fill) fill.style.width = pct + '%';
      const ring = card.querySelector('.dl-ring-fg');
      if (ring) ring.setAttribute('style', `stroke-dasharray:${circ.toFixed(1)};stroke-dashoffset:${(circ * (1 - pct / 100)).toFixed(1)}`);
      const pctEl = card.querySelector('[data-dl-pct]');
      if (pctEl) pctEl.textContent = `${Math.round(pct)}%`;
      const wrap = card.querySelector('[data-dl-barwrap]');
      if (wrap) wrap.setAttribute('aria-valuenow', String(Math.round(pct)));
    }
    if (!changed) return;
    const set = (sel, txt) => { const el = card.querySelector(sel); if (el && el.textContent !== txt) el.textContent = txt; };
    set('.dl-meta-size', (isFinished || d.total > 0) ? size : '');
    set('.dl-meta-speed', speed);
    set('.dl-meta-eta', eta);
    // La línea principal (MB) cambia seguido, pero es un bloque propio:
    // actualizarla no mueve nada de al lado.
    const sub = card.querySelector('[data-dl-sub]');
    if (sub && isActive && d.status === 'downloading' && d.total > 0) {
      const html = `<b>${escapeHtml(formatMB(d.downloaded))}</b> de ${escapeHtml(formatMB(d.total))}`;
      if (sub.innerHTML !== html) sub.innerHTML = html;
    }
  });
}

// Solo se puede desinstalar desde el Gestor si el Hub lo instaló de verdad
// (modo desktop) y el juego sigue registrado en la biblioteca local.
function dlCanUninstall(d) {
  if (!d || d.mode !== 'desktop' || d.status !== 'completed') return false;
  if (!window.OWSHubLibrary || owsEnvironment() !== 'desktop') return false;
  const inst = window.OWSHubLibrary.installed(d.slug);
  return !!(inst && inst.dir);
}

function dlCardHtml(d) {
  const meta = dlStatusMeta(d.status);
  const isActive = dlIsActive(d);
  const pct = Math.max(0, Math.min(100, Number(d.pct || 0)));
  const iconHtml = d.icon
    ? `<img src="${escapeHtml(d.icon)}" alt="${escapeHtml(d.name)}" class="dl-icon" loading="lazy" onerror="this.remove()" />`
    : `<div class="dl-icon dl-icon-fallback">🎮</div>`;

  let sub = '';
  if (d.status === 'completed') {
    sub = `Guardado como <b>${escapeHtml(d.filename || (d.slug + '.zip'))}</b>`;
  } else if (d.status === 'error') {
    sub = escapeHtml(d.error || 'Falló la descarga');
  } else if (d.status === 'cancelled') {
    sub = escapeHtml(d.error || 'Cancelada');
  } else if (d.status === 'extracting') {
    sub = 'Extrayendo todos los archivos del ZIP…';
  } else if (d.status === 'searching') {
    sub = 'Localizando el ejecutable del juego…';
  } else if (d.status === 'launching') {
    sub = 'Abriendo el juego…';
  } else if (d.total > 0) {
    sub = `<b>${escapeHtml(formatMB(d.downloaded))}</b> de ${escapeHtml(formatMB(d.total))}`;
  } else {
    sub = 'Conectando con itch.io…';
  }

  const barExtra = d.status === 'completed' ? ' dl-bar-done' : (d.status === 'error' ? ' dl-bar-error' : (d.status === 'cancelled' ? ' dl-bar-cancel' : ''));
  return `
    <article class="dl-card ${isActive ? 'dl-card-active' : ''} dl-card-${escapeHtml(d.status)}" data-dl-card="${escapeHtml(d.id)}">
      <div class="dl-thumb">
        ${iconHtml}
        ${dlRingHtml(d, pct)}
        ${isActive ? '' : `<span class="dl-thumb-state ${meta.cls}">${meta.icon}</span>`}
      </div>
      <div class="dl-main">
        <div class="dl-top">
          <h4 class="dl-name">${escapeHtml(d.name)}</h4>
          ${d.version ? `<span class="dl-version">v${escapeHtml(d.version)}</span>` : ''}
          <span class="dl-badge ${meta.cls}">${meta.icon} ${escapeHtml(meta.label)}</span>
        </div>
        <p class="dl-sub" data-dl-sub>${sub}</p>
        ${dlStepsHtml(d)}
        <div class="dl-bar-row">
          <div class="dl-progress" data-dl-barwrap role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${d.status === 'completed' ? 100 : Math.round(pct)}" aria-label="${escapeHtml(d.name)}">
            <div class="dl-progress-fill${barExtra}" data-dl-fill style="width:${d.status === 'completed' ? 100 : pct}%"></div>
            ${isActive ? '<div class="dl-progress-shine"></div>' : ''}
          </div>
          ${isActive ? `<span class="dl-pct" data-dl-pct>${Math.round(pct)}%</span>` : ''}
        </div>
        <div class="dl-foot">
          ${dlMetaHtml(d)}
          <span class="dl-actions">
            ${d.status === 'downloading' && d.mode !== 'android' ? `<button class="btn btn-ghost btn-sm dl-btn" type="button" data-dl-action="cancel" data-dl-id="${escapeHtml(d.id)}">Cancelar</button>` : ''}
            ${d.status === 'downloading' && d.mode === 'android' ? `<span class="dl-badge dl-badge-downloading">APK nativo</span>` : ''}
            ${(d.status === 'error' || d.status === 'cancelled') ? `<button class="btn btn-primary btn-sm dl-btn" type="button" data-dl-action="retry" data-dl-id="${escapeHtml(d.id)}">↻ Reintentar</button>` : ''}
            ${dlCanUninstall(d) ? `<button class="btn btn-danger btn-sm dl-btn" type="button" data-dl-action="uninstall" data-dl-id="${escapeHtml(d.id)}">🗑 Desinstalar</button>` : ''}
            ${(d.status === 'completed' || d.status === 'error' || d.status === 'cancelled') ? `<button class="btn btn-ghost btn-sm dl-btn dl-btn-quiet" type="button" data-dl-action="dismiss" data-dl-id="${escapeHtml(d.id)}">Quitar</button>` : ''}
          </span>
        </div>
      </div>
    </article>`;
}

function renderDownloadsSummary(items, active) {
  const box = document.getElementById('dl-summary');
  if (!box) return;
  const done = items.filter((d) => d.status === 'completed').length;
  const weight = items.reduce((acc, d) => acc + (Number(d.downloaded) || 0), 0);
  const speed = items.reduce((acc, d) => acc + (dlIsActive(d) ? (Number(d.speed) || 0) : 0), 0);
  box.classList.toggle('hidden', items.length === 0);
  const set = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
  set('dl-stat-active', String(active));
  set('dl-stat-done', String(done));
  set('dl-stat-size', weight > 0 ? formatMB(weight) : '0 MB');
  set('dl-stat-speed', formatSpeed(speed) || '—');
  box.classList.toggle('is-idle', active === 0);
}

function renderDownloads() {
  const list = document.getElementById('downloads-list');
  const empty = document.getElementById('downloads-empty');
  const count = document.getElementById('downloads-count');
  const clearBtn = document.getElementById('btn-clear-downloads');
  const badge = document.getElementById('nav-dl-badge');
  const statDl = document.getElementById('stat-downloads');
  syncDlToaster();
  if (!list || !empty) return;

  const items = Array.isArray(downloadsState) ? downloadsState : [];
  const activeItems = items.filter(dlIsActive);
  const active = activeItems.length;

  renderDownloadsSummary(items, active);
  if (statDl) statDl.textContent = items.filter((d) => d.status === 'completed').length;
  if (badge) {
    if (active > 0) { badge.textContent = active; badge.classList.remove('hidden'); }
    else badge.classList.add('hidden');
  }
  const badgeM = document.getElementById('nav-dl-badge-m');
  if (badgeM) {
    if (active > 0) { badgeM.textContent = active; badgeM.classList.remove('hidden'); }
    else badgeM.classList.add('hidden');
  }
  if (count) {
    count.textContent = items.length === 0
      ? 'Sin descargas'
      : `${items.length} ${items.length === 1 ? 'descarga' : 'descargas'}${active > 0 ? ` · ${active} en curso` : ''}`;
  }
  if (clearBtn) {
    const hasFinished = items.some((d) => ['completed', 'error', 'cancelled'].includes(d.status));
    clearBtn.classList.toggle('hidden', !hasFinished);
  }

  if (items.length === 0) {
    list.innerHTML = '';
    empty.classList.remove('hidden');
    dlListSig = '';
    dlWritten.clear();
    return;
  }
  empty.classList.add('hidden');

  // Firma estructural: si no cambió (mismos ids/status/orden/grupos) solo se
  // actualizan los números en sitio. Sin esto, cada chunk repintaba toda la
  // lista y los textos inline se movían entre sí.
  const sig = items.map((d) => `${d.id}~${d.status}~${d.mode}~${d.total}`).join('|') + `#${activeItems.length}`;
  if (sig === dlListSig) {
    patchDownloadsDom(items);
    return;
  }
  dlListSig = sig;
  dlWritten.clear();

  // Dos grupos: lo que está pasando ahora (destacado) y el historial (compacto).
  const history = items.filter((d) => !dlIsActive(d));
  const groups = [];
  if (activeItems.length) {
    groups.push(`
      <section class="dl-group dl-group-live">
        <header class="dl-group-head">
          <span class="dl-group-dot" aria-hidden="true"></span>
          <h4 class="dl-group-title">En curso</h4>
          <span class="dl-group-count">${activeItems.length}</span>
        </header>
        <div class="downloads-list">${activeItems.map(dlCardHtml).join('')}</div>
      </section>`);
  }
  if (history.length) {
    groups.push(`
      <section class="dl-group dl-group-history">
        <header class="dl-group-head">
          <h4 class="dl-group-title">${activeItems.length ? 'Terminadas' : 'Descargas'}</h4>
          <span class="dl-group-count">${history.length}</span>
        </header>
        <div class="downloads-list">${history.map(dlCardHtml).join('')}</div>
      </section>`);
  }
  list.innerHTML = groups.join('');
  // Los valores recién pintados no deben contarse como "cambio" en el
  // siguiente tick, así que se siembran desde el propio HTML.
  items.forEach((d) => {
    dlWritten.set(d.id, {
      size: dlMetaSlot(d, 'size'), speed: dlMetaSlot(d, 'speed'), eta: dlMetaSlot(d, 'eta'), pct: NaN
    });
  });
}

// Valor ya pintado de una ranura del pie (para comparar contra el nuevo).
function dlMetaSlot(d, slot) {
  const isFinished = ['completed', 'error', 'cancelled'].includes(d.status);
  if (slot === 'size') {
    if (!isFinished && !(d.total > 0)) return '';
    return d.total > 0 ? `${formatMB(d.downloaded)} / ${formatMB(d.total)}` : `${formatMB(d.downloaded)} descargados`;
  }
  if (slot === 'speed') return (!isFinished && d.speed > 0) ? formatSpeed(d.speed) : '';
  if (slot === 'eta') return (!isFinished && d.total > 0) ? dlEtaText(d) : '';
  return '';
}

// ── Toaster de descargas (ARriba) ────────────────────────────
// Si arrancás una descarga estando en otra sección, el aviso aparece arriba
// con el progreso en vivo. Click = abrir el Gestor. Se oculta solo cuando
// estás en la sección o cuando ya no queda nada en curso.
let dlToasterSig = '';
let dlToasterHideTimer = null;

function syncDlToaster() {
  const box = document.getElementById('dl-toaster');
  if (!box) return;
  const active = (Array.isArray(downloadsState) ? downloadsState : []).filter(dlIsActive);
  const inSection = owsCurrentView === 'sec-descargas';

  if (!active.length) {
    // Aviso de "listo" un instante antes de desaparecer
    const justFinished = box.querySelectorAll('.dl-toast-item');
    if (justFinished.length && !box.classList.contains('hidden')) {
      if (dlToasterHideTimer) return;
      dlToasterHideTimer = setTimeout(() => {
        dlToasterHideTimer = null;
        box.classList.add('hidden');
        box.innerHTML = '';
        dlToasterSig = '';
      }, 2600);
      return;
    }
    box.classList.add('hidden');
    box.innerHTML = '';
    dlToasterSig = '';
    return;
  }

  if (dlToasterHideTimer) { clearTimeout(dlToasterHideTimer); dlToasterHideTimer = null; }
  if (inSection) {
    // Ya está viendo el Gestor: el aviso sobra
    box.classList.add('hidden');
    box.innerHTML = '';
    dlToasterSig = '';
    return;
  }

  // Firma estructural (solo ids + estado): si no cambia, los números se
// parchean en sitio. Repintar el innerHTML en cada chunk/volteaba la
// animación de entrada y corría el borde de la caja en cada tick.
const sig = active.map((d) => `${d.id}:${d.status}`).join('|');
if (sig === dlToasterSig) {
  active.forEach((d) => {
    const item = box.querySelector(`[data-dl-toast="${String(d.id).replace(/"/g, '\\"')}"]`);
    if (!item) return;
    const pct = Math.max(0, Math.min(100, Number(d.pct || 0)));
    const bar = item.querySelector('.dl-toast-bar i');
    if (bar) bar.style.width = pct + '%';
    const info = item.querySelector('.dl-toast-info');
    if (info) {
      const meta = dlStatusMeta(d.status);
      const speed = formatSpeed(d.speed);
      const eta = dlEtaText(d);
      const size = d.total > 0
        ? `${formatMB(d.downloaded)} / ${formatMB(d.total)}`
        : 'Conectando con itch.io…';
      const txt = d.status === 'downloading'
        ? `${size}${speed ? ` · ${speed}` : ''}${eta ? ` · ${eta}` : ''}`
        : meta.label;
      if (info.textContent !== txt) info.textContent = txt;
    }
  });
  return;
}
dlToasterSig = sig;

box.innerHTML = active.map((d) => {
    const meta = dlStatusMeta(d.status);
    const pct = Math.max(0, Math.min(100, Number(d.pct || 0)));
    const speed = formatSpeed(d.speed);
    const eta = dlEtaText(d);
    const iconHtml = d.icon
      ? `<img src="${escapeHtml(d.icon)}" alt="" class="dl-toast-icon" loading="lazy" onerror="this.remove()" />`
      : `<span class="dl-toast-icon dl-toast-icon-fallback">🎮</span>`;
    const info = d.status === 'downloading'
      ? (d.total > 0 ? `${escapeHtml(formatMB(d.downloaded))} / ${escapeHtml(formatMB(d.total))}` : 'Conectando con itch.io…')
      : escapeHtml(meta.label);
    return `
      <div class="dl-toast-item" role="button" tabindex="0" data-dl-toast="${escapeHtml(d.id)}" title="Ver en el Gestor de Descargas">
        <span class="dl-toast-thumb">${iconHtml}</span>
        <span class="dl-toast-body">
          <span class="dl-toast-top">
            <b class="dl-toast-name">${escapeHtml(d.name)}</b>
            <span class="dl-badge ${meta.cls}">${meta.icon} ${escapeHtml(meta.label)}</span>
          </span>
          <span class="dl-toast-info">${info}${speed ? ` · ${escapeHtml(speed)}` : ''}${eta ? ` · ${escapeHtml(eta)}` : ''}</span>
          <span class="dl-toast-bar"><i style="width:${pct}%"></i></span>
        </span>
        <span class="dl-toast-go">Ver</span>
      </div>`;
  }).join('');
  box.classList.remove('hidden');
}

function bindDlToaster() {
  const box = document.getElementById('dl-toaster');
  if (!box || box.dataset.bound) return;
  box.dataset.bound = '1';
  const go = () => { try { scrollToDownloads(); } catch (_) {} };
  box.addEventListener('click', (e) => { if (e.target.closest('[data-dl-toast]')) go(); });
  box.addEventListener('keydown', (e) => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target.closest('[data-dl-toast]')) { e.preventDefault(); go(); }
  });
}

function scrollToDownloads(opts) {
  // Compat: antes hacía scroll; ahora ABRE la vista de Descargas
  showOwsSection('sec-descargas', { smooth: !(opts && opts.smooth === false), flash: true });
}

function cancelDownload(id) {
  const ctrl = dlControllers.get(String(id));
  if (ctrl) {
    try { ctrl.abort(); } catch (_) {}
  } else {
    updateDownload(id, { status: 'cancelled', error: 'Cancelada por el usuario' });
  }
  showToast('Descarga cancelada');
}

function retryDownload(id) {
  const found = downloadsState.find((d) => String(d.id) === String(id));
  if (!found) return;
  // Quita la fallida y arranca una fresca con los mismos datos
  downloadsState = downloadsState.filter((d) => String(d.id) !== String(id));
  renderDownloads();
  showDownloadToastStarted(found.name);
  if (found.mode === 'desktop') {
    startDesktopInstallManaged(found.slug, found.version, found.name);
  } else if (found.mode === 'android') {
    // Canal APK nativo: reutiliza la release ya cacheada y repite el flujo.
    startAndroidApkInstall(found.slug, found.name);
  } else {
    startBrowserDownloadManaged(found.slug, { url: found.url, filename: found.filename });
  }
}

function dismissDownload(id) {
  downloadsState = downloadsState.filter((d) => String(d.id) !== String(id));
  renderDownloads();
  try { persistDownloadsHistory(); } catch (_) {}
}

// Desinstalar desde la tarjeta del Gestor: borra la carpeta del juego de la
// biblioteca del Hub y quita la descarga del historial. Confirmación en dos
// toques, igual que en el modal del juego.
async function uninstallFromManager(btn, id) {
  const found = downloadsState.find((d) => String(d.id) === String(id));
  if (!found || !window.OWSHubLibrary) return;

  if (btn.dataset.uninstallArmed !== '1') {
    btn.dataset.uninstallArmed = '1';
    btn.textContent = '⚠ ¿Seguro?';
    clearTimeout(btn._uninstallTimer);
    btn._uninstallTimer = setTimeout(() => {
      btn.dataset.uninstallArmed = '0';
      btn.textContent = '🗑 Desinstalar';
    }, 5000);
    return;
  }

  clearTimeout(btn._uninstallTimer);
  btn.dataset.uninstallArmed = '0';
  btn.disabled = true;
  btn.textContent = '🗑 Borrando…';

  try {
    const res = await window.OWSHubLibrary.uninstall(found.slug, (e) => {
      if (e && e.type === 'error') showToast('No se pudo desinstalar: ' + e.error);
    });
    const freed = Number(res && res.bytes) || 0;
    dismissDownload(id);
    showToast(`${found.name} desinstalado${freed ? ` · ${formatMB(freed)} liberados` : ''} 🗑`);
  } catch (err) {
    showToast('No se pudo desinstalar: ' + ((err && err.message) || err));
    renderDownloads();
  }
}

function clearCompletedDownloads() {
  downloadsState = downloadsState.filter((d) => ['downloading', 'extracting', 'searching', 'launching'].includes(d.status));
  renderDownloads();
  try { persistDownloadsHistory(); } catch (_) {}
  showToast('Historial de descargas limpio 🧹');
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') { closeNewsModal(); closeReleaseModal(); closeEventModal(); try { closeAnnounceModal(); } catch (_) {} try { closeReleasesDock(); } catch (_) {} }
});

// ═══════════════════════════════════════════════
// INTRO CINEMÁTICA (GSAP) + SETUP WIZARD
// Flujo: intro → (CTA) → setup 3 pasos → auth
// Settings: localStorage ows_settings_v1 { downloadDir, nick, notifs, autoLaunch, showNews }
// ═══════════════════════════════════════════════

const OWS_SETUP_DONE_KEY = 'ows_setup_done_v1';
const OWS_SETTINGS_KEY   = 'ows_settings_v1';
let owsIntroTimeline = null;
let owsSetupStep = 1;

function defaultDownloadDir() {
  const ua = String(navigator.platform || navigator.userAgent || '').toLowerCase();
  if (/win/.test(ua)) return 'C:\\Juegos\\OWS';
  if (/mac/.test(ua)) return '~/Juegos/OWS';
  return '~/Juegos/OWS';
}

function getOwsSettings() {
  try {
    const raw = localStorage.getItem(OWS_SETTINGS_KEY);
    if (raw) return { downloadDir: defaultDownloadDir(), nick: '', notifs: true, autoLaunch: true, showNews: true, ...JSON.parse(raw) };
  } catch (_) {}
  return { downloadDir: defaultDownloadDir(), nick: '', notifs: true, autoLaunch: true, showNews: true };
}

function saveOwsSettings(patch) {
  const cur = getOwsSettings();
  const next = { ...cur, ...(patch || {}) };
  try { localStorage.setItem(OWS_SETTINGS_KEY, JSON.stringify(next)); } catch (_) {}
  try { window.OWSSettings = next; } catch (_) {}
  return next;
}

function initOwsSettings() {
  try { window.OWSSettings = getOwsSettings(); } catch (_) {}
  // Expone la carpeta elegida a la librería desktop (library.js la lee si existe)
  try {
    window.OWSHub = window.OWSHub || {};
    window.OWSHub.getDownloadDir = () => (getOwsSettings().downloadDir || defaultDownloadDir());
  } catch (_) {}
  // Pre-rellena inputs del setup si ya hay valores
  // (la ruta la decide renderDownloadStep: real en desktop, informativa en navegador)
  try {
    const s = getOwsSettings();
    const nick = document.getElementById('setup-nick');
    if (nick && !nick.value) nick.value = s.nick || '';
    if (s.notifs === false) { const el = document.getElementById('setup-opt-notifs'); if (el) el.checked = false; }
    if (s.autoLaunch === false) { const el = document.getElementById('setup-opt-autolaunch'); if (el) el.checked = false; }
    if (s.showNews === false) { const el = document.getElementById('setup-opt-news'); if (el) el.checked = false; }
  } catch (_) {}
}

function isSetupDone() {
  try { return localStorage.getItem(OWS_SETUP_DONE_KEY) === '1'; } catch (_) { return false; }
}
function markSetupDone() {
  try { localStorage.setItem(OWS_SETUP_DONE_KEY, '1'); } catch (_) {}
}

function applySetupNickToUser() {
  const s = getOwsSettings();
  if (s.nick && currentUser && !currentUser.username) {
    currentUser.username = s.nick;
    try { localStorage.setItem(USER_KEY, JSON.stringify(currentUser)); } catch (_) {}
  }
}

// ── Intro ──

function splitChars(el) {
  if (!el || el.dataset.split === '1') return;
  const text = el.textContent || '';
  el.dataset.split = '1';
  el.setAttribute('aria-label', text);
  el.textContent = '';
  [...text].forEach((ch) => {
    const span = document.createElement('span');
    span.className = 'ch';
    span.textContent = ch === ' ' ? '\u00A0' : ch;
    el.appendChild(span);
  });
}

function hideIntroInstant() {
  const intro = document.getElementById('intro-screen');
  if (intro) intro.classList.add('hidden');
  try { if (owsIntroTimeline) { owsIntroTimeline.kill(); owsIntroTimeline = null; } } catch (_) {}
}

function bindIntroButtons() {
  const skip = document.getElementById('btn-intro-skip');
  if (skip) skip.addEventListener('click', () => finishIntroFast());
  const toSetup = document.getElementById('btn-intro-setup');
  if (toSetup) toSetup.addEventListener('click', () => {
    hideIntroInstant();
    if (isSetupDone()) {
      if (hasOwsSession()) showDashboard();
      else showAuth({ fromSetup: true });
    }
    else showSetup(hasOwsSession() ? 'dashboard' : 'auth');
  });
  const toLogin = document.getElementById('btn-intro-login');
  if (toLogin) toLogin.addEventListener('click', () => {
    hideIntroInstant();
    showAuth({ fromSetup: false });
  });
  const replay = document.getElementById('btn-intro-replay');
  if (replay) replay.addEventListener('click', () => runIntroSequence());
}

function finishIntroFast() {
  // Salta la cinemática y muestra el CTA final
  try { if (owsIntroTimeline) { owsIntroTimeline.progress(1); } } catch (_) {}
  showIntroCta();
}

function showIntroCta() {
  const cta = document.getElementById('intro-cta');
  const prog = document.getElementById('intro-progress-wrap');
  const skip = document.getElementById('btn-intro-skip');
  if (prog) prog.classList.add('hidden');
  if (skip) skip.classList.add('hidden');
  if (!cta) return;
  cta.classList.remove('hidden');
  // Personaliza CTA según setup pendiente o no
  const btnSetup = document.getElementById('btn-intro-setup');
  if (btnSetup) btnSetup.textContent = isSetupDone() ? '🚀 Entrar a OWS Hub →' : '⚙ Empezar setup →';
  if (window.gsap) {
    try {
      gsap.fromTo(cta, { opacity: 0, y: 24, scale: 0.97 }, { opacity: 1, y: 0, scale: 1, duration: 0.6, ease: 'back.out(1.6)' });
      gsap.fromTo('.intro-cta-row .btn', { opacity: 0, y: 14 }, { opacity: 1, y: 0, duration: 0.45, stagger: 0.1, ease: 'power3.out', delay: 0.1 });
    } catch (_) {}
  }
}

function runIntroSequence() {
  hideSetup();
  const authSec = document.getElementById('auth-section');
  if (authSec) authSec.classList.add('hidden');
  const dashSec = document.getElementById('dashboard-section');
  if (dashSec) dashSec.classList.add('hidden');

  const intro = document.getElementById('intro-screen');
  if (!intro) { showAuth(); return; }
  intro.classList.remove('hidden');
  intro.classList.remove('is-leaving');

  const cta = document.getElementById('intro-cta');
  const prog = document.getElementById('intro-progress-wrap');
  const skip = document.getElementById('btn-intro-skip');
  if (cta) cta.classList.add('hidden');
  if (prog) prog.classList.remove('hidden');
  if (skip) skip.classList.remove('hidden');

  const kicker = document.getElementById('intro-kicker');
  const line1 = document.getElementById('intro-line-1');
  const line2 = document.getElementById('intro-line-2');
  const sub = document.getElementById('intro-sub');
  const feats = document.getElementById('intro-features');
  const fill = document.getElementById('intro-progress-fill');
  const pct = document.getElementById('intro-progress-pct');

  const hubBar = document.getElementById('intro-hub-bar');
  splitChars(line1);
  // "OWS Hub" se parte por palabras para conservar el estilo de cada una
  const introOws = document.getElementById('intro-il-ows');
  const introHubWord = document.getElementById('intro-il-hub');
  if (introOws && introHubWord) { splitChars(introOws); splitChars(introHubWord); }
  else { splitChars(line2); }

  // Fallback sin GSAP: muestra todo y termina en 1.2s
  if (!window.gsap) {
    [kicker, line1, line2, sub, feats].forEach((el) => { if (el) el.style.opacity = '1'; });
    if (hubBar) { hubBar.style.opacity = '1'; hubBar.style.transform = 'none'; }
    if (fill) fill.style.width = '100%';
    if (pct) pct.textContent = '100%';
    setTimeout(showIntroCta, 1200);
    return;
  }

  try { if (owsIntroTimeline) owsIntroTimeline.kill(); } catch (_) {}
  const progressObj = { v: 0 };

  const tl = gsap.timeline({
    defaults: { ease: 'power3.out' },
    onUpdate: () => {
      const p = Math.round((tl.progress() || 0) * 100);
      if (fill) fill.style.width = p + '%';
      if (pct) pct.textContent = p + '%';
    },
    onComplete: () => showIntroCta(),
  });
  owsIntroTimeline = tl;

  tl.set([kicker, sub, feats], { opacity: 0 })
    .set([line1, line2], { opacity: 1 })
    .set('#intro-line-1 .ch', { opacity: 0, y: 34, rotateX: -70 })
    .set('#intro-line-2 .ch', { opacity: 0, y: 90, rotateX: -80, scale: 0.7 })
    .set('.intro-chip', { opacity: 0, y: 14, scale: 0.92 })
    // Kicker
    .to(kicker, { opacity: 1, y: 0, duration: 0.5 })
    .fromTo(kicker, { letterSpacing: '0.6em' }, { letterSpacing: '0.32em', duration: 0.8 }, '<')
    // Línea 1 letra por letra
    .to('#intro-line-1 .ch', { opacity: 1, y: 0, rotateX: 0, duration: 0.5, stagger: 0.028, ease: 'back.out(1.7)' }, '-=0.3')
    // "OWS Hub": entrada grande con rebote + barra de acento
    .to('#intro-line-2 .ch', { opacity: 1, y: 0, rotateX: 0, scale: 1, duration: 0.7, stagger: 0.06, ease: 'back.out(1.6)' }, '-=0.2')
    .fromTo(hubBar, { opacity: 0, scaleX: 0 }, { opacity: 1, scaleX: 1, duration: 0.6, ease: 'power3.out' }, '-=0.25')
    .to(line2, { scale: 1.03, duration: 0.22, ease: 'sine.inOut', yoyo: true, repeat: 1, transformOrigin: '50% 50%' }, '-=0.1')
    // Sub + chips
    .to(sub, { opacity: 1, duration: 0.5 }, '-=0.2')
    .to(feats, { opacity: 1, duration: 0.4 }, '-=0.3')
    .to('.intro-chip', { opacity: 1, y: 0, scale: 1, duration: 0.4, stagger: 0.08, ease: 'back.out(2)' }, '-=0.3')
    // Respiro cinemático + leve zoom del fondo
    .to('.intro-inner', { scale: 1.02, duration: 0.6, ease: 'power1.inOut' }, '+=0.15')
    .to(progressObj, { v: 100, duration: 0.4 }, '<');
}

// ── Setup wizard ──

let owsSetupReturn = 'auth'; // 'auth' | 'dashboard': a dónde volver al terminar/omitir

function hasOwsSession() {
  try {
    return !!(localStorage.getItem(TOKEN_KEY) && currentUser);
  } catch (_) {
    return !!currentUser;
  }
}

function finishSetupDestination(omitido) {
  hideSetup();
  if (owsSetupReturn === 'dashboard' && hasOwsSession()) {
    showDashboard();
    showToast(omitido ? 'Setup omitido — ábrelo con ⚙ cuando quieras' : '¡Setup completo! Todo listo 🎮');
  } else {
    showAuth({ fromSetup: true });
    if (!omitido) {
      const s = getOwsSettings();
      showToast(`¡Todo listo${s.nick ? ', ' + s.nick : ''}! Inicia sesión para entrar 🌟`);
    } else {
      showToast('Setup omitido — puedes completarlo luego ⚙');
    }
  }
}

function bindSetupWizard() {
  const next = document.getElementById('btn-setup-next');
  const back = document.getElementById('btn-setup-back');
  const skipAll = document.getElementById('btn-setup-skipall');
  const browse = document.getElementById('btn-setup-browse');
  if (next) next.addEventListener('click', setupNext);
  if (back) back.addEventListener('click', setupBack);
  if (skipAll) skipAll.addEventListener('click', () => {
    markSetupDone();
    saveOwsSettings({});
    finishSetupDestination(true);
  });
  // Acceso permanente al setup desde el pie del menú lateral
  const openSetup = document.getElementById('btn-open-setup');
  if (openSetup) openSetup.addEventListener('click', () => showSetup('dashboard'));
  // ↺ restaura la carpeta detectada por defecto
  const dirReset = document.getElementById('btn-setup-dir-reset');
  if (dirReset) dirReset.addEventListener('click', () => {
    const input = document.getElementById('setup-download-dir');
    if (input && owsDetectedLibraryDir) {
      input.value = owsDetectedLibraryDir;
      saveOwsSettings({ downloadDir: owsDetectedLibraryDir, downloadMode: 'managed', libraryVerified: true });
      setDirStatus('✓ Biblioteca verificada y lista — puedes modificarla', 'ok');
      hideSetupAlert();
    }
    syncDirResetBtn();
  });
  // Al escribir a mano se marca como personalizada al instante
  const dirInput = document.getElementById('setup-download-dir');
  if (dirInput) dirInput.addEventListener('input', () => {
    if (owsEnvironment() !== 'desktop') return;
    hideSetupAlert();
    const cur = String(dirInput.value || '').trim();
    if (!cur) { setDirStatus('', ''); }
    else if (owsDetectedLibraryDir && cur === owsDetectedLibraryDir) {
      setDirStatus('✓ Biblioteca verificada y lista — puedes modificarla', 'ok');
    } else if (isValidLibraryDir(cur)) {
      setDirStatus('✎ Carpeta personalizada — se usará al instalar', 'ok');
    } else {
      setDirStatus('⚠ Esa ruta no parece válida (ej: C:\\Juegos\\OWS)', 'warn');
    }
    syncDirResetBtn();
  });
  if (browse) browse.addEventListener('click', setupBrowseDir);
  document.querySelectorAll('#setup-dots .setup-dot').forEach((d) => {
    d.addEventListener('click', () => {
      const n = Number(d.getAttribute('data-dot') || '1');
      if (n < owsSetupStep) setupGoToStep(n);
    });
  });
}

// Detecta entorno real: 'desktop' (Tauri, con biblioteca gestionada)
// o 'browser' (el navegador decide dónde cae el ZIP).
// OJO: este proyecto tiene withGlobalTauri desactivado (ver tauri.conf.json),
// así que window.__TAURI__ NO existe en el WebView. Puentes que sí existen:
// 1) window.__TAURI_INTERNALS__ (Tauri v2 siempre lo inyecta)
// 2) window.chrome.webview (WebView2 en Windows)
function isTauriWebview() {
  try {
    if (window.__TAURI__ && window.__TAURI__.core) return true;
    if (window.__TAURI_INTERNALS__ && typeof window.__TAURI_INTERNALS__.invoke === 'function') return true;
    if (window.chrome && window.chrome.webview) return true;
  } catch (_) {}
  return false;
}

function owsEnvironment() {
  try {
    if (window.OWSHub && window.OWSHub.isDesktop) return 'desktop';
    if (isTauriWebview()) return 'desktop';
    if (isAndroidApp()) return 'android';
  } catch (_) {}
  return 'browser';
}

// Plataforma del cliente para el Gestor de Actualizaciones: 'android' solo
// dentro de la app Android, 'windows' en el Hub de escritorio y en el
// navegador (los builds publicados para PC son los del Hub). Todo lo que
// pida versiones manda esta etiqueta: sin ella el backend servía "la última
// release" del repo ows-hub, que puede ser de Android, y se mezclaban.
function owsUpdatesPlatform() {
  return owsEnvironment() === 'android' ? 'android' : 'windows';
}

// Rótulo legible de la plataforma que se está mostrando.
function owsPlatformLabel(platform) {
  return String(platform || '') === 'android' ? 'Android' : 'Windows';
}

// ═══════════════════════════════════════════════════════
// OWS HUB — descarga obligatoria en navegador
// El Hub tiene su propio repo (OceanandWild/ows-hub) donde se publican los
// instaladores; la lectura va por el proxy del servidor
// (/ows-store/github/...) porque api.github.com sin token se come el rate limit
// muy rápido y desde el navegador no hay CORS.
// ═══════════════════════════════════════════════════════
const OWS_HUB_REPO = { owner: 'OceanandWild', repo: 'ows-hub' };
const OWS_HUB_RELEASES_URL = `https://github.com/${OWS_HUB_REPO.owner}/${OWS_HUB_REPO.repo}/releases/latest`;
// Página con TODAS las releases (Windows y Android conviven en el repo):
// sirve cuando hay que llevar al usuario a la otra plataforma.
const OWS_HUB_RELEASES_LIST_URL = `https://github.com/${OWS_HUB_REPO.owner}/${OWS_HUB_REPO.repo}/releases`;
const OWS_HUB_CACHE_KEY = 'ows_hub_release_cache_v1';
const OWS_HUB_CACHE_TTL_MS = 15 * 60 * 1000;
const OWS_HUB_FETCH_TIMEOUT_MS = 12000;

// Caché POR PLATAFORMA: Windows y Android publican releases distintas en el
// mismo repo, así que no pueden compartir la entrada del localStorage.
function owsHubCacheKey() {
  return `${OWS_HUB_CACHE_KEY}_${owsUpdatesPlatform()}`;
}

let owsHubReleasePromise = null;

// Prioridad de assets: instalador de Windows primero, luego portable, luego
// el paquete (.zip/.7z). Cualquier otro archivo se usa solo de último recurso.
// OJO: el repo publica Windows y Android juntos: en Windows NUNCA se elige
// un .apk (y en Android solo sirve el .apk).
function pickOwsHubAsset(assets) {
  const plat = owsUpdatesPlatform();
  const list = (Array.isArray(assets) ? assets : []).filter((a) => {
    if (!a || !a.browser_download_url) return false;
    const n = String(a.name || '').toLowerCase();
    if (plat === 'android') return n.endsWith('.apk');
    return !n.endsWith('.apk');
  });
  if (!list.length) return null;
  const rank = (name) => {
    const n = String(name || '').toLowerCase();
    if (/\.(exe|msi)$/.test(n)) {
      if (/setup|installer|owshub[-_ ]?hub/i.test(n)) return 0;
      return 1;
    }
    if (/\.(zip|7z)$/.test(n)) return 2;
    if (/\.(appx|msix|dmg|deb|rpm|appimage)$/.test(n)) return 3;
    return 9;
  };
  const sorted = [...list].sort((a, b) => {
    const d = rank(a.name) - rank(b.name);
    return d !== 0 ? d : (Number(b.size || 0) - Number(a.size || 0));
  });
  return sorted[0];
}

function readOwsHubCache() {
  try {
    const raw = localStorage.getItem(owsHubCacheKey());
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || !parsed.tag) return null;
    if ((Date.now() - Number(parsed.ts || 0)) > OWS_HUB_CACHE_TTL_MS) return null;
    return parsed;
  } catch (_) { return null; }
}

function writeOwsHubCache(payload) {
  try { localStorage.setItem(owsHubCacheKey(), JSON.stringify({ ...payload, ts: Date.now() })); } catch (_) {}
}

// Última release del Hub de LA PLATAFORMA CORRECTA (?platform=...): nunca
// lanza: si falla devuelve el caché (o null) para que el panel pueda degradar
// a un link genérico a la página de releases.
function fetchOwsHubRelease() {
  if (owsHubReleasePromise) return owsHubReleasePromise;
  const cached = readOwsHubCache();
  if (cached) return Promise.resolve(cached);

  const platform = owsUpdatesPlatform();
  owsHubReleasePromise = (async () => {
    try {
      const url = `${API_BASE}/ows-store/github/repos/${OWS_HUB_REPO.owner}/${OWS_HUB_REPO.repo}/releases/latest?platform=${platform}`;
      const res = await fetchWithTimeout(url, OWS_HUB_FETCH_TIMEOUT_MS);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const tag = String(data.tag_name || data.name || '').trim();
      if (!tag) throw new Error('sin tag');
      const asset = pickOwsHubAsset(data.assets);
      const payload = {
        tag,
        platform,
        // Los tags de Android son "android-v3.3.5": la versión se muestra
        // siempre como "3.3.5", igual que en Windows.
        version: tag.replace(/^(android|windows|win)[-_]/i, '').replace(/^v/i, ''),
        assetName: asset ? String(asset.name || '') : '',
        assetSize: asset ? Number(asset.size || 0) : 0,
        url: (asset && asset.browser_download_url) || OWS_HUB_RELEASES_URL,
        htmlUrl: String(data.html_url || OWS_HUB_RELEASES_URL),
        publishedAt: data.published_at || data.created_at || '',
      };
      writeOwsHubCache(payload);
      return payload;
    } catch (err) {
      console.warn('[OWS] No se pudo leer la release de OWS Hub:', err && err.message);
      const stale = (() => {
        try {
          const raw = localStorage.getItem(owsHubCacheKey());
          return raw ? JSON.parse(raw) : null;
        } catch (_) { return null; }
      })();
      // Sin red ni caché: al menos la página de releases siempre sirve.
      return stale || { tag: '', platform, version: '', assetName: '', assetSize: 0, url: OWS_HUB_RELEASES_URL, htmlUrl: OWS_HUB_RELEASES_URL, publishedAt: '' };
    }
  })();

  return owsHubReleasePromise;
}

// ¿Estamos dentro de la app Android (Capacitor)? getPlatform() solo existe
// cuando la web corre empaquetada como app nativa; en navegador y en el
// Hub desktop (Tauri) no está, así que no puede dar falsos positivos.
function isAndroidApp() {
  try {
    const cap = window.Capacitor;
    return !!(cap && typeof cap.getPlatform === 'function' && cap.getPlatform() === 'android');
  } catch (_) { return false; }
}

// ¿Hay que bloquear la descarga porque estamos en el navegador?
// En la app Android NO: ahí las descargas van por el canal APK nativo.
function hubIsRequired() { return owsEnvironment() === 'browser'; }

// ── Android (Capacitor): bundle nativo + canal de APKs ──
// Esta web no usa bundler, así que el JS de los plugins (@capacitor/core,
// FileTransfer, Filesystem, FileOpener, App…) se pre-empaqueta con esbuild
// en app/vendor/cap-native.js y solo se inyecta cuando la app corre en
// Android. En web y en el Hub desktop (Tauri) ese archivo no existe ni se pide.
const OWS_NATIVE_BUNDLE_URL = './vendor/cap-native.js';
const OWS_ANDROID_CHANNEL = 'owshub';
let owsNativePromise = null;
const androidReleaseCache = {};

function loadOwsNative() {
  if (window.OWSNative) return Promise.resolve(window.OWSNative);
  if (owsNativePromise) return owsNativePromise;
  owsNativePromise = new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = OWS_NATIVE_BUNDLE_URL;
    s.async = true;
    s.onload = () => resolve(window.OWSNative || null);
    s.onerror = () => { owsNativePromise = null; reject(new Error('módulo nativo no disponible')); };
    document.head.appendChild(s);
  });
  return owsNativePromise;
}

// Arranque del lado nativo en Android: barra de estado con el color de la
// marca y splash oculto por si el auto-hide nativo no corrió.
function bootAndroidNative() {
  loadOwsNative().then((n) => {
    if (!n) return;
    try { if (n.StatusBar) { n.StatusBar.setBackgroundColor({ color: '#050a12' }); n.StatusBar.setStyle({ style: 'LIGHT' }); } } catch (_) {}
    try { if (n.SplashScreen) n.SplashScreen.hide(); } catch (_) {}
  }).catch(() => {});
}

// Última release Android publicada para un slug (null = no hay APK).
async function fetchAndroidRelease(slug) {
  const s = String(slug || '').trim();
  if (!s) return null;
  try {
    const res = await fetch(API_BASE + '/ows-store/android/releases/' + encodeURIComponent(s) + '/latest');
    if (!res.ok) return null;
    const data = await res.json().catch(() => ({}));
    const rel = (data && data.release) || null;
    if (rel) androidReleaseCache[s] = rel;
    return rel;
  } catch (_) { return null; }
}

// Pinta el panel lateral + el aviso del Gestor con la misma release.
function applyOwsHubRelease(rel) {
  if (!rel) return;
  const env = owsEnvironment();
  const isDesktop = env === 'desktop';
  const isAndroid = env === 'android';
  const verLabel = rel.version ? `v${rel.version}` : 'OWS Hub';
  const sizeLabel = rel.assetSize ? ` · ${formatMB(rel.assetSize)}` : '';

  // ── Panel lateral ──
  const panel = document.getElementById('nav-hub-panel');
  if (panel) {
    panel.dataset.state = isDesktop ? 'desktop' : (isAndroid ? 'android' : (rel.tag ? 'ready' : 'error'));
    const sub = document.getElementById('nav-hub-sub');
    const note = document.getElementById('nav-hub-note');
    const btn = document.getElementById('nav-hub-download');
    const btnTxt = document.getElementById('nav-hub-download-txt');
    const chip = document.getElementById('nav-hub-version');
    const gh = document.getElementById('nav-hub-releases');

    if (isDesktop) {
      if (sub) sub.textContent = `Instalado${rel.version ? ` · v${rel.version}` : ''}`;
      if (note) note.innerHTML = 'Ya tienes <b>OWS Hub</b>: aquí puedes descargar, instalar y jugar con 1 clic.';
      if (btnTxt) btnTxt.textContent = '✓ OWS Hub activo';
      if (btn) {
        btn.href = rel.htmlUrl || OWS_HUB_RELEASES_URL;
        btn.removeAttribute('download');
        btn.setAttribute('aria-disabled', 'false');
        btn.dataset.hubMode = 'installed';
      }
    } else if (isAndroid) {
      // Ya estás en OWS Hub (la app Android): el panel no pide instalar nada.
      if (sub) sub.textContent = 'App instalada ✓';
      if (note) note.innerHTML = 'Ya estás en <b>OWS Hub</b> para Android. En PC está la app de escritorio, con instalación y ejecución de juegos en 1 clic.';
      if (btnTxt) btnTxt.textContent = 'OWS Hub para PC ↗';
      if (btn) {
        // rel es la release de Android (la de esta plataforma): para el PC va
        // el listado general, nunca la página del APK.
        btn.href = OWS_HUB_RELEASES_LIST_URL;
        btn.removeAttribute('download');
        btn.setAttribute('aria-disabled', 'false');
        btn.dataset.hubMode = 'pc';
      }
    } else {
      if (sub) sub.textContent = rel.tag ? `Última versión · ${verLabel}` : 'Descarga obligatoria';
      if (note) note.innerHTML = 'Estás en el navegador: para continuar con las descargas <b>necesitas OWS Hub</b>. Sin él no se pueden instalar ni lanzar los juegos.';
      if (btnTxt) btnTxt.textContent = rel.assetName ? '⬇ Descargar OWS Hub' : '⬇ Ver OWS Hub en GitHub';
      if (btn) {
        btn.href = rel.url || OWS_HUB_RELEASES_URL;
        if (rel.assetName) btn.setAttribute('download', ''); else btn.removeAttribute('download');
        btn.setAttribute('aria-disabled', 'false');
        btn.dataset.hubMode = 'required';
      }
    }
    if (chip) chip.textContent = rel.tag ? `${verLabel}${sizeLabel}` : '—';
    if (gh) gh.href = rel.htmlUrl || OWS_HUB_RELEASES_URL;
  }

  // ── Aviso del Gestor de Descargas ──
  const gate = document.getElementById('hub-gate');
  const gateDl = document.getElementById('hub-gate-download');
  const gateGh = document.getElementById('hub-gate-releases');
  if (gate) gate.classList.toggle('hidden', !hubIsRequired());
  if (gateDl) {
    gateDl.href = rel.url || OWS_HUB_RELEASES_URL;
    if (rel.assetName) gateDl.setAttribute('download', ''); else gateDl.removeAttribute('download');
  }
  if (gateGh) gateGh.href = rel.htmlUrl || OWS_HUB_RELEASES_URL;

  // ── Aviso del modal de un juego (si está abierto) ──
  const reqDl = document.getElementById('rm-hub-req-download');
  const reqGh = document.getElementById('rm-hub-req-releases');
  if (reqDl) {
    reqDl.href = rel.url || OWS_HUB_RELEASES_URL;
    if (rel.assetName) reqDl.setAttribute('download', ''); else reqDl.removeAttribute('download');
  }
  if (reqGh) reqGh.href = rel.htmlUrl || OWS_HUB_RELEASES_URL;
}

// Carga (una sola vez) + repinta panel y aviso.
function initOwsHubPanel() {
  const panel = document.getElementById('nav-hub-panel');
  const gate = document.getElementById('hub-gate');
  // El aviso del Gestor depende solo del entorno: se decide al instante.
  if (gate) gate.classList.toggle('hidden', !hubIsRequired());
  // App Android: precarga el bundle nativo de plugins. (setTimeout porque
  // los const del bloque Android se declaran más abajo y esta función corre
  // durante la evaluación inicial del script, antes de llegar a ellos.)
  if (owsEnvironment() === 'android') setTimeout(bootAndroidNative, 0);
  if (!panel && !gate) return;
  // Pintado inmediato con lo que haya en caché para que no parpadee "Buscando…".
  applyOwsHubRelease(readOwsHubCache());
  fetchOwsHubRelease().then((rel) => applyOwsHubRelease(rel)).catch(() => {});
  // Limpia restos de desinstalaciones anteriores (el juego ya salía de la
  // biblioteca; la carpeta quedó apartada porque algo la tenía abierta).
  if (window.OWSHubLibrary && owsEnvironment() === 'desktop') {
    window.OWSHubLibrary.sweepPendingRemovals().then((n) => {
      if (n > 0) console.log(`[OWS Hub] ${n} carpeta(s) de desinstalación pendiente borrada(s)`);
    });
  }
}

// Aviso inline del modal de un juego: en navegador NO hay descarga directa.
function hubRequiredNoticeHtml() {
  if (!hubIsRequired()) return '';
  let rel = readOwsHubCache();
  if (!rel || !rel.tag) {
    // Modal abierto antes de que llegue la release: dispara la carga (una sola
    // vez) y de paso refresca panel lateral + aviso del Gestor.
    fetchOwsHubRelease().then((r) => applyOwsHubRelease(r)).catch(() => {});
    rel = rel || { url: OWS_HUB_RELEASES_URL, htmlUrl: OWS_HUB_RELEASES_URL };
  }
  const href = escapeHtml(rel.url || OWS_HUB_RELEASES_URL);
  const ver = rel.version ? ` (v${escapeHtml(rel.version)})` : '';
  const size = rel.assetSize ? ` · ${escapeHtml(formatMB(rel.assetSize))}` : '';
  return `
    <div class="rm-hub-req">
      <span class="rm-hub-req-title">⛔ Descargas bloqueadas en el navegador</span>
      <p class="rm-hub-req-text">Para continuar con las descargas tienes que instalar <b>OWS Hub</b>${ver}${size}. Es gratis y en 1 clic podrás descargar, instalar y jugar.</p>
      <div class="rm-hub-req-actions">
        <a class="btn btn-primary btn-sm" id="rm-hub-req-download" href="${href}" target="_blank" rel="noopener" download>⬇ Descargar OWS Hub</a>
        <a class="btn btn-ghost btn-sm" id="rm-hub-req-releases" href="${escapeHtml(rel.htmlUrl || OWS_HUB_RELEASES_URL)}" target="_blank" rel="noopener">Releases ↗</a>
      </div>
    </div>`;
}

// ═══════════════════════════════════════════════════════════════
// GESTOR DE ACTUALIZACIONES — OWS Hub + proyectos
// ───────────────────────────────────────────────────────────────
// Una sola fuente de verdad: GET /ows-updates/check. El cliente manda su
// estado (versión del Hub + qué juegos tiene instalados y en qué versión) y
// el servidor devuelve el plan YA COMPARADO. Acá no se reimplementa la
// comparación de versiones ni se le pega a GitHub desde el navegador.
//
// Aplicar una actualización de juego = el mismo flujo de instalación que
// usa el modal de Lanzamientos (startDesktopInstallManaged), así el progreso
// aparece en el Gestor de Descargas sin duplicar código.
//
// El Hub launcher se actualiza a sí mismo con el plugin updater de Tauri
// (ya registrado en OWS-Desktop). Se llama por invoke directo
// ('plugin:updater|check' / 'plugin:updater|download_and_install') para no
// depender del paquete npm @tauri-apps/plugin-updater, que no está en el
// proyecto: los comandos son parte del plugin Rust y llegan por el mismo
// invoke que el resto.
// ═══════════════════════════════════════════════════════════════
const UPDATES_FILTER_KEY = 'ows_updates_filter_v1';
const UPDATES_STALE_MS = 5 * 60 * 1000;
const UPDATES_FETCH_TIMEOUT_MS = 20000;

let updatesState = {
  loaded: false,
  loading: false,
  error: '',
  checkedAt: '',
  filter: 'all',
  // Plataforma de los datos que se están mostrando (windows | android).
  platform: 'windows',
  hub: null,
  projects: [],
  counts: { total: 0, installed: 0, with_build: 0, updates: 0, pending: 0 },
};

// La versión del Hub que tenés CORRIENDO. Fuente: el propio .nav-version del
// HTML (lo mantiene el bump de versión) y, en desktop, el updater de Tauri
// (fuente de verdad real). Se consulta una vez y se cachea.
let owsHubLocalVersion = '';
let owsHubVersionChecked = false;
let owsHubUpdaterProbe = null; // promesa en vuelo del chequeo del updater

function parseHubVersionFromUi() {
  const el = document.querySelector('.nav-version');
  const txt = String((el && el.textContent) || '');
  const m = txt.match(/v?(\d+(?:\.\d+)+)/);
  return m ? m[1] : '';
}

// ── Updater de Tauri (plugin updater v2) ──────────────────────
// check: no necesita argumentos → devuelve { version, currentVersion, ... }
// download_and_install: sin onEventFn el pluginRust hace todo y muestra el
// diálogo nativo (tauri.conf.json tiene "dialog": true), así que no hace
// falta el Channel de @tauri-apps/api.
// cacheMs > 0 memoiza el resultado (el updater golpea el manifiesto de
// GitHub): el gestor lo consulta al armar la versión local y otra vez al
// validar el plan, y no tiene sentido pedirlo dos veces pegados.
function tauriUpdaterCheck(opts) {
  const cacheMs = Number((opts && opts.cacheMs) || 0);
  if (cacheMs > 0) {
    if (owsHubUpdaterProbe && (Date.now() - owsHubUpdaterProbe.at) < cacheMs) {
      return owsHubUpdaterProbe.promise;
    }
  }
  if (owsEnvironment() !== 'desktop') {
    const p = Promise.resolve(null);
    owsHubUpdaterProbe = { at: Date.now(), promise: p };
    return p;
  }
  const promise = (async () => {
    try {
      const upd = await tauriInvoke('plugin:updater|check', {}, 8000);
      if (!upd || typeof upd !== 'object') return null;
      return {
        available: String(upd.version || '') !== String(upd.currentVersion || ''),
        version: String(upd.version || '').replace(/^[vV]/, ''),
        currentVersion: String(upd.currentVersion || '').replace(/^[vV]/, ''),
        date: upd.date || '',
        notes: String(upd.body || '')
      };
    } catch (err) {
      // Hub viejo sin plugin updater, o sin red: la UI degrada a la
      // versión del HTML y al link de releases.
      if (!(opts && opts.quiet)) console.warn('[OWS] updater check falló:', (err && err.message) || err);
      return null;
    }
  })();
  owsHubUpdaterProbe = { at: Date.now(), promise };
  return promise;
}

async function hubLocalVersion() {
  if (owsHubVersionChecked) return owsHubLocalVersion;
  owsHubVersionChecked = true;
  // En desktop el updater conoce la versión real del binario (más fiable que
  // el texto del HTML, que puede quedar desfasado si el binario no se
  // reconstruyó). Si no hay updater, se usa la del frontend.
  const fromTauri = await tauriUpdaterCheck({ quiet: true, cacheMs: 60000 });
  owsHubLocalVersion = (fromTauri && fromTauri.currentVersion)
    ? String(fromTauri.currentVersion).replace(/^[vV]/, '')
    : parseHubVersionFromUi();
  return owsHubLocalVersion;
}

// Estado local instalado → "slug:version,slug:version" para el backend.
function installedMapParam() {
  try {
    if (!window.OWSHubLibrary || !window.OWSHubLibrary.installedList) return '';
    const list = window.OWSHubLibrary.installedList() || [];
    const parts = list
      .map((it) => {
        const slug = String(it.slug || '').trim();
        const ver = String(it.version || '').trim();
        return (slug && ver) ? `${slug}:${ver}` : '';
      })
      .filter(Boolean);
    return parts.join(',');
  } catch (_) { return ''; }
}

// ── Updater de Tauri (plugin updater v2) ──────────────────────
// Llamada directa al invoke: el helper tauriInvoke()Serializa mal los
// Channels, así que el updater va por su propio camino (además necesita
// timeouts largos: la descarga del instalador puede tardar minutos).
// OJO: Tauri v2 convierte los argumentos a camelCase, así que las claves
// van en camelCase (rid, onEvent, updateRid, bytesRid, restartAfterInstall).
function tauriUpdaterCall(cmd, args, timeoutMs) {
  const core = window.__TAURI__ && window.__TAURI__.core;
  const invoke = core && typeof core.invoke === 'function'
    ? core.invoke
    : (window.__TAURI_INTERNALS__ && typeof window.__TAURI_INTERNALS__.invoke === 'function'
        ? window.__TAURI_INTERNALS__.invoke.bind(window.__TAURI_INTERNALS__)
        : null);
  if (!invoke) return Promise.reject(new Error('WebView sin puente de Tauri'));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timeout')), Number(timeoutMs) || 15000);
    Promise.resolve()
      .then(() => invoke(cmd, args || {}))
      .then((v) => { clearTimeout(timer); resolve(v); })
      .catch((e) => { clearTimeout(timer); reject(e); });
  });
}

// Canal de Tauri para el progreso del updater (viene del core global por
// withGlobalTauri: true, sin paquete npm).
function tauriMakeChannel() {
  try {
    const core = window.__TAURI__ && window.__TAURI__.core;
    if (core && typeof core.Channel === 'function') return new core.Channel();
  } catch (_) {}
  return null;
}

// ── Carga del plan de actualizaciones ──────────────────────────
function updatesFilter() {
  try {
    const v = String(localStorage.getItem(UPDATES_FILTER_KEY) || '').trim();
    return ['all', 'pending', 'current', 'unavailable'].indexOf(v) >= 0 ? v : 'all';
  } catch (_) { return 'all'; }
}

function setUpdatesFilter(value) {
  const v = ['all', 'pending', 'current', 'unavailable'].indexOf(String(value || '')) >= 0 ? String(value) : 'all';
  updatesState.filter = v;
  try { localStorage.setItem(UPDATES_FILTER_KEY, v); } catch (_) {}
  document.querySelectorAll('[data-upd-filter]').forEach((chip) => {
    const on = chip.getAttribute('data-upd-filter') === v;
    chip.classList.toggle('upd-chip-active', on);
    chip.setAttribute('aria-selected', on ? 'true' : 'false');
  });
  renderUpdates();
}

async function loadUpdatesManager(opts) {
  const force = !!(opts && opts.force);
  // App Android: canal propio (APK del Hub) en lugar del updater de Tauri.
  if (owsEnvironment() === 'android') return loadUpdatesManagerAndroid(opts);
  if (updatesState.loading) return;
  if (!force && updatesState.loaded && !updatesState.error) {
    const age = updatesState.checkedAt ? (Date.now() - new Date(updatesState.checkedAt).getTime()) : Infinity;
    if (age < UPDATES_STALE_MS) { renderUpdates(); return; }
  }
  updatesState.loading = true;
  updatesState.error = '';
  try { renderUpdates(); } catch (_) {}

  try {
    const hubVer = await hubLocalVersion();
    const platform = owsUpdatesPlatform();
    const params = ['platform=' + platform];
    if (hubVer) params.push('hub=' + encodeURIComponent(hubVer));
    const inst = installedMapParam();
    if (inst) params.push('installed=' + encodeURIComponent(inst));
    const qs = params.length ? ('?' + params.join('&')) : '';
    const res = await fetchWithTimeout(API_BASE + '/ows-updates/check' + qs, UPDATES_FETCH_TIMEOUT_MS);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json().catch(() => ({}));
    if (!data || data.success !== true) throw new Error((data && data.error) || 'respuesta inválida');

    // El updater de Tauri es la fuente real de "¿hay versión nueva del Hub?".
    // El backend compara contra la release de GitHub; si el manifiesto local
    // dice otra cosa, gana el local (es lo que el instalador aplicaría).
    const tauriUpd = await tauriUpdaterCheck({ quiet: true, cacheMs: 60000 });
    const hubFromServer = data.hub || {};
    const hub = { ...hubFromServer };
    if (tauriUpd && tauriUpd.currentVersion) hub.current_version = tauriUpd.currentVersion;
    if (tauriUpd && tauriUpd.version) {
      hub.updater_available = tauriUpd.available;
      // El updater knows mejor: si dice que hay update, hay update.
      hub.update_available = tauriUpd.available;
      if (!hub.latest_version) hub.latest_version = tauriUpd.version;
      if (tauriUpd.notes && !hub.notes) hub.notes = tauriUpd.notes;
    }
    hub.can_self_update = !!(tauriUpd && tauriUpd.available);

    const projects = Array.isArray(data.projects) ? data.projects : [];
    const counts = data.counts || {};
    const pendingProjects = projects.filter((p) => p.update_available).length;

    updatesState = {
      loaded: true,
      loading: false,
      error: '',
      checkedAt: data.checked_at || new Date().toISOString(),
      filter: updatesState.filter || 'all',
      platform: data.platform || platform,
      hub,
      projects,
      counts: {
        total: Number(counts.total || projects.length),
        installed: Number(counts.installed || projects.filter((p) => p.installed).length),
        with_build: Number(counts.with_build || projects.filter((p) => p.has_build).length),
        updates: pendingProjects,
        pending: pendingProjects + (hub.update_available ? 1 : 0)
      }
    };
  } catch (err) {
    updatesState.loading = false;
    updatesState.loaded = false;
    updatesState.error = String((err && err.message) || err);
  }
  try { renderUpdates(); } catch (_) {}
  try { syncUpdatesBadge(); } catch (_) {}
}

// ── Android: la tarjeta del Hub consulta el canal APK propio ──
// Mismo estado que el gestor normal (para que renderUpdates y el badge del
// menú funcionen igual), pero sin proyectos de PC ni updater de Tauri.
async function loadUpdatesManagerAndroid(opts) {
  const force = !!(opts && opts.force);
  if (updatesState.loading) return;
  if (!force && updatesState.loaded && updatesState.android && !updatesState.error) {
    const age = updatesState.checkedAt ? (Date.now() - new Date(updatesState.checkedAt).getTime()) : Infinity;
    if (age < UPDATES_STALE_MS) { renderUpdates(); return; }
  }
  updatesState.loading = true;
  updatesState.error = '';
  try { renderUpdates(); } catch (_) {}

  try {
    const native = await loadOwsNative().catch(() => null);
    let info = { version: '', build: 0 };
    if (native && native.App && typeof native.App.getInfo === 'function') {
      try { info = await native.App.getInfo(); } catch (_) {}
    }
    const installedName = String((info && info.version) || '').trim();
    const installedCode = Number((info && info.build) || 0);
    const res = await fetch(API_BASE + '/ows-store/android/check-update', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_slug: OWS_ANDROID_CHANNEL,
        package_id: 'com.oceanandwild.owshub',
        installed_version_code: installedCode || 0,
        installed_version_name: installedName,
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const latest = (data && data.latest) || null;
    let updateAvailable = !!(data && data.update_available);
    // Sin versionCode en el lado nativo se compara por nombre (3.3.6 > 3.3.5).
    if (!installedCode && latest && latest.version_name && installedName) {
      updateAvailable = owshubCompareVersions(latest.version_name, installedName) > 0;
    }

    updatesState = {
      android: true,
      platform: 'android',
      loaded: true,
      loading: false,
      error: '',
      checkedAt: new Date().toISOString(),
      filter: updatesState.filter || 'all',
      hub: {
        name: 'OWS Hub (Android)',
        current_version: installedName || (installedCode ? String(installedCode) : ''),
        latest_version: latest ? latest.version_name : '',
        update_available: updateAvailable,
        can_self_update: true,
        notes: latest ? (latest.release_notes || '') : '',
        published_at: latest ? (latest.published_at || '') : '',
        html_url: OWS_HUB_RELEASES_URL,
        android_apk: latest,
      },
      projects: [],
      counts: { total: 0, installed: 0, with_build: 0, updates: updateAvailable ? 1 : 0, pending: updateAvailable ? 1 : 0 },
    };
  } catch (err) {
    updatesState.loading = false;
    updatesState.loaded = false;
    updatesState.error = String((err && err.message) || err);
  }
  try { renderUpdates(); } catch (_) {}
  try { syncUpdatesBadge(); } catch (_) {}
}

// Comparador semver-lite (solo para el canal Android del Hub).
function owshubCompareVersions(a, b) {
  const pa = String(a == null ? '' : a).trim().replace(/^[vV]/, '').split('.');
  const pb = String(b == null ? '' : b).trim().replace(/^[vV]/, '').split('.');
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const va = parseInt(pa[i], 10); const vb = parseInt(pb[i], 10);
    const na = Number.isFinite(va) ? va : 0;
    const nb = Number.isFinite(vb) ? vb : 0;
    if (na !== nb) return na > nb ? 1 : -1;
  }
  return 0;
}

// Actualización del propio OWS Hub en Android: mismo flujo de APK nativo.
async function runHubAndroidUpdate(btn) {
  if (btn) { btn.disabled = true; }
  try {
    const rel = (updatesState.hub && updatesState.hub.android_apk) || await fetchAndroidRelease(OWS_ANDROID_CHANNEL);
    if (!rel || !rel.apk_url) { showToast('Todavía no hay APK publicado para actualizar'); return; }
    androidReleaseCache[OWS_ANDROID_CHANNEL] = rel;
    await startAndroidApkInstall(OWS_ANDROID_CHANNEL, 'OWS Hub');
  } finally {
    if (btn) btn.disabled = false;
  }
}

// Arranca el gestor la primera vez (o refresca si ya quedó viejo).
function ensureUpdatesManager() {
  if (!updatesState.loaded || (updatesState.checkedAt && (Date.now() - new Date(updatesState.checkedAt).getTime()) > UPDATES_STALE_MS)) {
    loadUpdatesManager();
  } else {
    renderUpdates();
    syncUpdatesBadge();
  }
}

// ── Render ─────────────────────────────────────────────────────
function updatesStatusLabel(p) {
  if (p.update_available) return { text: 'Actualización disponible', cls: 'upd-st-update' };
  if (p.installed) return { text: 'Al día', cls: 'upd-st-ok' };
  if (p.has_build) return { text: 'No instalado', cls: 'upd-st-install' };
  return { text: 'Sin build', cls: 'upd-st-none' };
}

function updatesFilterProjects() {
  const all = Array.isArray(updatesState.projects) ? updatesState.projects : [];
  const f = updatesState.filter || 'all';
  // Primero lo que hay que hacer (update), después lo instalable, y al final
  // lo que no tiene nada que offerer.
  const rank = (p) => (p.update_available ? 0 : (p.installed ? 1 : (p.has_build ? 2 : 3)));
  const sorted = [...all].sort((a, b) => rank(a) - rank(b) || String(a.name).localeCompare(String(b.name)));
  if (f === 'pending') return sorted.filter((p) => p.update_available || !p.installed && p.has_build);
  if (f === 'current') return sorted.filter((p) => p.installed && !p.update_available);
  if (f === 'unavailable') return sorted.filter((p) => !p.has_build);
  return sorted;
}

function updatesRowHtml(p) {
  const slug = String(p.slug || '');
  const safeSlug = escapeHtml(slug);
  const inDesktop = owsEnvironment() === 'desktop';
  const st = updatesStatusLabel(p);
  const icon = String(p.icon_url || '')
    ? `<img class="upd-row-icon" src="${escapeHtml(p.icon_url)}" alt="" loading="lazy" />`
    : `<span class="upd-row-icon upd-row-icon-fallback" aria-hidden="true">🎮</span>`;

  const verChips = [];
  if (p.installed_version) verChips.push(`<span class="upd-ver-chip upd-ver-old">v${escapeHtml(p.installed_version)}</span>`);
  if (p.latest_version) verChips.push(`<span class="upd-ver-arrow" aria-hidden="true">→</span><span class="upd-ver-chip upd-ver-new">v${escapeHtml(p.latest_version)}</span>`);

  const metaBits = [];
  if (p.size_label) metaBits.push(`📦 ${escapeHtml(p.size_label)}`);
  if (p.released_at) {
    const d = formatReleaseDate(p.released_at);
    if (d) metaBits.push(`🗓️ ${escapeHtml(d)}`);
  }
  if (p.prerelease) metaBits.push(`<span class="upd-chip-pre">${escapeHtml(p.channel || 'beta')}</span>`);

  const actions = [];
  if (p.has_build) {
    if (inDesktop) {
      // Si la release es beta/alpha el botón lo dice: nada de prometer una
      // versión "nueva" sin advertir que es un canal de prueba.
      const chTag = p.prerelease ? ` <span class="upd-chip-pre">${escapeHtml(p.channel || 'beta')}</span>` : '';
      const label = p.update_available
        ? `⬇ Actualizar${p.latest_version ? ' a v' + escapeHtml(p.latest_version) : ''}`
        : `⬇ Instalar${p.latest_version ? ' v' + escapeHtml(p.latest_version) : ''}`;
      actions.push(`<button class="btn btn-primary btn-sm" data-upd-action="${p.update_available ? 'update' : 'install'}" data-slug="${safeSlug}">${label}</button>${chTag}`);
      if (p.installed) {
        actions.push(`<button class="btn btn-ghost btn-sm" data-upd-action="play" data-slug="${safeSlug}">▶ Jugar</button>`);
      }
    } else {
      actions.push(`<button class="btn btn-ghost btn-sm" data-upd-action="goto-releases" data-slug="${safeSlug}">Ver en Lanzamientos ↗</button>`);
    }
  }
  actions.push(`<button class="btn btn-ghost btn-sm" data-upd-action="changelog" data-slug="${safeSlug}">📜 Historial</button>`);

  return `
    <div class="upd-row" data-slug="${safeSlug}" data-kind="${escapeHtml(p.kind || '')}">
      <div class="upd-row-media">${icon}</div>
      <div class="upd-row-main">
        <div class="upd-row-top">
          <b class="upd-row-name">${escapeHtml(p.name || slug)}</b>
          <span class="upd-status ${st.cls}">${escapeHtml(st.text)}</span>
        </div>
        ${verChips.length ? `<div class="upd-row-vers">${verChips.join('')}</div>` : ''}
        ${p.notes ? `<p class="upd-row-notes">${escapeHtml(p.notes)}</p>` : ''}
        ${metaBits.length ? `<p class="upd-row-meta">${metaBits.join(' · ')}</p>` : ''}
        ${!p.has_build ? `<p class="upd-row-notes upd-row-na">Todavía no hay versión descargable de este juego.</p>` : ''}
      </div>
      <div class="upd-row-actions">${actions.join('')}</div>
    </div>`;
}

function renderUpdates() {
  const list = document.getElementById('updates-list');
  const empty = document.getElementById('updates-empty');
  const meta = document.getElementById('updates-checked');
  if (!list || !empty) return;

  // "Sin revisar" / "Revisado hace un momento" / "Ahora"
  if (meta) {
    if (updatesState.loading) meta.textContent = 'Buscando…';
    else if (updatesState.checkedAt) {
      const d = new Date(updatesState.checkedAt);
      meta.textContent = Number.isNaN(d.getTime())
        ? 'Revisado'
        : ('Revisado ' + d.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' }));
    } else meta.textContent = 'Sin revisar';
  }

  // Plataforma de las versiones listadas: el repo publica build de Windows y
  // de Android, y acá solo se muestra el de este cliente.
  const platChip = document.getElementById('updates-platform-chip');
  if (platChip) {
    const plat = updatesState.platform || owsUpdatesPlatform();
    platChip.dataset.platform = plat;
    platChip.textContent = plat === 'android' ? '🤖 Versiones de Android' : '🪟 Versiones de Windows';
  }

  // Contadores
  const setStat = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = String(val); };
  setStat('upd-stat-pending', updatesState.counts.pending || 0);
  setStat('upd-stat-installed', updatesState.counts.installed || 0);
  setStat('upd-stat-current', (updatesState.projects || []).filter((p) => p.installed && !p.update_available).length);
  setStat('upd-stat-new', updatesState.counts.with_build || 0);

  renderHubUpdateCard();

  // Filtros (sincroniza el chip activo con el estado)
  document.querySelectorAll('[data-upd-filter]').forEach((chip) => {
    const on = chip.getAttribute('data-upd-filter') === (updatesState.filter || 'all');
    chip.classList.toggle('upd-chip-active', on);
    chip.setAttribute('aria-selected', on ? 'true' : 'false');
  });

  if (updatesState.error) {
    list.innerHTML = `<div class="upd-error"><p>⚠️ No se pudo consultar las actualizaciones.</p><p class="upd-error-detail">${escapeHtml(updatesState.error)}</p><button class="btn btn-ghost btn-sm" data-upd-action="refresh">↻ Reintentar</button></div>`;
    empty.classList.add('hidden');
    return;
  }
  if (updatesState.loading && !updatesState.loaded) {
    list.innerHTML = `<p class="loading-note"><span class="btn-spinner"></span> Consultando OWS Hub y tus juegos…</p>`;
    empty.classList.add('hidden');
    return;
  }

  const visible = updatesFilterProjects();
  if (!visible.length) {
    list.innerHTML = '';
    empty.classList.remove('hidden');
    const sub = document.getElementById('updates-empty-sub');
    if (sub) {
      const f = updatesState.filter || 'all';
      if (updatesState.android) {
        sub.textContent = 'Aquí solo se actualiza esta app de Android. Los juegos de PC se actualizan desde OWS Hub para Windows.';
      } else if (f === 'pending') {
        sub.textContent = 'No tenés actualizaciones pendientes. Todo lo que tenés instalado está en la última versión.';
      } else if (f === 'current') {
        sub.textContent = 'No tenés juegos instalados todavía.';
      } else {
        sub.textContent = 'Nada para mostrar con este filtro.';
      }
    }
    return;
  }
  empty.classList.add('hidden');
  list.innerHTML = visible.map(updatesRowHtml).join('');
}

// Tarjeta del OWS Hub: versión local → última, estado y acciones.
function renderHubUpdateCard() {
  const card = document.getElementById('upd-hub-card');
  const state = document.getElementById('upd-hub-state');
  const cur = document.getElementById('upd-hub-current');
  const latest = document.getElementById('upd-hub-latest');
  const notes = document.getElementById('upd-hub-notes');
  const actions = document.getElementById('upd-hub-actions');
  const hint = document.getElementById('upd-hub-hint');
  if (!card) return;

  const hub = updatesState.hub || {};

  const inDesktop = owsEnvironment() === 'desktop';
  const isAndroid = owsEnvironment() === 'android';
  const hasUpdate = !!hub.update_available;

  if (updatesState.loading && !updatesState.loaded) card.dataset.state = 'loading';
  else if (updatesState.error) card.dataset.state = 'error';
  else if (hasUpdate) card.dataset.state = 'pending';
  else if (hub.unknown) card.dataset.state = 'unknown';
  else card.dataset.state = 'ok';

  if (cur) cur.textContent = hub.current_version ? ('v' + hub.current_version) : '—';
  if (latest) latest.textContent = hub.latest_version ? ('v' + hub.latest_version) : '—';

  if (state) {
    if (updatesState.loading && !updatesState.loaded) state.textContent = 'Buscando la última versión…';
    else if (updatesState.error) state.textContent = 'No se pudo consultar la release del Hub';
    else if (hasUpdate) state.textContent = isAndroid
      ? 'Hay una versión nueva de OWS Hub para Android'
      : (inDesktop ? 'Hay una versión nueva para instalar' : 'Hay una versión nueva disponible');
    else if (hub.unknown) state.textContent = 'Versión del Hub sin verificar';
    else state.textContent = 'Tu OWS Hub está actualizado';
  }

  if (notes) {
    const raw = String(hub.notes || '').trim();
    if (raw) {
      // Las notas de GitHub vienen en Markdown: se muestran con el
      // mini-markdown (negritas y links), siempre HTML escapado, y
      // recortadas.
      const cut = raw.length > 420 ? (raw.slice(0, 420).trim() + '…') : raw;
      notes.innerHTML = hubMdInline(hubMdEscape(cut));
      notes.classList.remove('hidden');
    } else {
      notes.innerHTML = '';
      notes.classList.add('hidden');
    }
  }

  if (actions) {
    const btns = [];
    if (hubUpdateBusy) {
      // Mientras baja o espera el reinicio: el botón no se puede tocar dos veces.
      btns.push(`<button class="btn btn-primary btn-sm" disabled>⬇ Actualizando…</button>`);
    } else if (hasUpdate) {
      if (isAndroid) {
        // Misma acción nativa que los juegos: baja el APK y abre el instalador.
        btns.push(`<button class="btn btn-primary btn-sm" data-upd-action="hub-apk">⬇ Actualizar APK${hub.latest_version ? ' v' + escapeHtml(hub.latest_version) : ''}</button>`);
      } else if (inDesktop && hub.can_self_update) {
        // Acción única y simple: descargar. El progreso vive en el toaster.
        btns.push(`<button class="btn btn-primary btn-sm" data-upd-action="hub-install">⬇ Descargar v${escapeHtml(hub.latest_version || '')}</button>`);
      } else {
        const href = hub.installer_url || hub.html_url || OWS_HUB_RELEASES_URL;
        const dl = inDesktop ? '' : ' download';
        btns.push(`<a class="btn btn-primary btn-sm" href="${escapeHtml(href)}" target="_blank" rel="noopener"${dl}>⬇ Descargar instalador</a>`);
      }
    } else if (!hub.unknown && !updatesState.error) {
      btns.push(`<span class="upd-hub-ok">✓ Al día</span>`);
    }
    if (hub.published_at) {
      const d = formatReleaseDate(hub.published_at);
      if (d) btns.push(`<span class="upd-hub-date">Publicada ${escapeHtml(d)}</span>`);
    }
    actions.innerHTML = btns.join('');
  }

  if (hint) {
    if (updatesState.error) {
      hint.textContent = 'Revisá tu conexión y tocá "Buscar actualizaciones".';
    } else if (hasUpdate && isAndroid) {
      hint.textContent = 'La actualización baja el APK y lo instala con el mismo paso de siempre.';
    } else if (hasUpdate && inDesktop && !hub.can_self_update) {
      hint.textContent = 'Tu versión del Hub no trae el actualizador: cerrá el Hub y usá el instalador.';
    } else if (hasUpdate && !inDesktop) {
      hint.textContent = 'Instalá el Hub y desde ahí aplicás la actualización sin pasos extra.';
    } else {
      hint.innerHTML = `<a href="${escapeHtml(hub.html_url || OWS_HUB_RELEASES_URL)}" target="_blank" rel="noopener">Releases ↗</a>`;
    }
  }
}

// Badge del menú: cuántas actualizaciones hay (Hub + juegos).
function syncUpdatesBadge() {
  const badge = document.getElementById('nav-upd-badge');
  if (!badge) return;
  const n = Number(updatesState.counts.pending || 0);
  badge.textContent = n > 99 ? '99+' : String(n);
  badge.classList.toggle('hidden', !(n > 0));
}

// ── Acciones del gestor ────────────────────────────────────────
// ═══════════════════════════════════════════════
// ACTUALIZACIÓN DEL HUB (rework 3.3.0)
// Flujo completo, paso a paso:
//   1) Botón simple ⬇ Descargar en la tarjeta del Hub.
//   2) #hub-upd-toaster: aviso FIJO con el progreso real mientras baja.
//   3) Al terminar: modal con cuenta regresiva de 5 s.
//   4) install(restartAfterInstall: true) → el Hub se reinicia solo.
//   5) Al arrancar de nuevo: modal con el changelog, UNA vez por versión.
//
// Por eso el plugin se usa con `download` + `install` por separado en vez
// de `download_and_install`: así el reinicio es un paso nuestro y podemos
// avisar antes de hacerlo. OJO con los nombres de los argumentos: Tauri v2
// los convierte a camelCase, así que van updateRid / bytesRid /
// restartAfterInstall (y rid / onEvent para el download).
// ═══════════════════════════════════════════════

const HUB_RESTART_SECONDS = 5;
// Novedades de la versión recién instalada. Vive en localStorage porque el
// reinicio mata la WebView: se escribe antes de instalar y se lee al arrancar.
const HUB_CHANGELOG_KEY = 'ows_hub_changelog_pending_v1';
// Marcado justo antes de instalar: al arrancar de nuevo, el Hub entra en
// pantalla completa UNA sola vez (se borra apenas se lee).
const HUB_FULLSCREEN_KEY = 'ows_hub_fullscreen_after_update_v1';
let hubUpdateBusy = false;
let hubRestartTimer = null;
let hubPendingInstall = null;   // { rid, bytesRid }

// ── Toaster fijo del Hub ────────────────────────────────────────
// A diferencia del de juegos, este NO se oculta solo: se queda mientras
// dura la descarga. Se pinta una vez y después se parchea en sitio para
// que la animación de entrada no se reinicie en cada chunk.
function hubUpdToastShow(version) {
  const box = document.getElementById('hub-upd-toaster');
  if (!box) return;
  box.innerHTML = `
    <div class="dl-toast-item hub-upd-toast-item" data-hub-upd="1">
      <span class="hub-upd-toast-thumb" aria-hidden="true">🖥</span>
      <span class="dl-toast-body">
        <span class="dl-toast-top">
          <b class="dl-toast-name">OWS Hub v${escapeHtml(version)}</b>
          <span class="dl-badge hub-upd-toast-badge">⬇ Descargando</span>
        </span>
        <span class="dl-toast-info hub-upd-toast-info">Conectando…</span>
        <span class="dl-toast-bar hub-upd-toast-bar"><i style="width:0%"></i></span>
      </span>
    </div>`;
  box.classList.remove('hidden');
}

function hubUpdToastPatch(pct, info, done) {
  const box = document.getElementById('hub-upd-toaster');
  if (!box) return;
  const item = box.querySelector('[data-hub-upd]');
  if (!item) return;
  const bar = item.querySelector('.hub-upd-toast-bar i');
  if (bar) bar.style.width = Math.max(0, Math.min(100, pct)) + '%';
  const txt = item.querySelector('.hub-upd-toast-info');
  if (txt && txt.textContent !== info) txt.textContent = info;
  const badge = item.querySelector('.hub-upd-toast-badge');
  if (badge && done) { badge.textContent = '✔ Listo'; badge.classList.add('dl-badge-done'); }
  if (done) item.classList.add('is-done');
}

function hubUpdToastHide() {
  const box = document.getElementById('hub-upd-toaster');
  if (!box) return;
  box.classList.add('hidden');
  box.innerHTML = '';
}

// ── Modal de reinicio (5 s) ──────────────────────────────────────
function openHubRestartModal(version) {
  const modal = document.getElementById('hub-restart-modal');
  if (!modal) return false;
  const verEl = document.getElementById('hub-restart-ver');
  if (verEl) verEl.textContent = 'v' + version;
  modal.classList.remove('hidden');
  hubRestartTick(version, HUB_RESTART_SECONDS);
  return true;
}

function hubRestartTick(version, left) {
  const ring = document.getElementById('hub-restart-prog');
  const big = document.getElementById('hub-restart-count');
  const secs = document.getElementById('hub-restart-secs');
  const n = Math.max(0, left);
  if (ring) {
    // Circumferencia del círculo r=52 → 326.7; se vacía a medida que baja.
    ring.style.strokeDashoffset = String(326.7 * (n / HUB_RESTART_SECONDS));
  }
  if (big) big.textContent = String(n);
  if (secs) secs.textContent = String(n);
  if (hubRestartTimer) clearTimeout(hubRestartTimer);
  if (n <= 0) { doHubInstall(); return; }
  hubRestartTimer = setTimeout(() => hubRestartTick(version, n - 1), 1000);
}

function closeHubRestartModal() {
  const modal = document.getElementById('hub-restart-modal');
  if (modal) modal.classList.add('hidden');
  if (hubRestartTimer) { clearTimeout(hubRestartTimer); hubRestartTimer = null; }
}

// Instala lo descargado y reinicia. A partir de acá el proceso se cierra,
// así que no se puede recuperar de un error: por eso el changelog se guarda
// ANTES de llamar.
async function doHubInstall() {
  if (!hubPendingInstall) { closeHubRestartModal(); return; }
  const { rid, bytesRid } = hubPendingInstall;
  hubPendingInstall = null;
  closeHubRestartModal();
  // Al volver a arrancar (proceso nuevo) el Hub se abre en pantalla completa.
  // Se marca acá y se lee apenas arranca: si la instalación falla, se desmarca.
  try { localStorage.setItem(HUB_FULLSCREEN_KEY, '1'); } catch (_) {}
  try {
    await tauriUpdaterCall('plugin:updater|install', {
      updateRid: rid,
      bytesRid: bytesRid,
      restartAfterInstall: true
    });
  } catch (err) {
    try { localStorage.removeItem(HUB_FULLSCREEN_KEY); } catch (_) {}
    hubUpdToastHide();
    showToast('No se pudo reiniciar el Hub: ' + String((err && err.message) || err));
    hubUpdateBusy = false;
    renderHubUpdateCard();
  }
}

// ── Pantalla completa tras actualizar ───────────────────────────
// Requiere el permiso core:window:allow-set-fullscreen (capabilities).
function hubGetWindowHandle() {
  try {
    const mod = window.__TAURI__ && window.__TAURI__.window;
    if (mod && typeof mod.getCurrentWindow === 'function') return mod.getCurrentWindow();
  } catch (_) {}
  return null;
}

function hubSetFullscreen(on) {
  const win = hubGetWindowHandle();
  if (!win || typeof win.setFullscreen !== 'function') return Promise.resolve(false);
  return Promise.resolve()
    .then(() => win.setFullscreen(!!on))
    .then(() => true)
    .catch(() => false);
}

function hubMaximizeWindow() {
  try {
    const win = hubGetWindowHandle();
    if (win && typeof win.maximize === 'function') { win.maximize(); return true; }
  } catch (_) {}
  return false;
}

// Se ejecuta una sola vez, en el arranque posterior a la actualización.
function hubFullscreenAfterUpdate() {
  if (window.__hubFsBoot) return;
  window.__hubFsBoot = '1';
  let flag = null;
  try {
    flag = localStorage.getItem(HUB_FULLSCREEN_KEY);
    localStorage.removeItem(HUB_FULLSCREEN_KEY);
  } catch (_) {}
  if (flag !== '1') { bindHubFullscreenKeys(); return; }
  // Espera un instante a que la ventana termine de mostrarse.
  setTimeout(() => {
    hubSetFullscreen(true).then((ok) => {
      if (ok) showToast('Pantalla completa · F11 o Esc para salir');
      else if (hubMaximizeWindow()) showToast('Ventana maximizada');
    });
  }, 450);
  bindHubFullscreenKeys();
}

// Salir de la pantalla completa: F11 siempre; Esc solo si no hay modal abierto.
function bindHubFullscreenKeys() {
  if (window.__hubFsKeys) return;
  window.__hubFsKeys = '1';
  document.addEventListener('keydown', (e) => {
    const k = String((e && e.key) || '');
    if (k === 'F11') { e.preventDefault(); hubSetFullscreen(false); return; }
    if (k !== 'Escape') return;
    const modalOpen = !!document.querySelector('.modal-overlay:not(.hidden), .release-overlay:not(.hidden), .news-modal-overlay:not(.hidden)');
    if (modalOpen) return;
    hubSetFullscreen(false);
  });
}

// ── Changelog: una vez por versión ──────────────────────────────
// Contenido REAL de cada versión (el body de la release de GitHub es el
// texto genérico del instalador, no un changelog: acá va lo que cambió).
// Se agrega una línea por versión NUEVA cuando se publica.
const HUB_CHANGELOGS = {
  '3.3.7': [
    'Android: el setup inicial ya no pide ruta de descargas ni avisa de descargar OWS Hub; se puede completar sin complicaciones.'
  ],
  '3.3.6': [
    'Android: arreglada la instalación del APK al actualizar OWS Hub (error con la carpeta de caché).',
    'Si falla una descarga o instalación en Android, ahora se muestra un cuadro con el detalle completo y opción de copiarlo.',
    'Nuevo respaldo: descargar el APK desde el navegador si el instalador no se abre.'
  ],
  '3.3.5': [
    'El menú lateral muestra solo "OWS Hub": marca limpia y sin etiquetas redundantes.',
    'Textos renovados en toda la app: ahora se distingue el estudio (Ocean & Wild Studios) del producto (OWS Hub).',
    'El modal de cada proyecto indica el peso del archivo a descargar, calculado automáticamente.'
  ],
  '3.3.4': [
    'Noticias rediseñadas: tarjetas con la última noticia destacada y el resto en grilla.',
    'Clic en una noticia abre una pantalla completa con fecha, título e contenido completo.',
    'Con imagen vertical el modal se reorganiza: texto a la izquierda e imagen a la derecha.',
    'Las noticias ahora pueden traer su imagen de portada y se muestran al abrir el dashboard.'
  ],
  '3.3.3': [
    'Después de actualizar, OWS Hub se abre en pantalla completa (F11 o Esc para salir).',
    'El modal de novedades ahora muestra el changelog real de la versión.'
  ],
  '3.3.2': [
    'Arreglada la barra de progreso del toaster: ahora se llena mientras descarga la actualización.'
  ],
  '3.3.1': [
    'Tarjeta de actualización ordenada: botón de descarga junto al ícono y al nombre, notas debajo.',
    'El aviso de descarga se cierra solo cuando termina, justo antes del aviso de reinicio.',
    'Corregido el texto del aviso previo al reinicio.'
  ],
  '3.3.0': [
    'Actualización del Hub en 1 clic desde el Gestor de Actualizaciones.',
    'Aviso fijo con progreso real mientras descarga (ya no desaparece a los pocos segundos).',
    'Cuenta regresiva de 5 segundos antes de reiniciar, con "Reiniciar ahora" o "Ahora no".',
    'Novedades de la versión nueva, mostradas una sola vez por versión.'
  ]
};

// Mini-markdown (siempre se escapa PRIMERO: nunca se inyecta HTML del backend).
function hubMdEscape(text) {
  return String(text == null ? '' : text)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
function hubMdInline(escaped) {
  return String(escaped || '')
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
}
function hubMdLite(text) {
  const lines = hubMdEscape(text).split(/\r?\n/);
  const out = [];
  let inList = false;
  const flush = () => { if (inList) { out.push('</ul>'); inList = false; } };
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) { flush(); continue; }
    const m = line.match(/^[-*•]\s+(.+)$/) || line.match(/^\d+[.)]\s+(.+)$/);
    if (m) {
      if (!inList) { out.push('<ul class="hub-changelog-list">'); inList = true; }
      out.push('<li>' + hubMdInline(m[1]) + '</li>');
    } else {
      flush();
      out.push('<p>' + hubMdInline(line) + '</p>');
    }
  }
  flush();
  return out.join('');
}
function hubChangelogHtml(version, notes) {
  const key = String(version || '').replace(/^[vV]/, '');
  const items = HUB_CHANGELOGS[key];
  if (items && items.length) {
    return '<ul class="hub-changelog-list">' +
      items.map((t) => '<li>' + hubMdInline(hubMdEscape(t)) + '</li>').join('') +
      '</ul>';
  }
  const raw = String(notes || '').trim();
  return raw ? hubMdLite(raw) : '';
}

// Se escribe antes de reiniciar y se lee al arrancar: como solo se
// borra cuando se muestra, cada actualización vuelve a escribirlo y el
// modal aparece una única vez por versión.
function hubChangelogSave(version, notes) {
  try {
    localStorage.setItem(HUB_CHANGELOG_KEY, JSON.stringify({
      version: String(version || ''),
      notes: String(notes || ''),
      at: Date.now()
    }));
  } catch (_) {}
}

function showHubChangelogOnBoot() {
  let data = null;
  try {
    const raw = localStorage.getItem(HUB_CHANGELOG_KEY);
    if (raw) data = JSON.parse(raw);
  } catch (_) { data = null; }
  if (!data || !data.version) return;
  // Si la instalación se canceló (el Hub se cerró antes de reiniciar), el
  // registro queda viejo: se descarta en vez de mostrar novedades de una
  // versión que nunca llegó a instalarse.
  if (!Number.isFinite(data.at) || (Date.now() - data.at) > 30 * 60 * 1000) {
    try { localStorage.removeItem(HUB_CHANGELOG_KEY); } catch (_) {}
    return;
  }
  try { localStorage.removeItem(HUB_CHANGELOG_KEY); } catch (_) {}
  openHubChangelogModal(data.version, data.notes);
}

function openHubChangelogModal(version, notes) {
  const modal = document.getElementById('hub-changelog-modal');
  if (!modal) return;
  const verEl = document.getElementById('hub-changelog-ver');
  if (verEl) verEl.textContent = 'v' + String(version || '').replace(/^[vV]/, '');
  const body = document.getElementById('hub-changelog-body');
  if (body) {
    // Prioridad: el changelog curado de la versión. Si no está (una release
    // vieja o una que lleguemos a publicar sin entrar acá), se cae a las
    // notas de la release, con el mini-markdown de abajo.
    const html = hubChangelogHtml(version, notes);
    body.innerHTML = html;
    body.classList.toggle('hidden', !html);
  }
  modal.classList.remove('hidden');
  const btn = modal.querySelector('[data-close="hub-changelog-modal"].btn');
  if (btn) setTimeout(() => { try { btn.focus(); } catch (_) {} }, 60);
}

function closeHubChangelogModal() {
  const modal = document.getElementById('hub-changelog-modal');
  if (modal) modal.classList.add('hidden');
}

// ── Flujo completo ──────────────────────────────────────────────
async function runHubSelfUpdate(btn) {
  if (owsEnvironment() !== 'desktop') {
    showToast('Las actualizaciones del Hub se aplican desde la app 🖥');
    return;
  }
  if (hubUpdateBusy) { showToast('Ya hay una actualización del Hub en curso.'); return; }
  hubUpdateBusy = true;
  if (btn) btn.disabled = true;

  try {
    // 1) Check fresco: el rid tiene que ser el de esta sesión.
    const upd = await tauriUpdaterCall('plugin:updater|check', {}, 15000);
    if (!upd || typeof upd !== 'object' || upd.rid === undefined || upd.rid === null) {
      throw new Error('no hay actualizaciones disponibles');
    }
    const version = String(upd.version || '').replace(/^[vV]/, '');
    if (!version || version === String(upd.currentVersion || '').replace(/^[vV]/, '')) {
      throw new Error('ya estás en la última versión');
    }

    // 2) Toaster fijo con el progreso real de la descarga.
    hubUpdToastShow(version);
    let total = 0;
    let done = 0;
    const ch = tauriMakeChannel();
    if (!ch) throw new Error('WebView sin canal de Tauri (reabrí el Hub)');
    ch.onmessage = (msg) => {
      try {
        const ev = (msg && msg.event) || '';
        const data = (msg && msg.data) || {};
        if (ev === 'Started') {
          total = Number(data.contentLength || 0) || 0;
          done = 0;
          hubUpdToastPatch(0, total > 0 ? `0 MB / ${formatMB(total)}` : 'Conectando…', false);
        } else if (ev === 'Progress') {
          done += Number(data.chunkLength || 0) || 0;
          const pct = total > 0 ? (done / total) * 100 : 0;
          const info = total > 0
            ? `${Math.round(pct)}% · ${formatMB(done)} / ${formatMB(total)}`
            : `${formatMB(done)} descargados`;
          hubUpdToastPatch(pct, info, false);
        } else if (ev === 'Finished') {
          hubUpdToastPatch(100, '100% · descargado', true);
        }
      } catch (_) {}
    };

    // 3) Descargar (no instala todavía: el reinicio es un paso aparte).
    const bytesRid = await tauriUpdaterCall('plugin:updater|download', { rid: upd.rid, onEvent: ch }, 15 * 60 * 1000);
    hubUpdToastPatch(100, '100% · verificado ✓', true);

    // 4) Las novedades se guardan ahora: el reinicio borra la memoria.
    //    Se prefieren las notas de la release (las trae el backend, texto
    //    completo) y se cae al body del manifiesto si no están.
    const hubNotes = (updatesState.hub && updatesState.hub.notes) || '';
    hubChangelogSave(version, hubNotes || upd.body || '');

    // 5) Aviso de 5 s y, al terminar, instalar + reiniciar. El toaster solo
    //    vive mientras baja: al estar listo, el modal toma el protagonismo.
    hubPendingInstall = { rid: upd.rid, bytesRid: bytesRid };
    hubUpdToastHide();
    if (!openHubRestartModal(version)) { await doHubInstall(); return; }
    // hubUpdateBusy sigue en true: la descarga está hecha pero la instalación
    // pendiente, así que el botón no debe volver a activarse.
    renderHubUpdateCard();
    return;
  } catch (err) {
    hubUpdToastHide();
    const msg = String((err && err.message) || err);
    showToast('No se pudo actualizar el Hub: ' + msg);
    hubUpdateBusy = false;
    renderHubUpdateCard();
  }
}

// Aplica la actualización/instalación de un juego con el MISMO flujo del modal
// de Lanzamientos → el progreso vive en el Gestor de Descargas.
async function runProjectUpdate(slug) {
  const proj = getDownloadProject(slug);
  const name = (proj && proj.name) || slug;
  const row = (updatesState.projects || []).find((p) => String(p.slug) === String(slug));
  const version = String((row && row.latest_version) || (proj && (proj.itch_version || proj.itchVersion)) || '');
  closeUpdatesModal();
  showDownloadToastStarted(name);
  // Cambia a Descargas para que el progreso de esta actualización se vea de una.
  showOwsSection('sec-descargas', { smooth: true });
  await startDesktopInstallManaged(slug, version, name);
  // Cuando termine, el gestor se refresca (la versión local cambió).
  try { loadUpdatesManager({ force: true }); } catch (_) {}
}

// ── Modal de historial de versiones ─────────────────────────────
let updatesModalToken = 0;

async function openUpdatesChangelog(slug) {
  const row = (updatesState.projects || []).find((p) => String(p.slug) === String(slug));
  const proj = getDownloadProject(slug);
  const name = (row && row.name) || (proj && proj.name) || slug;
  const installed = String((row && row.installed_version) || '').trim();
  const modal = document.getElementById('updates-modal');
  const body = document.getElementById('updates-modal-body');
  if (!modal || !body) return;
  const token = ++updatesModalToken;
  body.innerHTML = `
    <h3 class="form-title">📜 Historial de versiones — ${escapeHtml(name)}</h3>
    <p class="form-hint">Builds de <b>${owsPlatformLabel(updatesState.platform || owsUpdatesPlatform())}</b> · ${installed ? `Tenés <b>v${escapeHtml(installed)}</b> instalada.` : 'Todavía no lo instalaste.'}</p>
    <div id="upd-changelog-list" class="upd-changelog"><p class="loading-note">Cargando historial…</p></div>`;
  modal.classList.remove('hidden');
  try { document.body.style.overflow = 'hidden'; } catch (_) {}

  const box = document.getElementById('upd-changelog-list');
  try {
    const params = ['platform=' + owsUpdatesPlatform()];
    if (installed) params.push('installed=' + encodeURIComponent(installed));
    const qs = '?' + params.join('&');
    const res = await fetchWithTimeout(API_BASE + '/ows-updates/projects/' + encodeURIComponent(slug) + '/releases' + qs, UPDATES_FETCH_TIMEOUT_MS);
    const data = await res.json().catch(() => ({}));
    if (token !== updatesModalToken || !box) return;
    const list = Array.isArray(data.releases) ? data.releases : [];
    if (!list.length) {
      box.innerHTML = `<p class="loading-note">Este proyecto todavía no tiene versiones publicadas.</p>`;
      return;
    }
    box.innerHTML = list.map((r) => {
      const when = r.released_at ? formatReleaseDate(r.released_at) : '—';
      const isCurrent = installed && String(r.version) === installed;
      const plat = String(r.platform || 'all');
      return `
        <div class="upd-changelog-item">
          <div class="upd-changelog-top">
            <span class="upd-ver-chip upd-ver-new">v${escapeHtml(r.version || '?')}</span>
            <span class="upd-changelog-channel">${escapeHtml(r.channel || 'stable')}</span>
            ${plat !== 'all' && plat !== owsUpdatesPlatform() ? `<span class="upd-changelog-channel">${plat === 'android' ? '🤖 Android' : '🪟 Windows'}</span>` : ''}
            ${isCurrent ? '<span class="upd-chip-current">Tu versión</span>' : ''}
            <span class="upd-changelog-date">${escapeHtml(when)}</span>
          </div>
          ${r.file_label || r.size_label ? `<p class="upd-changelog-file">📦 ${escapeHtml([r.file_label, r.size_label].filter(Boolean).join(' · '))}</p>` : ''}
          ${r.notes ? `<p class="upd-changelog-notes">${escapeHtml(r.notes)}</p>` : ''}
        </div>`;
    }).join('');
  } catch (err) {
    if (token !== updatesModalToken || !box) return;
    box.innerHTML = `<p class="loading-note">⚠️ ${escapeHtml(String((err && err.message) || err))}</p>`;
  }
}

function closeUpdatesModal() {
  const modal = document.getElementById('updates-modal');
  if (!modal || modal.classList.contains('hidden')) return;
  updatesModalToken += 1; // invalida responses en vuelo
  modal.classList.add('hidden');
  try { document.body.style.overflow = ''; } catch (_) {}
}

// Delegación de clicks del Gestor (sobrevive a re-renders).
function bindUpdatesManager() {
  const list = document.getElementById('updates-list');
  if (list && !list.dataset.bound) {
    list.dataset.bound = '1';
    list.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-upd-action]');
      if (!btn) return;
      const action = btn.getAttribute('data-upd-action');
      const slug = btn.getAttribute('data-slug') || '';
      if (action === 'refresh') loadUpdatesManager({ force: true });
      else if (action === 'update' || action === 'install') runProjectUpdate(slug);
      else if (action === 'changelog') openUpdatesChangelog(slug);
      else if (action === 'goto-releases') { showOwsSection('sec-lanzamientos', { smooth: true }); }
      else if (action === 'play' && window.OWSHubLibrary) {
        window.OWSHubLibrary.launch(slug).catch((err) => showToast('No se pudo lanzar: ' + ((err && err.message) || err)));
      }
    });
  }
  // Acciones de la tarjeta del Hub (no viven dentro de #updates-list).
  const hubCard = document.getElementById('upd-hub-card');
  if (hubCard && !hubCard.dataset.bound) {
    hubCard.dataset.bound = '1';
    hubCard.addEventListener('click', (e) => {
      const apk = e.target.closest('[data-upd-action="hub-apk"]');
      if (apk) { runHubAndroidUpdate(apk); return; }
      const btn = e.target.closest('[data-upd-action="hub-install"]');
      if (btn) runHubSelfUpdate(btn);
    });
  }
  const filters = document.getElementById('upd-filters');
  if (filters && !filters.dataset.bound) {
    filters.dataset.bound = '1';
    filters.addEventListener('click', (e) => {
      const chip = e.target.closest('[data-upd-filter]');
      if (chip) setUpdatesFilter(chip.getAttribute('data-upd-filter'));
    });
  }
  const btnRefresh = document.getElementById('btn-updates-refresh');
  if (btnRefresh && !btnRefresh.dataset.bound) {
    btnRefresh.dataset.bound = '1';
    btnRefresh.addEventListener('click', () => loadUpdatesManager({ force: true }));
  }
  const btnGoto = document.getElementById('btn-updates-goto-releases');
  if (btnGoto && !btnGoto.dataset.bound) {
    btnGoto.dataset.bound = '1';
    btnGoto.addEventListener('click', () => showOwsSection('sec-lanzamientos', { smooth: true }));
  }
  const modal = document.getElementById('updates-modal');
  if (modal && !modal.dataset.bound) {
    modal.dataset.bound = '1';
    modal.addEventListener('click', (e) => {
      if (e.target === modal || e.target.closest('[data-close="updates-modal"]')) closeUpdatesModal();
    });
  }
  // Aviso de "actualizar desde la app" (navegador).
  const gate = document.getElementById('upd-gate');
  const gateDl = document.getElementById('upd-gate-download');
  if (gate) gate.classList.toggle('hidden', !hubIsRequired());
  if (gateDl) {
    let rel = readOwsHubCache();
    if (!rel || !rel.url) fetchOwsHubRelease().then((r) => applyOwsHubRelease(r)).catch(() => {});
    gateDl.href = (rel && rel.url) || OWS_HUB_RELEASES_URL;
    if (rel && rel.assetName) gateDl.setAttribute('download', ''); else gateDl.removeAttribute('download');
  }

  bindHubUpdateFlow();
}

// ═══════════════════════════════════════════════
// Rework 3.3.0 — eventos de los nuevos modales del Hub.
// El de reinicio NO se cierra clickando fuera: el contador sigue y el Hub
// se reinicia igual (cancelar es un botón explícito). El de novedades sí
// se cierra como cualquier otro modal.
// ═══════════════════════════════════════════════
function bindHubUpdateFlow() {
  const now = document.getElementById('hub-restart-now');
  if (now && !now.dataset.bound) {
    now.dataset.bound = '1';
    now.addEventListener('click', () => doHubInstall());
  }
  const cancel = document.getElementById('hub-restart-cancel');
  if (cancel && !cancel.dataset.bound) {
    cancel.dataset.bound = '1';
    cancel.addEventListener('click', () => {
      closeHubRestartModal();
      hubUpdToastHide();
      hubPendingInstall = null;
      hubUpdateBusy = false;
      showToast('Actualización descargada. Volvé a pulsar Descargar para instalarla.');
      renderHubUpdateCard();
    });
  }
  const chModal = document.getElementById('hub-changelog-modal');
  if (chModal && !chModal.dataset.bound) {
    chModal.dataset.bound = '1';
    chModal.addEventListener('click', (e) => {
      if (e.target === chModal || e.target.closest('[data-close="hub-changelog-modal"]')) closeHubChangelogModal();
    });
  }
  // Novedades de la versión que se acaba de instalar: se muestra una vez por
  // versión (el registro se borra al mostrarse).
  if (!window.__hubChangelogChecked) {
    window.__hubChangelogChecked = '1';
    showHubChangelogOnBoot();
  }
  // Si venimos de una actualización, arranca en pantalla completa.
  try { hubFullscreenAfterUpdate(); } catch (_) {}
}

function tauriInvoke(cmd, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    let invoker = null;
    try {
      const core = window.__TAURI__ && window.__TAURI__.core;
      if (core && typeof core.invoke === 'function') invoker = (c, a) => core.invoke(c, a);
      else if (window.__TAURI_INTERNALS__ && typeof window.__TAURI_INTERNALS__.invoke === 'function') {
        invoker = (c, a) => window.__TAURI_INTERNALS__.invoke(c, a);
      }
    } catch (_) {}
    const run = invoker
      ? Promise.resolve().then(() => invoker(cmd, args || {}))
      : import('@tauri-apps/api/core').then((mod) => mod.invoke(cmd, args || {}));
    const timer = setTimeout(() => reject(new Error('timeout')), Number(timeoutMs) || 6000);
    run.then((v) => { clearTimeout(timer); resolve(v); })
       .catch((e) => { clearTimeout(timer); reject(e); });
  });
}

function setDirStatus(msg, cls) {
  const el = document.getElementById('setup-dir-status');
  if (!el) return;
  el.textContent = msg || '';
  el.className = 'setup-dir-status' + (cls ? ' ' + cls : '');
}

function setEnvBadge(env) {
  const badge = document.getElementById('setup-env-badge');
  if (!badge) return;
  if (env === 'desktop') {
    badge.textContent = '🖥 App desktop';
    badge.classList.add('is-desktop');
  } else if (env === 'android') {
    badge.textContent = '🤖 App Android';
    badge.classList.add('is-desktop');
  } else {
    badge.textContent = '🌐 Navegador';
    badge.classList.remove('is-desktop');
  }
}

// Carpeta detectada por el backend (por defecto). Si el usuario la cambia,
// downloadMode pasa a 'custom' y la instalación extrae ahí de verdad.
let owsDetectedLibraryDir = '';

function isValidLibraryDir(p) {
  const s = String(p || '').trim();
  if (s.length < 3) return false;
  // Windows: C:\..., C:/... o UNC \\... · Unix: /...
  return /^[a-zA-Z]:[\\/]/.test(s) || s.startsWith('\\\\') || s.startsWith('/');
}

function syncDirResetBtn() {
  const reset = document.getElementById('btn-setup-dir-reset');
  const input = document.getElementById('setup-download-dir');
  if (!reset || !input) return;
  const cur = String(input.value || '').trim();
  const show = owsEnvironment() === 'desktop'
    && !!owsDetectedLibraryDir
    && cur !== '' && cur !== owsDetectedLibraryDir;
  reset.classList.toggle('hidden', !show);
}

// Paso 1 realista según entorno:
// - Desktop: detecta la biblioteca REAL (get_library_dir la crea), la muestra
//   y te deja modificarla: escríbela o pulsa 📂 (explorador nativo real).
//   Al instalar, el juego se extrae en TU carpeta (el ZIP temporal queda en la
//   biblioteca por defecto, eso lo fija el backend).
// - Navegador: no existe carpeta elegible (el navegador manda) → lo dice claro.
async function renderDownloadStep() {
  const input = document.getElementById('setup-download-dir');
  const browse = document.getElementById('btn-setup-browse');
  const hint = document.getElementById('setup-dir-hint');
  const env = owsEnvironment();
  setEnvBadge(env);

  if (env === 'desktop') {
    if (browse) {
      browse.classList.remove('hidden');
      browse.title = 'Elegir carpeta con el explorador';
    }
    if (input) {
      input.readOnly = false;
      input.placeholder = 'Ej: C:\\Juegos\\OWS';
      // Respeta lo que el usuario ya escribió; si está vacío, detecta
      if (!String(input.value || '').trim()) {
        input.value = '';
        input.placeholder = 'Detectando biblioteca…';
        setDirStatus('⏳ Detectando tu biblioteca…');
        try {
          const real = await tauriInvoke('get_library_dir', {}, 6000);
          const dir = String(real || '').trim();
          if (!dir) throw new Error('vacía');
          owsDetectedLibraryDir = dir;
          input.value = dir;
          input.placeholder = 'Ej: C:\\Juegos\\OWS';
          saveOwsSettings({ downloadDir: dir, downloadMode: 'managed', libraryVerified: true });
          setDirStatus('✓ Biblioteca verificada y lista — puedes modificarla', 'ok');
        } catch (_) {
          const s = getOwsSettings();
          if (!input.value) input.value = s.downloadDir || defaultDownloadDir();
          saveOwsSettings({ downloadMode: 'managed', libraryVerified: false });
          setDirStatus('⚠ No se pudo auto-detectar: escríbela manualmente', 'warn');
        }
      } else {
        // Ya hay valor (viene de atrás/adelante en el wizard): valida y marca
        const cur = String(input.value).trim();
        if (owsDetectedLibraryDir && cur === owsDetectedLibraryDir) {
          setDirStatus('✓ Biblioteca verificada y lista — puedes modificarla', 'ok');
        } else if (isValidLibraryDir(cur)) {
          setDirStatus('✎ Carpeta personalizada — se usará al instalar', 'ok');
        }
        saveOwsSettings({ downloadDir: cur });
      }
    }
    if (hint) hint.textContent = 'Ahí se instalan tus juegos. Puedes escribir otra ruta o pulsar 📂 para elegirla con el explorador (↺ vuelve a la de por defecto).';
    syncDirResetBtn();
    return;
  }

  if (env === 'android') {
    if (input) {
      input.readOnly = true;
      input.value = 'Almacenamiento de la app (automático)';
    }
    if (browse) browse.classList.add('hidden');
    const rst = document.getElementById('btn-setup-dir-reset');
    if (rst) rst.classList.add('hidden');
    if (hint) hint.textContent = 'En Android no hace falta elegir carpeta: el APK se descarga solo y Android te pide instalarlo. Solo cambia el nick si quieres y continúa.';
    saveOwsSettings({ downloadMode: 'android', libraryVerified: false, downloadDir: '' });
    setDirStatus('✓ Listo: las descargas se gestionan solas en tu teléfono', 'ok');
    return;
  }

  // Navegador
  if (input) {
    input.readOnly = true;
    input.value = 'Carpeta de Descargas de tu navegador';
  }
  if (browse) browse.classList.add('hidden');
  const reset = document.getElementById('btn-setup-dir-reset');
  if (reset) reset.classList.add('hidden');
  if (hint) hint.textContent = '⚠ Estás en el navegador: aquí NO se pueden continuar las descargas. Descarga OWS Hub (gratis, botón del menú lateral) y ábrelo para descargar, instalar y jugar con 1 clic.';
  saveOwsSettings({ downloadMode: 'browser', libraryVerified: false, downloadDir: '' });
  setDirStatus('⛔ Sin descargas en navegador: necesitas OWS Hub', 'warn');
}

async function setupBrowseDir() {
  // En desktop, 📂 abre el explorador NATIVO (plugin dialog del backend).
  // En navegador el botón está oculto.
  if (owsEnvironment() !== 'desktop') {
    showSetupAlert('En navegador no se puede elegir carpeta: manda tu navegador. Usa la app desktop para biblioteca gestionada. 🖥', 'success');
    return;
  }
  const input = document.getElementById('setup-download-dir');
  try {
    setDirStatus('⏳ Abriendo el explorador…');
    const picked = await tauriInvoke('plugin:dialog|open', {
      options: { directory: true, multiple: false, title: 'Elige tu biblioteca de juegos OWS' },
    }, 60000);
    const dir = String(picked || '').trim();
    if (!dir) { syncDirResetBtn(); return; } // canceló: no pasa nada
    if (input) input.value = dir;
    saveOwsSettings({ downloadDir: dir, libraryVerified: false });
    setDirStatus('✎ Carpeta personalizada — se usará al instalar', 'ok');
    syncDirResetBtn();
    showSetupAlert('Carpeta elegida ✓ — pulsa Continuar para guardarla.', 'success');
  } catch (_) {
    setDirStatus('⚠ No se pudo abrir el explorador: escríbela manualmente', 'warn');
    if (input) input.focus();
  }
}

function showSetup(returnTo) {
  owsSetupReturn = returnTo === 'dashboard' ? 'dashboard' : 'auth';
  hideIntroInstant();
  const authSec = document.getElementById('auth-section');
  if (authSec) authSec.classList.add('hidden');
  const dashSec = document.getElementById('dashboard-section');
  if (dashSec) dashSec.classList.add('hidden');
  const sec = document.getElementById('setup-screen');
  if (!sec) { finishSetupDestination(true); return; }
  sec.classList.remove('hidden');
  try { sec.scrollIntoView({ block: 'start' }); } catch (_) {}
  owsSetupStep = 1;
  setupGoToStep(1, true);
}

function hideSetup() {
  const sec = document.getElementById('setup-screen');
  if (sec) sec.classList.add('hidden');
}

function showSetupAlert(msg, type) {
  const el = document.getElementById('setup-alert');
  if (!el) return;
  el.textContent = msg;
  el.className = 'alert-box ' + (type || 'error');
  el.classList.remove('hidden');
  if (window.gsap) { try { gsap.fromTo(el, { opacity: 0, y: 8 }, { opacity: 1, y: 0, duration: 0.3 }); } catch (_) {} }
}
function hideSetupAlert() {
  const el = document.getElementById('setup-alert');
  if (el) el.classList.add('hidden');
}

function setupGoToStep(n, instant) {
  owsSetupStep = Math.max(1, Math.min(3, Number(n) || 1));
  hideSetupAlert();
  document.querySelectorAll('.setup-pane').forEach((p) => {
    const pn = Number(p.getAttribute('data-pane') || '1');
    p.classList.toggle('hidden', pn !== owsSetupStep);
  });
  const pill = document.getElementById('setup-step-pill');
  const title = document.getElementById('setup-title');
  const sub = document.getElementById('setup-sub');
  const back = document.getElementById('btn-setup-back');
  const next = document.getElementById('btn-setup-next');
  const titles = {
    1: ['Configuremos tu Hub 🚀', 'Primero: ¿dónde guardamos tus juegos?'],
    2: ['Hazlo tuyo ✨', 'Elige cómo se ve tu OWS Hub.'],
    3: ['¿Arrancamos? 🎮', 'Revisa y entra a OWS Hub.'],
  };
  if (pill) pill.textContent = `Paso ${owsSetupStep} de 3`;
  if (title) title.textContent = titles[owsSetupStep][0];
  if (sub) sub.textContent = titles[owsSetupStep][1];
  if (back) back.classList.toggle('is-visible', owsSetupStep > 1);
  if (next) next.innerHTML = owsSetupStep === 3 ? '✅ Terminar y entrar →' : 'Continuar →';
  document.querySelectorAll('#setup-dots .setup-dot').forEach((d) => {
    const dn = Number(d.getAttribute('data-dot') || '1');
    d.classList.toggle('is-active', dn === owsSetupStep);
    d.classList.toggle('is-done', dn < owsSetupStep);
  });
  if (owsSetupStep === 1) { try { renderDownloadStep(); } catch (_) {} }
  if (owsSetupStep === 3) renderSetupSummary();
  const card = document.querySelector('.setup-card');
  if (card && window.gsap && !instant) {
    try {
      const pane = document.querySelector(`.setup-pane[data-pane="${owsSetupStep}"]`);
      gsap.fromTo(pane, { opacity: 0, x: 26 }, { opacity: 1, x: 0, duration: 0.4, ease: 'power3.out' });
    } catch (_) {}
  }
  if (card && window.gsap && instant) {
    try {
      gsap.fromTo(card, { opacity: 0, y: 30, scale: 0.98 }, { opacity: 1, y: 0, scale: 1, duration: 0.6, ease: 'power3.out' });
    } catch (_) {}
  }
}

function setupNext() {
  hideSetupAlert();
  if (owsSetupStep === 1) {
    const nick = (document.getElementById('setup-nick') || {}).value || '';
    const env = owsEnvironment();
    if (env === 'desktop') {
      const dir = String((document.getElementById('setup-download-dir') || {}).value || '').trim();
      if (!dir) {
        showSetupAlert('Falta tu biblioteca 📁 — pulsa 📂 o escríbela (ej: C:\\Juegos\\OWS).', 'error');
        authShakeSetup();
        return;
      }
      if (!isValidLibraryDir(dir)) {
        showSetupAlert('Esa ruta no parece válida 📁 — usa una absoluta (ej: C:\\Juegos\\OWS).', 'error');
        authShakeSetup();
        return;
      }
      const custom = !owsDetectedLibraryDir || dir !== owsDetectedLibraryDir;
      saveOwsSettings({
        downloadDir: dir,
        nick: String(nick).trim().slice(0, 24),
        downloadMode: custom ? 'custom' : 'managed',
        libraryVerified: !custom,
      });
    } else if (env === 'android') {
      saveOwsSettings({ nick: String(nick).trim().slice(0, 24), downloadMode: 'android', downloadDir: '', libraryVerified: false });
    } else {
      // Navegador: no hay ruta que validar, solo se guarda el nick
      saveOwsSettings({ nick: String(nick).trim().slice(0, 24), downloadMode: 'browser', downloadDir: '' });
    }
    setupGoToStep(2);
  } else if (owsSetupStep === 2) {
    const notifs = document.getElementById('setup-opt-notifs');
    const auto = document.getElementById('setup-opt-autolaunch');
    const news = document.getElementById('setup-opt-news');
    saveOwsSettings({
      notifs: !notifs || !!notifs.checked,
      autoLaunch: !auto || !!auto.checked,
      showNews: !news || !!news.checked,
    });
    setupGoToStep(3);
  } else {
    // Finalizar
    markSetupDone();
    saveOwsSettings({});
    finishSetupDestination(false);
  }
}

function setupBack() {
  if (owsSetupStep > 1) setupGoToStep(owsSetupStep - 1);
}

function authShakeSetup() {
  const card = document.querySelector('.setup-card');
  if (!card) return;
  if (window.gsap) {
    try { gsap.fromTo(card, { x: 0 }, { keyframes: [{ x: -8 }, { x: 7 }, { x: -4 }, { x: 0 }], duration: 0.4 }); return; } catch (_) {}
  }
}

function renderSetupSummary() {
  const box = document.getElementById('setup-summary');
  if (!box) return;
  const s = getOwsSettings();
  const nick = (document.getElementById('setup-nick') || {}).value || s.nick || '—';
  const isAndroidMode = owsEnvironment() === 'android';
  const isBrowserMode = !isAndroidMode && (s.downloadMode || owsEnvironment()) === 'browser';
  const isCustom = s.downloadMode === 'custom';
  const dir = isAndroidMode
    ? 'Almacenamiento de la app (automático)'
    : isBrowserMode
    ? 'Descargas del navegador'
    : ((document.getElementById('setup-download-dir') || {}).value || s.downloadDir || defaultDownloadDir());
  const on = (v) => (v ? 'Sí ✓' : 'No');
  const esc = (typeof escapeHtml === 'function') ? escapeHtml : (t) => String(t || '');
  box.innerHTML = `
    <dl class="setup-summary-row"><dt>🖥 Entorno</dt><dd>${isAndroidMode ? 'App Android ✓' : (isBrowserMode ? 'Navegador 🌐' : 'App desktop ✓')}</dd></dl>
    <dl class="setup-summary-row"><dt>📁 Descargas en</dt><dd><code>${esc(dir)}</code>${isCustom ? ' ✎' : ''}</dd></dl>
    <dl class="setup-summary-row"><dt>🎮 Nick</dt><dd>${esc(nick || '—')}</dd></dl>
    <dl class="setup-summary-row"><dt>🔔 Notificaciones</dt><dd>${on(s.notifs)}</dd></dl>
    <dl class="setup-summary-row"><dt>🚀 Auto-abrir juegos</dt><dd>${on(s.autoLaunch)}</dd></dl>
    <dl class="setup-summary-row"><dt>📰 Noticias en inicio</dt><dd>${on(s.showNews)}</dd></dl>
  `;
  if (window.gsap) { try { gsap.fromTo(box, { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: 0.4 }); } catch (_) {} }
}

// ═══════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════

function showAlert(id, msg, type) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent  = msg;
  el.className    = `alert-box ${type}`;
  el.classList.remove('hidden');
}

function hideAlert(id) {
  const el = document.getElementById(id);
  if (el) el.classList.add('hidden');
}

let _toastTimer = null;
function showToast(msg) {
  const el = document.getElementById('toast');
  if (!el) return;
  // Los errores del backend pueden traer rutas larguísimas: se acotan para que
  // el toast no se deforme en una banda gigante de texto diminuto.
  const raw = String(msg || '');
  el.textContent = raw.length > 220 ? `${raw.slice(0, 217)}…` : raw;
  el.classList.remove('hidden');
  if (_toastTimer) clearTimeout(_toastTimer);
  // Los mensajes largos necesitan más tiempo para poder leerse.
  _toastTimer = setTimeout(() => el.classList.add('hidden'), raw.length > 120 ? 6000 : 3500);
}

let _toastDlTimer = null;
// Si el usuario está en otra sección, el aviso lo da el toaster de arriba
// (con progreso en vivo). Acá solo va el toast cuando ya está en el Gestor.
function showDownloadToastStarted(gameName) {
  const name = String(gameName || 'juego').trim() || 'juego';
  try { syncDlToaster(); } catch (_) {}
  if (owsCurrentView !== 'sec-descargas') return;
  showToast(`⬇ ${name} — la descarga ya aparece en el Gestor 👇`);
  const dl = document.getElementById('toast-dl');
  if (!dl) return;
  dl.innerHTML = `⬇ <b>&nbsp;${escapeHtml(name)} descargándose…&nbsp;</b>`;
  dl.classList.remove('hidden');
  if (_toastDlTimer) clearTimeout(_toastDlTimer);
  _toastDlTimer = setTimeout(() => dl.classList.add('hidden'), 4000);
}
