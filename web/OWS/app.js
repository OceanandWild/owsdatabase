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

// Reescribe URLs de la API hacia la base sana actual (failover ows-api-failover.js):
// si owsdatabase.onrender.com no responde, los links de descarga usan el espejo.
// URLs de otros hosts (GitHub, Cloudinary, itch.io) quedan intactas.
function apiUrl(url) {
  try {
    const fo = window.OWS_API_FAILOVER;
    if (fo && typeof fo.preferredUrl === 'function') return fo.preferredUrl(String(url));
  } catch (_) {}
  return String(url);
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
  ['event-modal', 'release-modal', 'announce-modal', 'news-modal', 'pcl-modal'].forEach((id) => {
    const overlay = document.getElementById(id);
    if (!overlay) return;
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay || (id === 'news-modal' && e.target.classList && e.target.classList.contains('news-modal'))) {
        if (id === 'event-modal') closeEventModal();
        else if (id === 'release-modal') closeReleaseModal();
        else if (id === 'news-modal') closeNewsModal();
        else if (id === 'pcl-modal') closeProjectChangelogModal();
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
      else if (id === 'pcl-modal') closeProjectChangelogModal();
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
      const ev = eventsRenderList[idx] || eventsCache[idx];
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
  // Reintento del estado de error de Noticias (botón único dentro de #news-empty)
  const newsEmpty = document.getElementById('news-empty');
  if (newsEmpty && !newsEmpty.dataset.retryBound) {
    newsEmpty.dataset.retryBound = '1';
    newsEmpty.addEventListener('click', (e) => {
      if (!e.target.closest('[data-news-retry]')) return;
      e.preventDefault();
      loadDashboardNews();
    });
  }
  // Changelogs de Proyectos: delegación en la lista (sobrevive a re-renders).
  // Un clic en la cabecera despliega el proyecto; uno en una versión abre el modal.
  const clList = document.getElementById('cl-list');
  if (clList && !clList.dataset.bound) {
    clList.dataset.bound = '1';
    clList.addEventListener('click', (e) => {
      if (e.target.closest('[data-cl-retry]')) {
        e.preventDefault();
        loadProjectChangelogs();
        return;
      }
      const verBtn = e.target.closest('[data-pcl-slug]');
      if (verBtn) {
        e.preventDefault();
        openProjectChangelogModal(verBtn.getAttribute('data-pcl-slug'), verBtn.getAttribute('data-pcl-ver'));
        return;
      }
      const head = e.target.closest('[data-cl-toggle]');
      if (head) {
        e.preventDefault();
        toggleProjectChangelog(head.getAttribute('data-cl-toggle'));
      }
    });
  }
  // Modal del changelog: salto directo al proyecto dentro de Lanzamientos.
  const pclBody = document.getElementById('pcl-modal-body');
  if (pclBody && !pclBody.dataset.bound) {
    pclBody.dataset.bound = '1';
    pclBody.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-pcl-goto-release]');
      if (!btn) return;
      e.preventDefault();
      const slug = btn.getAttribute('data-pcl-goto-release');
      closeProjectChangelogModal();
      showOwsSection('sec-lanzamientos');
      const proj = (typeof releasesCache !== 'undefined' ? releasesCache : [])
        .find((x) => String(x.slug) === String(slug));
      if (proj) setTimeout(() => { try { openReleaseModal(proj); } catch (_) {} }, 280);
    });
  }
  // Reintento manual de Lanzamientos: delegado en document porque el aviso
  // puede vivir en #rel-retry (fuera de la grilla) o dentro de #releases-grid.
  if (!document.body.dataset.relRetryBound) {
    document.body.dataset.relRetryBound = '1';
    document.addEventListener('click', (e) => {
      const retry = e.target.closest && e.target.closest('[data-releases-retry]');
      if (!retry) return;
      e.preventDefault();
      loadDashboardReleases();
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
      const item = e.target.closest('[data-slug]');
      if (!item) return;
      // Doble clic llega como 2 clicks seguidos: el 2º abre el modal directamente
      if (relClickTimer) {
        try { clearTimeout(relClickTimer); } catch (_) {}
        relClickTimer = null;
        if (!item.classList.contains('is-open')) toggleDockItem(item);
        const p = findProject(item.getAttribute('data-slug'));
        if (p) openReleaseModal(p, item);
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
      if (p) openReleaseModal(p, item);
    });
    releasesGrid.addEventListener('keydown', (e) => {
      const item = e.target.closest ? e.target.closest('[data-slug]') : null;
      if (!item) return;
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        // Enter simple = preview · con Ctrl/Cmd+Enter = modal directo (accesible sin ratón)
        if ((e.ctrlKey || e.metaKey)) {
          const p = findProject(item.getAttribute('data-slug'));
          if (p) openReleaseModal(p, item);
        } else {
          toggleDockItem(item);
        }
      }
    });
  }

  // ── Hero destacado + catálogo: 1 clic = detalles ──
  // Se delega en un único contenedor (#rel-body) para no atar listeners a
  // cada render. El dock conserva su propio comportamiento (1/2 clics).
  const relBody = document.getElementById('rel-body');
  if (relBody && !relBody.dataset.bound) {
    relBody.dataset.bound = '1';
    const openBySlug = (slug, card) => {
      const p = releasesCache.find((x) => String(x.slug) === String(slug));
      if (p) openReleaseModal(p, releaseFlipSource(card));
    };
    relBody.addEventListener('click', (e) => {
      // Un enlace real (itch.io) se abre solo: no debe disparar también el modal.
      if (e.target.closest('a[href]')) return;
      const filter = e.target.closest('[data-rel-filter]');
      if (filter) { setReleasesFilter(filter.getAttribute('data-rel-filter')); return; }
      const card = e.target.closest('[data-slug]');
      if (card) openBySlug(card.getAttribute('data-slug'), card);
    });
    relBody.addEventListener('keydown', (e) => {
      const card = e.target.closest && e.target.closest('[data-slug]');
      if (!card || e.target.closest('a[href], button')) return;
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        openBySlug(card.getAttribute('data-slug'), card);
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
const OWS_VIEWS = ['view-inicio', 'sec-modulos', 'sec-noticias', 'sec-lanzamientos', 'sec-changelogs', 'sec-eventos', 'sec-descargas', 'sec-actualizaciones'];
const OWS_VIEW_ROUTES = {
  'inicio': 'view-inicio',
  'modulos': 'sec-modulos',
  'noticias': 'sec-noticias',
  'lanzamientos': 'sec-lanzamientos',
  'changelogs': 'sec-changelogs',
  'eventos': 'sec-eventos',
  'descargas': 'sec-descargas',
  'actualizaciones': 'sec-actualizaciones',
  // compat con hashes viejos (#sec-modulos, #top, ...)
  'view-inicio': 'view-inicio',
  'sec-modulos': 'sec-modulos',
  'sec-noticias': 'sec-noticias',
  'sec-lanzamientos': 'sec-lanzamientos',
  'sec-changelogs': 'sec-changelogs',
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
  'sec-changelogs': 'Changelogs',
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

  // Noticias: mismo criterio que Lanzamientos. Al entrar, si nunca cargó o
  // falló, se reintenta (el plan gratuito de Render puede estar despertando).
  if (target === 'sec-noticias') {
    if (!newsLoading && newsLoadState !== 'ready') { try { loadDashboardNews(); } catch (_) {} }
    if (!quickNewsLoading && quickNewsLoadState !== 'ready') { try { loadQuickNews(); } catch (_) {} }
  }

  // Eventos: si la última carga falló, se reintenta al entrar.
  if (target === 'sec-eventos' && !eventsLoading && eventsLoadState !== 'ready') {
    try { loadDashboardEvents(); } catch (_) {}
  }

  // Changelogs de Proyectos: mismo criterio (el servidor puede estar despertando).
  if (target === 'sec-changelogs' && !pclLoading && pclLoadState !== 'ready') {
    try { loadProjectChangelogs(); } catch (_) {}
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
  bindTrailerPlayers();
  initDownloadsManager();
  initOwsSettings();
  initOwsHubPanel();
  bindSetupWizard();
  bindIntroButtons();
  // Rework 3.3.0: modales de reinicio/novedades + changelog de la versión
  // recién instalada. Va acá (y no dentro del bloque de sesión) para que
  // las novedades aparezcan siempre, haya sesión o no.
  try { bindHubUpdateFlow(); } catch (_) {}
  // La etiqueta de versión se toma del binario, no del texto fijo del HTML.
  // Va antes de que nada más la lea.
  try { syncHubVersionLabelFromBinary(); } catch (_) {}
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
    loadQuickNews();
    loadDashboardEvents();
    // Cuenta atrás de eventos viva (30 s): sin refetch salvo que expire una.
    try { startEventsCountdownTicker(); } catch (_) {}
    loadDashboardReleases();
    loadProjectChangelogs();
    syncProjectChangelogsTag();
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
      loadQuickNews();
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

let eventsCache = [];
// Eventos tal como se pintaron (tras filtro por proyecto + estado y orden).
// El modal se abre por índice, así que este array es el que manda.
let eventsRenderList = [];
// Estado de la carga de eventos: evita encadenar fetches y permite
// reintentar solo al entrar a la vista si la última carga falló.
let eventsLoadState = 'idle'; // idle | loading | ready | error
let eventsLoading = false;
// Filtro por proyecto de la sección Eventos: 'all' o el id/nombre del proyecto.
let eventsProjectFilter = 'all';

// Etiqueta pública del proyecto de un evento. Los proyectos solo-admin no
// muestran su nombre: se ven como "Proyecto interno" (lo sabe el backend).
function eventProjectLabel(ev) {
  if (!ev) return 'OWS';
  if (ev.project_is_admin) return 'Proyecto interno';
  return String(ev.project_name || 'OWS');
}

// Clave con la que se agrupa/filtra: el id si está vinculado, si no el nombre.
function eventProjectKey(ev) {
  if (!ev) return 'ows';
  if (ev.project_id != null) return `id:${Number(ev.project_id)}`;
  return `name:${String(ev.project_name || 'OWS').trim().toLowerCase()}`;
}

// ── Fecha esperada de inicio ───────────────────────────────────
// El admin puede publicar el inicio como tentativo: se muestra "Fecha
// esperada: … (por confirmar)" y NO se promete cuenta atrás exacta.
function eventStartsExpected(ev) {
  return !!(ev && (ev.starts_expected === true || ev.startsExpected === true));
}

// Solo los eventos que todavía no empezaron muestran la fecha como esperada:
// una vez en curso (o terminado) manda la fecha real.
function eventShowsExpectedDate(ev) {
  if (!eventStartsExpected(ev)) return false;
  return ev.phase !== 'active' && ev.phase !== 'ended';
}

// ── Marca de agua del proyecto (eventos y noticias) ────────────
// El backend adjunta `project_watermark` cuando el proyecto la tiene
// activada en el Admin. Se dibuja como chip sobre la portada del evento o
// de la noticia; es solo decorativa (no captura el click de la tarjeta).
const WATERMARK_POSITIONS = ['top-left', 'top-right', 'bottom-left', 'bottom-right', 'center'];

function watermarkPosition(value) {
  const pos = String(value || '').trim().toLowerCase();
  return WATERMARK_POSITIONS.includes(pos) ? pos : 'bottom-right';
}

function watermarkChip(item, opts) {
  const wm = (item && (item.project_watermark || item.projectWatermark)) || null;
  if (!wm || wm.enabled === false) return '';
  const text = String(wm.text || '').trim();
  if (!text) return '';
  let opacity = Number(wm.opacity);
  if (!Number.isFinite(opacity)) opacity = 35;
  opacity = Math.max(5, Math.min(100, Math.round(opacity)));
  const big = opts && opts.big ? ' wm-big' : '';
  return `<span class="img-watermark wm-${watermarkPosition(wm.position)}${big}" style="opacity:${(opacity / 100).toFixed(2)}" aria-hidden="true">${escapeHtml(text)}</span>`;
}

// ── Chips de estado de la sección Eventos ──────────────────────
// Todos / En curso / Próximos / Finalizados, con el conteo en vivo.
// El filtro por proyecto del select se combina con estos chips.
let eventsStatusFilter = 'all';

function eventStatusKey(ev) {
  const phase = String((ev && ev.phase) || '').trim().toLowerCase();
  if (phase === 'active') return 'live';
  if (phase === 'ended') return 'ended';
  return 'upcoming';
}

function eventsStatusCounts(list) {
  const counts = { all: 0, live: 0, upcoming: 0, ended: 0 };
  (Array.isArray(list) ? list : []).forEach((ev) => {
    counts.all += 1;
    const key = eventStatusKey(ev);
    counts[key] = (counts[key] || 0) + 1;
  });
  return counts;
}

function updateEventsStatusFilter(list) {
  const box = document.getElementById('events-status-filter');
  if (!box) return;
  const counts = eventsStatusCounts(list);
  const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = String(val); };
  set('ev-count-all', counts.all);
  set('ev-count-live', counts.live);
  set('ev-count-upcoming', counts.upcoming);
  set('ev-count-ended', counts.ended);
  box.querySelectorAll('[data-evstatus]').forEach((btn) => {
    const key = btn.getAttribute('data-evstatus') || 'all';
    const active = key === eventsStatusFilter;
    btn.classList.toggle('is-active', active);
    btn.setAttribute('aria-pressed', active ? 'true' : 'false');
    btn.classList.toggle('is-empty', key !== 'all' && !counts[key]);
  });
  if (!box.dataset.bound) {
    box.dataset.bound = '1';
    box.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-evstatus]');
      if (btn) setEventsStatusFilter(btn.getAttribute('data-evstatus'));
    });
  }
}

function setEventsStatusFilter(value) {
  const next = ['all', 'live', 'upcoming', 'ended'].includes(String(value)) ? String(value) : 'all';
  if (next === eventsStatusFilter) return;
  eventsStatusFilter = next;
  renderEvents(eventsCache);
}

// ── Desaparición automática de eventos ─────────────────────────
// El admin puede fijar cuándo se quita un evento terminado. Mientras corre la
// cuenta atrás, la tarjeta muestra "Desaparece en …" (semanas → días → horas →
// minutos → segundos); al llegar la fecha, la tarjeta se va sola del calendario.
function eventExpiresAt(ev) {
  const raw = ev && (ev.expires_at || ev.expiresAt);
  if (!raw) return '';
  const ts = Date.parse(raw);
  return Number.isFinite(ts) ? new Date(ts).toISOString() : '';
}

function eventExpiresInMs(ev) {
  const iso = eventExpiresAt(ev);
  if (!iso) return NaN;
  return Date.parse(iso) - Date.now();
}

// Texto largo y dinámico: "2 semanas, 3 días y 5 horas" cuando falta más de
// una semana; "4 días y 6 horas" cuando falta menos de una semana; "5 horas,
// 20 minutos y 9 segundos" cuando falta menos de un día, etc.
function lapseLabel(ms) {
  if (!Number.isFinite(ms) || ms < 0) ms = 0;
  const total = Math.floor(ms / 1000);
  const weeks = Math.floor(total / (7 * 86400));
  const days = Math.floor((total % (7 * 86400)) / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  const parts = [];
  const push = (n, one, many) => { if (n > 0) parts.push(`${n} ${n === 1 ? one : many}`); };
  if (weeks > 0) {
    push(weeks, 'semana', 'semanas');
    push(days, 'día', 'días');
    push(hours, 'hora', 'horas');
  } else if (days > 0) {
    push(days, 'día', 'días');
    push(hours, 'hora', 'horas');
    push(minutes, 'minuto', 'minutos');
  } else if (hours > 0) {
    push(hours, 'hora', 'horas');
    push(minutes, 'minuto', 'minutos');
    push(seconds, 'segundo', 'segundos');
  } else if (minutes > 0) {
    push(minutes, 'minuto', 'minutos');
    push(seconds, 'segundo', 'segundos');
  } else {
    push(seconds, 'segundo', 'segundos');
  }
  if (!parts.length) return '0 minutos';
  if (parts.length === 1) return parts[0];
  return `${parts.slice(0, -1).join(', ')} y ${parts[parts.length - 1]}`;
}

// Versión compacta para la tarjeta: "2s 3d", "4d 6h", "5h 20m", "20m 9s", "9s".
function lapseLabelShort(ms) {
  if (!Number.isFinite(ms) || ms < 0) ms = 0;
  const total = Math.floor(ms / 1000);
  const weeks = Math.floor(total / (7 * 86400));
  const days = Math.floor((total % (7 * 86400)) / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  if (weeks > 0) return `${weeks}s ${days}d`;
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

// ── Cuenta atrás viva ──────────────────────────────────────────
// Las cuentas atrás (inicio y desaparición) se refrescan solas: cada segundo
// si hay algo en horas/minutos/segundos, cada 15 s si faltan horas y cada 30 s
// si falta un día o más. Sin refetch: solo se reescribe el texto. Cuando un
// evento cumple su fecha de desaparición, la tarjeta se quita al instante y el
// feed se recarga (con enfriamiento para no encadenar pedidos).
const EVENTS_TICK_FAST_MS = 1000;
const EVENTS_TICK_MID_MS = 15000;
const EVENTS_TICK_SLOW_MS = 30000;
let eventsTickTimer = null;
let eventsLastCountdownReload = 0;
let eventsLastGoneReload = 0;

function eventsTickIntervalMs() {
  let interval = EVENTS_TICK_SLOW_MS;
  document.querySelectorAll('[data-ev-expiry]').forEach((el) => {
    const ms = Date.parse(el.getAttribute('data-ev-expiry') || '') - Date.now();
    if (!Number.isFinite(ms) || ms <= 0) return;
    if (ms < 3600000) interval = EVENTS_TICK_FAST_MS;
    else if (ms < 86400000 && interval > EVENTS_TICK_MID_MS) interval = EVENTS_TICK_MID_MS;
  });
  return interval;
}

function refreshEventCountdowns() {
  let anyStartExpired = false;
  document.querySelectorAll('[data-ev-countdown]').forEach((el) => {
    const iso = el.getAttribute('data-ev-countdown') || '';
    const phase = el.getAttribute('data-ev-phase') || '';
    const text = eventCountdown(iso, phase);
    if (!text) { anyStartExpired = true; return; }
    if (el.textContent !== text) el.textContent = text;
  });

  let anyGone = false;
  document.querySelectorAll('[data-ev-expiry]').forEach((el) => {
    const iso = el.getAttribute('data-ev-expiry') || '';
    const ms = Date.parse(iso) - Date.now();
    if (!Number.isFinite(ms)) return;
    if (ms <= 0) {
      // Se cumplió la fecha: el evento desaparece de OWS.
      anyGone = true;
      const card = el.closest('.event-card');
      if (card) card.remove();
      return;
    }
    const text = `🗑️ Desaparece en ${lapseLabelShort(ms)}`;
    if (el.textContent !== text) el.textContent = text;
    const long = `Desaparece de OWS en ${lapseLabel(ms)}`;
    if (el.getAttribute('title') !== long) el.setAttribute('title', long);
  });

  const grid = document.getElementById('events-grid');
  if (anyGone) {
    if (grid && !grid.children.length) {
      const empty = document.getElementById('events-empty');
      if (empty) empty.classList.remove('hidden');
    }
    if (eventsLoadState === 'ready' && !eventsLoading && Date.now() - eventsLastGoneReload > 15000) {
      eventsLastGoneReload = Date.now();
      loadDashboardEvents();
    }
  } else if (anyStartExpired && eventsLoadState === 'ready' && !eventsLoading && Date.now() - eventsLastCountdownReload > 120000) {
    eventsLastCountdownReload = Date.now();
    loadDashboardEvents();
  }
}

function scheduleEventsTick() {
  if (eventsTickTimer) clearTimeout(eventsTickTimer);
  eventsTickTimer = setTimeout(() => {
    refreshEventCountdowns();
    scheduleEventsTick();
  }, eventsTickIntervalMs());
}

function startEventsCountdownTicker() {
  if (eventsTickTimer) return;
  scheduleEventsTick();
}


// Opciones del filtro: una por proyecto presente entre los eventos.
// El estado (eventsProjectFilter) manda: el select solo lo refleja.
function renderEventsProjectFilter() {
  const sel = document.getElementById('events-filter-project');
  if (!sel) return;
  const seen = new Map();
  eventsCache.forEach((ev) => {
    const key = eventProjectKey(ev);
    if (!seen.has(key)) seen.set(key, eventProjectLabel(ev));
  });
  const rows = [...seen.entries()].sort((a, b) => a[1].localeCompare(b[1]));
  sel.innerHTML = '<option value="all">Todos los proyectos</option>' +
    rows.map(([key, label]) => `<option value="${escapeHtml(key)}">${escapeHtml(label)}</option>`).join('');
  // Si el proyecto filtrado dejó de existir, se vuelve a "todos".
  if (eventsProjectFilter !== 'all' && !rows.some(([key]) => key === eventsProjectFilter)) {
    eventsProjectFilter = 'all';
  }
  sel.value = eventsProjectFilter;
}

function onEventsProjectFilter(value) {
  eventsProjectFilter = value || 'all';
  renderEvents(eventsCache);
}

function renderEvents(eventsList) {
  const grid = document.getElementById('events-grid');
  const empty = document.getElementById('events-empty');
  const statEvents = document.getElementById('stat-events');
  if (!grid || !empty) return;

  let items = Array.isArray(eventsList) ? eventsList.slice() : [];
  if (statEvents) statEvents.textContent = items.length;
  eventsCache = items;
  renderEventsProjectFilter();
  updateEventsStatusFilter(items);
  const totalCount = items.length;
  if (eventsProjectFilter && eventsProjectFilter !== 'all') {
    items = items.filter((ev) => eventProjectKey(ev) === eventsProjectFilter);
  }
  if (eventsStatusFilter !== 'all') {
    items = items.filter((ev) => eventStatusKey(ev) === eventsStatusFilter);
  }
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
    syncNavBadges(newsEl ? newsEl.textContent : 0, totalCount);
  } catch (_) {}
  const noteEl = document.getElementById('events-status-note');
  if (noteEl) {
    const narrowed = (eventsProjectFilter && eventsProjectFilter !== 'all') || eventsStatusFilter !== 'all';
    noteEl.textContent = narrowed && totalCount ? `Mostrando ${items.length} de ${totalCount}` : '';
  }
  if (items.length === 0) {
    eventsRenderList = [];
    grid.innerHTML = '';
    const emptyTitle = empty.querySelector('.events-empty-title');
    const emptySub = empty.querySelector('.events-empty-sub');
    const filtered = totalCount > 0;
    if (emptyTitle) emptyTitle.textContent = filtered ? 'No hay eventos con este filtro' : 'No hay eventos programados';
    if (emptySub) {
      emptySub.textContent = filtered
        ? 'Probá con otro estado o volvé a "Todos" para ver el calendario completo.'
        : 'Cuando haya actualizaciones, lanzamientos o eventos, aparecerán aquí.';
    }
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');
  eventsRenderList = items;

  grid.innerHTML = items.map((ev, evIdx) => {
    const meta = eventCategoryMeta(ev.category);
    const hasImg = Boolean(ev.image_url || ev.cover_url);
    const img = escapeHtml(ev.image_url || ev.cover_url || '');
    const phaseClass = ev.phase === 'active' ? 'ev-active' : ev.phase === 'ended' ? 'ev-ended' : 'ev-upcoming';
    const expected = eventShowsExpectedDate(ev);
    // Desaparición automática: cuenta atrás viva sobre la tarjeta.
    const expiryIso = eventExpiresAt(ev);
    const expiresIn = eventExpiresInMs(ev);
    const disappearing = Boolean(expiryIso) && Number.isFinite(expiresIn) && expiresIn > 0;
    const expiryAttr = disappearing ? ` data-ev-expiry="${escapeHtml(expiryIso)}"` : '';
    const expiryShort = disappearing ? lapseLabelShort(expiresIn) : '';
    const expiryLong = disappearing ? `Desaparece de OWS en ${lapseLabel(expiresIn)}` : '';
    const phaseBadge = ev.phase === 'active'
      ? '<span class="ev-badge ev-badge-live">● En curso</span>'
      : ev.phase === 'ended'
        ? (disappearing
            ? `<span class="ev-badge ev-badge-expiry"${expiryAttr} title="${escapeHtml(expiryLong)}">🗑️ Desaparece en ${escapeHtml(expiryShort)}</span>`
            : '<span class="ev-badge ev-badge-ended">Finalizado</span>')
        : expected
          ? '<span class="ev-badge ev-badge-expected" title="Fecha esperada de inicio, todavía por confirmar">🕰️ Fecha por confirmar</span>'
          : `<span class="ev-badge ev-badge-soon" data-ev-countdown="${escapeHtml(ev.starts_at || '')}" data-ev-phase="${escapeHtml(ev.phase || '')}">${escapeHtml(eventCountdown(ev.starts_at, ev.phase)) || 'Próximamente'}</span>`;
    // En curso con desaparición: se avisa en el cuerpo (el badge lo ocupa "En curso").
    const expiryNote = disappearing && ev.phase === 'active'
      ? `<span class="event-card-note"${expiryAttr} title="${escapeHtml(expiryLong)}">🗑️ Se quita en ${escapeHtml(expiryShort)}</span>`
      : '';
    // Programados: marcador invisible para que la tarjeta también se vaya sola
    // si la fecha de desaparición llega mientras el evento sigue programado.
    const expiryMarker = disappearing && ev.phase !== 'active' && ev.phase !== 'ended'
      ? `<span class="ev-expiry-marker"${expiryAttr} style="display:none" aria-hidden="true">${escapeHtml(expiryShort)}</span>`
      : '';
    const dateRange = escapeHtml(formatEventRange(ev.starts_at, ev.ends_at));
    const dateLine = expected
      ? `<span class="event-card-date is-expected" title="Fecha esperada de inicio, por confirmar">🕰️ Fecha esperada: ${dateRange} <span class="ev-date-note">(por confirmar)</span></span>`
      : `<span class="event-card-date">📅 ${dateRange}</span>`;
    return `
      <article class="event-card glass-card ${phaseClass} ${hasImg ? '' : 'ev-noimg'}" data-ev-idx="${evIdx}" role="button" tabindex="0">
        <div class="event-card-media">
          ${hasImg
            ? `<img src="${img}" alt="${escapeHtml(ev.title)}" class="event-card-img" loading="lazy" />`
            : `<div class="event-card-img-fallback"><span>${meta.icon}</span></div>`}
          <div class="event-card-gradient"></div>
          ${hasImg ? watermarkChip(ev) : ''}
          <span class="ev-badge ev-badge-cat ${meta.cls}">${meta.icon} ${meta.label}</span>
          ${phaseBadge}
        </div>
        <div class="event-card-body">
          <span class="event-card-project">${escapeHtml(eventProjectLabel(ev))}</span>
          <h4 class="event-card-title">${escapeHtml(ev.title)}</h4>
          ${ev.description ? `<p class="event-card-desc">${escapeHtml(ev.description)}</p>` : ''}
          ${dateLine}
          ${expiryNote}
          ${expiryMarker}
        </div>
      </article>
    `;
  }).join('');
}

async function loadDashboardEvents() {
  if (eventsLoading) return;
  eventsLoading = true;
  eventsLoadState = 'loading';
  const empty = document.getElementById('events-empty');
  // Un solo aviso de error: se reemplaza en vez de apilarse en cada reintento.
  const clearNote = () => {
    if (empty) empty.querySelectorAll('.news-error').forEach((n) => n.remove());
  };
  // El filtro por proyecto se arma con lo que llega del servidor.
  const filterSel = document.getElementById('events-filter-project');
  if (filterSel && !filterSel.dataset.bound) {
    filterSel.dataset.bound = '1';
    filterSel.addEventListener('change', () => onEventsProjectFilter(filterSel.value));
  }
  try {
    const data = await fetchJsonWithRetry(API_BASE + '/ows-dashboard/events?limit=30', { timeoutsMs: [12000, 25000] });
    clearNote();
    eventsLoadState = 'ready';
    renderEvents((data && data.events) || []);
  } catch (err) {
    console.error('[OWS] No se pudieron cargar los eventos:', err);
    eventsLoadState = 'error';
    renderEvents([]);
    if (empty) {
      clearNote();
      const note = document.createElement('p');
      note.className = 'news-error';
      note.textContent = 'No se pudieron cargar los eventos. Revisa tu conexión.';
      empty.appendChild(note);
    }
  } finally {
    eventsLoading = false;
  }
}

function openEventModal(ev) {
  const modal = document.getElementById('event-modal');
  const body = document.getElementById('event-modal-body');
  if (!modal || !body || !ev) return;
  const meta = eventCategoryMeta(ev.category);
  const hasImg = Boolean(ev.image_url || ev.cover_url);
  const expected = eventShowsExpectedDate(ev);
  const startsText = ev.starts_at
    ? new Date(ev.starts_at).toLocaleString('es-ES', { day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' })
    : '—';
  const countdownText = (!expected && ev.phase !== 'ended') ? eventCountdown(ev.starts_at, ev.phase) : '';
  // Desaparición automática: fecha exacta + cuenta atrás larga y dinámica.
  const expiryIso = eventExpiresAt(ev);
  const expiresIn = eventExpiresInMs(ev);
  const expiryActive = Boolean(expiryIso) && Number.isFinite(expiresIn) && expiresIn > 0;
  const expiryLong = expiryActive ? `Desaparece de OWS en ${lapseLabel(expiresIn)}` : '';
  const expiryValue = expiryActive
    ? `${new Date(expiryIso).toLocaleString('es-ES', { day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit' })} <span class="ev-date-note">🗑️ Desaparece en ${escapeHtml(lapseLabel(expiresIn))}</span>`
    : 'Se queda en el calendario';
  const phaseText = ev.phase === 'active'
    ? 'En curso'
    : ev.phase === 'ended'
      ? 'Finalizado'
      : (expected ? 'Próximamente · fecha por confirmar' : 'Próximamente');
  body.innerHTML = `
    ${hasImg ? `<div class="modal-banner-wrap"><img src="${escapeHtml(ev.image_url || ev.cover_url || '')}" alt="${escapeHtml(ev.title)}" class="modal-banner" />${watermarkChip(ev, { big: true })}</div>` : ''}
    <div class="modal-head">
      <div class="modal-head-info">
        <span class="ev-badge ev-badge-cat ${meta.cls}" style="align-self:flex-start">${meta.icon} ${meta.label}</span>
        <h3 class="modal-title">${escapeHtml(ev.title)}</h3>
        <p class="modal-tagline">${escapeHtml(eventProjectLabel(ev))} · ${escapeHtml(formatEventRange(ev.starts_at, ev.ends_at))}</p>
      </div>
    </div>
    ${ev.description ? `<div class="modal-about"><p class="modal-about-text">${escapeHtml(ev.description)}</p></div>` : ''}
    <dl class="modal-data">
      <div class="data-row"><dt>${expected ? 'Fecha esperada de inicio' : 'Inicio'}</dt><dd>${escapeHtml(startsText)}${expected ? ' <span class="ev-date-note">(por confirmar)</span>' : ''}</dd></div>
      <div class="data-row"><dt>Fin</dt><dd>${escapeHtml(ev.ends_at ? new Date(ev.ends_at).toLocaleString('es-ES') : '—')}</dd></div>
      <div class="data-row"><dt>Estado</dt><dd>${phaseText}</dd></div>
      ${countdownText ? `<div class="data-row"><dt>Cuenta atrás</dt><dd>${escapeHtml(countdownText)}</dd></div>` : ''}
      ${ev.phase === 'ended' ? `<div class="data-row"><dt>Desaparición</dt><dd>${expiryValue}</dd></div>` : ''}
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
// Estado de la sección: distingue "sin noticias" de "no se pudo cargar",
// evita encadenar cargas y habilita un único reintento automático.
let newsLoadState = 'idle'; // idle | loading | ready | error
let newsLoading = false;
let newsAutoRetryTimer = 0;
let newsAutoRetryUsed = false;

function renderNewsLoading() {
  const list = document.getElementById('news-table-body');
  const empty = document.getElementById('news-empty');
  if (empty) empty.classList.add('hidden');
  if (list) {
    list.innerHTML = `
      <div class="news-loading" role="status" aria-live="polite">
        <span class="releases-spinner" aria-hidden="true"></span>
        <p class="news-loading-title">Cargando noticias…</p>
        <p class="news-loading-sub">La primera carga puede tardar si el servidor está despertando.</p>
      </div>`;
  }
  const count = document.getElementById('news-count');
  if (count) count.textContent = 'Cargando…';
}

// Estado vacío vs error de carga: mismo bloque, con un solo botón de
// reintento (antes los avisos de error se apilaban sin control).
function setNewsEmptyState(mode) {
  const empty = document.getElementById('news-empty');
  if (!empty) return;
  const isError = mode === 'error';
  const icon = document.getElementById('news-empty-icon');
  const title = document.getElementById('news-empty-title');
  const sub = document.getElementById('news-empty-sub');
  const retry = document.getElementById('news-retry');
  if (icon) icon.textContent = isError ? '⚠️' : '📰';
  if (title) title.textContent = isError ? 'No se pudieron cargar las noticias' : 'Aún no hay noticias';
  if (sub) sub.textContent = isError
    ? 'El servidor no respondió. Revisá tu conexión e intentalo de nuevo.'
    : 'Las últimas novedades de OWS Hub aparecerán aquí.';
  if (retry) retry.classList.toggle('hidden', !isError);
  empty.classList.remove('hidden');
}

// Un reintento automático y silencioso después de fallar: cubre el arranque
// en frío de Render (20-60s) sin obligar al usuario a tocar nada.
// Un reintento manual/por navegación renueva el cupo.
function scheduleNewsAutoRetry() {
  if (newsAutoRetryTimer || newsAutoRetryUsed) return;
  newsAutoRetryUsed = true;
  newsAutoRetryTimer = setTimeout(() => {
    newsAutoRetryTimer = 0;
    if (newsLoadState !== 'error') return;
    loadDashboardNews({ silent: true });
  }, 20000);
}

function renderNewsTable(newsList) {
  const list = document.getElementById('news-table-body');
  const empty = document.getElementById('news-empty');
  const count = document.getElementById('news-count');
  const statNews = document.getElementById('stat-news');
  if (!list || !empty) return;

  // null = la carga falló: no es "sin noticias", es error de conexión.
  if (newsList === null) {
    list.innerHTML = '';
    if (count) count.textContent = 'Sin conexión';
    setNewsEmptyState('error');
    return;
  }

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
    setNewsEmptyState('empty');
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
      ? `<img src="${escapeHtml(media)}" alt="" loading="lazy" />${watermarkChip(item)}`
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
      ${media ? `<img src="${escapeHtml(media)}" alt="${escapeHtml(item.title)}" />${watermarkChip(item)}` : ''}
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

async function loadDashboardNews(opts) {
  if (newsLoading) return;
  const silent = !!(opts && opts.silent);
  // Un intento pedido por el usuario (botón o navegación) renueva el cupo
  // del reintento automático.
  if (!silent) newsAutoRetryUsed = false;
  newsLoading = true;
  newsLoadState = 'loading';
  if (!silent) renderNewsLoading();
  try {
    const data = await fetchJsonWithRetry(API_BASE + '/ows-dashboard/news?limit=20', { timeoutsMs: [12000, 25000] });
    const items = (data && Array.isArray(data.news)) ? data.news : [];
    newsLoadState = 'ready';
    renderNewsTable(items);
  } catch (err) {
    console.error('[OWS] No se pudieron cargar las noticias:', err);
    newsLoadState = 'error';
    if (!silent) renderNewsTable(null);
    scheduleNewsAutoRetry();
  } finally {
    newsLoading = false;
  }
}

// ═══════════════════════════════════════════════
// ⚡ NOTICIAS RÁPIDAS — texto corto al pie de Noticias
// El tag "Nuevo" lo decide el servidor: se apaga solo a los pocos días
// de publicada la entrada, sin borrar nada.
// ═══════════════════════════════════════════════

function quickNewsWhen(value) {
  if (!value) return '';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  const diff = Date.now() - d.getTime();
  const mins = Math.round(diff / 60000);
  if (mins < 1) return 'ahora';
  if (mins < 60) return `hace ${mins} min`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `hace ${hours} h`;
  const days = Math.round(hours / 24);
  if (days === 1) return 'ayer';
  if (days < 30) return `hace ${days} días`;
  return d.toLocaleDateString('es-ES', { day: 'numeric', month: 'short' });
}

function renderQuickNews(list, meta) {
  const box = document.getElementById('qnews-list');
  const empty = document.getElementById('qnews-empty');
  const panel = document.getElementById('qnews-panel');
  const count = document.getElementById('qnews-count');
  const newTag = document.getElementById('qnews-new');
  if (!box || !empty) return;

  const items = Array.isArray(list) ? list : [];
  const hasNew = !!(meta && meta.has_new);
  if (count) count.textContent = items.length ? `${items.length}` : '0';
  if (newTag) newTag.classList.toggle('hidden', !hasNew);

  // Sin nada que contar, el panel entero se aparta para no dejar un hueco vacío.
  if (panel) panel.classList.toggle('hidden', items.length === 0 && !hasNew);
  if (!items.length) {
    box.innerHTML = '';
    empty.classList.remove('hidden');
    return;
  }

  empty.classList.add('hidden');
  box.innerHTML = items.map((item) => {
    const isNew = !!item.is_new;
    const tag = String(item.tag || '').trim();
    const link = String(item.link_url || '').trim();
    const foot = `<span class="qnews-item-when">${escapeHtml(quickNewsWhen(item.published_at || item.created_at))}</span>`;
    const body = `
      <span class="qnews-item-dot" aria-hidden="true"></span>
      <span class="qnews-item-text">${escapeHtml(item.text)}</span>
      <span class="qnews-item-side">
        ${isNew ? '<span class="qnews-item-new">✨ Nuevo</span>' : ''}
        ${tag ? `<span class="qnews-item-tag">${escapeHtml(tag)}</span>` : ''}
        ${foot}
      </span>
      ${link ? '<span class="qnews-item-cta" aria-hidden="true">↗</span>' : ''}`;
    return link
      ? `<a class="qnews-item${isNew ? ' is-new' : ''}" href="${escapeHtml(link)}" target="_blank" rel="noopener">${body}</a>`
      : `<div class="qnews-item${isNew ? ' is-new' : ''}">${body}</div>`;
  }).join('');
}

let quickNewsLoadState = 'idle'; // idle | loading | ready | error
let quickNewsLoading = false;

async function loadQuickNews() {
  if (quickNewsLoading) return;
  quickNewsLoading = true;
  try {
    const data = await fetchJsonWithRetry(API_BASE + '/ows-dashboard/quick-news?limit=12', { timeoutsMs: [12000, 25000] });
    quickNewsLoadState = 'ready';
    renderQuickNews((data && data.news) || [], (data && data.meta) || {});
  } catch (err) {
    console.error('[OWS] No se pudieron cargar las noticias rápidas:', err);
    quickNewsLoadState = 'error';
    // Sin datos el panel se aparta solo: no deja un hueco roto en la vista.
    renderQuickNews([], {});
  } finally {
    quickNewsLoading = false;
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
      <img src="${escapeHtml(banner)}" alt="${escapeHtml(alt)}" class="release-banner" loading="lazy" data-blurup />
    </div>`;
  }
  if (icon) {
    return `<div class="release-media">
      <img src="${escapeHtml(icon)}" alt="${escapeHtml(alt)}" class="release-banner${hero}" loading="lazy" data-blurup />
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
// Estados de carga: sin esto la grilla quedaba vacía mientras Render
// despertaba (free tier tarda 20-60s en el primer request) y parecía rota.
let releasesLoadState = 'idle'; // idle | loading | ready | error
let releasesLoading = false;
let releasesAutoRetryTimer = 0;
let releasesAutoRetryUsed = false;

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

// Fetch JSON con reintentos encadenados: el backend (plan gratuito de Render)
// puede tardar 20-60s en despertar. Se reintenta ante corte de red/timeout
// y ante un 5xx transitorio; nunca ante un 4xx, que ya es respuesta firme.
async function fetchJsonWithRetry(url, opts) {
  const timeouts = Array.isArray(opts && opts.timeoutsMs) && opts.timeoutsMs.length
    ? opts.timeoutsMs
    : [12000, 25000];
  let lastErr = null;
  for (let i = 0; i < timeouts.length; i++) {
    try {
      const res = await fetchWithTimeout(url, timeouts[i]);
      if (!res.ok) {
        const err = new Error(`Error del servidor (${res.status})`);
        if (res.status >= 400 && res.status < 500) err.noRetry = true;
        throw err;
      }
      return await res.json();
    } catch (err) {
      lastErr = err;
      if (err && err.noRetry) break;
    }
  }
  throw lastErr || new Error('No se pudo contactar al servidor');
}

function renderReleasesLoading() {
  const grid = document.getElementById('releases-grid');
  if (!grid) return;
  clearReleasesRetryNote();
  grid.innerHTML = `
    <div class="releases-placeholder" role="status" aria-live="polite">
      <span class="releases-spinner" aria-hidden="true"></span>
      <p class="releases-placeholder-title">Cargando lanzamientos…</p>
      <p class="releases-placeholder-sub">La primera carga puede tardar si el servidor está despertando.</p>
    </div>`;
  try { syncReleasesSpotlight(); } catch (_) {}
  // La ficha y el catálogo también "cargan": esqueletos en vez de vacío.
  const skel = releasesSkeletonHtml();
  const heroBox = document.getElementById('rel-hero');
  if (heroBox) { heroBox.classList.remove('hidden'); heroBox.innerHTML = skel.hero; }
  const cardsBox = document.getElementById('rel-cards');
  if (cardsBox) cardsBox.innerHTML = skel.cards;
  const emptyBox = document.getElementById('rel-cards-empty');
  if (emptyBox) emptyBox.classList.add('hidden');
  const count = document.getElementById('rel-count');
  if (count) count.textContent = 'Cargando…';
  const filters = document.getElementById('rel-filters');
  if (filters) filters.innerHTML = '';
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

// Las fechas de calendario (expected_date / confirmed_date) son columnas DATE:
// en la base no tienen hora ni zona, pero el backend las devuelve como
// "2026-10-15T00:00:00.000Z" — medianoche UTC. new Date() sobre eso, formateado
// en hora local (UTC-3 en Uruguay), retrocede un dia: 15 oct se veia como 14.
// Se parte la parte de la fecha (sin la hora) y se arma en hora local.
function parseDateValue(value) {
  const s = String(value == null ? '' : value).trim();
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ]|$)/.exec(s);
  if (m) return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

function formatReleaseDate(value) {
  if (!value) return null;
  const d = parseDateValue(value);
  if (!d) return null;
  return d.toLocaleDateString('es-ES', { day: 'numeric', month: 'short', year: 'numeric' });
}

function renderReleases(projects) {
  const grid = document.getElementById('releases-grid');
  if (!grid) return;
  // Al pintar datos reales, el aviso de "lista local" ya no corresponde.
  clearReleasesRetryNote();
  const items = Array.isArray(projects) ? projects : [];
  if (!items.length) {
    grid.innerHTML = '<p class="loading-note" style="color:var(--text-muted);font-size:0.85rem">Todavía no hay lanzamientos anunciados. ¡Volvé pronto! ✨</p>';
    releasesLoadState = 'ready';
    try { syncReleasesSpotlight(); } catch (_) {}
    renderReleasesChrome(items);
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
  renderReleasesChrome(items);
  // El trailer se apaga solo en su fecha de corte: hay que reprogramar el
  // timer en cada render, no solo en el primero.
  try { scheduleTrailerCutoff(); } catch (_) {}
}

// ═══════════════════════════════════════════
// LANZAMIENTOS · hero destacado + catálogo
// El dock de iconos (#releases-grid) sigue siendo el acceso rápido y no se
// toca. Encima se arma la ficha grande del juego destacado y, debajo, el
// catálogo en tarjetas (reutiliza .release-card / .release-media, que ya
// estaban definidos en el CSS junto a sus helpers de markup).
// ═══════════════════════════════════════════
let releasesFilter = 'all';
try { releasesFilter = localStorage.getItem('ows_releases_filter') || 'all'; } catch (_) {}

const RELEASE_FILTERS = [
  { key: 'all', label: 'Todos' },
  { key: 'launched', label: '¡Disponible ya!' },
  { key: 'development', label: 'En desarrollo' },
  { key: 'soon', label: 'Próximamente' },
  { key: 'cancelled', label: 'Cancelado' }
];

// El estado crudo puede venir vacío o con mayúsculas: se normaliza para que
// los filtros y el destacado no dependan de cómo lo escribió el backend.
function releaseFilterKey(p) {
  return String(p?.status || 'development').trim().toLowerCase();
}

function releasesAvailableFilters(items) {
  const used = new Set((items || []).map(releaseFilterKey));
  return RELEASE_FILTERS.filter((f) => f.key === 'all' || used.has(f.key));
}

function releasesFiltered(items) {
  const list = Array.isArray(items) ? items : [];
  if (releasesFilter === 'all') return list;
  return list.filter((p) => releaseFilterKey(p) === releasesFilter);
}

// Destacado: primero lo que tiene trailer vivo, después lo que ya se puede
// jugar, y después por estado. Los cancelados nunca quedan destacados si hay
// otra cosa. El sort es estable, así que los empates mantienen el orden que
// manda el servidor.
const RELEASE_FEATURED_RANK = { launched: 0, development: 1, soon: 2, cancelled: 3 };
function pickFeaturedRelease(items) {
  const usable = (items || []).filter((p) => releaseFilterKey(p) !== 'cancelled');
  const pool = usable.length ? usable : (items || []);
  if (!pool.length) return null;
  return pool.slice().sort((a, b) => {
    // Un trailer en cartelera se lleva la ficha: es lo que se quiere
    // empujar mientras el juego todavia no salio.
    const byTrailer = Number(releaseTrailerLive(b)) - Number(releaseTrailerLive(a));
    if (byTrailer) return byTrailer;
    const byBuild = Number(releaseHasBuild(b)) - Number(releaseHasBuild(a));
    if (byBuild) return byBuild;
    const rankA = RELEASE_FEATURED_RANK[releaseFilterKey(a)];
    const rankB = RELEASE_FEATURED_RANK[releaseFilterKey(b)];
    return (rankA == null ? 9 : rankA) - (rankB == null ? 9 : rankB);
  })[0];
}

function releaseStatusChip(p) {
  const meta = releaseStatusMeta(p.status);
  return `<span class="release-soon ${meta.cls}">${escapeHtml(meta.label)}</span>`;
}

// Fecha confirmada si existe; si no, la estimada (rotulada como tal).
function releaseDateChip(p) {
  const confirmed = p.confirmed_date || p.confirmedDate || '';
  const raw = confirmed || p.expected_date || p.expectedDate || '';
  const label = formatReleaseDate(raw);
  if (!label) return '';
  return `<span class="rel-chip">📅 ${escapeHtml(confirmed ? `Lanzamiento: ${label}` : `Fecha estimada: ${label}`)}</span>`;
}

// ══════════════════════════════════════════════════════════════
// TRÁILER DESTACADO
// El server manda trailer_url / trailer_title / trailer_until con cada proyecto
// (viven en metadata). Cuando trailer_until no esta escrito, el server lo
// resuelve contra la fecha de lanzamiento (confirmada > estimada), asi que el
// trailer se apaga solo el dia del lanzamiento a las 00:00 sin que nadie tenga
// que tocar el sitio ni acordarse de despublicarlo.
//
// El embed NO se monta al cargar: se pinta la miniatura de YouTube y el iframe
// (youtube-nocookie, sin cookies de terceros) recien cuando el usuario le da
// play. Cargar el embed siempre son ~1 MB extra para todo el Hub.
// ══════════════════════════════════════════════════════════════

// Saca el id de un video de YouTube desde cualquiera de sus formas de URL
// (watch?v=, youtu.be/, /embed/, /shorts/, /live/). Vacio si no es YouTube.
function youtubeVideoId(url) {
  const raw = String(url || '').trim();
  if (!raw) return '';
  let u;
  try { u = new URL(raw); } catch (_) { return ''; }
  const host = u.hostname.replace(/^www\./, '').toLowerCase();
  if (host === 'youtu.be') return (u.pathname.split('/').filter(Boolean)[0] || '').slice(0, 11);
  const hosts = ['youtube.com', 'm.youtube.com', 'music.youtube.com', 'youtube-nocookie.com'];
  if (hosts.indexOf(host) === -1) return '';
  if (u.pathname === '/watch') return (u.searchParams.get('v') || '').trim().slice(0, 11);
  const m = /^\/(?:embed|shorts|v|live)\/([A-Za-z0-9_-]{6,})/.exec(u.pathname);
  return m ? m[1].slice(0, 11) : '';
}

function releaseTrailerUrl(p) {
  return String((p && (p.trailer_url || p.trailerUrl)) || '').trim();
}

// Instante en que el trailer desaparece. parseDateValue arma la medianoche
// LOCAL (no UTC), que es justo lo que pide "desaparece el 15/10 a las 00:00".
function releaseTrailerUntil(p) {
  return parseDateValue((p && (p.trailer_until || p.trailerUntil)) || '');
}

// ¿El trailer sigue en cartelera? Sin fecha de corte, siempre visible.
function releaseTrailerLive(p) {
  if (!releaseTrailerUrl(p)) return false;
  const until = releaseTrailerUntil(p);
  if (!until) return true;
  return Date.now() < until.getTime();
}

// "2d 3h" / "3h 12m" / "45m" — para el chip del heroe.
function releaseCountdownText(target) {
  if (!target) return '';
  const ms = target.getTime() - Date.now();
  if (Number.isNaN(ms) || ms <= 0) return '';
  const mins = Math.floor(ms / 60000);
  const days = Math.floor(mins / 1440);
  const hours = Math.floor((mins % 1440) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins % 60}m`;
  return `${Math.max(1, mins % 60)}m`;
}

// Bloque del trailer. variant: 'hero' (ficha destacada) | 'modal' (detalle).
function releaseTrailerHtml(p, variant) {
  if (!releaseTrailerLive(p)) return '';
  const url = releaseTrailerUrl(p);
  if (!/^https?:\/\//i.test(url)) return '';
  const vid = youtubeVideoId(url);
  const title = String((p && (p.trailer_title || p.trailerTitle)) || '').trim() || `Tráiler de ${(p && p.name) || ''}`.trim();
  const left = releaseCountdownText(releaseTrailerUntil(p));
  const badge = left
    ? `<span class="rel-trailer-left" title="El tráiler sale de la cartelera cuando arranca el lanzamiento">⏳ En ${escapeHtml(left)}</span>`
    : '';
  const frame = vid
    ? `<iframe class="rel-trailer-frame" src="https://www.youtube-nocookie.com/embed/${escapeHtml(vid)}?autoplay=1&amp;rel=0&amp;modestbranding=1"
             title="${escapeHtml(title)}" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
             allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe>`
    : `<iframe class="rel-trailer-frame" src="${escapeHtml(url)}" title="${escapeHtml(title)}" allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe>`;
  const poster = vid
    ? `<img class="rel-trailer-thumb" src="https://i.ytimg.com/vi/${escapeHtml(vid)}/maxresdefault.jpg" alt="" loading="lazy"
             onerror="this.onerror=null;this.src='https://i.ytimg.com/vi/${escapeHtml(vid)}/hqdefault.jpg';" />`
    : `<span class="rel-trailer-thumb rel-trailer-thumb-fb" aria-hidden="true">🎬</span>`;
  return `
  <div class="rel-trailer rel-trailer--${escapeHtml(variant || 'hero')}" data-rel-trailer>
    <button type="button" class="rel-trailer-stage" data-trailer-play
            aria-label="Reproducir ${escapeHtml(title || 'el tráiler')}" data-embed="${escapeHtml(frame)}">
      ${poster}
      <span class="rel-trailer-play" aria-hidden="true"></span>
    </button>
    <div class="rel-trailer-meta">
      <b class="rel-trailer-title">${escapeHtml(title)}</b>
      ${badge}
    </div>
  </div>`;
}

// El trailer se apaga solo. El Hub no refresca la lista cuando ya esta en
// 'ready', asi que se programa un timer para el instante exacto del corte y se
// re-pinta sin volver a pegarle al server.
const TRAILER_CUTOFF_MAX_MS = 60 * 60 * 1000; // setTimeout revienta pasado ~24.8 dias
let trailerCutoffTimer = 0;

function nextTrailerCutoffMs() {
  const list = Array.isArray(releasesCache) ? releasesCache : [];
  let next = null;
  for (const p of list) {
    if (!releaseTrailerLive(p)) continue;
    const until = releaseTrailerUntil(p);
    if (!until) continue;
    const ms = until.getTime() - Date.now();
    if (ms > 0 && (next === null || ms < next)) next = ms;
  }
  return next;
}

function scheduleTrailerCutoff() {
  if (trailerCutoffTimer) { clearTimeout(trailerCutoffTimer); trailerCutoffTimer = 0; }
  const ms = nextTrailerCutoffMs();
  if (ms === null) return;
  trailerCutoffTimer = setTimeout(() => {
    trailerCutoffTimer = 0;
    try {
      // Re-pinta heroe + catalogo: el trailer ya no entra en el HTML.
      renderReleases(releasesCache);
      // Si el modal de ese juego esta abierto se le saca el bloque a mano
      // (re-abrirlo tiraria otra vez las consultas de versiones y descargas).
      document.querySelectorAll('[data-rel-trailer]').forEach((n) => n.remove());
    } catch (_) { /* si algo falla, el trailer se va en el proximo render */ }
    scheduleTrailerCutoff();
  }, Math.min(ms + 250, TRAILER_CUTOFF_MAX_MS));
}

// Click en el cartel → monta el iframe y arranca solo. Delegado: los bloques
// del heroe y del modal se re-crean en cada render.
function bindTrailerPlayers() {
  if (document.documentElement.dataset.trailerBound) return;
  document.documentElement.dataset.trailerBound = '1';
  document.addEventListener('click', (e) => {
    const btn = e.target.closest && e.target.closest('[data-trailer-play]');
    if (!btn) return;
    const wrap = btn.closest('[data-rel-trailer]');
    if (!wrap) return;
    e.preventDefault();
    e.stopPropagation();
    wrap.innerHTML = btn.getAttribute('data-embed') || '';
  });
}

function featuredReleaseHtml(p) {
  const meta = releaseStatusMeta(p.status);
  const banner = p.banner_url || p.bannerUrl || '';
  const icon = p.icon_url || p.iconUrl || '';
  const version = releaseEffectiveVersion(p);
  const itchUrl = p.itch_url || p.itchUrl || p.link_url || p.linkUrl || '';
  return `
  <article class="rel-hero${banner ? '' : ' rel-hero-fallback'}" data-slug="${escapeHtml(p.slug)}">
    ${banner
      ? `<div class="rel-hero-banner" data-parallax="1.6" aria-hidden="true"><img src="${escapeHtml(banner)}" alt="" loading="lazy" data-blurup /></div>
         <div class="rel-hero-scrim" aria-hidden="true"></div>`
      : ''}
    <div class="rel-hero-inner" data-parallax="0.45">
      ${icon
        ? `<img class="rel-hero-icon" src="${escapeHtml(icon)}" alt="${escapeHtml(p.name)}" loading="lazy" />`
        : '<div class="rel-hero-icon rel-hero-icon-fb" aria-hidden="true">🎮</div>'}
      <div class="rel-hero-body">
        <div class="rel-hero-chips">
          <span class="rel-chip rel-chip-star">★ Destacado</span>
          ${releaseStatusChip(p)}
          ${version ? `<span class="rel-chip rel-chip-ver">v${escapeHtml(version)}</span>` : ''}
          ${releaseDateChip(p)}
        </div>
        <h4 class="rel-hero-name">${escapeHtml(p.name)}</h4>
        ${p.genre ? `<p class="rel-hero-genre">${escapeHtml(p.genre)}</p>` : ''}
        ${p.description ? `<p class="rel-hero-desc">${escapeHtml(p.description)}</p>` : ''}
        ${releaseTrailerHtml(p, 'hero')}
        <div class="rel-hero-actions">
          <button type="button" class="btn btn-primary" data-rel-action="details" data-rel-slug="${escapeHtml(p.slug)}">Ver detalles →</button>
          ${itchUrl ? `<a class="btn btn-ghost" href="${escapeHtml(itchUrl)}" target="_blank" rel="noopener">Ver en itch.io ↗</a>` : ''}
        </div>
      </div>
    </div>
  </article>`;
}

function releaseCardItemHtml(p, index) {
  const dim = releaseFilterKey(p) === 'cancelled' ? ' is-dim' : '';
  return `
  <article class="release-card glass-card rel-card${dim}" style="--i:${index}" data-slug="${escapeHtml(p.slug)}" role="button" tabindex="0" aria-label="${escapeHtml(p.name)} — ver detalles">
    ${releaseMediaMarkup(p)}
    ${releaseStatusChip(p)}
    ${releaseBodyMarkup(p)}
  </article>`;
}

// Cuenta, filtros, destacado y tarjetas. Se vuelve a pintar cada vez que
// llega la versión de itch.io: por eso el filtro vive en el módulo y no se
// pierde entre renders.
function renderReleasesChrome(items) {
  const list = Array.isArray(items) ? items : [];

  const count = document.getElementById('rel-count');
  if (count) {
    count.textContent = list.length
      ? `${list.length} ${list.length === 1 ? 'lanzamiento' : 'lanzamientos'}`
      : 'Sin lanzamientos';
  }

  const filters = document.getElementById('rel-filters');
  if (filters) {
    const opts = releasesAvailableFilters(list);
    if (!opts.some((o) => o.key === releasesFilter)) releasesFilter = 'all';
    filters.innerHTML = opts.map((f) => `
      <button type="button" class="rel-filter${f.key === releasesFilter ? ' is-active' : ''}" data-rel-filter="${escapeHtml(f.key)}" aria-pressed="${f.key === releasesFilter ? 'true' : 'false'}">${escapeHtml(f.label)}</button>`).join('');
  }

  const visible = releasesFiltered(list);
  const featured = pickFeaturedRelease(visible);

  const heroBox = document.getElementById('rel-hero');
  if (heroBox) {
    heroBox.innerHTML = featured ? featuredReleaseHtml(featured) : '';
    heroBox.classList.toggle('hidden', !featured);
    if (featured) {
      sweepBlurUp(heroBox);
      bindHeroParallax(heroBox.querySelector('.rel-hero'));
    }
  }

  const cardsBox = document.getElementById('rel-cards');
  const emptyBox = document.getElementById('rel-cards-empty');
  const rest = featured ? visible.filter((p) => p !== featured) : visible;
  if (cardsBox) {
    cardsBox.innerHTML = rest.map((p, i) => releaseCardItemHtml(p, i)).join('');
    sweepBlurUp(cardsBox);
  }
  if (emptyBox) {
    const showEmpty = !rest.length;
    emptyBox.classList.toggle('hidden', !showEmpty);
    if (showEmpty) {
      // Tres vacíos distintos: sin nada publicado, filtro sin resultados, o
      // un solo juego que ya está en el destacado.
      const copy = !list.length
        ? ['🚀', 'Todavía no hay lanzamientos anunciados', 'Cuando anunciemos un juego, aparece acá.']
        : !visible.length
          ? ['🔍', 'No hay lanzamientos con este estado', 'Probá con otro estado o volvé a «Todos».']
          : ['⭐', 'Este es el único lanzamiento por ahora', 'Cuando anunciemos el próximo juego, aparece acá al lado del destacado.'];
      emptyBox.innerHTML = `
        <span class="rel-empty-ico" aria-hidden="true">${copy[0]}</span>
        <p class="rel-empty-title">${copy[1]}</p>
        <p class="rel-empty-sub">${copy[2]}</p>`;
    }
  }
}

function setReleasesFilter(key) {
  releasesFilter = RELEASE_FILTERS.some((f) => f.key === key) ? key : 'all';
  try { localStorage.setItem('ows_releases_filter', releasesFilter); } catch (_) {}
  renderReleasesChrome(releasesCache);
}

// Mientras el servidor despierta: esqueletos con shimmer en vez del vacío.
function releasesSkeletonHtml() {
  const hero = `
    <div class="rel-hero rel-hero-fallback rel-skel-hero" aria-hidden="true">
      <div class="rel-hero-inner">
        <div class="rel-shimmer rel-skel-icon"></div>
        <div class="rel-hero-body">
          <div class="rel-shimmer rel-skel-line" style="width:150px;height:18px"></div>
          <div class="rel-shimmer rel-skel-line" style="width:min(420px,70%);height:32px"></div>
          <div class="rel-shimmer rel-skel-line" style="width:min(520px,88%);height:14px"></div>
          <div class="rel-shimmer rel-skel-line" style="width:190px;height:38px;border-radius:999px"></div>
        </div>
      </div>
    </div>`;
  const cards = [0, 1, 2].map(() => `
    <div class="rel-card rel-skel" aria-hidden="true">
      <div class="release-media rel-shimmer"></div>
      <div class="rel-skel-body">
        <div class="rel-shimmer rel-skel-line" style="width:60%;height:16px"></div>
        <div class="rel-shimmer rel-skel-line" style="width:38%;height:10px"></div>
        <div class="rel-shimmer rel-skel-line" style="width:85%;height:12px"></div>
        <div class="rel-shimmer rel-skel-line" style="width:45%;height:12px"></div>
      </div>
    </div>`).join('');
  return { hero, cards };
}

// ═══════════════════════════════════════════
// P2 · blur-up, paralaje y transición al modal
// ═══════════════════════════════════════════

// ── Blur-up: las portadas entran desenfocadas y se definen al cargar ──
// El evento `load` no burbujea, así que se escucha en captura desde el
// documento: alcanza también a las imágenes que se pinten más adelante.
function blurUpSettle(img) {
  if (!img || img.dataset.blurDone === '1') return;
  img.dataset.blurDone = '1';
  const lista = () => img.classList.add('is-loaded');
  // Si ya está en caché el evento load no vuelve a llegar: se resuelve acá.
  if (img.complete && img.naturalWidth > 0) { lista(); return; }
  // Red de seguridad: si el evento load se retrasa (pestaña en 2º plano,
  // carga muy lenta), se revisa de nuevo antes de dejarla invisible.
  setTimeout(() => { if (img.complete || img.naturalWidth > 0) lista(); }, 700);
}
document.addEventListener('load', (e) => {
  const t = e.target;
  if (t && t.tagName === 'IMG' && t.hasAttribute('data-blurup')) {
    t.classList.add('is-loaded');
    blurUpSettle(t);
  }
}, true);
document.addEventListener('error', (e) => {
  const t = e.target;
  if (t && t.tagName === 'IMG' && t.hasAttribute('data-blurup')) {
    // Rota: se muestra igual y el .release-media-empty tapa el hueco.
    t.classList.add('is-loaded');
    blurUpSettle(t);
  }
}, true);
function sweepBlurUp(scope) {
  (scope || document).querySelectorAll('img[data-blurup]').forEach(blurUpSettle);
}

// ── Paralaje de la ficha: banner y contenido se desplazan con el mouse ──
// Se saltea con "menos movimiento" o en pantallas táctiles (pointer: coarse).
// Ojo con el marcador: se llama hero-parallax y no parallax para no pisar
// el atributo que lleva la profundidad de cada capa.
function bindHeroParallax(hero) {
  if (!hero || hero.dataset.heroParallax === '1') return;
  hero.dataset.heroParallax = '1';
  const reposo = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches
    || window.matchMedia('(hover: none)').matches;
  if (reposo()) return;
  let px = 0, py = 0, raf = 0;
  // Tope del desplazamiento: el banner lleva un sangrado de 50px a los
  // costados y 34px arriba/abajo, asi que el limite se queda por debajo de
  // ese sobrante y la imagen nunca deja el borde de la tarjeta. Las capas
  // menos profundas (el texto) se mueven menos para no arrimar el texto
  // al borde.
  const LIM_X = 40, LIM_Y = 24;
  const limitar = (v, tope) => Math.max(-tope, Math.min(tope, v));
  const apply = () => {
    raf = 0;
    hero.querySelectorAll('[data-parallax]').forEach((el) => {
      const depth = parseFloat(el.getAttribute('data-parallax')) || 0.5;
      const topeX = LIM_X * Math.min(1, depth);
      const topeY = LIM_Y * Math.min(1, depth);
      const dx = limitar(-px * depth * 100, topeX);
      const dy = limitar(-py * depth * 60, topeY);
      el.style.transform = `translate3d(${dx.toFixed(2)}px, ${dy.toFixed(2)}px, 0)`;
    });
  };
  const programar = () => { if (!raf) raf = requestAnimationFrame(apply); };
  hero.addEventListener('pointermove', (e) => {
    const r = hero.getBoundingClientRect();
    px = (e.clientX - r.left) / Math.max(1, r.width) - 0.5;
    py = (e.clientY - r.top) / Math.max(1, r.height) - 0.5;
    programar();
  });
  hero.addEventListener('pointerleave', () => { px = 0; py = 0; programar(); });
}

// ── Transición compartida tarjeta → modal (FLIP simplificado) ──
// La portada de origen vuela hasta el banner del modal, así se ve de un
// vistazo de qué juego se abrió el detalle. El destino es un contenedor
// propio (.rd-hero-flip) porque la imagen de adentro ya tiene su animación.
function releaseFlipSource(card) {
  if (!card || !card.querySelector) return null;
  // La ficha destacada se anima desde la tarjeta, no desde el banner: el
  // banner tiene sangrado para el parallax y su caja es mas grande que la
  // tarjeta, asi que la portada arrancaria descentrada y agrandada.
  if (card.classList && card.classList.contains('rel-hero')) return card;
  return card.querySelector('.release-media')
    || card.querySelector('.rel-hero-banner')
    || card;
}

function flipReleaseCover(fromEl) {
  if (!fromEl || !fromEl.getBoundingClientRect) return;
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const target = document.querySelector('#release-modal-body .rd-hero-flip');
  if (!target) return;
  const to = target.getBoundingClientRect();
  const from = fromEl.getBoundingClientRect();
  if (!to.width || !from.width || !from.height) return;
  const dx = from.left - to.left;
  const dy = from.top - to.top;
  const sx = from.width / to.width;
  const sy = from.height / to.height;
  target.style.transformOrigin = 'top left';
  target.style.transition = 'none';
  target.style.transform = `translate(${dx.toFixed(1)}px, ${dy.toFixed(1)}px) scale(${sx.toFixed(3)}, ${sy.toFixed(3)})`;
  void target.offsetWidth; // fuerza el layout para tomar el estado inicial
  const limpiar = () => {
    target.style.transition = '';
    target.style.transform = '';
    target.style.transformOrigin = '';
    target.removeEventListener('transitionend', limpiar);
  };
  // El "ir" va en rAF, con un timeout de respaldo: si la pestaña está en
  // segundo plano rAF se frena y la portada quedaría congelada en el aire.
  let arranco = false;
  const arrancar = () => {
    if (arranco) return;
    arranco = true;
    target.style.transition = 'transform 0.42s cubic-bezier(0.22, 0.8, 0.32, 1)';
    target.style.transform = 'none';
    target.addEventListener('transitionend', limpiar);
    setTimeout(limpiar, 800);
  };
  requestAnimationFrame(arrancar);
  setTimeout(arrancar, 48);
}

// Aviso + reintento manual cuando se pintó la lista local por falta de
// servidor. Es un aviso único: si ya había uno, se reemplaza (antes se
// apilaba una copia por cada reintento fallido).
function appendReleasesRetryNote() {
  // Nota al pie del bloque nuevo; si no existe (versión vieja del HTML),
  // se cae al dock como antes.
  const slot = document.getElementById('rel-retry') || document.getElementById('releases-grid');
  if (!slot) return;
  clearReleasesRetryNote();
  slot.insertAdjacentHTML('beforeend', `
    <div class="releases-retry-note">
      <span>Sin respuesta del servidor: se muestra la lista local.</span>
      <button type="button" class="btn btn-ghost btn-sm" data-releases-retry>↻ Reintentar</button>
    </div>`);
}

// Quita los avisos de reintento (al recuperar datos o antes de repintar).
function clearReleasesRetryNote() {
  document.querySelectorAll('.releases-retry-note').forEach((n) => n.remove());
}

const RELEASES_FETCH_TIMEOUT_MS = 12000;
// Rescate silencioso tras caer a la lista local: más margen para el
// arranque en frío de Render (20-60s).
const RELEASES_RESCUE_TIMEOUT_MS = 26000;

// Pide los proyectos del hub: 1 request (/ows-hub/summary) en vez de 3, con
// fallback a /ows-launch-projects si el hub aún no está desplegado.
async function fetchReleaseProjects(timeoutsMs) {
  try {
    const hub = await fetchJsonWithRetry(API_BASE + '/ows-hub/summary', { timeoutsMs });
    if (hub && Array.isArray(hub.projects)) return hub.projects;
    throw new Error('Respuesta inesperada de /ows-hub/summary');
  } catch (hubErr) {
    const data = await fetchJsonWithRetry(API_BASE + '/ows-launch-projects', { timeoutsMs });
    if (!data || !Array.isArray(data.projects)) throw new Error('Respuesta inesperada de /ows-launch-projects');
    return data.projects;
  }
}

// Un rescate automático y silencioso después de caer a la lista local: si el
// servidor terminó de despertar, la lista real reemplaza a la local sin que
// el usuario haga nada. Una vez por caída; un reintento manual renueva el cupo.
function scheduleReleasesAutoRetry() {
  if (releasesAutoRetryTimer || releasesAutoRetryUsed) return;
  releasesAutoRetryUsed = true;
  releasesAutoRetryTimer = setTimeout(() => {
    releasesAutoRetryTimer = 0;
    if (releasesLoadState !== 'error') return;
    loadDashboardReleases({ silent: true });
  }, 15000);
}

async function loadDashboardReleases(opts) {
  // Si nada responde se pintan los datos locales en vez de dejar la vista vacía.
  if (releasesLoading) return;
  const silent = !!(opts && opts.silent);
  releasesLoading = true;
  if (!silent) {
    releasesAutoRetryUsed = false;
    releasesLoadState = 'loading';
    renderReleasesLoading();
  }
  let projects = null;
  try {
    projects = await fetchReleaseProjects(silent
      ? [RELEASES_RESCUE_TIMEOUT_MS, RELEASES_RESCUE_TIMEOUT_MS]
      : [RELEASES_FETCH_TIMEOUT_MS]);
  } catch (err) {
    if (silent) console.warn('[OWS] Rescate silencioso de lanzamientos sin respuesta:', err);
    else console.error('[OWS] No se pudieron cargar los lanzamientos, usando fallback local:', err);
  } finally {
    releasesLoading = false;
  }
  if (projects) {
    renderReleases(projects);
    enrichReleasesWithItch(projects);
    return;
  }
  if (silent) return;
  // Nada respondió: datos locales + aviso único, y rescate automático.
  renderReleases(RELEASES_FALLBACK);
  appendReleasesRetryNote();
  // 'error' (no 'ready') para que al volver a entrar en la vista reintente solo.
  releasesLoadState = 'error';
  scheduleReleasesAutoRetry();
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

function openReleaseModal(project, originEl) {
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
        ? `<div class="rd-hero-flip"><img src="${escapeHtml(banner)}" alt="${escapeHtml(p.name)} — Banner" class="rd-hero-img" /></div>`
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
        ${releaseTrailerHtml(p, 'modal') ? `
        <section>
          <h4 class="rd-sec-title">Tráiler</h4>
          ${releaseTrailerHtml(p, 'modal')}
        </section>` : ''}
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
  // La portada viaja desde la tarjeta (o del dock) hasta acá: continuidad
  // visual entre la sección y el detalle.
  flipReleaseCover(originEl);
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
  // Multi-plataforma: la tarjeta principal es la de ESTE cliente (Windows en
  // desktop, Android en la app). La otra plataforma, si tiene build, se anuncia
  // como línea secundaria en vez de robarse la tarjeta (antes la release más
  // nueva ganaba sin importar su plataforma).
  const here = owsUpdatesPlatform();
  const platMatch = (r) => {
    const rp = String((r && (r.platform || '')) || 'windows').toLowerCase();
    return rp === 'all' || rp === here;
  };
  const latest = ((list && (list.find(platMatch) || list[0])) || null) || releaseLatestOf(p);
  const other = (list || []).find((r) => r && r !== latest && !platMatch(r) && r.id) || null;
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
        ${other ? `<p class="rm-rel-other">${here === 'android' ? '🪟' : '🤖'} También disponible en ${here === 'android' ? 'Windows' : 'Android'} · <b>v${escapeHtml(other.version || '?')}</b></p>` : ''}
      </div>`;
    if (list && list.length > 1) {
      html += `<div class="rm-rel-history">` + list.slice(1, 5).map((r) => {
        const rp = String(r.platform || 'windows').toLowerCase();
        const tag = rp === 'android' ? ' 🤖' : (rp === 'all' ? '' : '');
        return `
        <div class="rm-rel-old"><span>v${escapeHtml(r.version || '?')}${tag}</span><span>${escapeHtml(r.channel || '')}</span><span>${r.released_at ? escapeHtml(formatReleaseDate(r.released_at) || '') : ''}</span></div>`;
      }).join('') + `</div>`;
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
      const direct = apiUrl(`${API_BASE}/ows-launch-projects/${encodeURIComponent(slug)}/download`);
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
    // La "última" en caché es la de esta plataforma (o la primera si no hay):
    // sin esto una release Android más nueva quedaba como versión visible en PC.
    const herePlat = owsUpdatesPlatform();
    const latest = releases.length
      ? (releases.find((r) => String(r.platform || 'windows').toLowerCase() === herePlat || String(r.platform || '').toLowerCase() === 'all') || releases[0])
      : null;
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
        // La versión la manda la release oficial (multi-plataforma), no itch.
        const ver = (proj && releaseEffectiveVersion(proj)) || '';
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
          // Timeouts anti-cuelgue (v3.4.4, par del fix desktop en Rust): si el
          // servidor muere a mitad de la descarga, esto falla con error claro
          // (y botón Reintentar) en vez de quedar en 0% para siempre.
          await native.FileTransfer.downloadFile({ url: rel.apk_url, path: forms[f], progress: true, connectTimeout: 30000, readTimeout: 60000 });
          // El instalador de Android rechaza el APK con "error en el análisis
          // del paquete" si el archivo quedó trunco (típico en 600+ MB con
          // WiFi inestable). Se verifica el tamaño contra el publicado ANTES
          // de abrir el instalador: si no coincide se borra el parcial y se
          // pide reintentar, en vez del error críptico del sistema.
          const expected = Number(rel.size_bytes || 0);
          if (expected > 0) {
            let actual = -1;
            try {
              const st = await native.Filesystem.stat({ path: 'owshub-apk/' + fname, directory: rootDir });
              actual = Number(st && st.size);
            } catch (_) { actual = -1; }
            if (Number.isFinite(actual) && actual >= 0 && actual !== expected) {
              try { await native.Filesystem.deleteFile({ path: 'owshub-apk/' + fname, directory: rootDir }); } catch (_) {}
              throw Object.assign(
                new Error(`descarga incompleta (${formatMB(actual)} de ${formatMB(expected)}): reintentá con WiFi estable`),
                { owsDetail: `Esperado: ${expected} bytes\nRecibido: ${actual} bytes\nURL: ${rel.apk_url || ''}` }
              );
            }
          }
          savedPath = plain;
        } catch (dlErr) {
          if (dlErr && dlErr.owsDetail) throw dlErr;
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
      // Se abrió el instalador del sistema: se registra la versión para que
      // el Gestor la compare y ofrezca actualizar cuando salga una nueva.
      try { saveAndroidInstalled(s, rel.version_name || ''); } catch (_) {}
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
  // v3.4.5 — watchdog anti-cuelgue: si el instalador (JS→Rust) no emite
  // NINGÚN evento en 3 min (sea por listen, IPC o red), se marca error con
  // Reintentar en vez de quedar en 0% para siempre. Las descargas sanas
  // emiten eventos por chunk (varias veces por segundo), así que no hay
  // falsos positivos. El intervalo se limpia al terminar.
  let lastEvAt = Date.now();
  let settled = false;
  const watch = setInterval(() => {
    try {
      if (settled) { clearInterval(watch); return; }
      const d = (Array.isArray(downloadsState) ? downloadsState : []).find((x) => String(x.id) === String(id));
      if (!d || !dlIsActive(d)) { clearInterval(watch); return; }
      if (Date.now() - lastEvAt > 180000) {
        settled = true;
        clearInterval(watch);
        updateDownload(id, { status: 'error', error: 'El instalador no responde (sin progreso 3 min). Reintentá.' });
        try { window.OWSHubInstallProgress && window.OWSHubInstallProgress({ type: 'error', error: 'instalador sin respuesta' }); } catch (_) {}
        showToast('El instalador no responde · tocá Reintentar 🔁');
      }
    } catch (_) {}
  }, 15000);
  const onEvent = (e) => {
    lastEvAt = Date.now();
    if (e && (e.type === 'done' || e.type === 'error')) settled = true;
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
    await window.OWSHubLibrary.downloadAndInstall(slug, onEvent, { version: remoteVersion });
  } catch (err) {
    // ANTES: catch (_) {} — se tragaba el error en silencio y la tarjeta
    // quedaba en "Iniciando la descarga…" al 0% para siempre, sin dar ninguna
    // pista. El comentario decía "error ya reflejado en el Gestor", pero eso
    // solo es cierto si el fallo llegó por un evento {type:'error'}: si el
    // invoke a Rust falla (timeout, comando inexistente, panic) se perdía.
    // Ahora se refleja en la tarjeta para que se vea el motivo real.
    settled = true;
    try { clearInterval(watch); } catch (_) {}
    const msg = String((err && err.message) || err || 'no se pudo iniciar la descarga');
    updateDownload(id, { status: 'error', error: msg });
    try { window.OWSHubInstallProgress && window.OWSHubInstallProgress({ type: 'error', error: msg }); } catch (_) {}
    try { pushHubEventToManager(id, { type: 'error', error: msg }); } catch (_) {}
    showToast(`Falló la descarga de ${name}: ${msg}`);
  } finally {
    settled = true;
    try { clearInterval(watch); } catch (_) {}
  }
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
  const url = apiUrl((opts && opts.url) || `${API_BASE}/ows-launch-projects/${encodeURIComponent(s)}/download`);
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
  try { owsBgOnDownloadStart(entry); } catch (_) {}
  try { owsBgSyncTitle(); } catch (_) {}
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
  try { owsBgOnDownloadTick(next); } catch (_) {}
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
  } else if (d.downloaded > 0) {
    // Llegan bytes pero el servidor no declaró Content-Length: no se puede
    // saber el total, así que se muestra lo bajado sin porcentaje.
    sub = `<b>${escapeHtml(formatMB(d.downloaded))}</b> descargados`;
  } else {
    // Antes decía "Conectando con itch.io…": quedó de cuando todo venía de
    // itch.io. Ahora la fuente puede ser el CDN de GitHub, así que el texto
    // es neutro (y no promete un origen que ya no es el real).
    sub = 'Iniciando la descarga…';
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
        : (d.downloaded > 0 ? `${formatMB(d.downloaded)} descargados` : 'Iniciando la descarga…');
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
      ? (d.total > 0
          ? `${escapeHtml(formatMB(d.downloaded))} / ${escapeHtml(formatMB(d.total))}`
          : (d.downloaded > 0
              ? `${escapeHtml(formatMB(d.downloaded))} descargados`
              : 'Iniciando la descarga…'))
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
    // v3.4.5: en desktop la cancelación llega al Rust (antes el backend
    // seguía descargando en segundo plano y podía pisar un reintento).
    try {
      const found = (Array.isArray(downloadsState) ? downloadsState : []).find((d) => String(d.id) === String(id));
      if (found && found.mode === 'desktop' && window.OWSHubLibrary && typeof window.OWSHubLibrary.cancel === 'function') {
        window.OWSHubLibrary.cancel(found.slug).catch(() => {});
      }
    } catch (_) {}
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

// ═══════════════════════════════════════════════
// SEGUNDO PLANO + NOTIFICACIÓN DE PROGRESO
// Las descargas/instalaciones (juegos y Hub) ya siguen corriendo al cambiar
// de vista (fetch/Rust no se cancelan); este módulo avisa aunque no estés
// en el Gestor: toaster persistente + título con % + notificación del SO.
// ═══════════════════════════════════════════════
const OWS_BG_NOTIFY_MILESTONES = [25, 50, 75];
const owsBgNotified = new Map(); // id -> Set(hitos avisados)
let owsBgTitleBase = '';

function owsBgNotifsOn() {
  try { return getOwsSettings().notifs !== false; } catch (_) { return true; }
}

function owsBgEnsurePermission() {
  try {
    if (!owsBgNotifsOn()) return;
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission().catch(() => {});
    }
    // Tauri: pide permiso al plugin una vez (no-op en navegador).
    try {
      if (typeof tauriInvoke === 'function') {
        tauriInvoke('plugin:notification|request_permission', {}, 4000).catch(() => {});
      }
    } catch (_) {}
  } catch (_) {}
}

function owsBgNotify(title, body) {
  if (!owsBgNotifsOn()) return;
  const t = String(title || 'OWS Hub');
  const b = String(body || '');
  // 1) Tauri nativo (funciona con la ventana minimizada / en otra vista).
  try {
    if (typeof tauriInvoke === 'function' && (isTauriWebview() || (window.OWSHub && window.OWSHub.isDesktop))) {
      tauriInvoke('plugin:notification|notify', { title: t, body: b }, 4000).catch(() => {});
    }
  } catch (_) {}
  // 2) Web Notification (navegador + WebView2).
  try {
    if ('Notification' in window && Notification.permission === 'granted') {
      const n = new Notification(t, { body: b, silent: true });
      setTimeout(() => { try { n.close(); } catch (_) {} }, 6000);
    }
  } catch (_) {}
}

function owsBgMarkNotified(id, key) {
  const k = String(id || '');
  if (!k) return false;
  let set = owsBgNotified.get(k);
  if (!set) { set = new Set(); owsBgNotified.set(k, set); }
  if (set.has(key)) return false;
  set.add(key);
  return true;
}

function owsBgSyncTitle() {
  try {
    const active = (Array.isArray(downloadsState) ? downloadsState : []).filter(dlIsActive);
    if (!owsBgTitleBase) owsBgTitleBase = document.title || 'OWS Hub';
    if (!active.length) {
      if (document.title !== owsBgTitleBase) document.title = owsBgTitleBase;
      return;
    }
    const top = active[0];
    const pct = Math.max(0, Math.min(100, Number(top.pct || 0)));
    document.title = `(${pct}%) ${top.name || 'Descargando'} — OWS Hub`;
  } catch (_) {}
}

function owsBgOnDownloadStart(d) {
  try {
    if (!d) return;
    // El progreso ya vive en el toaster aunque cambies de sección; se avisa
    // una vez para que sepas que puedes seguir usando el Hub tranquilo.
    if (owsCurrentView !== 'sec-descargas') { try { syncDlToaster(); } catch (_) {} }
    owsBgNotify(`⬇ ${d.name || 'Descarga'} en segundo plano`, 'Puedes seguir usando OWS Hub · el progreso sigue arriba y en Descargas.');
  } catch (_) {}
}

function owsBgOnDownloadTick(d) {
  try {
    if (!d) return;
    owsBgSyncTitle();
    const pct = Math.max(0, Math.min(100, Number(d.pct || 0)));
    for (const m of OWS_BG_NOTIFY_MILESTONES) {
      if (pct >= m && owsBgMarkNotified(d.id, 'm' + m)) {
        owsBgNotify(`${d.name || 'Descarga'} · ${Math.round(pct)}%`, `${formatMB(d.downloaded)} / ${formatMB(d.total || d.downloaded)} · sigue en segundo plano`);
      }
    }
    if (d.status === 'completed' && owsBgMarkNotified(d.id, 'done')) {
      owsBgNotify(`✓ ${d.name || 'Descarga'} listo`, d.mode === 'desktop' ? 'Instalado · el juego ya se está abriendo 🎮' : 'Descarga completa · míralo en el Gestor');
      try { owsBgSyncTitle(); } catch (_) {}
    } else if ((d.status === 'error' || d.status === 'cancelled') && owsBgMarkNotified(d.id, 'end')) {
      owsBgNotify(`⚠ ${d.name || 'Descarga'} ${d.status === 'cancelled' ? 'cancelada' : 'falló'}`, String(d.error || 'Reintenta desde el Gestor de Descargas'));
      try { owsBgSyncTitle(); } catch (_) {}
    }
  } catch (_) {}
}

let owsBgHubLastMilestone = 0;
function owsBgOnHubTick(pct, info, done, version) {
  try {
    if (!owsBgTitleBase) owsBgTitleBase = document.title || 'OWS Hub';
    if (done) {
      document.title = owsBgTitleBase;
      owsBgNotify(`✓ OWS Hub v${version || ''} listo`, 'Se descargó en segundo plano · confirma el reinicio 🎉');
      return;
    }
    document.title = `(${Math.round(pct)}%) Actualizando OWS Hub — en segundo plano`;
    for (const m of OWS_BG_NOTIFY_MILESTONES) {
      if (pct >= m && owsBgHubLastMilestone < m) {
        owsBgHubLastMilestone = m;
        owsBgNotify(`OWS Hub · ${m}%`, String(info || 'Descargando actualización en segundo plano…'));
      }
    }
    if (pct <= 1) owsBgHubLastMilestone = 0;
  } catch (_) {}
}

function initOwsSettings() {
  try { window.OWSSettings = getOwsSettings(); } catch (_) {}
  try { owsBgEnsurePermission(); } catch (_) {}
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
  return payload;
}

// Último payload bueno aunque esté vencido: es la degradación final de la UI
// cuando ninguna fuente fresca responde.
function readOwsHubCacheRaw() {
  try {
    const raw = localStorage.getItem(owsHubCacheKey());
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return (parsed && parsed.tag) ? parsed : null;
  } catch (_) { return null; }
}

// ═══════════════════════════════════════════════════════════════
// RESILIENCIA SIN RENDER — fuentes alternativas de la release del Hub
// ───────────────────────────────────────────────────────────────
// El proxy del backend (/ows-store/github/...) es la fuente principal, pero
// cuando Render no responde (suspendido, dormido, 502) la UI NO se queda sin
// versión ni sin botón de descarga: se prueba esta cadena en orden:
//
//   1) proxy del backend (el failover al espejo ya actúa dentro de fetch)
//   2) api.github.com directo (CORS abierto; 60 pedidos/h por IP sin token)
//   3) manifiesto estático en owsdatabase, servido fuera de Render:
//      raw.githubusercontent.com → cdn.jsdelivr.net
//   4) último caché local, aunque esté vencido
//   5) link genérico a la página de releases (la UI nunca se rompe)
//
// Los manifiestos (ows-hub-update.json, ows-hub-android-update.json) los
// publica cada release en la raíz de owsdatabase — la misma técnica que ya
// usa ows-store-tauri-update.json — así que no dependen ni de Render ni del
// límite de la API de GitHub.
// ═══════════════════════════════════════════════════════════════
const OWS_GITHUB_API_BASE = 'https://api.github.com';
const OWS_DBDATA_FILES = { owner: 'OceanandWild', repo: 'owsdatabase', branch: 'main' };
const OWS_HUB_WINDOWS_MANIFEST = 'ows-hub-update.json';
const OWS_HUB_ANDROID_MANIFEST = 'ows-hub-android-update.json';

// URLs del manifiesto estático: raw primero (más fresco) y jsDelivr después
// (infraestructura distinta, sirve aunque raw esté bloqueado en la red).
function owsManifestUrls(fileName) {
  const f = String(fileName || '').trim();
  if (!f) return [];
  const { owner, repo, branch } = OWS_DBDATA_FILES;
  return [
    `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${f}`,
    `https://cdn.jsdelivr.net/gh/${owner}/${repo}@${branch}/${f}`,
  ];
}

// Plataformas de una release de GitHub (mismo criterio que el backend): el
// repo ows-hub publica Windows y Android mezclados y "la última" puede ser
// de la otra plataforma.
function owsGithubReleasePlatforms(release) {
  const tag = String((release && (release.tag_name || release.name)) || '').trim().toLowerCase();
  const names = (Array.isArray(release && release.assets) ? release.assets : [])
    .map((a) => String((a && a.name) || '').toLowerCase())
    .filter(Boolean);
  const hasApk = names.some((n) => n.endsWith('.apk'));
  const hasDesktop = names.some((n) => /\.(exe|msi)$/.test(n) || n === 'latest.json' || n === 'latest.yml');
  const out = [];
  if (hasDesktop) out.push('windows');
  if (hasApk) out.push('android');
  if (out.length) return out;
  if (/android/i.test(tag)) return ['android'];
  if (/windows/i.test(tag) || /^win[-_]/i.test(tag)) return ['windows'];
  return ['windows'];
}

// Versión visible de una release: "android-v3.3.5" / "v3.4.17" → "3.3.5" / "3.4.17".
function owsGithubReleaseVersion(release) {
  return String((release && (release.tag_name || release.name)) || '')
    .trim()
    .replace(/^(android|windows|win)[-_]/i, '')
    .replace(/^[vV]/, '');
}

// Nombre de archivo a partir de una URL de descarga.
function owsFileNameFromUrl(url) {
  const u = String(url || '');
  const seg = (u.split('/').pop() || '').split('?')[0];
  try { return decodeURIComponent(seg); } catch (_) { return seg; }
}

// ── Traducciones a payload (misma forma use cual use la fuente) ──
function owsHubPayloadFromProxy(data, platform) {
  const tag = String((data && (data.tag_name || data.name)) || '').trim();
  if (!tag) throw new Error('sin tag');
  const asset = pickOwsHubAsset(data && data.assets);
  return {
    tag,
    platform,
    // Los tags de Android son "android-v3.3.5": la versión se muestra
    // siempre como "3.3.5", igual que en Windows.
    version: tag.replace(/^(android|windows|win)[-_]/i, '').replace(/^v/i, ''),
    assetName: asset ? String(asset.name || '') : '',
    assetSize: asset ? Number(asset.size || 0) : 0,
    url: (asset && asset.browser_download_url) || OWS_HUB_RELEASES_URL,
    htmlUrl: String((data && data.html_url) || OWS_HUB_RELEASES_URL),
    publishedAt: (data && (data.published_at || data.created_at)) || '',
  };
}

function owsHubPayloadFromGithubRelease(release, platform) {
  const tag = String((release && (release.tag_name || release.name)) || '').trim();
  const asset = pickOwsHubAsset(release && release.assets);
  return {
    tag,
    platform,
    version: owsGithubReleaseVersion(release),
    assetName: asset ? String(asset.name || '') : '',
    assetSize: asset ? Number(asset.size || 0) : 0,
    url: (asset && asset.browser_download_url) || OWS_HUB_RELEASES_URL,
    htmlUrl: String((release && release.html_url) || OWS_HUB_RELEASES_URL),
    publishedAt: (release && (release.published_at || release.created_at)) || '',
  };
}

// latest.json (formato del updater de Tauri) → payload de la UI.
function owsHubPayloadFromWindowsManifest(manifest) {
  const version = String((manifest && manifest.version) || '').trim().replace(/^[vV]/, '');
  if (!/^\d/.test(version)) throw new Error('manifiesto sin versión');
  const platforms = (manifest && manifest.platforms) || {};
  const target = platforms['windows-x86_64'] || platforms['windows-aarch64'] || {};
  const url = String((target && target.url) || '').trim();
  const tag = `v${version}`;
  return {
    tag,
    platform: 'windows',
    version,
    assetName: url ? owsFileNameFromUrl(url) : '',
    assetSize: 0,
    url: url || OWS_HUB_RELEASES_URL,
    htmlUrl: `https://github.com/${OWS_HUB_REPO.owner}/${OWS_HUB_REPO.repo}/releases/tag/${tag}`,
    publishedAt: String((manifest && manifest.pub_date) || ''),
  };
}

// Manifiesto Android (misma info que una fila de ows_android_releases).
function owsHubPayloadFromAndroidManifest(manifest) {
  const version = String((manifest && (manifest.version_name || manifest.version)) || '').trim().replace(/^[vV]/, '');
  if (!version) throw new Error('manifiesto sin versión');
  const url = String((manifest && (manifest.apk_url || manifest.url)) || '').trim();
  if (!url) throw new Error('manifiesto sin apk_url');
  return {
    tag: `android-v${version}`,
    platform: 'android',
    version,
    assetName: owsFileNameFromUrl(url),
    assetSize: Number((manifest && manifest.size_bytes) || 0),
    url,
    htmlUrl: OWS_HUB_RELEASES_LIST_URL,
    publishedAt: String((manifest && manifest.published_at) || ''),
  };
}

// ── Fuentes individuales (cada una lanza si no puede responder) ──
async function fetchOwsHubReleaseFromProxy(platform) {
  const url = `${API_BASE}/ows-store/github/repos/${OWS_HUB_REPO.owner}/${OWS_HUB_REPO.repo}/releases/latest?platform=${platform}`;
  const res = await fetchWithTimeout(url, OWS_HUB_FETCH_TIMEOUT_MS);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return owsHubPayloadFromProxy(await res.json(), platform);
}

async function fetchOwsHubReleaseFromGithubApi(platform) {
  const { owner, repo } = OWS_HUB_REPO;
  const url = `${OWS_GITHUB_API_BASE}/repos/${owner}/${repo}/releases?per_page=30`;
  const res = await fetchWithTimeout(url, OWS_HUB_FETCH_TIMEOUT_MS);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const list = await res.json().catch(() => null);
  if (!Array.isArray(list)) throw new Error('respuesta inválida');
  const matches = list
    .filter((r) => r && !r.draft && owsGithubReleasePlatforms(r).indexOf(platform) !== -1)
    .sort((a, b) => {
      // Igual que el backend: por versión y no por fecha (los tags de Android
      // y Windows comparten número y el orden por fecha los mezcla).
      const d = owshubCompareVersions(owsGithubReleaseVersion(a), owsGithubReleaseVersion(b));
      if (d !== 0) return -d;
      return String(b.published_at || b.created_at || '').localeCompare(String(a.published_at || a.created_at || ''));
    });
  if (!matches.length) throw new Error('sin releases de la plataforma');
  return owsHubPayloadFromGithubRelease(matches[0], platform);
}

async function fetchOwsHubReleaseFromManifest(platform) {
  const file = platform === 'android' ? OWS_HUB_ANDROID_MANIFEST : OWS_HUB_WINDOWS_MANIFEST;
  let lastError = null;
  for (const url of owsManifestUrls(file)) {
    try {
      const res = await fetchWithTimeout(url, OWS_HUB_FETCH_TIMEOUT_MS);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json().catch(() => null);
      if (!data) throw new Error('JSON inválido');
      return platform === 'android'
        ? owsHubPayloadFromAndroidManifest(data)
        : owsHubPayloadFromWindowsManifest(data);
    } catch (err) { lastError = err; }
  }
  throw lastError || new Error('sin manifiesto');
}

// Última release del Hub de LA PLATAFORMA CORRECTA (?platform=...): nunca
// lanza; agota la cadena de fuentes y, si todo falla, devuelve el último
// caché (aunque esté vencido) o el link genérico a la página de releases.
function fetchOwsHubRelease() {
  if (owsHubReleasePromise) return owsHubReleasePromise;
  const cached = readOwsHubCache();
  if (cached) return Promise.resolve(cached);

  const platform = owsUpdatesPlatform();
  owsHubReleasePromise = (async () => {
    // 1) Proxy del backend (el failover al espejo ya actúa dentro de fetch).
    try {
      return writeOwsHubCache(await fetchOwsHubReleaseFromProxy(platform));
    } catch (err) {
      console.warn('[OWS] Release del Hub: backend no disponible:', (err && err.message) || err);
    }
    // 2) api.github.com directo.
    try {
      return writeOwsHubCache(await fetchOwsHubReleaseFromGithubApi(platform));
    } catch (err) {
      console.warn('[OWS] Release del Hub: API de GitHub sin respuesta:', (err && err.message) || err);
    }
    // 3) Manifiesto estático (raw → jsDelivr).
    try {
      return writeOwsHubCache(await fetchOwsHubReleaseFromManifest(platform));
    } catch (err) {
      console.warn('[OWS] Release del Hub: manifiesto estático no disponible:', (err && err.message) || err);
    }
    // 4-5) Caché vencido o link genérico. Si no hay ni caché se limpia la memo
    // para que el próximo intento (reabrir el panel, "Reintentar") vuelva a
    // probar la cadena en vez de repetir el resultado vacío de esta vez.
    const stale = readOwsHubCacheRaw();
    if (!stale) owsHubReleasePromise = null;
    return stale || { tag: '', platform, version: '', assetName: '', assetSize: 0, url: OWS_HUB_RELEASES_URL, htmlUrl: OWS_HUB_RELEASES_URL, publishedAt: '' };
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

// ── Respaldo sin Render para releases Android ──
// Misma cadena que la release del Hub: backend → api.github.com directo
// (solo canales con repo conocido) → manifiesto estático (raw → jsDelivr) →
// caché local de la última release vista. Sin backend, el canal APK del Hub
// sigue detectando versiones y bajando el .apk directo de GitHub.
const OWS_ANDROID_MANIFEST_FILES = {
  [OWS_ANDROID_CHANNEL]: OWS_HUB_ANDROID_MANIFEST,
  'ows-store': 'ows-store-android-update.json',
};
const OWS_ANDROID_CHANNEL_REPOS = {
  [OWS_ANDROID_CHANNEL]: OWS_HUB_REPO,
};
const OWS_ANDROID_RELEASE_CACHE_KEY = 'ows_android_release_cache_v1';

function readAndroidReleaseCache(slug) {
  try {
    const raw = localStorage.getItem(OWS_ANDROID_RELEASE_CACHE_KEY);
    const all = raw ? JSON.parse(raw) : {};
    const rel = all && all[String(slug || '').trim()];
    return (rel && rel.apk_url) ? rel : null;
  } catch (_) { return null; }
}

function writeAndroidReleaseCache(slug, rel) {
  const s = String(slug || '').trim();
  if (!s || !rel || !rel.apk_url) return rel || null;
  try {
    const raw = localStorage.getItem(OWS_ANDROID_RELEASE_CACHE_KEY);
    const all = raw ? JSON.parse(raw) : {};
    all[s] = rel;
    localStorage.setItem(OWS_ANDROID_RELEASE_CACHE_KEY, JSON.stringify(all));
  } catch (_) {}
  return rel;
}

// El asset .apk más pesado de una release de GitHub (mismo criterio que el
// backend al registrarla).
function pickOwsAndroidApkAsset(assets) {
  const list = (Array.isArray(assets) ? assets : []).filter((a) =>
    a && a.browser_download_url && String(a.name || '').toLowerCase().endsWith('.apk')
  );
  if (!list.length) return null;
  return [...list].sort((a, b) => Number(b.size || 0) - Number(a.size || 0))[0];
}

async function fetchAndroidReleaseFromGithub(slug) {
  const src = OWS_ANDROID_CHANNEL_REPOS[String(slug || '').trim()];
  if (!src) return null;
  const url = `${OWS_GITHUB_API_BASE}/repos/${src.owner}/${src.repo}/releases?per_page=30`;
  const res = await fetchWithTimeout(url, OWS_HUB_FETCH_TIMEOUT_MS);
  if (!res.ok) return null;
  const list = await res.json().catch(() => null);
  if (!Array.isArray(list)) return null;
  const matches = list
    .filter((r) => r && !r.draft && owsGithubReleasePlatforms(r).indexOf('android') !== -1)
    .sort((a, b) => {
      const d = owshubCompareVersions(owsGithubReleaseVersion(a), owsGithubReleaseVersion(b));
      if (d !== 0) return -d;
      return String(b.published_at || b.created_at || '').localeCompare(String(a.published_at || a.created_at || ''));
    });
  const release = matches[0];
  if (!release) return null;
  const asset = pickOwsAndroidApkAsset(release.assets);
  if (!asset) return null;
  return {
    project_slug: String(slug || '').trim(),
    package_id: '',
    // La release de GitHub no trae versionCode: el cliente compara por nombre.
    version_name: owsGithubReleaseVersion(release),
    version_code: 0,
    apk_url: String(asset.browser_download_url || ''),
    sha256: '',
    size_bytes: Number(asset.size || 0),
    release_notes: String(release.body || '').trim(),
    published_at: release.published_at || release.created_at || '',
    source: 'github',
  };
}

async function fetchAndroidReleaseFromManifest(slug) {
  const file = OWS_ANDROID_MANIFEST_FILES[String(slug || '').trim()];
  if (!file) return null;
  for (const url of owsManifestUrls(file)) {
    try {
      const res = await fetchWithTimeout(url, OWS_HUB_FETCH_TIMEOUT_MS);
      if (!res.ok) continue;
      const data = await res.json().catch(() => null);
      if (!data) continue;
      const apkUrl = String(data.apk_url || data.url || '').trim();
      const version = String(data.version_name || data.version || '').trim().replace(/^[vV]/, '');
      if (!apkUrl || !version) continue;
      return {
        project_slug: String(slug || '').trim(),
        package_id: String(data.package_id || ''),
        version_name: version,
        version_code: Number(data.version_code || 0),
        apk_url: apkUrl,
        sha256: String(data.sha256 || ''),
        size_bytes: Number(data.size_bytes || data.size || 0),
        release_notes: String(data.release_notes || data.notes || ''),
        published_at: String(data.published_at || data.pub_date || ''),
        source: 'manifest',
      };
    } catch (_) {}
  }
  return null;
}

// Última release Android publicada para un slug (null = no hay APK). Nunca
// lanza: agota la cadena de respaldo y termina en el caché local.
async function fetchAndroidRelease(slug) {
  const s = String(slug || '').trim();
  if (!s) return null;
  // 1) Backend (el failover al espejo ya actúa dentro de fetch).
  try {
    const res = await fetch(API_BASE + '/ows-store/android/releases/' + encodeURIComponent(s) + '/latest');
    if (res.ok) {
      const data = await res.json().catch(() => ({}));
      const rel = (data && data.release) || null;
      if (rel && rel.apk_url) {
        androidReleaseCache[s] = rel;
        return writeAndroidReleaseCache(s, rel);
      }
    }
  } catch (_) {}
  // 2) api.github.com directo (solo canales con repo conocido).
  try {
    const rel = await fetchAndroidReleaseFromGithub(s);
    if (rel) {
      androidReleaseCache[s] = rel;
      return writeAndroidReleaseCache(s, rel);
    }
  } catch (_) {}
  // 3) Manifiesto estático.
  try {
    const rel = await fetchAndroidReleaseFromManifest(s);
    if (rel) {
      androidReleaseCache[s] = rel;
      return writeAndroidReleaseCache(s, rel);
    }
  } catch (_) {}
  // 4) Caché local: sin backend, lo último visto sigue sirviendo para instalar.
  const cached = readAndroidReleaseCache(s);
  if (cached) androidReleaseCache[s] = cached;
  return cached;
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
  // true = datos de respaldo (sin backend): la UI avisa "sin conexión".
  stale: false,
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

// Versión del binario, SIN red: la expone el núcleo de Tauri y ya viene
// compilada en el ejecutable. Es la única fuente confiable. El chequeo del
// updater pega al CDN de GitHub y con la red lenta se cae (por eso la 3.4.11
// seguia mostrando 3.4.10 teniendo el binario en 3.4.11: se uso el texto del
// HTML, que era viejo). El permiso core:app:allow-version ya viene incluido
// en core:default.
function hubBinaryVersion() {
  return Promise.resolve()
    .then(() => tauriInvoke('plugin:app|version', {}, 4000))
    .then((v) => {
      const s = String(v == null ? '' : v).trim().replace(/^[vV]/, '');
      return /^\d+(\.\d+)*$/.test(s) ? s : '';
    })
    .catch(() => '');
}

// Escribe la versión real en la barra lateral. El HTML queda como valor
// inicial de respaldo (navegador), nunca como la fuente de verdad.
function syncHubVersionLabelFromBinary() {
  if (owsEnvironment() !== 'desktop') return;
  try {
    hubLocalVersion().then((v) => {
      if (!v) return;
      const el = document.querySelector('.nav-version');
      if (el) el.textContent = 'OWS Hub · v' + v;
    }).catch(() => {});
  } catch (_) {}
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
      // El chequeo pega al CDN de GitHub (latest.json). Con 8 s una red lenta o
      // un cache frio daba timeout y el probe volvia null: el Hub_thenesia
      // "no trae el actualizador" y empujaba al instalador manual aunque el
      // updater estivesseperfecto. Con 20 s seguiaimming dejando pasar los
      //UNE stalls de GitHub, así que ahora usa el mismo check con reintentos
      // que el botón de actualizar (45 s x 3).
      const upd = await hubUpdaterCheckFresh();
      if (!upd || typeof upd !== 'object') return null;
      return {
        // Sin version no se puede afirmar que haya update: una comparacion
        // ingenua de strings daba true con ambos vacios.
        available: !!upd.version && String(upd.version) !== String(upd.currentVersion || ''),
        version: String(upd.version || '').replace(/^[vV]/, ''),
        currentVersion: String(upd.currentVersion || '').replace(/^[vV]/, ''),
        date: upd.date || '',
        notes: String(upd.body || '')
      };
    } catch (err) {
      // Hub viejo sin plugin updater, o sin red: la UI degrada a la
      // versión del HTML y al link de releases. Un fallo NO se cachea: si se
      // guardara, la UI quedaria 60 s mintiendo sobre el updater.
      if (!(opts && opts.quiet)) console.warn('[OWS] updater check falló:', (err && err.message) || err);
      try { owsHubUpdaterProbe = null; } catch (_) {}
      return null;
    }
  })();
  owsHubUpdaterProbe = { at: Date.now(), promise };
  return promise;
}

async function hubLocalVersion() {
  // Si ya se resolvio y dio algo usable se reusa; si fallo, se reintenta.
  if (owsHubVersionChecked && owsHubLocalVersion) return owsHubLocalVersion;
  // 1) Binario: la version compilada en el ejecutable. Sin red, nunca falla.
  //    Es la unica fuente confiable: el updater pega al CDN de GitHub y con
  //    la red lenta se cae, y ahi se terminaba usando el texto del HTML.
  let v = await hubBinaryVersion();
  // 2) Updater: depende de la red.
  if (!v) {
    const fromTauri = await tauriUpdaterCheck({ quiet: true, cacheMs: 60000 });
    if (fromTauri && fromTauri.currentVersion) {
      v = String(fromTauri.currentVersion).replace(/^[vV]/, '');
    }
  }
  // 3) HTML: ultimo respaldo (navegador).
  if (!v) v = parseHubVersionFromUi();
  owsHubLocalVersion = v || '';
  owsHubVersionChecked = true;
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
function tauriInvokeRaw(cmd, args) {
  const core = window.__TAURI__ && window.__TAURI__.core;
  const invoke = core && typeof core.invoke === 'function'
    ? core.invoke
    : (window.__TAURI_INTERNALS__ && typeof window.__TAURI_INTERNALS__.invoke === 'function'
        ? window.__TAURI_INTERNALS__.invoke.bind(window.__TAURI_INTERNALS__)
        : null);
  if (!invoke) return Promise.reject(new Error('WebView sin puente de Tauri'));
  return Promise.resolve().then(() => invoke(cmd, args || {}));
}

function tauriUpdaterCall(cmd, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timeout')), Number(timeoutMs) || 15000);
    tauriInvokeRaw(cmd, args)
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

  const platform = owsUpdatesPlatform();
  let hubVer = '';
  try {
    hubVer = await hubLocalVersion();
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
    // El probe puede fallar por red sin que al Hub le falte el updater: sin
    // distinguirlos la UI acusa al updater de algo que no es.
    hub.updater_probe_ok = !!tauriUpd;

    const projects = Array.isArray(data.projects) ? data.projects : [];
    const counts = data.counts || {};
    const pendingProjects = projects.filter((p) => p.update_available).length;

    updatesState = {
      loaded: true,
      loading: false,
      error: '',
      stale: false,
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
    writeUpdatesProjectsCache(platform, projects);
  } catch (err) {
    // Backend caído (Render suspendido/dormido): en vez del error pelado se
    // arma un estado degradado — tarjeta del Hub con la cadena de respaldo
    // (GitHub / manifiesto / caché; en desktop además el updater de Tauri) y
    // juegos con la última copia guardada. Si no hay NINGUNA señal, se cae al
    // error de siempre para no mostrar "al día" sin datos.
    let degraded = null;
    try { degraded = await buildUpdatesFallbackState(platform, hubVer); } catch (_) {}
    if (degraded) {
      updatesState = degraded;
    } else {
      updatesState.loading = false;
      updatesState.loaded = false;
      updatesState.error = String((err && err.message) || err);
    }
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

    // Canal del Hub: backend primero; si Render no contesta, se resuelve con
    // la cadena de respaldo (api.github.com / manifiesto / caché) y la
    // comparación se hace en el cliente — la actualización APK no depende de
    // que el backend esté arriba.
    let latest = null;
    let updateAvailable = false;
    let backendOk = false;
    let backendErr = null;
    try {
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
      latest = (data && data.latest) || null;
      updateAvailable = !!(data && data.update_available);
      backendOk = true;
    } catch (err) {
      backendErr = err;
      console.warn('[OWS] Canal Android: backend no disponible, probando respaldo:', (err && err.message) || err);
      latest = await fetchAndroidRelease(OWS_ANDROID_CHANNEL).catch(() => null);
    }
    // Comparación en cliente cuando el backend no pudo opinar (o no trajo
    // versionCode): por versionCode si ambos lo tienen, si no por nombre
    // (3.3.6 > 3.3.5).
    if (latest && latest.version_name && installedName) {
      const latestCode = Number(latest.version_code || 0);
      if (latestCode > 0 && installedCode > 0) {
        updateAvailable = latestCode > installedCode;
      } else if (!installedCode || !backendOk) {
        updateAvailable = owshubCompareVersions(latest.version_name, installedName) > 0;
      }
    }

    // Proyectos multi-plataforma en Android: el servidor ya filtra por
    // plataforma y compara contra lo instalado (se manda installed=slug:ver
    // desde el registro local de APKs). Así Wilder Gambit y demás juegos con
    // build Android aparecen para instalar/actualizar desde el Gestor.
    // Si Render no contesta, se muestra la última copia guardada.
    const projectsCache = readUpdatesProjectsCache('android');
    let projects = projectsCache ? projectsCache.projects : [];
    let projectsFresh = false;
    try {
      const inst = androidInstalledMapParam();
      const qs = inst ? ('?platform=android&installed=' + encodeURIComponent(inst)) : '?platform=android';
      const pres = await fetch(API_BASE + '/ows-updates/projects' + qs);
      const pdata = await pres.json().catch(() => ({}));
      if (pres.ok && Array.isArray(pdata.projects)) {
        projects = pdata.projects;
        projectsFresh = true;
        writeUpdatesProjectsCache('android', projects);
      }
    } catch (_) {}

    // Sin canal, sin respaldo y sin copia guardada no hay nada honesto que
    // mostrar: se conserva el error original.
    if (!backendOk && !latest && !projects.length) {
      throw backendErr || new Error('Sin respuesta del canal de actualizaciones');
    }

    const pendingProjects = projects.filter((p) => p.update_available).length;
    updatesState = {
      android: true,
      platform: 'android',
      loaded: true,
      loading: false,
      error: '',
      stale: !backendOk || !projectsFresh,
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
      projects,
      counts: {
        total: projects.length,
        installed: projects.filter((p) => p.installed).length,
        with_build: projects.filter((p) => p.has_build).length,
        updates: pendingProjects,
        pending: pendingProjects + (updateAvailable ? 1 : 0),
      },
    };
  } catch (err) {
    updatesState.loading = false;
    updatesState.loaded = false;
    updatesState.error = String((err && err.message) || err);
  }
  try { renderUpdates(); } catch (_) {}
  try { syncUpdatesBadge(); } catch (_) {}
}

// ── Caché local de la lista de proyectos ───────────────────────
// Última lista vista por plataforma: con el backend caído el Gestor muestra
// esa copia en vez de quedarse en blanco o mentir con "no hay nada".
const UPDATES_PROJECTS_CACHE_KEY = 'ows_updates_projects_cache_v1';
function readUpdatesProjectsCache(platform) {
  try {
    const raw = localStorage.getItem(UPDATES_PROJECTS_CACHE_KEY);
    const all = raw ? JSON.parse(raw) : {};
    const entry = all && all[String(platform || 'windows')];
    if (!entry || !Array.isArray(entry.projects) || !entry.projects.length) return null;
    return { ts: Number(entry.ts || 0), projects: entry.projects };
  } catch (_) { return null; }
}
function writeUpdatesProjectsCache(platform, projects) {
  if (!Array.isArray(projects)) return;
  try {
    const raw = localStorage.getItem(UPDATES_PROJECTS_CACHE_KEY);
    const all = raw ? JSON.parse(raw) : {};
    all[String(platform || 'windows')] = { ts: Date.now(), projects };
    localStorage.setItem(UPDATES_PROJECTS_CACHE_KEY, JSON.stringify(all));
  } catch (_) {}
}

// ── Estado degradado del Gestor cuando el backend no contesta ──
// La tarjeta del Hub se resuelve con la cadena de respaldo (proxy ya agotado
// → api.github.com → manifiesto → caché; en desktop además el updater de
// Tauri, que no depende del backend) y los juegos con la última copia
// guardada. Devuelve null si no hay NINGUNA señal: en ese caso el llamador
// conserva el error de siempre con "Reintentar".
async function buildUpdatesFallbackState(platform, hubVer) {
  const cache = readUpdatesProjectsCache(platform);
  const cachedProjects = cache ? cache.projects : [];
  const tauriUpd = await tauriUpdaterCheck({ quiet: true, cacheMs: 60000 }).catch(() => null);
  let rel = null;
  try { rel = await fetchOwsHubRelease(); } catch (_) { rel = null; }

  const current = String(hubVer || '').replace(/^[vV]/, '');
  const latest = String((rel && rel.version) || '').replace(/^[vV]/, '');
  let updateAvailable = !!(latest && current) && owshubCompareVersions(latest, current) > 0;
  // En desktop el updater de Tauri es la fuente real de "¿hay versión nueva?".
  if (tauriUpd && String(tauriUpd.currentVersion || '') && typeof tauriUpd.available === 'boolean') {
    updateAvailable = tauriUpd.available;
  }

  if ((!rel || !rel.tag) && !tauriUpd && !cachedProjects.length) return null;

  const hub = {
    name: 'OWS Hub',
    current_version: current || String((tauriUpd && tauriUpd.currentVersion) || '').replace(/^[vV]/, ''),
    latest_version: latest || String((tauriUpd && tauriUpd.version) || '').replace(/^[vV]/, ''),
    update_available: updateAvailable,
    can_self_update: !!(tauriUpd && tauriUpd.available),
    updater_available: !!(tauriUpd && tauriUpd.available),
    updater_probe_ok: !!tauriUpd,
    notes: (tauriUpd && tauriUpd.notes) || '',
    published_at: (rel && rel.publishedAt) || (tauriUpd && tauriUpd.date) || '',
    html_url: (rel && rel.htmlUrl) || OWS_HUB_RELEASES_URL,
    // Link directo al asset de GitHub: la descarga no pasa por Render.
    installer_url: (rel && rel.url) || '',
    installer_name: (rel && rel.assetName) || '',
    installer_size: (rel && rel.assetSize) || 0,
  };

  const pendingProjects = cachedProjects.filter((p) => p.update_available).length;
  return {
    loaded: true,
    loading: false,
    error: '',
    stale: true,
    checkedAt: (cache && cache.ts) ? new Date(cache.ts).toISOString() : new Date().toISOString(),
    filter: updatesState.filter || 'all',
    platform,
    hub,
    projects: cachedProjects,
    counts: {
      total: cachedProjects.length,
      installed: cachedProjects.filter((p) => p.installed).length,
      with_build: cachedProjects.filter((p) => p.has_build).length,
      updates: pendingProjects,
      pending: pendingProjects + (updateAvailable ? 1 : 0),
    },
  };
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

// ── APKs instalados en Android (registro local) ──
// Android no tiene OWSHubLibrary: se guarda qué versión de cada APK se abrió
// para instalar, y el Gestor la compara contra la publicada para ofrecer
// actualizar. El Hub mismo se excluye (su versión la da el paquete nativo).
const OWS_ANDROID_INSTALLED_KEY = 'ows_android_installed_v1';
function getAndroidInstalledMap() {
  try {
    const raw = localStorage.getItem(OWS_ANDROID_INSTALLED_KEY);
    const obj = raw ? JSON.parse(raw) : {};
    if (obj && typeof obj === 'object') {
      const out = {};
      Object.keys(obj).forEach((k) => {
        const v = String(obj[k] || '').trim();
        if (k && v) out[String(k)] = v;
      });
      return out;
    }
  } catch (_) {}
  return {};
}
function androidInstalledMapParam() {
  const map = getAndroidInstalledMap();
  return Object.keys(map).map((s) => `${s}:${map[s]}`).join(',');
}
function saveAndroidInstalled(slug, version) {
  const s = String(slug || '').trim();
  const v = String(version || '').trim();
  if (!s || !v || s === OWS_ANDROID_CHANNEL) return;
  try {
    const map = getAndroidInstalledMap();
    map[s] = v;
    localStorage.setItem(OWS_ANDROID_INSTALLED_KEY, JSON.stringify(map));
  } catch (_) {}
}

// Instalar/actualizar un JUEGO en Android desde el Gestor: mismo flujo de APK
// nativo que el Hub (descarga con % en el Gestor + instalador del sistema).
async function runProjectApkInstall(slug) {
  const s = String(slug || '').trim();
  if (!s) return;
  const row = (updatesState.projects || []).find((p) => String(p.slug) === s);
  const proj = getDownloadProject(s);
  const name = (row && row.name) || (proj && proj.name) || s;
  await startAndroidApkInstall(s, name);
  try { loadUpdatesManager({ force: true }); } catch (_) {}
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

  // Flujo de versiones en celdas con etiqueta: se lee de un vistazo qué hay
  // instalada y qué hay disponible, incluso cuando son la misma versión.
  const verCells = [];
  verCells.push(`<span class="upd-ver-cell"><small>Instalada</small><b class="upd-ver-chip upd-ver-old">${p.installed_version ? 'v' + escapeHtml(p.installed_version) : '—'}</b></span>`);
  if (p.latest_version) {
    verCells.push(`<span class="upd-ver-arrow" aria-hidden="true">→</span>`);
    verCells.push(`<span class="upd-ver-cell"><small>${p.update_available ? 'Nueva' : 'Última'}</small><b class="upd-ver-chip upd-ver-new">v${escapeHtml(p.latest_version)}</b></span>`);
  }

  const metaBits = [];
  if (p.size_label) metaBits.push(`<span class="upd-meta-bit">📦 ${escapeHtml(p.size_label)}</span>`);
  if (p.released_at) {
    const d = formatReleaseDate(p.released_at);
    if (d) metaBits.push(`<span class="upd-meta-bit">🗓️ ${escapeHtml(d)}</span>`);
  }
  if (p.prerelease) metaBits.push(`<span class="upd-chip-pre">${escapeHtml(p.channel || 'beta')}</span>`);

  const actions = [];
  const inAndroid = owsEnvironment() === 'android';
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
    } else if (inAndroid) {
      // App Android: instalar/actualizar el APK directo (canal ows_android_releases).
      const chTag = p.prerelease ? ` <span class="upd-chip-pre">${escapeHtml(p.channel || 'beta')}</span>` : '';
      const label = p.update_available
        ? `⬇ Actualizar${p.latest_version ? ' a v' + escapeHtml(p.latest_version) : ''}`
        : (p.installed ? `⬇ Reinstalar${p.latest_version ? ' v' + escapeHtml(p.latest_version) : ''}` : `⬇ Instalar APK${p.latest_version ? ' v' + escapeHtml(p.latest_version) : ''}`);
      actions.push(`<button class="btn btn-primary btn-sm" data-upd-action="${p.update_available ? 'apk-update' : 'apk-install'}" data-slug="${safeSlug}">📲 ${label}</button>${chTag}`);
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
        <div class="upd-row-vers">${verCells.join('')}</div>
        ${p.notes ? `<p class="upd-row-notes">${escapeHtml(p.notes)}</p>` : ''}
        ${metaBits.length ? `<p class="upd-row-meta">${metaBits.join('')}</p>` : ''}
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
      const time = Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' });
      if (updatesState.stale) {
        // Datos de respaldo: no se puede decir "Revisado": la lista puede ser
        // la última copia guardada o solo la info del Hub.
        meta.textContent = 'Sin conexión' + ((updatesState.projects || []).length
          ? (time ? ' · copia de las ' + time : ' · última copia guardada')
          : ' · información del Hub');
      } else {
        meta.textContent = Number.isNaN(d.getTime()) ? 'Revisado' : ('Revisado ' + time);
      }
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

  // Contador al lado de cada filtro: se ve de una cuántos hay en cada estado.
  const all = Array.isArray(updatesState.projects) ? updatesState.projects : [];
  const counts = {
    all: all.length,
    pending: all.filter((p) => p.update_available || (!p.installed && p.has_build)).length,
    current: all.filter((p) => p.installed && !p.update_available).length,
    unavailable: all.filter((p) => !p.has_build).length
  };
  document.querySelectorAll('[data-upd-count]').forEach((el) => {
    el.textContent = String(counts[el.getAttribute('data-upd-count')] || 0);
  });

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
      if (updatesState.stale && !(updatesState.projects || []).length) {
        // Sin backend y sin copia guardada: dejar claro que no es que "no
        // hay nada", sino que no se pudo consultar.
        sub.textContent = 'Sin conexión con el servidor: no se pudo consultar tus juegos. Tocá «Buscar actualizaciones» para reintentar.';
      } else if (updatesState.android) {
        sub.textContent = 'Sin juegos con APK todavía: cuando un proyecto publique su versión Android aparecerá acá para instalarlo.';
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
    else if (updatesState.stale) state.textContent = 'Sin conexión · última versión conocida';
    else if (hub.unknown) state.textContent = 'Versión del Hub sin verificar';
    else state.textContent = 'Tu OWS Hub está actualizado';
  }

  if (notes) {
    const raw = String(hub.notes || '').trim();
    if (raw) {
      // Las notas de GitHub vienen en Markdown: se muestran con el
      // mini-markdown (negritas y links), siempre HTML escapado.
      notes.innerHTML = hubMdInline(hubMdEscape(raw));
      notes.classList.remove('hidden', 'is-open');
      // El bloque se recorta con un degradado y se despliega con el boton:
      // antes tenia scroll interno y la barra cortaba el texto a mitad.
      const more = document.getElementById('upd-hub-notes-more');
      if (more) {
        const desborda = notes.scrollHeight > notes.clientHeight + 6;
        more.classList.toggle('hidden', !desborda);
        more.textContent = 'Ver todas las novedades';
        more.setAttribute('aria-expanded', 'false');
      }
    } else {
      notes.innerHTML = '';
      notes.classList.add('hidden');
      notes.classList.remove('is-open');
      const more = document.getElementById('upd-hub-notes-more');
      if (more) more.classList.add('hidden');
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
      // "No pude comprobarlo" y "no lo tenés" son cosas distintas: la primera
      // se arregla reintentando, la segunda no.
      hint.textContent = hub.updater_probe_ok
        ? 'Esta versión del Hub no trae el actualizador: cerrá el Hub y usá el instalador.'
        : 'No se pudo comprobar la actualización automática (se cortó la consulta). Tocá «Buscar actualizaciones» otra vez, o cerrá el Hub y usá el instalador.';
    } else if (hasUpdate && !inDesktop) {
      hint.textContent = 'Instalá el Hub y desde ahí aplicás la actualización sin pasos extra.';
    } else if (updatesState.stale) {
      // Datos de respaldo: el link de releases queda siempre a mano y la
      // descarga directa apunta al asset de GitHub (sin pasar por Render).
      hint.innerHTML = 'Sin conexión con el servidor: mostrando la última versión conocida. <a href="' + escapeHtml(hub.html_url || OWS_HUB_RELEASES_URL) + '" target="_blank" rel="noopener">Releases ↗</a>';
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
// Retardo del cierre del toaster una vez llena la barra (ver runHubSelfUpdate).
let hubUpdHideTimer = null;

// ── Toaster fijo del Hub ────────────────────────────────────────
// A diferencia del de juegos, este NO se oculta solo: se queda mientras
// dura la descarga. Se pinta una vez y después se parchea en sitio para
// que la animación de entrada no se reinicie en cada chunk.
function hubUpdToastShow(version) {
  const box = document.getElementById('hub-upd-toaster');
  if (!box) return;
  clearTimeout(hubUpdHideTimer);
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
  try {
    owsBgHubLastMilestone = 0;
    owsBgNotify(`⬇ OWS Hub v${version} en segundo plano`, 'Puedes seguir usando el Hub · el progreso sigue arriba.');
  } catch (_) {}
}

function hubUpdToastPatch(pct, info, done) {
  const box = document.getElementById('hub-upd-toaster');
  if (!box) return;
  const item = box.querySelector('[data-hub-upd]');
  if (!item) return;
  const bar = item.querySelector('.hub-upd-toast-bar i');
  if (bar) {
    if (done) {
      // El 100% final va SIN transicion: con la animacion de 0.25s la barra
      // se quedaba en la mitad del recorrido y parecia que la descarga no
      // habia terminado (el toaster se cerraba antes de que llegara al final).
      bar.style.transition = 'none';
      void bar.offsetWidth; // fuerza el corte antes del último salto
      bar.style.width = '100%';
    } else {
      // En curso nunca llega al 100%: la barra llena es sinónimo de "listo".
      bar.style.width = Math.max(0, Math.min(99, pct)) + '%';
    }
  }
  const txt = item.querySelector('.hub-upd-toast-info');
  if (txt && txt.textContent !== info) txt.textContent = info;
  const badge = item.querySelector('.hub-upd-toast-badge');
  if (badge && done) { badge.textContent = '✔ Listo'; badge.classList.add('dl-badge-done'); }
  if (done) item.classList.add('is-done');
  try {
    const nameEl = item.querySelector('.dl-toast-name');
    const ver = nameEl ? String(nameEl.textContent || '').replace(/^OWS Hub v/i, '').trim() : '';
    owsBgOnHubTick(Number(pct) || 0, String(info || ''), !!done, ver);
  } catch (_) {}
}

function hubUpdToastHide() {
  clearTimeout(hubUpdHideTimer);
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
  const { rid, bytesRid, version } = hubPendingInstall;
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
    hubUpdateBusy = false;
    // No un toast genérico: el toast se iba y el usuario veía el Hub igual,
    // sin entender por qué la actualización no se había aplicado. El modal
    // además ofrece el instalador, que es el camino que sí funciona.
    showToast('No se pudo aplicar la actualización: ' + String((err && err.message) || err));
    let current = '';
    try { current = String(await hubLocalVersion() || '').replace(/^[vV]/, ''); } catch (_) { current = ''; }
    openHubUpdateFailedModal(String(version || ''), current || 'la anterior');
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
// Versión con anuncio destacado (se resalta en el modal de novedades y en
// la tarjeta de actualización): el lanzamiento multi-plataforma de Wilder Gambit.
const HUB_CHANGELOG_HIGHLIGHT = '3.4.0';
const HUB_CHANGELOGS = {
  '3.4.16': [
    'Noticias ya no se queda en blanco si el servidor no responde: ahora muestra qué pasó y un botón para reintentar en el momento.',
    'El Hub distingue "todavía no hay noticias" de "no se pudo conectar", en vez de mostrar las dos situaciones igual.',
    'Al volver a entrar a Noticias, la sección reintenta sola: si el servidor ya está despierto, la lista aparece sin que hagas nada.',
    'Lanzamientos ya no repite el aviso de la lista local: aparece una sola vez por carga, y el botón Reintentar ahora sí responde.',
    'Mientras el servidor despierta, el Hub se rescata solo: los datos reales reemplazan a los locales apenas están disponibles.',
    'Eventos recibió el mismo tratamiento, y el Admin ya acepta descripciones de noticia de hasta 4000 caracteres (antes 500).',
  ],
  '3.4.15': [
    'Actualizar el Hub ya no falla con un "timeout" al toque. Cuando GitHub tardaba en responder, la comprobación se agotaba a los 15 segundos y el Hub se rindía sin descargar nada.',
    'La comprobación ahora espera bastante más y reintenta sola hasta tres veces, distinguiendo los problemas de conexión de los errores de verdad.',
    'La descarga ya no se corta a los 15 minutos: si sigue avanzando, termina. El corte solo se activa si se queda quieta un rato largo.',
    'El aviso de descarga muestra velocidad y cuánto falta, así se distingue una descarga lenta de una que se colgó.',
    'Cuando la descarga falla por la red, el mensaje lo dice claro en vez de mostrar un error técnico.',
  ],
  '3.4.14': [
    'Lanzamientos ya muestra el tráiler del juego destacado, arriba de la ficha, sin salir del Hub.',
    'El tráiler sale de la cartelera solo: desaparece a las 00:00 del día del lanzamiento, sin que nadie tenga que despublicarlo.',
    'Un juego con tráiler en cartelera se lleva la ficha destacada mientras todavía no salió.',
    'El video no se carga hasta que tocás el play: el Hub sigue arrancando igual de rápido.',
  ],
  '3.4.13': [
    'Las fechas de lanzamiento ya se muestran en el día correcto: si cargabas el 15 de octubre en el Admin, el Hub mostraba el 14.',
    'Se toma solo la parte de la fecha, sin la hora, así que coincide con lo que cargaste.',
    'Las fechas que sí tienen hora (publicación de una build o de una noticia) no cambian.',
  ],
  '3.4.12': [
    'La versión se lee ahora del binario, sin depender de internet. Antes, con la red lenta, el Hub caía a un número viejo y seguía anunciándose como una versión anterior a la instalada.',
    'El CI escribe la versión en el HTML al compilar, así que el valor de respaldo ya no queda desfasado.',
  ],
  '3.4.11': [
    'El Hub ya no anuncia una versión equivocada: la de la barra lateral salía de un texto fijo que no se actualizaba al publicar.',
    'El Gestor ya no pide instalar una y otra vez algo que ya tenés, y el modal de novedades compara contra la versión real.',
    'La versión ahora se lee siempre del binario; el texto del HTML queda solo como respaldo para el navegador.',
  ],
  '3.4.10': [
    'Las fechas de lanzamiento ya no se muestran un día antes: si en el Admin cargabas el 15 de octubre, el Hub mostraba el 14.',
    'El modal de novedades ahora muestra las novedades reales de la versión, en vez del texto genérico del instalador.',
    'Si la actualización se descarga pero no llega a aplicarse, el Hub te lo dice al volver a abrir y te ofrece el instalador, en vez de festejar un cambio que no ocurrió.',
    'El Hub ya no dice que tu versión "no trae el actualizador" cuando lo que pasó es que se cortó la consulta: ahora distingue las dos cosas y te deja reintentar.',
  ],
  '3.4.9': [
    'Las fechas de lanzamiento ya no se muestran un día antes: si en el Admin cargabas el 15 de octubre, el Hub mostraba el 14.',
    'La fecha estimada y la confirmada se interpretan en hora local, así que coinciden con lo que se cargó.',
    'Los cruces de mes y de año también se veían mal antes: el 1 de enero aparecía como 31 de diciembre del año anterior.',
    'Las fechas que sí traen hora (la publicación de una build o de una noticia) no cambian: siguen en hora local.',
  ],
  '3.4.8': [
    'La ficha destacada de Lanzamientos ya no deja franjas vacías en los bordes al mover el mouse sobre la portada.',
    'El velo de lectura va en su propia capa: el texto mantiene el contraste mientras la portada se mueve.',
    'Al abrir un juego, la portada vuela desde la tarjeta correcta.',
    'La ficha del Hub muestra la versión instalada y la disponible en celdas con etiqueta.',
    'Las novedades de cada versión se despliegan con un botón en vez de cortarse con una barra de scroll.',
    'Contador al lado de cada filtro de actualizaciones.',
    'La barra de progreso de la descarga del Hub llega al 100%.',
  ],
  '3.4.7': [
    'Lanzamientos completamente rediseñado: ficha destacada del juego con su banner, y debajo el catálogo en tarjetas con portada, estado, versión y plataformas.',
    'Filtros por estado y contador de lanzamientos, para ver rápido qué hay disponible y qué viene.',
    'Animaciones nuevas: las tarjetas entran en escala, la portada se agranda al pasar el cursor y la ficha tiene un efecto de profundidad al mover el mouse.',
    'Al abrir un juego la portada vuela desde la tarjeta hasta el detalle, y se ve de un vistazo de qué juego es.',
    'Mientras el servidor despierta, la sección muestra esqueletos de carga en vez de quedarse en blanco.',
    'El acceso rápido de iconos se mantiene igual: pasar el cursor para ver el nombre, 1 clic para la info rápida y 2 clics para los detalles.',
  ],
  '3.4.6': [
    '⚡ Noticias Rápidas: una sección nueva al pie de Noticias, con avisos cortos que se publican al instante.',
    'Las noticias rápidas recién publicadas llevan el tag ✨ Nuevo, que se borra solo a los 3 días.',
    'Eventos por proyecto: filtrá la sección Eventos por proyecto y cada evento muestra a qué juego pertenece.',
  ],
  '3.4.5': [
    'Si una descarga se queda sin progreso 3 minutos, el Gestor la marca como error con botón Reintentar (nunca más 0% eterno).',
    'El botón Cancelar ahora detiene de verdad la descarga en curso.',
    'Timeout también al iniciar la conexión con el servidor.',
  ],
  '3.4.4': [
    'Las descargas ya no se cuelgan en 0%: si el servidor deja de responder a mitad de la descarga, el Hub corta con un error claro y botón de Reintentar.',
    'En Android los tiempos de espera de descarga ahora son explícitos (30 s conexión / 60 s lectura).',
  ],
  '3.4.3': [
    'Descargas e instalaciones en segundo plano: instala o actualiza juegos y el Hub y sigue usando la app con total normalidad.',
    'Notificación de progreso: aviso del sistema al empezar, hitos de 25/50/75 %, % en el título y aviso al terminar o fallar.',
    'La actualización del Hub también avisa en segundo plano mientras se descarga.',
  ],
  '3.4.2': [
    'Android: si un APK se descarga incompleto, el Hub lo detecta por tamaño y te pide reintentar con WiFi en vez de fallar en el instalador.'
  ],
  '3.4.0': [
    '✨ ¡Wilder Gambit 1.0.0 ya está acá! Primera versión completa, disponible para Windows y Android.',
    'En Lanzamientos cada juego muestra su versión por plataforma: tarjeta de Windows en PC y botón de APK en Android.',
    'En Android el Gestor de Actualizaciones ahora lista tus juegos: instalá y actualizá sus APK sin salir del Hub.',
    'El servidor elige automáticamente el archivo de la versión oficial cuando conviven varias builds.'
  ],
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

async function showHubChangelogOnBoot() {
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
  const target = String(data.version || '').replace(/^[vV]/, '');
  // El registro se escribe antes de instalar: puede que al arrancar la
  // version sea otra y la instalacion no se haya aplicado. Se verifica contra
  // la version real antes de celebrar un update que no ocurrio.
  let current = '';
  try { current = String(await hubLocalVersion() || '').replace(/^[vV]/, ''); } catch (_) { current = ''; }
  if (target && current && current !== target) {
    openHubUpdateFailedModal(target, current);
    return;
  }
  openHubChangelogModal(data.version, data.notes);
}

function openHubChangelogModal(version, notes) {
  const modal = document.getElementById('hub-changelog-modal');
  if (!modal) return;
  const verEl = document.getElementById('hub-changelog-ver');
  if (verEl) verEl.textContent = 'v' + String(version || '').replace(/^[vV]/, '');
  // Estado normal: se restaura por si el modal anterior fue el de "no se aplicó".
  const titleEl0 = document.getElementById('hub-changelog-title');
  if (titleEl0) titleEl0.textContent = '¡Actualizaste a esta versión!';
  const subEl0 = document.getElementById('hub-changelog-sub');
  if (subEl0) subEl0.textContent = 'Esto es lo nuevo en OWS Hub. Se muestra una sola vez por versión.';
  const installEl0 = document.getElementById('hub-changelog-install');
  if (installEl0) installEl0.classList.add('hidden');
  // La versión destacada (lanzamiento) lleva aro dorado + píldora ✨.
  try {
    const card = modal.querySelector('.hub-changelog-card');
    const hot = String(version || '').replace(/^[vV]/, '') === HUB_CHANGELOG_HIGHLIGHT;
    if (card) card.classList.toggle('is-highlight', hot);
    let pill = modal.querySelector('.hub-changelog-hot');
    if (hot && !pill && card) {
      pill = document.createElement('p');
      pill.className = 'hub-changelog-hot';
      pill.textContent = '✨ Novedad destacada';
      const head = card.querySelector('.hub-changelog-head');
      if (head) head.appendChild(pill);
    }
    if (!hot && pill) pill.remove();
  } catch (_) {}
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

// El registro de novedades se escribe ANTES de instalar, pero la instalación
// puede no aplicarse: instalador bloqueado por el proceso abierto, falta de
// permisos, cierre a mitad. Si al arrancar seguimos en la versión anterior,
// mostrar "¡Actualizaste!" seria mentira y dejaria al usuario creyendo que
// quedo al dia mientras la app sigue vieja (y el updoder volveria a pedir lo
// mismo sin explicar por que).
function openHubUpdateFailedModal(target, current) {
  const modal = document.getElementById('hub-changelog-modal');
  if (!modal) return;
  const verEl = document.getElementById('hub-changelog-ver');
  if (verEl) verEl.textContent = 'v' + target;
  const titleEl = document.getElementById('hub-changelog-title');
  if (titleEl) titleEl.textContent = 'La actualización no se aplicó';
  const subEl = document.getElementById('hub-changelog-sub');
  if (subEl) {
    subEl.textContent = 'La descarga terminó, pero el Hub sigue en la v' + current +
      '. Suele pasar cuando el instalador no puede reemplazar la app porque el proceso quedó abierto.';
  }
  const body = document.getElementById('hub-changelog-body');
  if (body) {
    body.innerHTML = '<ul class="hub-changelog-list">' +
      '<li>Cerrá el Hub por completo, incluido el ícono de la bandeja del sistema, y volvé a abrirlo.</li>' +
      '<li>Si sigue igual, ejecutá el instalador de la v' + escapeHtml(target) +
      ' encima de la anterior: reemplaza la versión vieja sin perder tus datos.</li>' +
      '</ul>';
    body.classList.remove('hidden');
  }
  const installEl = document.getElementById('hub-changelog-install');
  if (installEl) {
    installEl.textContent = '⬇ Descargar instalador v' + target;
    installEl.href = OWS_HUB_RELEASES_URL;
    installEl.classList.remove('hidden');
  }
  modal.classList.remove('hidden');
}

// ── Check del updater con reintentos ────────────────────────────
// Medido contra github.com: resolver releases/latest/download/latest.json
// falla ~25% de las veces (se queda colgado 20-45 s sin entregar el primer
// byte) y los que salen bien llegan hasta 14,5 s. Con el timeout de 15 s el
// botón moría con "timeout" sin llegar a descargar nada. Ahora cada intento
// tiene 45 s y se reintenta: el chequeo es barato y suele pasar al segundo.
// OJO: no se reusa el probe memoizado de tauriUpdaterCheck porque el `rid`
// que devuelve `plugin:updater|check` es un recurso de esta sesión y tiene
// que ser fresco.
const HUB_CHECK_TIMEOUT_MS = 45 * 1000;
const HUB_CHECK_ATTEMPTS = 3;

// Solo se reintenta lo que es claramente la red: si el Hub no trae el plugin
// updater, o no hay nada que actualizar, repetir no cambia nada.
function hubCheckIsRetryable(err) {
  const msg = String((err && err.message) || err || '').toLowerCase();
  return /timeout|timed out|network|connect|econn|eai|dns|aborted|socket|reset|error sending request/.test(msg);
}

async function hubUpdaterCheckFresh() {
  let last = null;
  for (let i = 1; i <= HUB_CHECK_ATTEMPTS; i += 1) {
    try {
      // Llamada directa, sin pasar por el memo: es justamente un check fresco.
      return await tauriUpdaterCall('plugin:updater|check', {}, HUB_CHECK_TIMEOUT_MS);
    } catch (err) {
      last = err;
      if (!hubCheckIsRetryable(err)) throw err;
      if (i < HUB_CHECK_ATTEMPTS) {
        // Espera corta y creciente: si el primer salto fue un cold start de
        // TLS contra GitHub, el segundo ya entra caliente.
        await new Promise((r) => setTimeout(r, 800 * i));
      }
    }
  }
  throw last || new Error('timeout');
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
  // Vive acá y no dentro del try porque el catch lo necesita para nombrar la
  // versión que no se pudo bajar (si el check falló, queda vacío).
  let version = '';

  try {
    // 1) Check fresco (con reintentos): el rid tiene que ser el de esta sesión.
    const upd = await hubUpdaterCheckFresh();
    if (!upd || typeof upd !== 'object' || upd.rid === undefined || upd.rid === null) {
      throw new Error('no hay actualizaciones disponibles');
    }
    version = String(upd.version || '').replace(/^[vV]/, '');
    if (!version || version === String(upd.currentVersion || '').replace(/^[vV]/, '')) {
      throw new Error('ya estás en la última versión');
    }

    // 2) Toaster fijo con el progreso real de la descarga.
    hubUpdToastShow(version);
    let total = 0;
    let done = 0;
    let speed = 0;           // bytes/s (media móvil, para el texto del toaster)
    let lastTick = 0;
    let lastBytes = 0;
    let lastPaint = 0;
    let lastProgressAt = Date.now();
    const ch = tauriMakeChannel();
    if (!ch) throw new Error('WebView sin canal de Tauri (reabrí el Hub)');

    // El progreso llega chunk por chunk: pintar en cada evento golpea el DOM
    // sin necesidad. Con red lenta lo que importa es que se lea "va lento,
    // faltan N min", no un número que cambia cientos de veces por segundo.
    // OJO: .dl-toast-info es nowrap con ellipsis, así que todo tiene que
    // entrar en el ancho del sidebar — de ahí la ETA corta ("~24 min") y la
    // unidad una sola vez ("1,3 / 10,7 MB").
    const hubProgressInfo = (pct) => {
      const bits = [];
      if (total > 0) {
        const got = formatMB(done).replace(/\s+[KMG]B$/, '');
        bits.push(`${Math.round(pct)}% · ${got} / ${formatMB(total)}`);
      } else {
        bits.push(`${formatMB(done)} descargados`);
      }
      const sp = formatSpeed(speed);
      if (sp) bits.push(sp);
      const secs = (total > 0 && speed > 0 && done < total)
        ? Math.round((total - done) / speed)
        : 0;
      if (secs > 0) {
        const mins = Math.round(secs / 60);
        bits.push(mins >= 1 ? `~${mins} min` : `~${secs} s`);
      }
      // Por debajo de ~30 KB/s la ETA puede ser media hora o más: decirlo
      // evita que el usuario lea "0%" como una descarga colgada.
      if (speed > 0 && speed < 30 * 1024) bits.push('lento');
      return bits.join(' · ');
    };

    ch.onmessage = (msg) => {
      try {
        const ev = (msg && msg.event) || '';
        const data = (msg && msg.data) || {};
        const now = Date.now();
        if (ev === 'Started') {
          total = Number(data.contentLength || 0) || 0;
          done = 0;
          speed = 0;
          lastTick = now;
          lastBytes = 0;
          lastPaint = 0;
          lastProgressAt = now;
          hubUpdToastPatch(0, total > 0 ? `0 MB / ${formatMB(total)}` : 'Conectando…', false);
        } else if (ev === 'Progress') {
          done += Number(data.chunkLength || 0) || 0;
          lastProgressAt = now;
          // Media móvil con ventana de 1,5 s: el número sigue el alugeo real
          // en vez del promedio desde cero (que tarda minutos en arrancar).
          const dt = (now - lastTick) / 1000;
          if (dt >= 1.5) {
            const inst = (done - lastBytes) / dt;
            speed = speed > 0 ? (speed * 0.6 + inst * 0.4) : inst;
            lastTick = now;
            lastBytes = done;
          }
          if (now - lastPaint < 400) return;
          lastPaint = now;
          const pct = total > 0 ? (done / total) * 100 : 0;
          hubUpdToastPatch(pct, hubProgressInfo(pct), false);
        } else if (ev === 'Finished') {
          lastProgressAt = Date.now();
          hubUpdToastPatch(100, '100% · verificado ✓', true);
        }
      } catch (_) {}
    };

    // 3) Descargar (no instala todavía: el reinicio es un paso aparte).
    //    El timeout fijo de 15 min mataba descargas legítimas en redes lentas
    //    (11,2 MB a 7 KB/s son ~25 min). Ahora es un watchdog de estancamiento
    //    —se rearma con cada chunk— más un tope absoluto amplio: si sigue
    //    avanzando, el timeout no lo toca.
    const HUB_DL_STALL_MS = 90 * 1000;
    const HUB_DL_MAX_MS = 90 * 60 * 1000;
    const dlStarted = Date.now();
    const bytesRid = await new Promise((resolve, reject) => {
      const fail = () => {
        clearInterval(guard);
        reject(new Error('timeout'));
      };
      const guard = setInterval(() => {
        const t = Date.now();
        if (t - dlStarted > HUB_DL_MAX_MS) fail();
        else if (t - lastProgressAt > HUB_DL_STALL_MS) fail();
      }, 5000);
      tauriInvokeRaw('plugin:updater|download', { rid: upd.rid, onEvent: ch })
        .then((v) => { clearInterval(guard); resolve(v); })
        .catch((e) => { clearInterval(guard); reject(e); });
    });
    hubUpdToastPatch(100, '100% · verificado ✓', true);

    // 4) Las novedades se guardan ahora: el reinicio borra la memoria.
    //    Se prefieren las notas de la release (las trae el backend, texto
    //    completo) y se cae al body del manifiesto si no están.
    const hubNotes = (updatesState.hub && updatesState.hub.notes) || '';
    hubChangelogSave(version, hubNotes || upd.body || '');

    // 5) Aviso de 5 s y, al terminar, instalar + reiniciar. El toaster se
    //    queda un instante mas con la barra llena: si se esconde en el acto,
    //    el 100% no se llega a ver y parece que la descarga quedo a mitad.
    hubPendingInstall = { rid: upd.rid, bytesRid: bytesRid, version: version };
    clearTimeout(hubUpdHideTimer);
    hubUpdHideTimer = setTimeout(() => hubUpdToastHide(), 900);
    if (!openHubRestartModal(version)) { await doHubInstall(); return; }
    // hubUpdateBusy sigue en true: la descarga está hecha pero la instalación
    // pendiente, así que el botón no debe volver a activarse.
    renderHubUpdateCard();
    return;
  } catch (err) {
    hubUpdToastHide();
    const msg = String((err && err.message) || err);
    if (/timeout|timed out/i.test(msg)) {
      // GitHub se cuelga de forma intermitente: esto no es que el updater esté
      // roto ni que falte la v3.4.14. Decirlo así evita que el usuario vaya a
      // buscar el problema en otro lado.
      showToast('No se pudo contactar con GitHub' + (version ? ` para bajar la v${version}` : '') +
        '. Tu internet puede estar bien: es que sus servidores responden lento. Probá de nuevo en un rato.');
    } else {
      showToast('No se pudo actualizar el Hub: ' + msg);
    }
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
      else if (action === 'apk-install' || action === 'apk-update') runProjectApkInstall(slug);
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
  // Desplegar/plegar las novedades del Hub.
  const notesMore = document.getElementById('upd-hub-notes-more');
  if (notesMore && !notesMore.dataset.bound) {
    notesMore.dataset.bound = '1';
    notesMore.addEventListener('click', () => {
      const notes = document.getElementById('upd-hub-notes');
      if (!notes) return;
      const open = notes.classList.toggle('is-open');
      notesMore.textContent = open ? 'Ver menos' : 'Ver todas las novedades';
      notesMore.setAttribute('aria-expanded', open ? 'true' : 'false');
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
// CHANGELOGS DE PROYECTOS — proyectos ya lanzados
// ═══════════════════════════════════════════════
// Lista desplegable por proyecto (icono + nombre): al abrir muestra sus
// versiones y cada una se abre en un modal con los datos y el changelog
// completo. Solo proyectos lanzados; el servidor entrega `new_until` para que
// el tag "Nuevo" de la sección se apague solo (18/10/2026 00:00, hora UY).

const PCL_NEW_UNTIL_FALLBACK = Date.parse('2026-10-18T00:00:00-03:00');

let pclCache = [];
let pclLoadState = 'idle'; // idle | loading | ready | error
let pclLoading = false;
let pclNewUntil = PCL_NEW_UNTIL_FALLBACK;
let pclTagTimer = 0;

function pclTagAlive() {
  const until = Number.isFinite(pclNewUntil) ? pclNewUntil : PCL_NEW_UNTIL_FALLBACK;
  return Number.isFinite(until) ? Date.now() < until : false;
}

// Muestra u oculta el tag "Nuevo" (menú + sección) y programa el apagado.
function syncProjectChangelogsTag() {
  const alive = pclTagAlive();
  ['nav-cl-new', 'cl-new-tag'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('hidden', !alive);
  });
  if (pclTagTimer) { clearTimeout(pclTagTimer); pclTagTimer = 0; }
  if (!alive) return;
  const until = Number.isFinite(pclNewUntil) ? pclNewUntil : PCL_NEW_UNTIL_FALLBACK;
  const wait = until - Date.now() + 1000;
  if (wait > 0) {
    pclTagTimer = setTimeout(() => { try { syncProjectChangelogsTag(); } catch (_) {} }, Math.min(wait, 2147000000));
  }
}

function pclPlatformLabel(platform) {
  const p = String(platform || '').toLowerCase();
  if (p === 'android') return '🤖 Android';
  if (p === 'all') return '🌐 Todas';
  return '🪟 Windows';
}

function pclVersionLabel(version) {
  return String(version || '').trim().replace(/^[vV]/, '');
}

function pclVersionCountLabel(n) {
  const total = Number(n) || 0;
  return total === 1 ? '1 versión' : `${total} versiones`;
}

// Igual que el anterior, pero para la frase del modal ("publicada(s)").
function pclPublishedCountLabel(n) {
  const total = Number(n) || 0;
  return total === 1 ? '1 versión publicada' : `${total} versiones publicadas`;
}

function pclFindProject(slug) {
  const key = String(slug || '').trim();
  return pclCache.find((p) => String(p.slug || '').trim() === key) || null;
}

function pclFindVersion(slug, version) {
  const p = pclFindProject(slug);
  if (!p) return null;
  const key = String(version || '').trim().toLowerCase().replace(/^v/, '');
  return (p.versions || []).find((v) => String(v.version || '').trim().toLowerCase().replace(/^v/, '') === key) || null;
}

function renderProjectChangelogsLoading() {
  const list = document.getElementById('cl-list');
  const empty = document.getElementById('cl-empty');
  const count = document.getElementById('cl-count');
  if (empty) empty.classList.add('hidden');
  if (count) count.textContent = 'Cargando…';
  if (list) {
    list.innerHTML = `
      <div class="cl-placeholder" role="status" aria-live="polite">
        <span class="releases-spinner" aria-hidden="true"></span>
        <p class="cl-placeholder-title">Cargando changelogs…</p>
        <p class="cl-placeholder-sub">La primera carga puede tardar si el servidor está despertando.</p>
      </div>`;
  }
}

function renderProjectChangelogsError() {
  const list = document.getElementById('cl-list');
  const empty = document.getElementById('cl-empty');
  const count = document.getElementById('cl-count');
  if (empty) empty.classList.add('hidden');
  if (count) count.textContent = 'Sin conexión';
  if (list) {
    list.innerHTML = `
      <div class="cl-placeholder is-error" role="status">
        <span class="cl-placeholder-ico" aria-hidden="true">⚠️</span>
        <p class="cl-placeholder-title">No se pudieron cargar los changelogs</p>
        <p class="cl-placeholder-sub">El servidor puede estar despertando. Probá de nuevo en unos segundos.</p>
        <button type="button" class="btn btn-ghost btn-sm" data-cl-retry>↻ Reintentar</button>
      </div>`;
  }
}

function renderProjectChangelogs() {
  const list = document.getElementById('cl-list');
  const empty = document.getElementById('cl-empty');
  const count = document.getElementById('cl-count');
  if (!list) return;
  const items = (Array.isArray(pclCache) ? pclCache : [])
    .filter((p) => p && String(p.slug || '').trim() && Array.isArray(p.versions) && p.versions.length);
  if (count) {
    count.textContent = items.length
      ? `${items.length} ${items.length === 1 ? 'proyecto' : 'proyectos'}`
      : 'Sin changelogs';
  }
  if (!items.length) {
    list.innerHTML = '';
    if (empty) empty.classList.remove('hidden');
    return;
  }
  if (empty) empty.classList.add('hidden');
  list.innerHTML = items.map((p) => {
    const slug = String(p.slug).trim();
    const versions = p.versions;
    const latest = versions[0] || {};
    const icon = String(p.icon_url || '').trim();
    const latestWhen = formatReleaseDate(latest.released_at) || '';
    const versionsHtml = versions.map((v) => {
      const bits = [];
      if (Array.isArray(v.platforms) && v.platforms.length) {
        bits.push(v.platforms.map(pclPlatformLabel).join(' · '));
      }
      if (v.channel && v.channel !== 'stable') bits.push(v.channel);
      if (v.size_label) bits.push(`💾 ${v.size_label}`);
      const peek = String(v.summary || '').trim();
      return `
        <li class="cl-version-item">
          <button type="button" class="cl-version" data-pcl-slug="${escapeHtml(slug)}" data-pcl-ver="${escapeHtml(v.version)}" aria-haspopup="dialog" title="Ver el changelog completo de esta versión">
            <span class="cl-ver-line">
              <span class="cl-ver-tag">v${escapeHtml(pclVersionLabel(v.version))}</span>
              ${v.is_latest ? '<span class="cl-ver-pill cl-ver-latest">✨ Última</span>' : (v.is_new ? '<span class="cl-ver-pill cl-ver-new">Nuevo</span>' : '')}
              <span class="cl-ver-when">${escapeHtml(formatReleaseDate(v.released_at) || 'Sin fecha')}</span>
              <span class="cl-ver-cta">Ver notas →</span>
            </span>
            ${bits.length ? `<span class="cl-ver-meta">${escapeHtml(bits.join(' · '))}</span>` : ''}
            ${peek ? `<span class="cl-ver-peek">${escapeHtml(peek)}</span>` : ''}
          </button>
        </li>`;
    }).join('');
    return `
      <article class="cl-project glass-card" data-cl-project="${escapeHtml(slug)}">
        <button type="button" class="cl-head" data-cl-toggle="${escapeHtml(slug)}" aria-expanded="false" aria-controls="cl-body-${escapeHtml(slug)}">
          <span class="cl-ico">
            ${icon ? `<img src="${escapeHtml(icon)}" alt="" class="cl-ico-img" loading="lazy" />` : '<span class="cl-ico-emoji" aria-hidden="true">🎮</span>'}
          </span>
          <span class="cl-titles">
            <span class="cl-name">${escapeHtml(p.name)} <span class="cl-status">🎮 Lanzado</span></span>
            <span class="cl-sub">${escapeHtml([p.genre, pclVersionCountLabel(versions.length)].filter(Boolean).join(' · '))}</span>
          </span>
          <span class="cl-latest">${latest.version ? `Última: <b>v${escapeHtml(pclVersionLabel(latest.version))}</b>` : ''}${latestWhen ? `<small>${escapeHtml(latestWhen)}</small>` : ''}</span>
          <span class="cl-chevron" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>
          </span>
        </button>
        <div class="cl-body" id="cl-body-${escapeHtml(slug)}" role="region" aria-label="Versiones de ${escapeHtml(p.name)}">
          <div class="cl-body-inner">
            <ul class="cl-versions">${versionsHtml}</ul>
            ${p.link_url ? `<a class="cl-project-link" href="${escapeHtml(p.link_url)}" target="_blank" rel="noopener">Ver proyecto ↗</a>` : ''}
          </div>
        </div>
      </article>`;
  }).join('');
}

// Abre/cierra el cuerpo de un proyecto con animación (max-height medida).
function pclSetBodyOpen(card, open) {
  if (!card) return;
  const body = card.querySelector('.cl-body');
  const head = card.querySelector('.cl-head');
  if (!body) return;
  if (open) {
    body.style.maxHeight = body.scrollHeight + 'px';
    card.classList.add('is-open');
    if (head) head.setAttribute('aria-expanded', 'true');
    // Al terminar la animación se suelta el límite: si el contenido cambia de
    // alto (resize, texto que reflowea) nada queda recortado.
    const release = (e) => {
      if (e.target !== body) return;
      body.removeEventListener('transitionend', release);
      if (card.classList.contains('is-open')) body.style.maxHeight = 'none';
    };
    body.addEventListener('transitionend', release);
  } else {
    if (body.style.maxHeight === 'none') body.style.maxHeight = body.scrollHeight + 'px';
    void body.offsetHeight; // reflow: registra la altura real antes de ir a 0
    card.classList.remove('is-open');
    body.style.maxHeight = '0px';
    if (head) head.setAttribute('aria-expanded', 'false');
  }
}

function toggleProjectChangelog(slug) {
  const list = document.getElementById('cl-list');
  if (!list) return;
  const key = String(slug || '').trim();
  const card = Array.from(list.querySelectorAll('.cl-project'))
    .find((c) => c.getAttribute('data-cl-project') === key);
  if (!card) return;
  const willOpen = !card.classList.contains('is-open');
  // Dropdown: se despliega uno por vez; los demás se pliegan con animación.
  list.querySelectorAll('.cl-project.is-open').forEach((other) => {
    if (other !== card) pclSetBodyOpen(other, false);
  });
  pclSetBodyOpen(card, willOpen);
}

// ── Modal con los datos y el changelog de una versión ──
function openProjectChangelogModal(slug, version) {
  const p = pclFindProject(slug);
  const v = pclFindVersion(slug, version);
  const modal = document.getElementById('pcl-modal');
  const body = document.getElementById('pcl-modal-body');
  if (!modal || !body || !p || !v) return;
  const icon = String(p.icon_url || '').trim();
  const ver = `v${pclVersionLabel(v.version)}`;
  const date = v.released_at ? parseDateValue(v.released_at) : null;
  const whenLong = date ? date.toLocaleDateString('es-ES', { day: 'numeric', month: 'long', year: 'numeric' }) : '';
  const chips = [];
  if (Array.isArray(v.platforms) && v.platforms.length) v.platforms.forEach((pl) => chips.push(pclPlatformLabel(pl)));
  if (v.channel) chips.push(v.channel);
  if (v.size_label) chips.push(`💾 ${v.size_label}`);
  if (v.file_label) chips.push(`📦 ${v.file_label}`);

  // Contenido: secciones estructuradas (si el proyecto las tiene) + notas.
  const secs = (v.sections && typeof v.sections === 'object') ? v.sections : {};
  const sectionDefs = [
    ['adiciones', '✨ Nuevo', 'cl-sec-new'],
    ['mejoras', '🛠️ Mejoras', 'cl-sec-improve'],
    ['arreglos', '🐞 Arreglos', 'cl-sec-fix'],
    ['rendimiento', '⚡ Rendimiento', 'cl-sec-perf'],
    ['otros', '📌 Otros', 'cl-sec-other'],
  ];
  const sectionsHtml = sectionDefs.map(([key, label, cls]) => {
    const arr = Array.isArray(secs[key]) ? secs[key] : [];
    if (!arr.length) return '';
    return `<div class="cl-sec ${cls}"><h4 class="cl-sec-title">${label}</h4><ul class="cl-sec-list">${arr.map((t) => `<li>${escapeHtml(t)}</li>`).join('')}</ul></div>`;
  }).join('');
  const notesLines = Array.isArray(v.notes_lines) ? v.notes_lines : [];
  const notesHtml = notesLines.length
    ? `<div class="cl-notes"><p class="cl-notes-title">📝 Notas de la versión</p>${notesLines.map((l) => `<p class="cl-note-line">${escapeHtml(l)}</p>`).join('')}</div>`
    : '';
  const noNotesHtml = (!sectionsHtml && !notesHtml)
    ? '<div class="cl-notes"><p class="cl-note-line cl-note-empty">Esta versión todavía no tiene notas publicadas.</p></div>'
    : '';

  body.innerHTML = `
    <div class="pcl-head">
      <span class="pcl-ico">${icon ? `<img src="${escapeHtml(icon)}" alt="" class="pcl-ico-img" />` : '<span class="pcl-ico-emoji" aria-hidden="true">🎮</span>'}</span>
      <div class="pcl-head-info">
        <span class="pcl-project">${escapeHtml(p.name)}</span>
        <h3 class="pcl-version">${escapeHtml(ver)} ${v.is_latest ? '<span class="cl-ver-pill cl-ver-latest">✨ Última</span>' : (v.is_new ? '<span class="cl-ver-pill cl-ver-new">Nuevo</span>' : '')}</h3>
        <span class="pcl-sub">📅 ${escapeHtml(whenLong || 'Sin fecha')} · ${escapeHtml(pclPublishedCountLabel((p.versions || []).length))}</span>
      </div>
    </div>
    ${chips.length ? `<div class="pcl-chips">${chips.map((c) => `<span class="pcl-chip">${escapeHtml(c)}</span>`).join('')}</div>` : ''}
    ${sectionsHtml}
    ${notesHtml}
    ${noNotesHtml}
    <div class="pcl-foot">
      ${p.link_url ? `<a class="btn btn-ghost btn-sm" href="${escapeHtml(p.link_url)}" target="_blank" rel="noopener">Ver proyecto ↗</a>` : ''}
      <button type="button" class="btn btn-primary btn-sm" data-pcl-goto-release="${escapeHtml(p.slug)}">Ver en Lanzamientos 🚀</button>
    </div>
  `;
  modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeProjectChangelogModal() {
  const modal = document.getElementById('pcl-modal');
  if (modal) modal.classList.add('hidden');
  // Solo se libera el scroll si no queda ningún otro modal abierto.
  try {
    if (!document.querySelector('.modal-overlay:not(.hidden), .release-overlay:not(.hidden), .news-modal-overlay:not(.hidden)')) {
      document.body.style.overflow = '';
    }
  } catch (_) { document.body.style.overflow = ''; }
}

async function loadProjectChangelogs(opts) {
  if (pclLoading) return;
  const silent = !!(opts && opts.silent);
  pclLoading = true;
  if (!silent) {
    pclLoadState = 'loading';
    renderProjectChangelogsLoading();
  }
  try {
    const data = await fetchJsonWithRetry(API_BASE + '/ows-hub/project-changelogs', { timeoutsMs: [12000, 25000] });
    pclCache = (data && Array.isArray(data.projects)) ? data.projects : [];
    const until = data && data.meta && data.meta.new_until ? Date.parse(data.meta.new_until) : NaN;
    if (Number.isFinite(until)) pclNewUntil = until;
    syncProjectChangelogsTag();
    pclLoadState = 'ready';
    renderProjectChangelogs();
  } catch (err) {
    console.error('[OWS] No se pudieron cargar los changelogs de proyectos:', err);
    pclLoadState = 'error';
    if (!silent) renderProjectChangelogsError();
  } finally {
    pclLoading = false;
  }
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
