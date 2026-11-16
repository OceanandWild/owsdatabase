/* ============================================================================
   OWS Admin Panel — shell v1
   ----------------------------------------------------------------------------
   Capa de navegación sobre el panel existente:
     · barra superior con 5 accesos configurables (Alt+1…Alt+5)
     · barra lateral de texto con acordeones
     · Inicio y Ajustes (menú superior, sesión, integraciones)
     · paleta de búsqueda (Ctrl/Cmd+K)
   No reemplaza secciones ni CRUD: usa switchAdminTab/switchAdminSub y los
   paneles que ya existen en index.html.
   ========================================================================== */
(function () {
  'use strict';

  /* ── Manifest de navegación ─────────────────────────────────────────── */

  const HOME = {
    id: 'inicio',
    label: 'Inicio',
    route: '/inicio',
    page: 'inicio',
    group: 'General',
    groupId: ''
  };

  const NAV_GROUPS = [
    {
      id: 'contenido',
      label: 'Contenido',
      items: [
        { id: 'noticias', label: 'Noticias', route: '/contenido/noticias', tab: 'news', sub: 'main' },
        { id: 'noticias-rapidas', label: 'Rápidas', fullLabel: 'Noticias rápidas', route: '/contenido/noticias-rapidas', tab: 'news', sub: 'quick', child: true },
        { id: 'noticias-modales', label: 'Modales de noticias', route: '/contenido/noticias-modales', tab: 'news', sub: 'modals', child: true },
        { id: 'eventos', label: 'Eventos', route: '/contenido/eventos', tab: 'events', sub: 'main' },
        { id: 'eventos-modales', label: 'Modales de eventos', route: '/contenido/eventos-modales', tab: 'events', sub: 'popups', child: true },
        { id: 'eventos-presets', label: 'Presets', route: '/contenido/eventos-presets', tab: 'events', sub: 'presets', child: true }
      ]
    },
    {
      id: 'desarrollo',
      label: 'Desarrollo',
      items: [
        { id: 'progreso', label: 'Progreso', route: '/desarrollo/progreso', tab: 'manage', sub: 'main' },
        { id: 'actualizaciones', label: 'Actualizaciones', route: '/desarrollo/actualizaciones', tab: 'updates', sub: 'main' },
        { id: 'historial', label: 'Historial', route: '/desarrollo/historial', tab: 'updates', sub: 'history' },
        { id: 'devlog', label: 'Devlog', route: '/desarrollo/devlog', tab: 'manage', sub: 'devlog' },
        { id: 'actividad', label: 'Actividad', route: '/desarrollo/actividad', tab: 'manage', sub: 'activity' },
        { id: 'analytics', label: 'Analytics', route: '/desarrollo/analytics', tab: 'manage', sub: 'analytics' },
        { id: 'hitos', label: 'Hitos', route: '/desarrollo/hitos', tab: 'manage', sub: 'hitos' },
        { id: 'codigo-fuente', label: 'Código Fuente', route: '/desarrollo/codigo-fuente', page: 'codigo' }
      ]
    },
    {
      id: 'catalogo',
      label: 'Proyectos',
      items: [
        { id: 'proyectos', label: 'Todos los proyectos', route: '/catalogo/proyectos', tab: 'projects', sub: 'main' }
      ]
    },
    {
      id: 'operaciones',
      label: 'Operaciones',
      items: [
        { id: 'estado', label: 'Estado', route: '/operaciones/estado', tab: 'incidents', sub: 'main' },
        { id: 'estado-en-curso', label: 'En curso', route: '/operaciones/estado/en-curso', tab: 'incidents', sub: 'live', child: true },
        { id: 'estado-registro', label: 'Registro', fullLabel: 'Registro de incidentes', route: '/operaciones/estado/registro', tab: 'incidents', sub: 'log', child: true },
        { id: 'informes', label: 'Informes', route: '/operaciones/informes', tab: 'reports', sub: 'main' },
        { id: 'informes-activos', label: 'Activos', route: '/operaciones/informes/activos', tab: 'reports', sub: 'live', child: true },
        { id: 'informes-historial', label: 'Historial', fullLabel: 'Historial de informes', route: '/operaciones/informes/historial', tab: 'reports', sub: 'log', child: true }
      ]
    },
    {
      id: 'equipo',
      label: 'Equipo',
      items: [
        { id: 'usuarios', label: 'Usuarios', route: '/equipo/usuarios', tab: 'users', sub: 'main' }
      ]
    },
    {
      id: 'estudio',
      label: 'Estudio',
      items: [
        { id: 'notas', label: 'Notas', fullLabel: 'Notas y anotaciones', route: '/estudio/notas', page: 'notas' }
      ]
    },
    {
      id: 'ajustes',
      label: 'Ajustes',
      items: [
        { id: 'menu-superior', label: 'Menú superior', route: '/ajustes/menu-superior', page: 'menu' },
        { id: 'sesion', label: 'Sesión', fullLabel: 'Sesión y dispositivos', route: '/ajustes/sesion', page: 'sesion' },
        { id: 'integraciones', label: 'Integraciones', route: '/ajustes/integraciones', page: 'integraciones' }
      ]
    }
  ];

  const ALL_ITEMS = [HOME].concat(
    NAV_GROUPS.flatMap((group) =>
      group.items.map((item) => Object.assign({}, item, { group: group.label, groupId: group.id }))
    )
  );

  const BY_ROUTE = new Map(ALL_ITEMS.map((item) => [item.route, item]));

  const PROJECT_ROUTE_RE = /^\/catalogo\/proyectos\/([^/]+)$/;

  // El catálogo real lo carga admin-app.js y lo publica en
  // window.OWS_ADMIN_PROJECTS. Acá se convierte en destinos del sidebar,
  // la paleta y los accesos de la barra superior.
  function projectNavItems() {
    const list = Array.isArray(window.OWS_ADMIN_PROJECTS) ? window.OWS_ADMIN_PROJECTS : [];
    return list.map((p) => {
      const slug = String((p && p.slug) || '').trim();
      if (!slug) return null;
      return {
        id: 'proyecto-' + slug,
        label: p.name || slug,
        route: '/catalogo/proyectos/' + encodeURIComponent(slug),
        tab: 'projects',
        sub: 'detail',
        group: 'Proyectos',
        groupId: 'catalogo',
        projectSlug: slug,
        adminOnly: p.admin_only === true
      };
    }).filter(Boolean);
  }

  function allNavItems() {
    return ALL_ITEMS.concat(projectNavItems());
  }

  function projectItemForSlug(slug) {
    const wanted = String(slug || '').toLowerCase();
    return projectNavItems().find((item) => item.projectSlug.toLowerCase() === wanted) || null;
  }

  const ALIASES = {
    '/news': '/contenido/noticias',
    '/news/quick': '/contenido/noticias-rapidas',
    '/news/modals': '/contenido/noticias-modales',
    '/events': '/contenido/eventos',
    '/events/popups': '/contenido/eventos-modales',
    '/events/presets': '/contenido/eventos-presets',
    '/projects': '/catalogo/proyectos',
    '/manage': '/desarrollo/progreso',
    '/updates': '/desarrollo/actualizaciones',
    '/history': '/desarrollo/historial',
    '/updates/history': '/desarrollo/historial',
    '/manage/devlog': '/desarrollo/devlog',
    '/desarrollo/bitacora': '/desarrollo/devlog',
    '/manage/activity': '/desarrollo/actividad',
    '/manage/analytics': '/desarrollo/analytics',
    '/manage/hitos': '/desarrollo/hitos',
    '/manage/milestones': '/desarrollo/hitos',
    '/source': '/desarrollo/codigo-fuente',
    '/codigo-fuente': '/desarrollo/codigo-fuente',
    '/desarrollo/source': '/desarrollo/codigo-fuente',
    '/incidents': '/operaciones/estado',
    '/incidents/live': '/operaciones/estado/en-curso',
    '/incidents/log': '/operaciones/estado/registro',
    '/operaciones/estado/live': '/operaciones/estado/en-curso',
    '/reports': '/operaciones/informes',
    '/reports/live': '/operaciones/informes/activos',
    '/reports/log': '/operaciones/informes/historial',
    '/operaciones/informes/live': '/operaciones/informes/activos',
    '/users': '/equipo/usuarios',
    '/notes': '/estudio/notas',
    '/notas': '/estudio/notas',
    '/estudio': '/estudio/notas'
  };

  const LEGACY_ROUTES = {
    news: { main: '/contenido/noticias', quick: '/contenido/noticias-rapidas', modals: '/contenido/noticias-modales' },
    events: { main: '/contenido/eventos', popups: '/contenido/eventos-modales', presets: '/contenido/eventos-presets' },
    manage: {
      main: '/desarrollo/progreso',
      devlog: '/desarrollo/devlog',
      activity: '/desarrollo/actividad',
      analytics: '/desarrollo/analytics',
      hitos: '/desarrollo/hitos'
    },
    projects: { main: '/catalogo/proyectos' },
    updates: { main: '/desarrollo/actualizaciones', history: '/desarrollo/historial' },
    incidents: { main: '/operaciones/estado', live: '/operaciones/estado/en-curso', log: '/operaciones/estado/registro' },
    reports: { main: '/operaciones/informes', live: '/operaciones/informes/activos', log: '/operaciones/informes/historial' },
    users: { main: '/equipo/usuarios' }
  };

  const DEFAULT_SLOTS = [
    '/contenido/noticias',
    '/contenido/eventos',
    '/desarrollo/progreso',
    '/operaciones/estado',
    '/equipo/usuarios'
  ];

  const LS_SLOTS = 'ows.admin.topSlots.v1';
  const SS_GROUP = 'ows.admin.sidebarGroup.v1';
  const SS_LAST = 'ows.admin.lastRoute.v1';
  const LS_SIDEBAR = 'ows.admin.sidebarCollapsed.v1';

  /* ── Estado ─────────────────────────────────────────────────────────── */

  let slots = loadSlots();
  let currentRoute = '';
  let started = false;
  let applyDepth = 0;
  let paletteResults = [];
  let paletteIndex = 0;
  let resizeTimer = null;
  let sidebarCollapsed = readSidebarCollapsed();
  let sourceCache = null;
  let sourceError = '';
  let sourceLoading = false;
  let sourceFilter = 'all';
  let sourceQuery = '';
  let sourceModalScope = '';
  let paypalIntegration = null;
  let paypalIntegrationAt = 0;
  let paypalIntegrationBusy = false;

  /* ── Utilidades ─────────────────────────────────────────────────────── */

  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function fold(value) {
    const text = String(value == null ? '' : value).toLowerCase();
    try {
      return text.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    } catch (_) {
      return text;
    }
  }

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  function itemLabel(item) {
    return item && (item.fullLabel || item.label) || '';
  }

  function normalizeRoute(value) {
    let route = String(value == null ? '' : value).trim();
    if (!route) return '';
    if (route.charAt(0) === '#') route = route.slice(1);
    if (route.charAt(0) !== '/') route = '/' + route;
    route = route.replace(/\/{2,}/g, '/');
    if (route.length > 1) route = route.replace(/\/+$/, '');
    return route;
  }

  function resolveItem(value) {
    const clean = normalizeRoute(value);
    if (!clean) return null;
    const canonical = ALIASES[clean] || clean;

    const direct = BY_ROUTE.get(canonical);
    if (direct) return direct;

    const projectMatch = PROJECT_ROUTE_RE.exec(canonical);
    if (projectMatch) {
      let slug = projectMatch[1];
      try { slug = decodeURIComponent(slug); } catch (_) {}
      const known = projectItemForSlug(slug);
      if (known) return known;
      return {
        id: 'proyecto-' + slug,
        label: slug,
        route: canonical,
        tab: 'projects',
        sub: 'detail',
        group: 'Proyectos',
        groupId: 'catalogo',
        projectSlug: slug,
        adminOnly: false
      };
    }

    // Alias viejo: /projects/<slug> → /catalogo/proyectos/<slug>
    const legacy = /^\/projects\/([^/]+)$/.exec(canonical);
    if (legacy) return resolveItem('/catalogo/proyectos/' + legacy[1]);

    return null;
  }

  function readHashRoute() {
    const raw = window.location.hash || '';
    if (!raw || raw === '#') return '';
    return normalizeRoute(raw);
  }

  function readLastRoute() {
    try { return normalizeRoute(sessionStorage.getItem(SS_LAST) || ''); } catch (_) { return ''; }
  }

  function readStoredGroup() {
    try { return sessionStorage.getItem(SS_GROUP) || ''; } catch (_) { return ''; }
  }

  function readSidebarCollapsed() {
    try { return localStorage.getItem(LS_SIDEBAR) === '1'; } catch (_) { return false; }
  }

  function loadSlots() {
    let stored = null;
    try { stored = JSON.parse(localStorage.getItem(LS_SLOTS) || 'null'); } catch (_) { stored = null; }
    if (!Array.isArray(stored)) return DEFAULT_SLOTS.slice();
    const next = stored.slice(0, 5).map((route) => {
      const item = resolveItem(route);
      return item ? item.route : '';
    });
    while (next.length < 5) next.push('');
    return next;
  }

  function saveSlots() {
    try { localStorage.setItem(LS_SLOTS, JSON.stringify(slots)); } catch (_) {}
  }

  function adminName() {
    try {
      if (typeof getCurrentAdminName === 'function') return getCurrentAdminName();
    } catch (_) {}
    return 'Admin';
  }

  function hasToken() {
    try { return typeof adminToken !== 'undefined' && !!adminToken; } catch (_) { return false; }
  }

  function trustLabel() {
    try {
      if (typeof getTrustToken === 'function' && getTrustToken()) return 'Dispositivo de confianza';
    } catch (_) {}
    return 'Solo token';
  }

  function formatRemaining(ms) {
    if (!Number.isFinite(ms)) return '—';
    if (ms <= 0) return 'Vencida';
    const minutes = Math.round(ms / 60000);
    if (minutes < 1) return 'menos de 1 min';
    if (minutes < 60) return minutes + ' min';
    const hours = Math.floor(minutes / 60);
    const rest = minutes % 60;
    return rest ? hours + ' h ' + rest + ' min' : hours + ' h';
  }

  function formatDate(timestamp) {
    try {
      return new Date(timestamp).toLocaleString('es-AR', {
        day: '2-digit',
        month: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch (_) {
      return '—';
    }
  }

  function toast(message) {
    try {
      if (typeof showToast === 'function') showToast(message);
    } catch (_) {}
  }

  function currentSubForTab(tab) {
    try {
      if (typeof adminSubState !== 'undefined' && adminSubState[tab]) return adminSubState[tab];
    } catch (_) {}
    return 'main';
  }

  function routeForLegacy(tab, sub) {
    const routes = LEGACY_ROUTES[tab];
    if (!routes) return null;
    return routes[sub] || routes.main || null;
  }

  /* ── Routing ────────────────────────────────────────────────────────── */

  function navigate(value, options) {
    const opts = options || {};
    const item = resolveItem(value) || HOME;
    const hash = '#' + item.route;

    if (window.location.hash === hash) {
      applyRoute(item.route);
      return;
    }

    if (opts.replace) {
      try {
        window.history.replaceState(null, '', hash);
      } catch (_) {
        window.location.hash = hash;
      }
      applyRoute(item.route);
      return;
    }

    window.location.hash = hash;
  }

  function applyRoute(value) {
    const item = resolveItem(value);
    if (!item) {
      navigate('/inicio', { replace: true });
      return;
    }

    // Todo proyecto (público o solo-admin) se abre en su ficha de detalle
    // dentro de Proyectos. Gestión sigue siendo el listado operativo.
    const targetTab = item.projectSlug ? 'projects' : item.tab;
    const targetSub = item.projectSlug ? 'detail' : item.sub;

    currentRoute = item.route;
    try { sessionStorage.setItem(SS_LAST, item.route); } catch (_) {}

    applyDepth++;
    try {
      if (item.page) {
        hideLegacyTabs();
        showShellPage(item.page);
      } else {
        hideShellPages();
        if (typeof switchAdminTab === 'function') switchAdminTab(targetTab);
        if (targetSub && typeof switchAdminSub === 'function') switchAdminSub(targetTab, targetSub);
      }
    } finally {
      applyDepth--;
    }

    syncNav(item);
    syncSlots();
    closeMenubar();
    closeSidebar();
    closeSessionMenu();
    updateRailToast();

    document.title = itemLabel(item) + ' · OWS Admin Panel';
    window.scrollTo({ top: 0, behavior: 'auto' });

    // La ficha del proyecto se pinta desde admin-app.js con los datos que ya
    // están en caché (o los pide si hace falta).
    if (item.projectSlug) {
      const slug = item.projectSlug;
      window.setTimeout(() => {
        try {
          if (typeof window.owsOpenProjectDetail === 'function') window.owsOpenProjectDetail(slug);
        } catch (_) {}
      }, 40);
    }
  }

  function hideLegacyTabs() {
    document.querySelectorAll('.admin-main > .tab-content').forEach((pane) => {
      pane.classList.add('hidden');
    });
  }

  function hideShellPages() {
    document.querySelectorAll('.admin-main > .ows-page').forEach((pane) => {
      pane.classList.add('hidden');
    });
  }

  function showShellPage(page) {
    hideShellPages();
    const pane = document.getElementById('ows-page-' + page);
    if (pane) pane.classList.remove('hidden');

    if (page === 'inicio') {
      renderInicio();
      refreshApiPill();
    } else if (page === 'menu') {
      renderSlotEditor();
    } else if (page === 'sesion') {
      refreshClocks();
    } else if (page === 'integraciones') {
      refreshApiPill();
      renderIntegrations();
      renderPayPalIntegration();
    } else if (page === 'codigo') {
      renderSourcePage();
      loadSourceCode(!sourceCache);
    } else if (page === 'notas') {
      if (typeof window.owsNotesPageOpen === 'function') window.owsNotesPageOpen();
    }
  }

  function syncNav(item) {
    document.querySelectorAll('.ows-nav-home, .ows-nav-link, .ows-project-link').forEach((link) => {
      const active = link.getAttribute('data-ows-route') === item.route;
      link.classList.toggle('is-active', active);
      if (active) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });

    document.querySelectorAll('.ows-group').forEach((group) => {
      group.classList.toggle('has-active', !!item.groupId && group.getAttribute('data-ows-group') === item.groupId);
    });

    syncMenubarState();

    if (item.groupId) openGroup(item.groupId);
  }

  function syncSlots() {
    document.querySelectorAll('.ows-slot[data-ows-route]').forEach((slot) => {
      const active = slot.getAttribute('data-ows-route') === currentRoute;
      slot.classList.toggle('is-active', active);
      if (active) slot.setAttribute('aria-current', 'page');
      else slot.removeAttribute('aria-current');
    });
  }

  /* ── Barra lateral ──────────────────────────────────────────────────── */

  function openGroup(id) {
    document.querySelectorAll('.ows-group').forEach((group) => {
      const open = !!id && group.getAttribute('data-ows-group') === id;
      group.classList.toggle('is-open', open);
      const toggle = group.querySelector('.ows-group-toggle');
      if (toggle) toggle.setAttribute('aria-expanded', String(open));
    });
    try { sessionStorage.setItem(SS_GROUP, id || ''); } catch (_) {}
  }

  function sidebarIsOpen() {
    const sidebar = document.getElementById('ows-sidebar');
    return !!sidebar && sidebar.classList.contains('is-open');
  }

  function openSidebar() {
    const sidebar = document.getElementById('ows-sidebar');
    const scrim = document.getElementById('ows-scrim');
    const button = document.getElementById('ows-menu-btn');
    if (!sidebar) return;
    sidebar.classList.add('is-open');
    if (scrim) scrim.hidden = false;
    document.body.classList.add('ows-drawer-open');
    if (button) button.setAttribute('aria-expanded', 'true');
    const close = document.getElementById('ows-sidebar-close');
    if (close) close.focus();
    updateRailToast();
  }

  function closeSidebar() {
    if (!sidebarIsOpen()) return;
    const sidebar = document.getElementById('ows-sidebar');
    const scrim = document.getElementById('ows-scrim');
    const button = document.getElementById('ows-menu-btn');
    const hadFocus = !!sidebar && sidebar.contains(document.activeElement);
    if (sidebar) sidebar.classList.remove('is-open');
    if (scrim) scrim.hidden = true;
    document.body.classList.remove('ows-drawer-open');
    if (button) button.setAttribute('aria-expanded', 'false');
    if (hadFocus && button) button.focus();
    updateRailToast();
  }

  /* ── Slots de la barra superior ─────────────────────────────────────── */

  function renderSlots() {
    const box = document.getElementById('ows-top-slots');
    if (!box) return;

    box.innerHTML = slots.map((route, index) => {
      const item = route ? resolveItem(route) : null;
      const label = item ? itemLabel(item) : 'Elegir acceso';
      const active = item && item.route === currentRoute ? ' is-active' : '';
      const href = item ? '#' + item.route : '#/ajustes/menu-superior';
      const routeAttr = item
        ? ' data-ows-route="' + esc(item.route) + '"'
        : ' data-ows-slot-config="1"';
      const content = item
        ? '<span class="ows-slot-num">' + (index + 1) + '</span>'
        : '<span class="ows-slot-empty" aria-hidden="true">+</span>';

      return '<div class="ows-slot-wrap" data-slot-wrap="' + index + '">' +
        '<a class="ows-slot' + active + '" href="' + href + '"' + routeAttr +
          ' aria-label="' + esc(label) + ' · Alt+' + (index + 1) + '">' + content + '</a>' +
        '<span class="ows-slot-panel" role="tooltip">' +
          '<span class="ows-slot-name">' + esc(label) + '</span>' +
          '<span class="ows-slot-kbd">Alt ' + (index + 1) + '</span>' +
        '</span>' +
      '</div>';
    }).join('');

    positionSlotPanels();
  }

  function positionSlotPanels() {
    const wraps = document.querySelectorAll('.ows-slot-wrap');
    if (!wraps.length) return;

    wraps.forEach((wrap) => {
      const panel = wrap.querySelector('.ows-slot-panel');
      if (!panel) return;
      wrap.classList.remove('is-flip-left', 'is-flip-right');
      const rect = panel.getBoundingClientRect();
      if (rect.left < 8) wrap.classList.add('is-flip-left');
      else if (rect.right > window.innerWidth - 8) wrap.classList.add('is-flip-right');
    });
  }

  /* ── Menú de secciones con desplegables ─────────────────────────────── */

  function menuItemsOf(group) {
    // El grupo Proyectos suma un destino por cada proyecto del catálogo.
    return group.id === 'catalogo'
      ? group.items.concat(projectNavItems())
      : group.items;
  }

  function renderMenubar() {
    const box = document.getElementById('ows-menubar');
    if (!box) return;

    const home = '<a class="ows-menu-home" href="#' + HOME.route + '" data-ows-route="' + HOME.route + '">Inicio</a>';

    box.innerHTML = home + NAV_GROUPS.map((group) => {
      const items = menuItemsOf(group);
      const links = items.map((item) =>
        '<a class="ows-menu-link' + (item.child ? ' is-child' : '') + '"' +
          ' href="#' + esc(item.route) + '" data-ows-route="' + esc(item.route) + '">' +
          esc(itemLabel(item)) + '</a>'
      ).join('');

      return '<div class="ows-menu-group" data-menu-group="' + esc(group.id) + '">' +
        '<button type="button" class="ows-menu-toggle" aria-expanded="false" aria-haspopup="true" aria-controls="ows-menu-' + esc(group.id) + '">' +
          '<span>' + esc(group.label) + '</span>' +
          '<span class="ows-menu-chev" aria-hidden="true"></span>' +
        '</button>' +
        '<div class="ows-menu-panel" id="ows-menu-' + esc(group.id) + '" role="group" aria-label="' + esc(group.label) + '">' +
          links +
        '</div>' +
      '</div>';
    }).join('');

    syncMenubarState();
  }

  function closeMenubar() {
    document.querySelectorAll('.ows-menu-group.is-open').forEach((group) => {
      group.classList.remove('is-open');
      const toggle = group.querySelector('.ows-menu-toggle');
      if (toggle) toggle.setAttribute('aria-expanded', 'false');
    });
  }

  function toggleMenuGroup(group) {
    if (!group) return;
    const open = group.classList.contains('is-open');
    closeMenubar();
    if (open) return;
    group.classList.add('is-open');
    const toggle = group.querySelector('.ows-menu-toggle');
    if (toggle) toggle.setAttribute('aria-expanded', 'true');
  }

  function syncMenubarState() {
    const item = resolveItem(currentRoute || readHashRoute());
    const route = item ? item.route : '';

    document.querySelectorAll('.ows-menu-home, .ows-menu-link').forEach((link) => {
      const active = link.getAttribute('data-ows-route') === route;
      link.classList.toggle('is-active', active);
      if (active) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });

    document.querySelectorAll('.ows-menu-group').forEach((group) => {
      const active = !!item && !!item.groupId && group.getAttribute('data-menu-group') === item.groupId;
      group.classList.toggle('has-active', active);
    });
  }

  function renderSlotEditor() {
    const box = document.getElementById('ows-slot-editor');
    if (!box) return;

    // El grupo Proyectos suma un destino por cada proyecto cargado.
    const groups = [{ label: 'General', items: [HOME] }].concat(
      NAV_GROUPS.map((group) => group.id === 'catalogo'
        ? Object.assign({}, group, { items: group.items.concat(projectNavItems()) })
        : group)
    );

    box.innerHTML = slots.map((route, index) => {
      return '<label class="ows-slot-row">' +
        '<span class="ows-slot-row-num">' + (index + 1) + '</span>' +
        '<span class="ows-slot-row-body">' +
          '<span class="ows-slot-row-title">Acceso ' + (index + 1) + ' <kbd>Alt ' + (index + 1) + '</kbd></span>' +
          '<select data-ows-slot-select="' + index + '" aria-label="Sección del acceso ' + (index + 1) + '">' +
            buildSlotOptions(groups, route) +
          '</select>' +
        '</span>' +
      '</label>';
    }).join('');
  }

  function buildSlotOptions(groups, selected) {
    let html = '<option value="">Sin asignar</option>';
    groups.forEach((group) => {
      html += '<optgroup label="' + esc(group.label) + '">';
      group.items.forEach((item) => {
        html += '<option value="' + esc(item.route) + '"' +
          (item.route === selected ? ' selected' : '') + '>' +
          esc(itemLabel(item)) + '</option>';
      });
      html += '</optgroup>';
    });
    return html;
  }

  function resetSlots() {
    slots = DEFAULT_SLOTS.slice();
    saveSlots();
    renderSlots();
    renderSlotEditor();
    renderInicio();
    toast('Menú superior restablecido.');
  }

  /* ── Páginas del shell ──────────────────────────────────────────────── */

  function renderSidebarIdentity() {
    const name = adminName();
    const initial = (String(name || 'A').trim().charAt(0) || 'A').toUpperCase();
    setText('sidebar-admin-name', name);
    setText('ows-sidebar-name', name);
    setText('ows-session-name', name);
    const sidebarAvatar = document.getElementById('ows-sidebar-avatar');
    if (sidebarAvatar) sidebarAvatar.textContent = initial;
    const sessionAvatar = document.getElementById('ows-session-avatar');
    if (sessionAvatar) sessionAvatar.textContent = initial;
  }

  function renderInicio() {
    renderSidebarIdentity();
    setText('ows-home-name', adminName());
    setText('ows-home-account', adminName());

    const quick = document.getElementById('ows-quick-grid');
    if (quick) {
      const cards = slots.map((route, index) => {
        const item = route ? resolveItem(route) : null;
        if (!item) return '';
        return '<a class="ows-quick-card" href="#' + esc(item.route) + '" data-ows-route="' + esc(item.route) + '">' +
          '<span class="ows-quick-num">' + (index + 1) + '</span>' +
          '<span class="ows-quick-text"><b>' + esc(itemLabel(item)) + '</b>' +
            '<small>' + esc(item.group || 'General') + '</small></span>' +
        '</a>';
      }).join('');
      quick.innerHTML = cards ||
        '<p class="ows-muted">No hay accesos configurados. Elegilos en Ajustes · Menú superior.</p>';
    }

    const sections = document.getElementById('ows-home-sections');
    if (sections) {
      sections.innerHTML = NAV_GROUPS.map((group) => {
        return '<div class="ows-home-group-block">' +
          '<span class="ows-home-group-label">' + esc(group.label) + '</span>' +
          '<div class="ows-home-links">' +
            group.items.map((item) =>
              '<a href="#' + esc(item.route) + '" data-ows-route="' + esc(item.route) + '">' +
                esc(itemLabel(item)) + '</a>'
            ).join('') +
          '</div>' +
        '</div>';
      }).join('');
    }

    refreshClocks();
  }

  function refreshClocks() {
    let expiresAt = null;
    try {
      if (typeof adminTokenExpiresAt === 'function') expiresAt = adminTokenExpiresAt();
    } catch (_) {}

    const remaining = expiresAt ? formatRemaining(expiresAt - Date.now()) : '—';
    const expiryText = expiresAt
      ? formatDate(expiresAt) + ' · ' + remaining
      : 'Sin vencimiento visible';

    setText('ows-home-expiry', remaining);
    setText('ows-home-trust', trustLabel());
    setText('ows-session-account', adminName());
    setText('ows-session-expiry', expiryText);
    setText('ows-session-token', hasToken() ? 'Token activo' : 'Sin token');
    setText('ows-session-trust', trustLabel());
  }

  function currentApiState() {
    const fo = window.OWS_API_FAILOVER;
    const configured = typeof API_BASE !== 'undefined' ? API_BASE : 'https://owsdatabase.onrender.com';
    const primary = fo ? fo.primary : configured;
    const active = fo ? fo.clientBase() : configured;
    return {
      configured: configured,
      primary: primary,
      active: active,
      isPrimary: active === primary,
      mirrors: fo && Array.isArray(fo.mirrors) ? fo.mirrors : []
    };
  }

  function refreshApiPill() {
    const state = currentApiState();

    const pill = document.getElementById('ows-api-pill');
    if (pill) {
      pill.classList.toggle('is-backup', !state.isPrimary);
      pill.title = state.isPrimary ? 'API principal activa' : 'Usando el espejo de respaldo';
    }
    setText('ows-api-label', state.isPrimary ? 'API' : 'Espejo');
    setText('ows-home-api', state.isPrimary ? 'API principal' : 'API espejo');

    const homeApi = document.getElementById('ows-home-api');
    if (homeApi) homeApi.classList.toggle('is-warn', !state.isPrimary);

    renderIntegrations();
  }

  function renderIntegrations() {
    const state = currentApiState();
    setText('ows-integ-main', state.configured);
    setText('ows-integ-active', state.active);

    const homeBase = document.getElementById('ows-home-api-base');
    if (homeBase) {
      homeBase.textContent = state.active.replace(/^https?:\/\//, '');
      if (state.isPrimary) delete homeBase.dataset.state;
      else homeBase.dataset.state = 'warn';
    }

    const stateEl = document.getElementById('ows-integ-state');
    if (stateEl) {
      stateEl.textContent = state.isPrimary ? 'Principal' : 'Espejo de respaldo';
      stateEl.dataset.state = state.isPrimary ? 'ok' : 'warn';
    }

    setText(
      'ows-integ-mirror',
      state.mirrors.length ? state.mirrors.join(' · ') : 'Sin espejo configurado'
    );
  }

  /* ── PayPal: switch live / sandbox ─────────────────────────────────── */

  function paypalEnvLabel(value) {
    return String(value || '').toLowerCase() === 'sandbox'
      ? 'Sandbox (pruebas)'
      : 'Live (cobros reales)';
  }

  function setPayPalResult(message, state) {
    const node = document.getElementById('ows-paypal-env-result');
    if (!node) return;
    node.textContent = message || '';
    if (state) node.dataset.state = state;
    else delete node.dataset.state;
  }

  function paypalEnvEntry(data, name) {
    const list = data && Array.isArray(data.environments) ? data.environments : [];
    for (let i = 0; i < list.length; i++) {
      if (list[i] && list[i].environment === name) return list[i];
    }
    return null;
  }

  function applyPayPalIntegration(data) {
    if (!data) return;

    const environment = String(data.environment || '').toLowerCase() === 'sandbox' ? 'sandbox' : 'live';
    const envEl = document.getElementById('ows-paypal-env');
    if (envEl) {
      envEl.textContent = paypalEnvLabel(environment)
        + (data.purchasesEnabled === false ? ' · compras pausadas' : '');
      envEl.dataset.state = environment === 'sandbox' ? 'warn' : 'ok';
    }

    const live = paypalEnvEntry(data, 'live');
    const sandbox = paypalEnvEntry(data, 'sandbox');

    function missingCredentialLabels(item) {
      const vars = item && item.vars;
      if (!vars) return [];
      const missing = [];
      if (!vars.clientId) missing.push('CLIENT_ID');
      if (!vars.clientSecret) missing.push('CLIENT_SECRET');
      return missing;
    }

    function credentialHint(item) {
      if (!item) return '';
      const quirks = Array.isArray(item.quirks) ? item.quirks : [];
      if (item.configured) {
        return quirks.length ? 'Revisar en Render: ' + quirks.join(', ') : '';
      }
      const liveEnv = item.environment === 'live';
      const names = [];
      if (!item.vars || !item.vars.clientId) names.push(liveEnv ? 'PAYPAL_CLIENT_ID' : 'PAYPAL_SANDBOX_CLIENT_ID');
      if (!item.vars || !item.vars.clientSecret) names.push(liveEnv ? 'PAYPAL_CLIENT_SECRET' : 'PAYPAL_SANDBOX_CLIENT_SECRET');
      const missing = names.length ? 'Faltan en Render: ' + names.join(', ') : '';
      return [missing].concat(quirks).filter(Boolean).join(' · ');
    }

    const credentials = function (item) {
      if (!item) return '—';
      if (!item.configured) {
        const missing = missingCredentialLabels(item);
        return missing.length ? 'Faltan: ' + missing.join(' + ') : 'Faltan';
      }
      const tail = String(item.clientIdTail || '').trim();
      return tail ? 'Configuradas · …' + tail : 'Configuradas';
    };

    setText('ows-paypal-live', credentials(live));
    const liveEl = document.getElementById('ows-paypal-live');
    if (liveEl) {
      liveEl.dataset.state = live && live.configured ? 'ok' : 'warn';
      liveEl.title = credentialHint(live);
    }

    setText('ows-paypal-sandbox', credentials(sandbox));
    const sandboxEl = document.getElementById('ows-paypal-sandbox');
    if (sandboxEl) {
      sandboxEl.dataset.state = sandbox && sandbox.configured ? 'ok' : 'warn';
      sandboxEl.title = credentialHint(sandbox);
    }

    const service = String(data.service || '').trim();
    setText('ows-paypal-service', service || '—');
    const serviceEl = document.getElementById('ows-paypal-service');
    if (serviceEl) {
      serviceEl.title = service
        ? 'Servicio de Render que respondió esta consulta'
        : 'Render no expone RENDER_SERVICE_NAME en esta instancia';
    }

    setText(
      'ows-paypal-webhooks',
      'Live ' + Number(live && live.webhooks || 0) + ' · Sandbox ' + Number(sandbox && sandbox.webhooks || 0)
    );

    setText(
      'ows-paypal-updated',
      data.updatedAt
        ? formatDate(data.updatedAt) + ' · ' + (data.updatedBy || 'panel')
        : 'Valor del entorno'
    );

    const select = document.getElementById('ows-paypal-env-select');
    if (select) {
      select.value = environment;
      for (let i = 0; i < select.options.length; i++) {
        const option = select.options[i];
        const item = paypalEnvEntry(data, option.value);
        const missing = !!item && !item.configured;
        option.disabled = missing;
        option.textContent = option.value === 'sandbox'
          ? (missing ? 'Sandbox (sin credenciales)' : 'Sandbox (pruebas)')
          : (missing ? 'Live (sin credenciales)' : 'Live (cobros reales)');
      }
    }

    const save = document.getElementById('ows-paypal-env-save');
    if (save) save.disabled = false;
  }

  async function loadPayPalIntegration(force) {
    if (paypalIntegrationBusy) return;
    if (!force && paypalIntegration && Date.now() - paypalIntegrationAt < 20000) {
      applyPayPalIntegration(paypalIntegration);
      return;
    }
    if (typeof adminFetch !== 'function') return;

    paypalIntegrationBusy = true;
    try {
      const res = await adminFetch(apiBase() + '/ows-admin-panel/integrations/paypal', { cache: 'no-store' });
      const data = await res.json().catch(function () { return {}; });
      if (!res.ok) throw new Error(data.error || 'No se pudo consultar PayPal.');
      paypalIntegration = data;
      paypalIntegrationAt = Date.now();
      applyPayPalIntegration(data);
      setPayPalResult('', '');
    } catch (err) {
      setPayPalResult(err && err.message ? err.message : 'No se pudo consultar PayPal.', 'warn');
    } finally {
      paypalIntegrationBusy = false;
    }
  }

  function renderPayPalIntegration() {
    if (paypalIntegration) applyPayPalIntegration(paypalIntegration);
    loadPayPalIntegration(false);
  }

  async function savePayPalEnvironment() {
    const select = document.getElementById('ows-paypal-env-select');
    const button = document.getElementById('ows-paypal-env-save');
    if (!select) return;

    const environment = select.value === 'sandbox' ? 'sandbox' : 'live';
    const current = paypalIntegration ? paypalIntegration.environment : '';
    if (environment === current) {
      setPayPalResult('Ese entorno ya está activo.', '');
      return;
    }

    const question = environment === 'sandbox'
      ? 'Vas a activar PayPal Sandbox: los pagos son de prueba y no se cobra dinero real. ¿Continuar?'
      : 'Vas a activar PayPal Live: los próximos pagos se cobran de verdad. ¿Continuar?';
    if (typeof window.confirm === 'function' && !window.confirm(question)) return;

    if (button) {
      button.disabled = true;
      button.textContent = 'Guardando…';
    }
    setPayPalResult('', '');

    try {
      const res = await adminFetch(apiBase() + '/ows-admin-panel/integrations/paypal', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ environment: environment })
      });
      const data = await res.json().catch(function () { return {}; });
      if (!res.ok) throw new Error(data.error || 'No se pudo guardar el entorno.');

      paypalIntegration = data;
      paypalIntegrationAt = Date.now();
      applyPayPalIntegration(data);
      setPayPalResult('Aplicado: ' + paypalEnvLabel(data.environment) + '.', 'ok');
      toast('PayPal en ' + paypalEnvLabel(data.environment) + '.');
    } catch (err) {
      setPayPalResult(err && err.message ? err.message : 'No se pudo guardar el entorno.', 'warn');
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent = 'Aplicar';
      }
    }
  }

  async function testPayPalEnvironment() {
    const select = document.getElementById('ows-paypal-env-select');
    const button = document.getElementById('ows-paypal-env-test');
    if (!select) return;

    const environment = select.value === 'sandbox' ? 'sandbox' : 'live';
    if (button) {
      button.disabled = true;
      button.textContent = 'Probando…';
    }
    setPayPalResult('Probando credenciales ' + paypalEnvLabel(environment) + '…', '');

    try {
      const res = await adminFetch(apiBase() + '/ows-admin-panel/integrations/paypal/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ environment: environment })
      });
      const data = await res.json().catch(function () { return {}; });
      if (!res.ok) {
        const quirks = Array.isArray(data.quirks) ? data.quirks : [];
        const message = data.detail ? (data.error || 'PayPal rechazó las credenciales') + ': ' + data.detail
          : (data.error || 'PayPal rechazó las credenciales.');
        throw new Error(message + (quirks.length ? ' · Revisar: ' + quirks.join(', ') : ''));
      }
      setPayPalResult(
        'Credenciales ' + paypalEnvLabel(environment) + ' OK · webhooks: ' + Number(data.webhooks || 0) + '.',
        'ok'
      );
    } catch (err) {
      setPayPalResult(err && err.message ? err.message : 'No se pudo probar PayPal.', 'warn');
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent = 'Probar';
      }
    }
  }

  /* ── Código Fuente ──────────────────────────────────────────────────── */

  function apiBase() {
    return typeof API_BASE !== 'undefined' ? API_BASE : 'https://owsdatabase.onrender.com';
  }

  function sourceHeaders(extra) {
    const base = typeof adminHeaders === 'function' ? adminHeaders() : {};
    return Object.assign({}, base, extra || {});
  }

  function formatSourceAgo(iso) {
    if (!iso) return 'sin fecha';
    const time = new Date(iso).getTime();
    if (Number.isNaN(time)) return 'sin fecha';
    const diff = Date.now() - time;
    if (diff < 0) return 'recién';
    const minutes = Math.floor(diff / 60000);
    if (minutes < 1) return 'hace instantes';
    if (minutes < 60) return 'hace ' + minutes + ' min';
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return 'hace ' + hours + ' h';
    const days = Math.floor(hours / 24);
    if (days === 1) return 'ayer';
    if (days < 30) return 'hace ' + days + ' días';
    const months = Math.floor(days / 30);
    if (months < 12) return 'hace ' + months + (months === 1 ? ' mes' : ' meses');
    const years = Math.floor(months / 12);
    return 'hace ' + years + (years === 1 ? ' año' : ' años');
  }

  function sourceMinutesLabel(total) {
    const minutes = Math.max(0, Math.round(Number(total) || 0));
    if (minutes < 60) return minutes + ' min';
    const hours = Math.floor(minutes / 60);
    const rest = minutes % 60;
    return rest ? hours + ' h ' + rest + ' min' : hours + ' h';
  }

  function sourceStateMeta(entry) {
    if (!entry || !entry.source) return { cls: 'is-missing', label: 'Sin código', icon: '📭' };
    if (entry.state === 'stale') return { cls: 'is-stale', label: 'Revisar', icon: '⚠️' };
    return { cls: 'is-current', label: 'Al día', icon: '✅' };
  }

  async function loadSourceCode(showLoading) {
    const list = document.getElementById('src-list');
    if (!list || sourceLoading) return;
    sourceLoading = true;
    if (showLoading) list.innerHTML = '<p class="loading-note">Cargando código fuente…</p>';
    try {
      const res = await fetch(apiBase() + '/ows-source-code', { headers: sourceHeaders() });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || ('Error ' + res.status));
      sourceCache = data;
      sourceError = '';
    } catch (err) {
      sourceError = err && err.message ? err.message : 'No se pudo cargar el código fuente.';
    } finally {
      sourceLoading = false;
    }
    renderSourcePage();
  }

  function sourceCardHtml(entry) {
    const meta = sourceStateMeta(entry);
    const src = entry.source || null;
    const isHub = entry.kind === 'hub';
    const activity = entry.activity || {};
    const owner = !!(sourceCache && sourceCache.owner);
    const icon = isHub
      ? '<span class="src-icon-fallback">🧭</span>'
      : (entry.icon_url
        ? '<img src="' + esc(entry.icon_url) + '" alt="" loading="lazy" />'
        : '<span class="src-icon-fallback">📁</span>');

    const chips = [];
    if (src) {
      if (src.version) chips.push('<span class="src-chip">📦 v' + esc(src.version) + '</span>');
      chips.push('<span class="src-chip">🗓️ ' + esc(formatSourceAgo(src.updated_at)) + '</span>');
      if (src.file_label) chips.push('<span class="src-chip">📁 ' + esc(src.file_label) + '</span>');
      if (src.updated_by) chips.push('<span class="src-chip">👤 ' + esc(src.updated_by) + '</span>');
    } else {
      chips.push('<span class="src-chip is-muted">Sin código cargado</span>');
    }

    const actions = [];
    if (src && src.download_url) {
      actions.push('<a class="ows-btn ows-btn-ghost" href="' + esc(src.download_url) + '" target="_blank" rel="noopener">⬇ Descargar</a>');
    }
    if (owner) {
      actions.push('<button type="button" class="ows-btn' + (src ? ' ows-btn-ghost' : '') + '" data-src-action="edit" data-src-scope="' + esc(entry.scope) + '">' +
        (src ? '✏️ Actualizar' : '📤 Cargar código') + '</button>');
      if (src) {
        actions.push('<button type="button" class="ows-btn ows-btn-danger" data-src-action="remove" data-src-scope="' + esc(entry.scope) + '">🗑️ Quitar</button>');
      }
    }

    const activityText = activity.reason || (src
      ? 'Sin devlogs ni sesiones posteriores a la última actualización.'
      : 'Sin código cargado: todavía no hay una fecha contra la cual comparar la actividad.');
    const activityBits = [];
    if (src) {
      if (activity.devlogs) activityBits.push(activity.devlogs + ' devlog' + (activity.devlogs === 1 ? '' : 's'));
      if (activity.sessions) activityBits.push(activity.sessions + ' sesi' + (activity.sessions === 1 ? 'ón' : 'ones'));
      if (activity.minutes) activityBits.push(sourceMinutesLabel(activity.minutes));
      if (activity.active_days > 1) activityBits.push(activity.active_days + ' días activos');
    }

    return `
      <article class="src-card ${meta.cls}">
        <div class="src-card-top">
          <div class="src-card-id">
            <span class="src-card-icon">${icon}</span>
            <div class="src-card-copy">
              <h3>${esc(entry.name || entry.slug || 'Proyecto')}</h3>
              <span class="src-card-kind">${isHub ? 'OWS Hub' : 'Proyecto'}${entry.slug ? ' · ' + esc(entry.slug) : ''}${entry.admin_only ? ' · 🔒 solo-admin' : ''}</span>
            </div>
          </div>
          <span class="src-state ${meta.cls}">${meta.icon} ${meta.label}</span>
        </div>
        <div class="src-card-meta">${chips.join('')}</div>
        ${src && src.notes ? '<p class="src-card-notes">📝 ' + esc(src.notes) + '</p>' : ''}
        <p class="src-card-activity ${activity.stale ? 'is-warn' : ''}">
          <b>${src ? (activity.stale ? 'Actividad posterior' : 'Sin cambios pendientes') : 'Todavía sin código'}</b>
          <span>${esc(activityText)}</span>
          ${activityBits.length ? '<small>' + esc(activityBits.join(' · ')) + '</small>' : ''}
        </p>
        <div class="src-card-actions">${actions.join('') || '<span class="ows-muted">Solo lectura.</span>'}</div>
      </article>`;
  }

  function renderSourcePage() {
    const list = document.getElementById('src-list');
    if (!list) return;

    const data = sourceCache;
    const summary = (data && data.summary) || { total: 0, current: 0, stale: 0, missing: 0 };
    setText('src-stat-total', String(summary.total || 0));
    setText('src-stat-current', String(summary.current || 0));
    setText('src-stat-stale', String(summary.stale || 0));
    setText('src-stat-missing', String(summary.missing || 0));

    const owner = !!(data && data.owner);
    const ownerBadge = document.getElementById('src-owner-badge');
    if (ownerBadge) {
      ownerBadge.textContent = owner ? '👑 Owner · edición habilitada' : '🔒 Solo lectura';
      ownerBadge.classList.toggle('is-owner', owner);
    }
    const ownerNote = document.getElementById('src-owner-note');
    if (ownerNote) {
      ownerNote.textContent = owner
        ? 'Sos el Owner: podés cargar, reemplazar o quitar el código de cualquier proyecto y del Hub. Cada guardado renueva la fecha que usa el aviso de desactualización.'
        : 'Solo el Owner (OceanandWild) puede cargar o reemplazar el código. Podés descargar lo que ya está publicado.';
    }

    document.querySelectorAll('[data-src-filter]').forEach((button) => {
      button.classList.toggle('active', button.getAttribute('data-src-filter') === sourceFilter);
    });

    if (sourceError) {
      list.innerHTML = '<div class="src-empty">' +
        '<p>⚠️ ' + esc(sourceError) + '</p>' +
        '<button type="button" class="ows-btn" data-src-action="refresh">Reintentar</button>' +
        '</div>';
      return;
    }
    if (!data) {
      list.innerHTML = '<p class="loading-note">Cargando código fuente…</p>';
      return;
    }

    const query = fold(sourceQuery);
    const entries = (data.entries || []).filter((entry) => {
      if (sourceFilter === 'stale' && entry.state !== 'stale') return false;
      if (sourceFilter === 'current' && entry.state !== 'current') return false;
      if (sourceFilter === 'missing' && entry.state !== 'missing') return false;
      if (!query) return true;
      const haystack = fold([entry.name, entry.slug, entry.kind, entry.source && entry.source.version].filter(Boolean).join(' '));
      return haystack.indexOf(query) !== -1;
    });

    if (!entries.length) {
      list.innerHTML = '<div class="src-empty"><p>No hay resultados con este filtro.</p>' +
        '<button type="button" class="ows-btn ows-btn-ghost" data-src-action="clear">Limpiar filtros</button></div>';
      return;
    }

    list.innerHTML = entries.map(sourceCardHtml).join('');
  }

  function openSourceModal(scope) {
    const data = sourceCache;
    if (!data || !data.owner) {
      toast('Solo el Owner puede editar el código fuente.');
      return;
    }
    const entry = (data.entries || []).find((item) => item.scope === scope);
    if (!entry) {
      toast('No se encontró ese proyecto en el listado.');
      return;
    }
    const src = entry.source || {};
    const body = document.getElementById('src-modal-body');
    if (!body) return;
    sourceModalScope = scope;
    const name = entry.name || entry.slug || 'Proyecto';

    body.innerHTML = `
      <h3 class="form-title">${src.id ? '✏️ Actualizar' : '📤 Cargar'} código fuente</h3>
      <p class="form-hint">${esc(name)} · ${entry.kind === 'hub' ? 'OWS Hub' : 'Proyecto'} — la descarga queda disponible para todos los admins; solo el Owner puede modificarla.</p>
      <form data-src-form="1" data-src-scope="${esc(entry.scope)}">
        <div class="field-row">
          <div class="field-group">
            <label for="src-version">Versión <span class="opt-tag">opcional</span></label>
            <input type="text" id="src-version" maxlength="60" placeholder="Ej: 3.4.5" value="${esc(src.version || '')}" autocomplete="off" />
          </div>
          <div class="field-group">
            <label for="src-file-label">Nombre del archivo <span class="opt-tag">opcional</span></label>
            <input type="text" id="src-file-label" maxlength="160" placeholder="Ej: ows-hub-src.zip" value="${esc(src.file_label || '')}" autocomplete="off" />
          </div>
        </div>
        <div class="field-group">
          <label for="src-url">URL de descarga *</label>
          <input type="url" id="src-url" required placeholder="https://github.com/…/archive/refs/heads/main.zip" value="${esc(src.download_url || '')}" autocomplete="off" />
          <small class="form-hint">ZIP del repositorio o enlace de descarga directa. Se abre en el navegador del admin.</small>
        </div>
        <div class="field-group">
          <label for="src-notes">Notas <span class="opt-tag">opcional</span></label>
          <textarea id="src-notes" rows="3" maxlength="1000" placeholder="Qué incluye esta entrega, rama, commit…">${esc(src.notes || '')}</textarea>
        </div>
        <div id="src-alert" class="alert-box hidden"></div>
        <button type="submit" class="btn btn-primary btn-block" id="src-save">${src.id ? '💾 Guardar cambios' : '📤 Publicar código'}</button>
      </form>`;

    const modal = document.getElementById('src-modal');
    if (modal) modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    const first = document.getElementById('src-version');
    if (first) first.focus();
  }

  function closeSourceModal() {
    const modal = document.getElementById('src-modal');
    if (modal) modal.classList.add('hidden');
    sourceModalScope = '';
    try {
      if (!document.querySelector('.devmodal-overlay:not(.hidden)')) document.body.style.overflow = '';
    } catch (_) {
      document.body.style.overflow = '';
    }
  }

  async function saveSourceCode(form) {
    const scope = form.getAttribute('data-src-scope') || sourceModalScope;
    const version = (document.getElementById('src-version').value || '').trim();
    const url = (document.getElementById('src-url').value || '').trim();
    const fileLabel = (document.getElementById('src-file-label').value || '').trim();
    const notes = (document.getElementById('src-notes').value || '').trim();
    const alert = document.getElementById('src-alert');
    const button = document.getElementById('src-save');
    const fail = (message) => {
      if (alert) {
        alert.textContent = message;
        alert.classList.remove('hidden');
      } else {
        toast(message);
      }
    };

    if (!/^https?:\/\//i.test(url)) {
      fail('La URL debe empezar con http:// o https://');
      return;
    }
    if (button) {
      button.disabled = true;
      button.textContent = 'Guardando…';
    }
    try {
      const res = await fetch(apiBase() + '/ows-source-code', {
        method: 'PUT',
        headers: sourceHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ scope, version, download_url: url, file_label: fileLabel, notes })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || ('Error ' + res.status));
      closeSourceModal();
      toast('Código fuente actualizado ✔');
      sourceCache = null;
      await loadSourceCode(true);
    } catch (err) {
      fail(err && err.message ? err.message : 'No se pudo guardar.');
      if (button) {
        button.disabled = false;
        button.textContent = '💾 Guardar cambios';
      }
    }
  }

  async function removeSourceCode(scope) {
    const entry = ((sourceCache && sourceCache.entries) || []).find((item) => item.scope === scope);
    const name = entry ? (entry.name || entry.slug) : 'este proyecto';
    if (!window.confirm('¿Quitar el código fuente de ' + name + '? La descarga dejará de estar disponible.')) return;
    try {
      const res = await fetch(apiBase() + '/ows-source-code/' + encodeURIComponent(scope), {
        method: 'DELETE',
        headers: sourceHeaders()
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || ('Error ' + res.status));
      toast('Código fuente quitado');
      sourceCache = null;
      await loadSourceCode(true);
    } catch (err) {
      toast('⚠️ ' + (err && err.message ? err.message : 'No se pudo quitar.'));
    }
  }

  function handleSourceAction(action, scope) {
    if (action === 'refresh') {
      sourceCache = null;
      loadSourceCode(true);
      return;
    }
    if (action === 'edit') {
      openSourceModal(scope);
      return;
    }
    if (action === 'remove') {
      removeSourceCode(scope);
      return;
    }
    if (action === 'clear') {
      sourceFilter = 'all';
      sourceQuery = '';
      const input = document.getElementById('src-search');
      if (input) input.value = '';
      renderSourcePage();
      return;
    }
    if (action === 'close') closeSourceModal();
  }

  /* ── Barra lateral plegable + aviso de sección ──────────────────────── */

  function applySidebarCollapsed() {
    document.body.classList.toggle('ows-sidebar-collapsed', sidebarCollapsed);
    const button = document.getElementById('ows-menu-btn');
    if (button) {
      button.setAttribute('aria-expanded', String(!sidebarCollapsed));
      button.setAttribute('aria-label', sidebarCollapsed ? 'Mostrar navegación (Ctrl+B)' : 'Ocultar navegación (Ctrl+B)');
      button.title = sidebarCollapsed ? 'Mostrar menú · Ctrl+B' : 'Ocultar menú · Ctrl+B';
    }
    updateRailToast();
  }

  function toggleSidebarCollapsed(force) {
    sidebarCollapsed = typeof force === 'boolean' ? force : !sidebarCollapsed;
    try { localStorage.setItem(LS_SIDEBAR, sidebarCollapsed ? '1' : '0'); } catch (_) {}
    applySidebarCollapsed();
  }

  function toggleNavigation() {
    if (window.innerWidth <= 1023) {
      if (sidebarIsOpen()) closeSidebar();
      else openSidebar();
      return;
    }
    toggleSidebarCollapsed();
  }

  function updateRailToast() {
    const rail = document.getElementById('ows-rail-toast');
    if (!rail) return;
    const item = resolveItem(currentRoute || readHashRoute());
    const panel = document.getElementById('admin-panel');
    const panelVisible = !!panel && !panel.classList.contains('hidden');
    const show = !!item && sidebarCollapsed && !sidebarIsOpen() && window.innerWidth > 1023 && panelVisible;

    if (item) {
      setText('ows-rail-toast-group', item.group || 'General');
      setText('ows-rail-toast-title', itemLabel(item));
      setText('ows-rail-toast-sub', item.projectSlug ? 'Proyecto · ' + item.projectSlug : (item.child ? 'Subsección' : ''));
    }

    if (show) {
      rail.hidden = false;
      window.requestAnimationFrame(() => rail.classList.add('is-visible'));
    } else {
      rail.classList.remove('is-visible');
      window.setTimeout(() => {
        if (!rail.classList.contains('is-visible')) rail.hidden = true;
      }, 260);
    }
  }

  /* ── Acciones ───────────────────────────────────────────────────────── */

  function runAction(action) {
    if (action === 'logout') {
      if (typeof adminLogout === 'function') adminLogout();
      return;
    }
    if (action === 'slots-reset') {
      resetSlots();
      return;
    }
    if (action === 'session-renew') {
      renewSession();
      return;
    }
    if (action === 'api-probe') {
      probeApi();
      return;
    }
    if (action === 'paypal-env-save') {
      savePayPalEnvironment();
      return;
    }
    if (action === 'paypal-env-test') {
      testPayPalEnvironment();
      return;
    }
    if (action === 'rail-open') {
      toggleSidebarCollapsed(false);
    }
  }

  async function renewSession() {
    const button = document.getElementById('ows-session-renew');
    if (button) {
      button.disabled = true;
      button.textContent = 'Renovando…';
    }

    let ok = false;
    try {
      if (typeof refreshSessionSilently === 'function') ok = await refreshSessionSilently();
    } catch (_) {
      ok = false;
    }

    if (button) {
      button.disabled = false;
      button.textContent = 'Renovar ahora';
    }
    toast(ok ? 'Sesión renovada.' : 'No se pudo renovar: falta el dispositivo de confianza.');
    refreshClocks();
  }

  async function probeApi() {
    const button = document.getElementById('ows-integ-probe');
    const result = document.getElementById('ows-integ-result');

    if (!window.OWS_API_FAILOVER) {
      if (result) result.textContent = 'El failover no está disponible en esta carga.';
      return;
    }

    if (button) {
      button.disabled = true;
      button.textContent = 'Probando…';
    }
    if (result) {
      result.textContent = '';
      delete result.dataset.state;
    }

    const ok = await (async () => {
      try {
        return await window.OWS_API_FAILOVER.probePrimary();
      } catch (_) {
        return false;
      }
    })();

    if (button) {
      button.disabled = false;
      button.textContent = 'Probar principal';
    }
    if (result) {
      result.textContent = ok
        ? 'La API principal respondió.'
        : 'La principal no respondió; sigue el espejo.';
      result.dataset.state = ok ? 'ok' : 'warn';
    }
    refreshApiPill();
  }

  /* ── Paleta de búsqueda ─────────────────────────────────────────────── */

  function paletteIsOpen() {
    const backdrop = document.getElementById('ows-palette');
    return !!backdrop && !backdrop.hidden;
  }

  function openPalette() {
    const backdrop = document.getElementById('ows-palette');
    const input = document.getElementById('ows-palette-input');
    if (!backdrop) return;

    backdrop.hidden = false;
    document.body.classList.add('ows-palette-open');
    paletteIndex = 0;

    if (input) {
      input.value = '';
      input.focus();
    }
    renderPalette('');
  }

  function closePalette() {
    const backdrop = document.getElementById('ows-palette');
    if (!backdrop || backdrop.hidden) return;

    const hadFocus = backdrop.contains(document.activeElement);
    backdrop.hidden = true;
    document.body.classList.remove('ows-palette-open');

    if (hadFocus) {
      const trigger = document.getElementById('ows-palette-trigger');
      if (trigger) trigger.focus();
    }
  }

  function togglePalette() {
    if (paletteIsOpen()) closePalette();
    else openPalette();
  }

  function renderPalette(query) {
    const box = document.getElementById('ows-palette-results');
    if (!box) return;

    const term = fold(query).trim();
    paletteResults = allNavItems().filter((item) => {
      if (!term) return true;
      const haystack = fold(
        itemLabel(item) + ' ' + item.label + ' ' + (item.group || '') + ' ' + (item.route || '') + ' ' + (item.id || '')
      );
      return haystack.indexOf(term) !== -1;
    });

    if (!paletteResults.length) {
      paletteIndex = 0;
      box.innerHTML = '<p class="ows-palette-empty">Sin resultados para “' + esc(query) + '”.</p>';
      return;
    }

    if (paletteIndex >= paletteResults.length) paletteIndex = paletteResults.length - 1;
    if (paletteIndex < 0) paletteIndex = 0;

    box.innerHTML = paletteResults.map((item, index) => {
      const active = index === paletteIndex ? ' is-active' : '';
      return '<button type="button" class="ows-palette-item' + active + '"' +
        ' data-ows-route="' + esc(item.route) + '"' +
        ' role="option" aria-selected="' + (index === paletteIndex) + '">' +
        '<span class="ows-palette-item-main">' + esc(itemLabel(item)) + '</span>' +
        '<span class="ows-palette-item-group">' + esc(item.group || 'General') + '</span>' +
      '</button>';
    }).join('');
  }

  function movePalette(delta) {
    if (!paletteResults.length) return;
    const total = paletteResults.length;
    paletteIndex = (paletteIndex + delta + total) % total;
    const input = document.getElementById('ows-palette-input');
    renderPalette(input ? input.value : '');
    const active = document.querySelector('.ows-palette-item.is-active');
    if (active) active.scrollIntoView({ block: 'nearest' });
  }

  function runPaletteSelection() {
    const item = paletteResults[paletteIndex];
    if (!item) return;
    closePalette();
    navigate(item.route);
  }

  /* ── Menú de sesión ─────────────────────────────────────────────────── */

  function closeSessionMenu() {
    const menu = document.getElementById('ows-session-menu');
    const trigger = document.getElementById('ows-session-trigger');
    if (!menu || menu.hidden) return;
    menu.hidden = true;
    if (trigger) trigger.setAttribute('aria-expanded', 'false');
  }

  function toggleSessionMenu() {
    const menu = document.getElementById('ows-session-menu');
    const trigger = document.getElementById('ows-session-trigger');
    if (!menu) return;
    const willOpen = menu.hidden;
    menu.hidden = !willOpen;
    if (trigger) trigger.setAttribute('aria-expanded', String(willOpen));
    if (willOpen) refreshClocks();
  }

  /* ── Eventos del shell ──────────────────────────────────────────────── */

  function bindShellEvents() {
    document.addEventListener('click', (event) => {
      const target = event.target;
      if (!target || !target.closest) return;

      const routeEl = target.closest('[data-ows-route]');
      if (routeEl) {
        const isAnchor = routeEl.tagName === 'A';
        const modified = event.metaKey || event.ctrlKey || event.shiftKey || event.altKey;
        // Ctrl/Cmd/Shift+clic conserva el comportamiento nativo del enlace.
        if (isAnchor && modified) return;
        if (isAnchor) event.preventDefault();
        closePalette();
        navigate(routeEl.getAttribute('data-ows-route'));
        return;
      }

      const configEl = target.closest('[data-ows-slot-config]');
      if (configEl) {
        event.preventDefault();
        navigate('/ajustes/menu-superior');
        return;
      }

      const filterEl = target.closest('[data-src-filter]');
      if (filterEl) {
        event.preventDefault();
        sourceFilter = filterEl.getAttribute('data-src-filter') || 'all';
        renderSourcePage();
        return;
      }

      const srcEl = target.closest('[data-src-action]');
      if (srcEl) {
        event.preventDefault();
        handleSourceAction(
          srcEl.getAttribute('data-src-action'),
          srcEl.getAttribute('data-src-scope') || ''
        );
        return;
      }

      const actionEl = target.closest('[data-ows-action]');
      if (actionEl) {
        event.preventDefault();
        runAction(actionEl.getAttribute('data-ows-action'));
      }
    });

    document.querySelectorAll('.ows-group-toggle').forEach((button) => {
      button.addEventListener('click', () => {
        const group = button.closest('.ows-group');
        if (!group) return;
        const id = group.getAttribute('data-ows-group');
        if (group.classList.contains('is-open')) openGroup('');
        else openGroup(id);
      });
    });

    document.addEventListener('change', (event) => {
      const select = event.target && event.target.closest
        ? event.target.closest('[data-ows-slot-select]')
        : null;
      if (!select) return;

      const index = Number(select.getAttribute('data-ows-slot-select'));
      const route = select.value;

      if (route) {
        const duplicate = slots.indexOf(route);
        if (duplicate !== -1 && duplicate !== index) slots[duplicate] = '';
      }
      slots[index] = route;
      saveSlots();
      renderSlots();
      renderSlotEditor();
      renderInicio();

      const status = document.getElementById('ows-slots-status');
      if (status) {
        status.textContent = 'Guardado en este navegador.';
        window.setTimeout(() => {
          if (status.textContent === 'Guardado en este navegador.') status.textContent = '';
        }, 2400);
      }
    });

    const paletteTrigger = document.getElementById('ows-palette-trigger');
    if (paletteTrigger) paletteTrigger.addEventListener('click', togglePalette);

    const paletteInput = document.getElementById('ows-palette-input');
    if (paletteInput) {
      paletteInput.addEventListener('input', () => {
        paletteIndex = 0;
        renderPalette(paletteInput.value);
      });
      paletteInput.addEventListener('keydown', (event) => {
        if (event.key === 'ArrowDown') {
          event.preventDefault();
          movePalette(1);
        } else if (event.key === 'ArrowUp') {
          event.preventDefault();
          movePalette(-1);
        } else if (event.key === 'Enter') {
          event.preventDefault();
          runPaletteSelection();
        } else if (event.key === 'Escape') {
          event.preventDefault();
          event.stopPropagation();
          closePalette();
        }
      });
    }

    const palette = document.getElementById('ows-palette');
    if (palette) {
      palette.addEventListener('click', (event) => {
        if (event.target === palette) closePalette();
      });
    }

    const sessionTrigger = document.getElementById('ows-session-trigger');
    if (sessionTrigger) {
      sessionTrigger.addEventListener('click', (event) => {
        event.stopPropagation();
        toggleSessionMenu();
      });
    }

    const menubar = document.getElementById('ows-menubar');
    if (menubar) {
      menubar.addEventListener('click', (event) => {
        if (!event.target || !event.target.closest) return;
        const toggle = event.target.closest('.ows-menu-toggle');
        if (toggle) {
          event.preventDefault();
          toggleMenuGroup(toggle.closest('.ows-menu-group'));
          return;
        }
        if (event.target.closest('.ows-menu-home, .ows-menu-link')) closeMenubar();
      });

      menubar.addEventListener('keydown', (event) => {
        if (!event.target || !event.target.closest) return;
        const toggle = event.target.closest('.ows-menu-toggle');
        if (!toggle || event.key !== 'ArrowDown') return;
        event.preventDefault();
        const group = toggle.closest('.ows-menu-group');
        toggleMenuGroup(group);
        const first = group ? group.querySelector('.ows-menu-panel a') : null;
        if (first) first.focus();
      });
    }

    document.addEventListener('click', (event) => {
      if (!event.target || !event.target.closest) return;
      if (!event.target.closest('.ows-session')) closeSessionMenu();
      if (!event.target.closest('.ows-menubar')) closeMenubar();
    });

    const menuButton = document.getElementById('ows-menu-btn');
    if (menuButton) {
      menuButton.addEventListener('click', toggleNavigation);
    }

    const sidebarClose = document.getElementById('ows-sidebar-close');
    if (sidebarClose) sidebarClose.addEventListener('click', closeSidebar);

    const scrim = document.getElementById('ows-scrim');
    if (scrim) scrim.addEventListener('click', closeSidebar);

    const srcSearch = document.getElementById('src-search');
    if (srcSearch) {
      srcSearch.addEventListener('input', () => {
        sourceQuery = srcSearch.value;
        renderSourcePage();
      });
    }

    const srcModal = document.getElementById('src-modal');
    if (srcModal) {
      srcModal.addEventListener('click', (event) => {
        if (event.target === srcModal) closeSourceModal();
      });
    }

    document.addEventListener('submit', (event) => {
      const form = event.target && event.target.closest
        ? event.target.closest('[data-src-form]')
        : null;
      if (!form) return;
      event.preventDefault();
      saveSourceCode(form);
    });

    document.addEventListener('keydown', (event) => {
      if ((event.ctrlKey || event.metaKey) && !event.altKey && String(event.key).toLowerCase() === 'k') {
        event.preventDefault();
        togglePalette();
        return;
      }

      if ((event.ctrlKey || event.metaKey) && !event.altKey && String(event.key).toLowerCase() === 'b') {
        const tag = (event.target && event.target.tagName || '').toLowerCase();
        if (tag === 'input' || tag === 'textarea' || tag === 'select' ||
            (event.target && event.target.isContentEditable)) return;
        event.preventDefault();
        toggleNavigation();
        return;
      }

      if (event.key === 'Escape') {
        const srcModal = document.getElementById('src-modal');
        if (srcModal && !srcModal.classList.contains('hidden')) {
          closeSourceModal();
          return;
        }
        if (paletteIsOpen()) {
          closePalette();
          return;
        }
        if (sidebarIsOpen()) {
          closeSidebar();
          return;
        }
        if (document.querySelector('.ows-menu-group.is-open')) {
          closeMenubar();
          return;
        }
        closeSessionMenu();
        return;
      }

      if (!event.altKey || event.ctrlKey || event.metaKey) return;

      const match = /^([1-5])$/.exec(String(event.key)) ||
        /^Digit([1-5])$/.exec(String(event.code));
      if (!match) return;

      const tag = (event.target && event.target.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select' ||
          (event.target && event.target.isContentEditable)) return;

      const route = slots[Number(match[1]) - 1];
      if (!route) return;

      event.preventDefault();
      navigate(route);
    });

    window.addEventListener('resize', () => {
      if (window.innerWidth > 1023) closeSidebar();
      updateRailToast();
      if (resizeTimer) window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(positionSlotPanels, 120);
    });

    window.addEventListener('hashchange', () => {
      const item = resolveItem(readHashRoute());
      if (!item) {
        navigate('/inicio', { replace: true });
        return;
      }
      applyRoute(item.route);
    });
  }

  /* ── Arranque ───────────────────────────────────────────────────────── */

  function start() {
    if (!document.getElementById('ows-top-slots')) return;

    if (!started) {
      started = true;
      bindShellEvents();
      renderSlots();
      renderMenubar();
      renderSlotEditor();
      renderInicio();
      refreshClocks();
      refreshApiPill();
      renderSidebarIdentity();
      applySidebarCollapsed();

      const storedGroup = readStoredGroup();
      if (storedGroup) openGroup(storedGroup);

      // Las etiquetas largas dependen del ancho real de la fuente: al terminar
      // de cargar, se recalculan los extremos para que el overlay no se corte.
      try {
        if (document.fonts && document.fonts.ready) {
          document.fonts.ready.then(positionSlotPanels).catch(function () {});
        }
      } catch (_) {}

      window.setInterval(refreshApiPill, 15000);
      window.setInterval(refreshClocks, 30000);
    }

    const initial = resolveItem(readHashRoute()) || resolveItem(readLastRoute()) || HOME;
    navigate(initial.route, { replace: true });
  }

  /* ── Integración con la lógica existente ────────────────────────────── */

  const originalSwitchTab = window.switchAdminTab;
  if (typeof originalSwitchTab === 'function') {
    window.switchAdminTab = function (tab) {
      const result = originalSwitchTab.apply(this, arguments);
      if (applyDepth === 0 && started) {
        const route = routeForLegacy(tab, currentSubForTab(tab));
        if (route) navigate(route);
      }
      return result;
    };
  }

  const originalSwitchSub = window.switchAdminSub;
  if (typeof originalSwitchSub === 'function') {
    window.switchAdminSub = function (tab, sub) {
      const result = originalSwitchSub.apply(this, arguments);
      if (applyDepth === 0 && started) {
        const route = routeForLegacy(tab, sub);
        if (route) navigate(route);
      }
      return result;
    };
  }

  // admin-app.js avisa cada vez que termina de cargar o refrescar el catálogo
  // de proyectos. Así el sidebar, la paleta y los slots ven los cambios sin
  // recargar la página.
  window.owsRefreshProjectNav = function () {
    if (!started) return;
    renderSlots();
    renderMenubar();
    renderSlotEditor();

    const item = resolveItem(currentRoute || readHashRoute());
    if (!item) return;
    syncNav(item);
    document.title = itemLabel(item) + ' · OWS Admin Panel';

    // Si el catálogo llega después de un deep link a un proyecto, la ficha
    // se vuelve a pintar ahora que el slug ya existe en el registro.
    if (item.projectSlug && typeof window.owsOpenProjectDetail === 'function') {
      try { window.owsOpenProjectDetail(item.projectSlug); } catch (_) {}
    }
  };

  // Navegación programática para botones de la ficha de proyecto.
  window.owsNavigate = function (route, options) { navigate(route, options); };

  const originalOpenPanel = window.openPanel;
  if (typeof originalOpenPanel === 'function') {
    window.openPanel = function () {
      const result = originalOpenPanel.apply(this, arguments);
      try {
        start();
      } catch (error) {
        console.error('[OWS shell] No se pudo iniciar la interfaz.', error);
      }
      return result;
    };
  }

  document.addEventListener('DOMContentLoaded', () => {
    const panel = document.getElementById('admin-panel');
    if (panel && !panel.classList.contains('hidden')) {
      try { start(); } catch (_) {}
    }
  });
})();
