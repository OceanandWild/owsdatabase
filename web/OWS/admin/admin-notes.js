/* ============================================================================
   OWS Admin Panel — Notas y anotaciones
   ----------------------------------------------------------------------------
   Espacio interno del estudio para tareas, ideas, referencias y apuntes.
   Cada nota conserva su autor, categoría, lista, proyecto, etiquetas,
   checklist, enlaces, prioridad, estado, vencimiento y visibilidad.

   Los proyectos narrativos usan UNA estructura excluyente:
     · Temporadas + episodios
     · Solo capítulos
   La estructura se define por proyecto en "Estructura narrativa" y el
   servidor limpia los campos que no correspondan.

   Este archivo se apoya en admin-app.js (adminFetch, API_BASE, showToast,
   escapeHtml) y se abre desde admin-shell.js con window.owsNotesPageOpen().
   ========================================================================== */
(function () {
  'use strict';

  const PAGE_ID = 'ows-page-notas';
  const MODAL_ID = 'notes-modal-root';
  const SEARCH_DEBOUNCE = 320;

  const TYPES = {
    note: { label: 'Nota', icon: '📝' },
    task: { label: 'Tarea', icon: '✅' },
    idea: { label: 'Idea', icon: '💡' },
    reference: { label: 'Referencia', icon: '🔗' }
  };

  const STATUSES = {
    open: { label: 'Pendiente', icon: '○' },
    doing: { label: 'En curso', icon: '◐' },
    done: { label: 'Lista', icon: '●' }
  };

  const PRIORITIES = {
    low: { label: 'Baja' },
    normal: { label: 'Normal' },
    high: { label: 'Alta' },
    urgent: { label: 'Urgente' }
  };

  const STORY_STRUCTURES = {
    seasons: { label: 'Temporadas + episodios', short: 'Temporadas' },
    chapters: { label: 'Solo capítulos', short: 'Capítulos' }
  };

  const VIEWS = [
    { id: 'all', label: 'Todas', icon: '🗂️', stat: 'active' },
    { id: 'pinned', label: 'Fijadas', icon: '📌', stat: 'pinned' },
    { id: 'tasks', label: 'Tareas', icon: '✅', stat: 'tasks' },
    { id: 'ideas', label: 'Ideas', icon: '💡', stat: 'ideas' },
    { id: 'overdue', label: 'Vencidas', icon: '⏰', stat: 'overdue' },
    { id: 'private', label: 'Privadas', icon: '🔒', stat: 'private' },
    { id: 'done', label: 'Completadas', icon: '✔️', stat: 'done' }
  ];

  const MONTHS_SHORT = ['ene', 'feb', 'mar', 'abr', 'may', 'jun', 'jul', 'ago', 'sep', 'oct', 'nov', 'dic'];

  const state = {
    opened: false,
    booted: false,
    loading: false,
    metaLoading: false,
    loadError: '',
    metaError: '',
    meta: null,
    notes: [],
    total: 0,
    offset: 0,
    limit: 100,
    hasMore: false,
    filters: {
      view: 'all',
      q: '',
      category_id: '',
      list_id: '',
      project_slug: '',
      tag: '',
      author: '',
      status: '',
      type: '',
      priority: '',
      sort: 'updated',
      archived: '0'
    },
    selection: new Set(),
    editor: null,
    manager: null,
    searchTimer: null,
    searchValue: ''
  };

  /* ── Helpers generales ──────────────────────────────────────────────── */

  function pageEl() {
    return document.getElementById(PAGE_ID);
  }

  function esc(value) {
    if (typeof escapeHtml === 'function') return escapeHtml(value);
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function toast(message) {
    if (typeof showToast === 'function') showToast(message);
  }

  function apiBase() {
    const base = typeof API_BASE !== 'undefined' && API_BASE
      ? String(API_BASE)
      : 'https://owsdatabase.onrender.com';
    const clean = base.replace(/\/+$/, '');
    return /\/ows-admin$/i.test(clean) ? clean : clean + '/ows-admin';
  }

  async function api(path, options) {
    if (typeof adminFetch !== 'function') {
      throw new Error('El panel todavía no terminó de cargar.');
    }
    const res = await adminFetch(apiBase() + path, options || {});
    let data = null;
    try {
      const text = await res.text();
      if (text) data = JSON.parse(text);
    } catch (_) {}
    if (!res.ok) {
      const err = new Error((data && (data.error || data.message)) || ('Error ' + res.status));
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data || {};
  }

  function jsonOptions(method, payload) {
    return {
      method: method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload || {})
    };
  }

  function noteTypeMeta(type) {
    return TYPES[type] || TYPES.note;
  }

  function statusMeta(status) {
    return STATUSES[status] || STATUSES.open;
  }

  function priorityMeta(priority) {
    return PRIORITIES[priority] || PRIORITIES.normal;
  }

  function projectBySlug(slug) {
    const wanted = String(slug || '').toLowerCase();
    if (!wanted) return null;
    const projects = (state.meta && state.meta.projects) || [];
    return projects.find((project) => String(project.slug || '').toLowerCase() === wanted) || null;
  }

  function categoryById(id) {
    const wanted = Number(id);
    const categories = (state.meta && state.meta.categories) || [];
    return categories.find((category) => Number(category.id) === wanted) || null;
  }

  function listById(id) {
    const wanted = Number(id);
    const lists = (state.meta && state.meta.lists) || [];
    return lists.find((list) => Number(list.id) === wanted) || null;
  }

  function multiLineText(value) {
    return esc(value).replace(/\n/g, '<br>');
  }

  function noteExcerpt(body) {
    const clean = String(body || '').trim();
    if (!clean) return '';
    return clean.length > 320 ? clean.slice(0, 320).trimEnd() + '…' : clean;
  }

  function splitTags(value) {
    let source = [];
    if (Array.isArray(value)) source = value;
    else source = String(value || '').split(',');
    const out = [];
    const seen = new Set();
    source.forEach((raw) => {
      const tag = String(raw == null ? '' : raw).replace(/^#+/, '').trim().slice(0, 40);
      if (!tag) return;
      const key = tag.toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      out.push(tag);
    });
    return out.slice(0, 24);
  }

  function parseDateParts(value) {
    const match = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(value || ''));
    if (!match) return null;
    return { y: Number(match[1]), m: Number(match[2]), d: Number(match[3]) };
  }

  function fmtDate(value) {
    const parts = parseDateParts(value);
    if (!parts) return '';
    return parts.d + ' ' + MONTHS_SHORT[Math.max(0, Math.min(11, parts.m - 1))] + ' ' + parts.y;
  }

  function fmtDateTime(value) {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '';
    const day = String(date.getDate()).padStart(2, '0');
    const month = MONTHS_SHORT[date.getMonth()] || '';
    const hh = String(date.getHours()).padStart(2, '0');
    const mm = String(date.getMinutes()).padStart(2, '0');
    return day + ' ' + month + ' ' + date.getFullYear() + ' · ' + hh + ':' + mm;
  }

  function todayIso() {
    const now = new Date();
    return now.getFullYear() + '-' +
      String(now.getMonth() + 1).padStart(2, '0') + '-' +
      String(now.getDate()).padStart(2, '0');
  }

  function relativeTime(value) {
    if (!value) return '';
    const time = new Date(value).getTime();
    if (Number.isNaN(time)) return '';
    const diff = Date.now() - time;
    if (diff < 45 * 1000) return 'recién';
    if (diff < 60 * 60 * 1000) return 'hace ' + Math.max(1, Math.floor(diff / 60000)) + ' min';
    if (diff < 24 * 60 * 60 * 1000) return 'hace ' + Math.floor(diff / 3600000) + ' h';
    if (diff < 7 * 24 * 60 * 60 * 1000) return 'hace ' + Math.floor(diff / 86400000) + ' d';
    return fmtDate(String(value).slice(0, 10));
  }

  function dueInfo(note) {
    if (!note || !note.due_date) return null;
    if (note.status === 'done') {
      return { label: fmtDate(note.due_date), cls: 'is-done', title: 'Fecha objetivo' };
    }
    const today = todayIso();
    if (note.due_date < today) {
      return { label: 'Venció ' + fmtDate(note.due_date), cls: 'is-overdue', title: 'Vencida' };
    }
    if (note.due_date === today) {
      return { label: 'Vence hoy', cls: 'is-today', title: 'Para hoy' };
    }
    return { label: 'Vence ' + fmtDate(note.due_date), cls: '', title: 'Fecha objetivo' };
  }

  function noteStoryLabel(note) {
    if (!note) return '';
    if (note.story_mode === 'seasons') {
      const season = note.season_number ? 'T' + note.season_number : '';
      const episode = note.episode_number ? 'E' + note.episode_number : '';
      if (season && episode) return season + ' · ' + episode;
      if (season) return season;
      if (episode) return episode;
      return 'Temporadas';
    }
    if (note.story_mode === 'chapters') {
      if (note.chapter_number) return 'Cap. ' + note.chapter_number;
      return 'Capítulos';
    }
    return '';
  }

  function optionsHtml(items, selected) {
    return items.map((item) => {
      const value = String(item.value);
      const active = value === String(selected == null ? '' : selected);
      return '<option value="' + esc(value) + '"' + (active ? ' selected' : '') + '>' +
        esc(item.label) + '</option>';
    }).join('');
  }

  function statValue(key, fallback) {
    const stats = state.meta && state.meta.stats;
    if (!stats) return fallback == null ? 0 : fallback;
    return Number(stats[key]) || 0;
  }

  function selectionIds() {
    return Array.from(state.selection);
  }

  function updateLocalNote(note) {
    if (!note || !note.id) return;
    const index = state.notes.findIndex((item) => Number(item.id) === Number(note.id));
    if (index >= 0) state.notes[index] = note;
  }

  function clearFilters() {
    state.filters = {
      view: 'all',
      q: '',
      category_id: '',
      list_id: '',
      project_slug: '',
      tag: '',
      author: '',
      status: '',
      type: '',
      priority: '',
      sort: 'updated',
      archived: '0'
    };
    state.searchValue = '';
    const input = document.getElementById('notes-search');
    if (input) input.value = '';
    const archived = document.getElementById('notes-archived');
    if (archived) archived.checked = false;
    const sort = document.getElementById('notes-sort');
    if (sort) sort.value = 'updated';
  }

  function renderStats() {
    const host = document.getElementById('notes-stats');
    if (!host) return;
    const items = [
      { key: 'active', label: 'Activas', icon: '🗂️', filter: { view: 'all', status: '', type: '' } },
      { key: 'open', label: 'Pendientes', icon: '○', filter: { view: 'all', status: 'open', type: '' } },
      { key: 'doing', label: 'En curso', icon: '◐', filter: { view: 'all', status: 'doing', type: '' } },
      { key: 'done', label: 'Listas', icon: '●', filter: { view: 'done', status: '', type: '' } },
      { key: 'overdue', label: 'Vencidas', icon: '⏰', filter: { view: 'overdue', status: '', type: '' } },
      { key: 'pinned', label: 'Fijadas', icon: '📌', filter: { view: 'pinned', status: '', type: '' } },
      { key: 'private', label: 'Privadas', icon: '🔒', filter: { view: 'private', status: '', type: '' } }
    ];
    const f = state.filters;
    host.innerHTML = items.map((item) => {
      const active = f.view === item.filter.view && f.status === item.filter.status &&
        (!item.filter.type || f.type === item.filter.type) &&
        (item.key !== 'active' || (f.archived === '0' && !f.category_id && !f.list_id &&
          !f.project_slug && !f.tag && !f.author && !f.q));
      return '<button type="button" class="notes-stat' + (active ? ' is-active' : '') + '" data-notes-stat="' + item.key + '" title="' + esc(item.label) + '">' +
        '<span class="notes-stat-icon" aria-hidden="true">' + item.icon + '</span>' +
        '<strong>' + statValue(item.key) + '</strong>' +
        '<small>' + esc(item.label) + '</small>' +
        '</button>';
    }).join('');
  }

  function setActor(value) {
    const actor = document.getElementById('notes-actor');
    if (!actor) return;
    const name = String(value || (typeof getCurrentAdminName === 'function' ? getCurrentAdminName() : '') || 'Admin');
    actor.textContent = 'Sesión: ' + name;
    actor.title = 'Autor de las notas nuevas';
  }

  /* ── Estructura visual de la página ────────────────────────────────── */

  function renderShell() {
    const page = pageEl();
    if (!page) return false;
    if (page.dataset.notesReady === '1') return true;

    page.dataset.notesReady = '1';
    page.innerHTML =
      '<section class="ows-page-head ows-page-head--plain notes-head">' +
        '<div class="ows-page-head-copy">' +
          '<span class="ows-eyebrow">Estudio</span>' +
          '<h2 class="ows-page-title">Notas y anotaciones</h2>' +
          '<p class="ows-page-sub">Tareas, ideas, referencias y apuntes internos. Cada nota guarda quién la creó, para qué proyecto es y en qué punto de la historia va.</p>' +
        '</div>' +
        '<div class="ows-page-head-meta">' +
          '<span class="ows-badge is-muted" id="notes-actor">Sesión: Admin</span>' +
          '<button type="button" class="ows-btn ows-btn-ghost" data-notes-action="refresh">↻ Actualizar</button>' +
          '<button type="button" class="ows-btn ows-btn-ghost" data-notes-action="manage-projects">🎬 Estructura narrativa</button>' +
          '<button type="button" class="ows-btn" data-notes-action="new">＋ Nueva nota</button>' +
        '</div>' +
      '</section>' +
      '<div class="notes-stats" id="notes-stats" aria-label="Resumen de notas"></div>' +
      '<div class="glass-card notes-toolbar">' +
        '<label class="notes-search" for="notes-search">' +
          '<span aria-hidden="true">🔍</span>' +
          '<input type="text" id="notes-search" placeholder="Buscar por título, texto, etiqueta o capítulo…" autocomplete="off" />' +
        '</label>' +
        '<select id="notes-type" class="notes-select" aria-label="Filtrar por tipo">' +
          '<option value="">Todos los tipos</option>' +
          '<option value="note">📝 Notas</option>' +
          '<option value="task">✅ Tareas</option>' +
          '<option value="idea">💡 Ideas</option>' +
          '<option value="reference">🔗 Referencias</option>' +
        '</select>' +
        '<select id="notes-status" class="notes-select" aria-label="Filtrar por estado">' +
          '<option value="">Todos los estados</option>' +
          '<option value="open">Pendientes</option>' +
          '<option value="doing">En curso</option>' +
          '<option value="done">Listas</option>' +
        '</select>' +
        '<select id="notes-priority" class="notes-select" aria-label="Filtrar por prioridad">' +
          '<option value="">Toda prioridad</option>' +
          '<option value="urgent">Urgente</option>' +
          '<option value="high">Alta</option>' +
          '<option value="normal">Normal</option>' +
          '<option value="low">Baja</option>' +
        '</select>' +
        '<select id="notes-sort" class="notes-select" aria-label="Ordenar notas">' +
          '<option value="updated">Última edición</option>' +
          '<option value="created">Más recientes</option>' +
          '<option value="due">Vencimiento</option>' +
          '<option value="priority">Prioridad</option>' +
          '<option value="title">Título (A-Z)</option>' +
        '</select>' +
        '<label class="notes-archive-toggle" title="Ver solamente las notas archivadas">' +
          '<input type="checkbox" id="notes-archived" /> <span>Archivo</span>' +
        '</label>' +
        '<button type="button" class="notes-clear" data-notes-action="clear-filters" title="Quitar todos los filtros">Limpiar</button>' +
      '</div>' +
      '<div class="notes-layout">' +
        '<aside class="glass-card notes-rail" id="notes-rail" aria-label="Filtros y colecciones"></aside>' +
        '<section class="notes-main">' +
          '<div class="notes-bar">' +
            '<div class="notes-bar-left">' +
              '<p class="notes-count" id="notes-count">Cargando notas…</p>' +
              '<button type="button" class="notes-select-visible" data-notes-action="select-visible" title="Seleccionar las notas visibles para acciones masivas">Seleccionar visibles</button>' +
            '</div>' +
            '<div class="notes-bulk hidden" id="notes-bulk"></div>' +
          '</div>' +
          '<div class="notes-active" id="notes-active-filters"></div>' +
          '<div class="notes-grid" id="notes-grid" aria-live="polite"></div>' +
          '<div class="notes-more">' +
            '<button type="button" class="ows-btn ows-btn-ghost hidden" id="notes-load-more" data-notes-action="load-more">Cargar más notas</button>' +
          '</div>' +
        '</section>' +
      '</div>';

    let modal = document.getElementById(MODAL_ID);
    if (!modal) {
      modal = document.createElement('div');
      modal.id = MODAL_ID;
      modal.className = 'notes-modal-root';
      document.body.appendChild(modal);
    }

    page.addEventListener('click', onPageClick);
    page.addEventListener('input', onPageInput);
    page.addEventListener('change', onPageChange);
    page.addEventListener('keydown', onPageKeydown);

    if (document.body.dataset.notesModalBound !== '1') {
      document.body.dataset.notesModalBound = '1';
      modal.addEventListener('click', onModalClick);
      modal.addEventListener('input', onModalInput);
      modal.addEventListener('change', onModalChange);
      modal.addEventListener('submit', onModalSubmit);
      document.addEventListener('keydown', onGlobalKeydown);
    }

    syncToolbar();
    renderStats();
    renderRail();
    renderBulk();
    return true;
  }

  function open() {
    if (!renderShell()) return;
    state.opened = true;
    if (!state.booted) {
      state.booted = true;
      boot();
      return;
    }
    syncToolbar();
    renderStats();
    renderRail();
    renderBulk();
    if (!state.notes.length && !state.loading) loadNotes({ reset: true });
  }

  async function boot() {
    const input = document.getElementById('notes-search');
    if (input) input.value = state.searchValue;
    await Promise.allSettled([loadMeta(), loadNotes({ reset: true })]);
  }

  async function refresh(options) {
    const silent = !!(options && options.silent);
    await Promise.allSettled([loadMeta(), loadNotes({ reset: true })]);
    if (!silent) toast('Notas actualizadas');
  }

  async function loadMeta() {
    state.metaLoading = true;
    try {
      const data = await api('/notes/meta');
      state.meta = {
        categories: Array.isArray(data.categories) ? data.categories : [],
        lists: Array.isArray(data.lists) ? data.lists : [],
        projects: Array.isArray(data.projects) ? data.projects : [],
        tags: Array.isArray(data.tags) ? data.tags : [],
        authors: Array.isArray(data.authors) ? data.authors : [],
        stats: data.stats && typeof data.stats === 'object' ? data.stats : {}
      };
      state.metaError = '';
      setActor(data.actor);
    } catch (err) {
      state.metaError = err && err.message ? err.message : 'No se pudieron cargar los filtros.';
      if (state.opened) toast('⚠️ ' + state.metaError);
    } finally {
      state.metaLoading = false;
      renderStats();
      renderRail();
      renderBulk();
    }
  }

  function notesQuery() {
    const f = state.filters;
    const params = new URLSearchParams();
    if (f.view && f.view !== 'all') params.set('view', f.view);
    if (f.q) params.set('q', f.q);
    if (f.category_id) params.set('category_id', String(f.category_id));
    if (f.list_id) params.set('list_id', String(f.list_id));
    if (f.project_slug) params.set('project_slug', f.project_slug);
    if (f.tag) params.set('tag', f.tag);
    if (f.author) params.set('author', f.author);
    if (f.status) params.set('status', f.status);
    if (f.type) params.set('type', f.type);
    if (f.priority) params.set('priority', f.priority);
    params.set('sort', f.sort || 'updated');
    params.set('archived', f.archived || '0');
    params.set('limit', String(state.limit));
    params.set('offset', String(state.offset));
    return params.toString();
  }

  async function loadNotes(options) {
    const reset = !options || options.reset !== false;
    if (reset) {
      state.offset = 0;
      state.selection.clear();
    }
    const token = (state.loadToken || 0) + 1;
    state.loadToken = token;
    state.loading = true;
    state.loadError = '';
    if (reset) renderBoardLoading();
    else syncBoardBusy(true);

    try {
      const data = await api('/notes?' + notesQuery());
      if (token !== state.loadToken) return;
      const incoming = Array.isArray(data.notes) ? data.notes : [];
      if (reset) {
        state.notes = incoming;
      } else {
        const seen = new Set(state.notes.map((note) => Number(note.id)));
        incoming.forEach((note) => {
          if (!seen.has(Number(note.id))) state.notes.push(note);
        });
      }
      state.total = Number(data.total) || 0;
      state.hasMore = data.has_more === true;
      state.offset = reset
        ? incoming.length
        : state.offset + incoming.length;
      renderBoard();
      renderCount();
      renderActiveFilters();
      renderBulk();
    } catch (err) {
      if (token !== state.loadToken) return;
      state.loadError = err && err.message ? err.message : 'No se pudieron cargar las notas.';
      renderBoardError(state.loadError);
      renderCount();
    } finally {
      if (token === state.loadToken) {
        state.loading = false;
        syncLoadMore();
        syncBoardBusy(false);
        renderCount();
      }
    }
  }

  function syncToolbar() {
    const f = state.filters;
    const type = document.getElementById('notes-type');
    const status = document.getElementById('notes-status');
    const priority = document.getElementById('notes-priority');
    const sort = document.getElementById('notes-sort');
    const archived = document.getElementById('notes-archived');
    const search = document.getElementById('notes-search');
    if (type) type.value = f.type || '';
    if (status) status.value = f.status || '';
    if (priority) priority.value = f.priority || '';
    if (sort) sort.value = f.sort || 'updated';
    if (archived) archived.checked = f.archived === '1' || f.archived === 'all';
    if (search && document.activeElement !== search) search.value = state.searchValue || '';
  }

  function syncLoadMore() {
    const button = document.getElementById('notes-load-more');
    if (!button) return;
    const show = state.hasMore && !state.loading;
    button.classList.toggle('hidden', !show);
    button.disabled = !!state.loading;
  }

  function syncBoardBusy(busy) {
    const grid = document.getElementById('notes-grid');
    if (grid) grid.classList.toggle('is-busy', !!busy);
  }

  function renderCount() {
    const host = document.getElementById('notes-count');
    if (!host) return;
    if (state.loading && !state.notes.length) {
      host.textContent = 'Cargando notas…';
      return;
    }
    if (state.loadError && !state.notes.length) {
      host.textContent = 'No se pudieron cargar las notas.';
      return;
    }
    const shown = state.notes.length;
    const total = state.total;
    let text = shown === total
      ? total + (total === 1 ? ' nota' : ' notas')
      : shown + ' de ' + total + ' notas';
    if (state.filters.archived === '1' || state.filters.archived === 'all') text += ' · archivo';
    host.textContent = text;
  }

  /* ── Barra lateral de colecciones ──────────────────────────────────── */

  function railSection(label, body, actionHtml) {
    return '<section class="notes-rail-section">' +
      '<div class="notes-rail-head">' +
        '<span class="notes-rail-label">' + esc(label) + '</span>' +
        (actionHtml || '') +
      '</div>' +
      body +
    '</section>';
  }

  function railItem(kind, value, label, count, options) {
    const opts = options || {};
    const marker = opts.color
      ? '<span class="notes-rail-dot" style="--notes-accent:' + esc(opts.color) + '"></span>'
      : '<span class="notes-rail-icon" aria-hidden="true">' + (opts.icon || '•') + '</span>';
    return '<button type="button" class="notes-rail-item' + (opts.active ? ' is-active' : '') + '"' +
      ' data-notes-rail="' + esc(kind) + '" data-value="' + esc(value) + '"' +
      (opts.title ? ' title="' + esc(opts.title) + '"' : '') + '>' +
      marker +
      '<span class="notes-rail-text">' + esc(label) + '</span>' +
      (opts.badge ? '<span class="notes-rail-badge">' + esc(opts.badge) + '</span>' : '') +
      (count == null ? '' : '<span class="notes-rail-count">' + (Number(count) || 0) + '</span>') +
    '</button>';
  }

  function railEmpty(text) {
    return '<p class="notes-rail-empty">' + esc(text) + '</p>';
  }

  function renderRail() {
    const host = document.getElementById('notes-rail');
    if (!host) return;

    if (!state.meta && (state.metaLoading || !state.booted)) {
      host.innerHTML = '<div class="notes-rail-loading">' +
        '<span></span><span></span><span></span><span></span><span></span><span></span>' +
        '</div>';
      return;
    }

    if (!state.meta) {
      host.innerHTML = '<div class="notes-rail-fail">' +
        '<p>No se pudieron cargar las colecciones.</p>' +
        (state.metaError ? '<small>' + esc(state.metaError) + '</small>' : '') +
        '<button type="button" class="ows-btn ows-btn-ghost" data-notes-action="retry-meta">Reintentar</button>' +
        '</div>';
      return;
    }

    const f = state.filters;
    const meta = state.meta;
    const viewBody = VIEWS.map((view) => railItem('view', view.id, view.label, statValue(view.stat), {
      active: f.view === view.id && !f.status && !f.type &&
        (view.id !== 'all' || (!f.category_id && !f.list_id && !f.project_slug && !f.tag && !f.author && !f.q)),
      icon: view.icon
    })).join('');

    let categoryBody = (meta.categories || []).map((category) => railItem(
      'category',
      category.id,
      category.icon ? category.icon + ' ' + category.name : category.name,
      category.count,
      {
        active: String(f.category_id) === String(category.id),
        color: category.color,
        title: 'Categoría · ' + category.name
      }
    )).join('');

    if (statValue('uncategorized') > 0) {
      categoryBody += railItem('category', 'none', 'Sin categoría', statValue('uncategorized'), {
        active: f.category_id === 'none',
        color: '#6b7280'
      });
    }
    if (!categoryBody) categoryBody = railEmpty('Todavía no hay categorías.');

    let listBody = (meta.lists || []).map((list) => railItem(
      'list',
      list.id,
      list.name,
      list.count,
      {
        active: String(f.list_id) === String(list.id),
        color: list.color,
        title: list.description || 'Lista · ' + list.name
      }
    )).join('');

    if (statValue('unlisted') > 0) {
      listBody += railItem('list', 'none', 'Sin lista', statValue('unlisted'), {
        active: f.list_id === 'none',
        color: '#6b7280'
      });
    }
    if (!listBody) listBody = railEmpty('Todavía no hay listas.');

    const projects = (meta.projects || []).slice().sort((a, b) =>
      String(a.name || a.slug).localeCompare(String(b.name || b.slug), 'es'));
    let projectBody = projects.map((project) => railItem(
      'project',
      project.slug,
      project.name || project.slug,
      project.note_count,
      {
        active: f.project_slug === project.slug,
        icon: project.is_story ? '🎬' : '📁',
        badge: project.is_story
          ? (project.story_structure === 'chapters' ? 'Cap.' : 'Temp.')
          : '',
        title: project.is_story
          ? 'Proyecto narrativo · ' + (project.story_structure === 'chapters' ? 'Solo capítulos' : 'Temporadas + episodios')
          : 'Proyecto'
      }
    )).join('');
    if (!projectBody) projectBody = railEmpty('Todavía no hay proyectos con notas.');
    else projectBody = '<div class="notes-rail-scroll">' + projectBody + '</div>';

    const tags = (meta.tags || []).slice(0, 36);
    const tagBody = tags.length
      ? '<div class="notes-tag-cloud">' + tags.map((entry) =>
          '<button type="button" class="notes-mini-tag' + (f.tag === entry.tag ? ' is-active' : '') + '"' +
            ' data-notes-rail="tag" data-value="' + esc(entry.tag) + '" title="' + esc(entry.tag) + '">' +
            '#' + esc(entry.tag) + ' <span>' + (Number(entry.count) || 0) + '</span>' +
          '</button>'
        ).join('') + '</div>'
      : railEmpty('Las etiquetas aparecen cuando agregás notas.');

    const authorBody = (meta.authors || []).map((author) => railItem(
      'author',
      author.name,
      author.name,
      author.count,
      {
        active: String(f.author).toLowerCase() === String(author.name).toLowerCase(),
        icon: '👤',
        title: 'Notas creadas por ' + author.name
      }
    )).join('') || railEmpty('Sin autores todavía.');

    const manageActions =
      '<div class="notes-rail-actions">' +
        '<button type="button" data-notes-action="manage-taxonomy">⚙️ Categorías y listas</button>' +
        '<button type="button" data-notes-action="manage-projects">🎬 Estructura narrativa</button>' +
      '</div>';

    host.innerHTML =
      railSection('Vistas', viewBody) +
      railSection('Categorías', categoryBody,
        '<button type="button" class="notes-rail-manage" data-notes-action="manage-taxonomy" title="Gestionar categorías">＋</button>') +
      railSection('Listas', listBody,
        '<button type="button" class="notes-rail-manage" data-notes-action="manage-taxonomy" title="Gestionar listas">＋</button>') +
      railSection('Proyectos', projectBody,
        '<button type="button" class="notes-rail-manage" data-notes-action="manage-projects" title="Configurar estructura narrativa">⚙</button>') +
      railSection('Etiquetas', tagBody) +
      railSection('Autores', authorBody) +
      manageActions;
  }

  /* ── Filtros activos ────────────────────────────────────────────────── */

  function renderActiveFilters() {
    const host = document.getElementById('notes-active-filters');
    if (!host) return;
    const f = state.filters;
    const chips = [];
    const viewLabels = {
      pinned: 'Fijadas',
      tasks: 'Tareas',
      ideas: 'Ideas',
      overdue: 'Vencidas',
      private: 'Privadas',
      done: 'Completadas'
    };

    if (f.view !== 'all') chips.push({ key: 'view', label: 'Vista: ' + (viewLabels[f.view] || f.view) });
    if (f.q) chips.push({ key: 'q', label: 'Búsqueda: “' + f.q + '”' });
    if (f.category_id) {
      const category = f.category_id === 'none' ? null : categoryById(f.category_id);
      chips.push({ key: 'category_id', label: 'Categoría: ' + (category ? category.name : 'Sin categoría') });
    }
    if (f.list_id) {
      const list = f.list_id === 'none' ? null : listById(f.list_id);
      chips.push({ key: 'list_id', label: 'Lista: ' + (list ? list.name : 'Sin lista') });
    }
    if (f.project_slug) {
      const project = projectBySlug(f.project_slug);
      chips.push({ key: 'project_slug', label: 'Proyecto: ' + (project ? project.name : f.project_slug) });
    }
    if (f.tag) chips.push({ key: 'tag', label: 'Etiqueta: #' + f.tag });
    if (f.author) chips.push({ key: 'author', label: 'Autor: ' + f.author });
    if (f.status) chips.push({ key: 'status', label: 'Estado: ' + statusMeta(f.status).label });
    if (f.type) chips.push({ key: 'type', label: 'Tipo: ' + noteTypeMeta(f.type).label });
    if (f.priority) chips.push({ key: 'priority', label: 'Prioridad: ' + priorityMeta(f.priority).label });
    if (f.archived !== '0') chips.push({ key: 'archived', label: f.archived === 'all' ? 'Archivo + activas' : 'Solo archivo' });
    if (f.sort !== 'updated') {
      const sortLabels = { created: 'Más recientes', due: 'Vencimiento', priority: 'Prioridad', title: 'Título A-Z' };
      chips.push({ key: 'sort', label: 'Orden: ' + (sortLabels[f.sort] || f.sort) });
    }

    if (!chips.length) {
      host.innerHTML = '';
      return;
    }

    host.innerHTML = chips.map((chip) =>
      '<button type="button" class="notes-filter-chip" data-notes-remove-filter="' + esc(chip.key) + '" title="Quitar filtro">' +
        esc(chip.label) + ' <span aria-hidden="true">✕</span>' +
      '</button>'
    ).join('') +
    '<button type="button" class="notes-filter-clear" data-notes-action="clear-filters">Limpiar todo</button>';
  }

  /* ── Tablero de notas ───────────────────────────────────────────────── */

  function noteCardHtml(note) {
    const type = noteTypeMeta(note.type);
    const status = statusMeta(note.status);
    const priority = priorityMeta(note.priority);
    const due = dueInfo(note);
    const story = noteStoryLabel(note);
    const checklist = Array.isArray(note.checklist) ? note.checklist : [];
    const links = Array.isArray(note.links) ? note.links : [];
    const tags = Array.isArray(note.tags) ? note.tags : [];
    const doneChecks = checklist.filter((item) => item.done === true).length;
    const nextCheck = checklist.find((item) => item.done !== true);
    const selected = state.selection.has(Number(note.id));
    const classes = ['notes-card'];
    if (note.is_pinned) classes.push('is-pinned');
    if (note.is_private) classes.push('is-private');
    if (note.is_archived) classes.push('is-archived');
    if (note.status === 'done') classes.push('is-done');
    if (due && due.cls === 'is-overdue') classes.push('is-overdue');
    if (selected) classes.push('is-selected');

    let chips = '<span class="notes-chip is-status is-' + esc(note.status) + '">' +
      status.icon + ' ' + esc(status.label) + '</span>';

    if (note.priority === 'high' || note.priority === 'urgent') {
      chips += '<span class="notes-chip is-priority is-' + esc(note.priority) + '">⚡ ' + esc(priority.label) + '</span>';
    }
    if (note.category) {
      chips += '<span class="notes-chip is-category" style="--notes-accent:' + esc(note.category.color) + '">' +
        '<i aria-hidden="true"></i>' + esc(note.category.name) + '</span>';
    }
    if (note.list) {
      chips += '<span class="notes-chip is-list" style="--notes-accent:' + esc(note.list.color) + '">' +
        '🗃️ ' + esc(note.list.name) + '</span>';
    }
    if (note.project_name) {
      chips += '<span class="notes-chip is-project">🎬 ' + esc(note.project_name) +
        (story ? ' <b>' + esc(story) + '</b>' : '') + '</span>';
    }
    if (due) {
      chips += '<span class="notes-chip is-due ' + due.cls + '" title="' + esc(due.title) + '">📅 ' + esc(due.label) + '</span>';
    }
    if (note.is_private) {
      chips += '<span class="notes-chip is-private" title="Solo vos y el Owner pueden verla">🔒 Privada</span>';
    }
    if (links.length) {
      chips += '<span class="notes-chip is-links" title="' + links.length + ' enlace(s)">🔗 ' + links.length + '</span>';
    }

    const tagHtml = tags.length
      ? '<div class="notes-card-tags">' + tags.slice(0, 5).map((tag) =>
          '<span class="notes-mini-tag">#' + esc(tag) + '</span>'
        ).join('') + (tags.length > 5 ? '<span class="notes-mini-tag is-more">+' + (tags.length - 5) + '</span>' : '') + '</div>'
      : '';

    const checklistHtml = checklist.length
      ? '<div class="notes-checklist">' +
          '<div class="notes-checklist-head">' +
            '<span>☑️ ' + doneChecks + '/' + checklist.length + '</span>' +
            '<em>' + (nextCheck ? esc(nextCheck.text) : 'Todos los pasos listos') + '</em>' +
          '</div>' +
          '<div class="notes-progress"><i style="width:' + Math.round((doneChecks / checklist.length) * 100) + '%"></i></div>' +
        '</div>'
      : '';

    const body = noteExcerpt(note.body);

    return '<article class="' + classes.join(' ') + '" data-notes-open="' + Number(note.id) + '" tabindex="0" role="button"' +
        ' aria-label="Abrir nota: ' + esc(note.title) + '">' +
      '<div class="notes-card-top">' +
        '<label class="notes-pick" title="Seleccionar para acciones masivas">' +
          '<input type="checkbox" data-notes-select="' + Number(note.id) + '"' + (selected ? ' checked' : '') +
            ' aria-label="Seleccionar ' + esc(note.title) + '" />' +
        '</label>' +
        '<span class="notes-type-tag">' + type.icon + ' ' + esc(type.label) + '</span>' +
        '<span class="notes-card-flags">' +
          (note.is_pinned ? '<span title="Fijada">📌</span>' : '') +
          (note.is_archived ? '<span title="Archivada">📦</span>' : '') +
        '</span>' +
      '</div>' +
      '<h3 class="notes-card-title">' + esc(note.title) + '</h3>' +
      (body ? '<p class="notes-card-body">' + multiLineText(body) + '</p>' : '') +
      '<div class="notes-card-chips">' + chips + '</div>' +
      tagHtml +
      checklistHtml +
      '<footer class="notes-card-foot">' +
        '<span class="notes-card-author" title="Creada por ' + esc(note.created_by) + '">👤 ' + esc(note.created_by) + '</span>' +
        '<span class="notes-card-updated" title="Última edición: ' + esc(fmtDateTime(note.updated_at)) + '">' +
          (note.status === 'done' && note.completed_at ? 'Lista ' + esc(relativeTime(note.completed_at)) : esc(relativeTime(note.updated_at))) +
        '</span>' +
        '<div class="notes-card-actions">' +
          '<button type="button" class="notes-icon-btn' + (note.is_pinned ? ' is-on' : '') + '" data-notes-action="pin" data-id="' + Number(note.id) + '"' +
            ' title="' + (note.is_pinned ? 'Quitar de fijadas' : 'Fijar arriba') + '" aria-label="' + (note.is_pinned ? 'Quitar de fijadas' : 'Fijar') + '">📌</button>' +
          '<button type="button" class="notes-icon-btn" data-notes-action="archive" data-id="' + Number(note.id) + '" data-archived="' + (note.is_archived ? '1' : '0') + '"' +
            ' title="' + (note.is_archived ? 'Desarchivar' : 'Archivar') + '" aria-label="' + (note.is_archived ? 'Desarchivar' : 'Archivar') + '">' + (note.is_archived ? '↩️' : '📦') + '</button>' +
          '<button type="button" class="notes-icon-btn" data-notes-action="edit" data-id="' + Number(note.id) + '" title="Editar nota" aria-label="Editar nota">✏️</button>' +
          '<button type="button" class="notes-icon-btn is-danger" data-notes-action="delete" data-id="' + Number(note.id) + '" title="Eliminar nota" aria-label="Eliminar nota">🗑️</button>' +
        '</div>' +
      '</footer>' +
    '</article>';
  }

  function renderBoardLoading() {
    const host = document.getElementById('notes-grid');
    if (!host) return;
    if (state.notes.length) {
      syncBoardBusy(true);
      return;
    }
    host.innerHTML = '<div class="notes-skeleton"></div><div class="notes-skeleton"></div>' +
      '<div class="notes-skeleton"></div><div class="notes-skeleton"></div>';
    renderCount();
  }

  function renderBoardError(message) {
    const host = document.getElementById('notes-grid');
    if (!host) return;
    host.innerHTML = '<div class="notes-empty is-error">' +
      '<div class="notes-empty-icon" aria-hidden="true">⚠️</div>' +
      '<h3>No se pudieron cargar las notas</h3>' +
      '<p>' + esc(message || 'Revisá la conexión con la API e intentá de nuevo.') + '</p>' +
      '<div class="notes-empty-actions">' +
        '<button type="button" class="ows-btn ows-btn-ghost" data-notes-action="retry">Reintentar</button>' +
      '</div>' +
    '</div>';
  }

  function renderBoard() {
    const host = document.getElementById('notes-grid');
    if (!host) return;
    if (!state.notes.length) {
      const f = state.filters;
      const narrowed = !!(f.q || f.category_id || f.list_id || f.project_slug || f.tag || f.author ||
        f.status || f.type || f.priority || f.view !== 'all');
      const archiveOnly = f.archived !== '0' && !narrowed;
      const hasFilters = narrowed || f.archived !== '0';
      host.innerHTML = '<div class="notes-empty">' +
        '<div class="notes-empty-icon" aria-hidden="true">' + (archiveOnly ? '📦' : '🗒️') + '</div>' +
        '<h3>' + (archiveOnly
          ? 'El archivo está vacío'
          : (hasFilters ? 'Ninguna nota coincide con los filtros' : 'Todavía no hay notas')) + '</h3>' +
        '<p>' + (archiveOnly
          ? 'Las notas que archives van a quedar guardadas acá, fuera del tablero activo.'
          : (hasFilters
            ? 'Probá con otra búsqueda o quitá los filtros activos.'
            : 'Creá la primera nota para dejar tareas, ideas y referencias del estudio en un solo lugar.')) + '</p>' +
        '<div class="notes-empty-actions">' +
          (hasFilters ? '<button type="button" class="ows-btn ows-btn-ghost" data-notes-action="clear-filters">Limpiar filtros</button>' : '') +
          '<button type="button" class="ows-btn" data-notes-action="new">＋ ' + (hasFilters ? 'Nueva nota' : 'Crear la primera nota') + '</button>' +
        '</div>' +
      '</div>';
      renderCount();
      return;
    }
    host.innerHTML = state.notes.map(noteCardHtml).join('');
    renderCount();
  }

  /* ── Acciones masivas ───────────────────────────────────────────────── */

  function renderBulk() {
    const host = document.getElementById('notes-bulk');
    if (!host) return;
    const count = state.selection.size;
    host.classList.toggle('hidden', count === 0);
    if (!count) {
      host.innerHTML = '';
      return;
    }

    const prevStatus = (document.getElementById('notes-bulk-status') || {}).value || 'open';
    const prevCategory = (document.getElementById('notes-bulk-category') || {}).value || '';
    const prevList = (document.getElementById('notes-bulk-list') || {}).value || '';

    const categories = (state.meta && state.meta.categories) || [];
    const lists = (state.meta && state.meta.lists) || [];
    const categoryOptions = '<option value="">Sin categoría</option>' + categories.map((category) =>
      '<option value="' + Number(category.id) + '">' + esc(category.name) + '</option>'
    ).join('');
    const listOptions = '<option value="">Sin lista</option>' + lists.map((list) =>
      '<option value="' + Number(list.id) + '">' + esc(list.name) + '</option>'
    ).join('');

    host.innerHTML =
      '<div class="notes-bulk-head">' +
        '<b>' + count + (count === 1 ? ' nota seleccionada' : ' notas seleccionadas') + '</b>' +
        '<button type="button" data-notes-bulk="clear">✕ Limpiar</button>' +
      '</div>' +
      '<div class="notes-bulk-grid">' +
        '<div class="notes-bulk-row">' +
          '<select id="notes-bulk-status" aria-label="Nuevo estado">' +
            '<option value="open">Pendiente</option>' +
            '<option value="doing">En curso</option>' +
            '<option value="done">Lista</option>' +
          '</select>' +
          '<button type="button" data-notes-bulk="status">Estado</button>' +
        '</div>' +
        '<div class="notes-bulk-row">' +
          '<select id="notes-bulk-category" aria-label="Nueva categoría">' + categoryOptions + '</select>' +
          '<button type="button" data-notes-bulk="category">Categoría</button>' +
        '</div>' +
        '<div class="notes-bulk-row">' +
          '<select id="notes-bulk-list" aria-label="Nueva lista">' + listOptions + '</select>' +
          '<button type="button" data-notes-bulk="list">Lista</button>' +
        '</div>' +
        '<div class="notes-bulk-actions">' +
          '<button type="button" data-notes-bulk="pin">📌 Fijar</button>' +
          '<button type="button" data-notes-bulk="unpin">Quitar fijado</button>' +
          '<button type="button" data-notes-bulk="archive">📦 Archivar</button>' +
          '<button type="button" data-notes-bulk="unarchive">↩️ Desarchivar</button>' +
          '<button type="button" class="is-danger" data-notes-bulk="delete">🗑️ Eliminar</button>' +
        '</div>' +
      '</div>';

    const statusSelect = document.getElementById('notes-bulk-status');
    const categorySelect = document.getElementById('notes-bulk-category');
    const listSelect = document.getElementById('notes-bulk-list');
    if (statusSelect) statusSelect.value = prevStatus;
    if (categorySelect) categorySelect.value = prevCategory;
    if (listSelect) listSelect.value = prevList;
  }

  function syncSelectionUi() {
    const grid = document.getElementById('notes-grid');
    if (!grid) return;
    grid.querySelectorAll('[data-notes-select]').forEach((input) => {
      const id = Number(input.getAttribute('data-notes-select'));
      const selected = state.selection.has(id);
      input.checked = selected;
      const card = input.closest('.notes-card');
      if (card) card.classList.toggle('is-selected', selected);
    });
  }

  async function runBulk(action) {
    const ids = selectionIds();
    if (!ids.length) return;
    if (action === 'clear') {
      state.selection.clear();
      syncSelectionUi();
      renderBulk();
      return;
    }
    if (action === 'delete' && !confirm('¿Eliminar ' + ids.length + ' nota(s) permanentemente? Esta acción no se puede deshacer.')) {
      return;
    }

    const payload = { ids: ids, action: action };
    if (action === 'status') {
      const select = document.getElementById('notes-bulk-status');
      payload.status = select ? select.value : 'open';
    } else if (action === 'category') {
      const select = document.getElementById('notes-bulk-category');
      payload.category_id = select && select.value ? Number(select.value) : null;
    } else if (action === 'list') {
      const select = document.getElementById('notes-bulk-list');
      payload.list_id = select && select.value ? Number(select.value) : null;
    }

    try {
      const data = await api('/notes/bulk', jsonOptions('POST', payload));
      const updated = Number(data.updated) || 0;
      toast('✅ ' + (updated || ids.length) + ' nota(s) actualizadas');
      state.selection.clear();
      await refresh({ silent: true });
    } catch (err) {
      toast('⚠️ ' + err.message);
    }
  }

  async function quickPatch(note, patch, message) {
    try {
      await api('/notes/' + Number(note.id), jsonOptions('PATCH', patch));
      toast(message);
      await refresh({ silent: true });
    } catch (err) {
      toast('⚠️ ' + err.message);
    }
  }

  async function quickDelete(note) {
    if (!confirm('¿Eliminar la nota “' + String(note.title || '').slice(0, 80) + '” permanentemente?')) return;
    try {
      await api('/notes/' + Number(note.id), { method: 'DELETE' });
      toast('🗑️ Nota eliminada');
      state.selection.delete(Number(note.id));
      await refresh({ silent: true });
    } catch (err) {
      toast('⚠️ ' + err.message);
    }
  }

  /* ── Editor de notas ────────────────────────────────────────────────── */

  function newCheckId() {
    return 'c' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
  }

  function editorDraftFromNote(note) {
    const type = note ? (note.type || note.note_type || 'note') : '';
    return {
      id: note ? Number(note.id) : null,
      title: note ? String(note.title || '') : '',
      body: note ? String(note.body || '') : '',
      note_type: TYPES[type] ? type : 'note',
      status: note && STATUSES[note.status] ? note.status : 'open',
      priority: note && PRIORITIES[note.priority] ? note.priority : 'normal',
      category_id: note && note.category_id ? String(note.category_id) : '',
      list_id: note && note.list_id ? String(note.list_id) : '',
      project_slug: note ? String(note.project_slug || '') : '',
      project_name: note ? String(note.project_name || '') : '',
      story_mode: note ? String(note.story_mode || 'none') : 'none',
      season_number: note && note.season_number != null ? String(note.season_number) : '',
      episode_number: note && note.episode_number != null ? String(note.episode_number) : '',
      chapter_number: note && note.chapter_number != null ? String(note.chapter_number) : '',
      chapter_title: note ? String(note.chapter_title || '') : '',
      tags: note && Array.isArray(note.tags) ? note.tags.join(', ') : '',
      checklist: note && Array.isArray(note.checklist)
        ? note.checklist.map((item) => ({
            id: item.id || newCheckId(),
            text: String(item.text || ''),
            done: item.done === true
          }))
        : [],
      links: note && Array.isArray(note.links)
        ? note.links.map((item) => ({
            label: String(item.label || ''),
            url: String(item.url || '')
          }))
        : [],
      due_date: note && note.due_date ? String(note.due_date) : '',
      is_pinned: !!(note && note.is_pinned),
      is_archived: !!(note && note.is_archived),
      is_private: !!(note && note.is_private),
      created_by: note ? String(note.created_by || '') : '',
      updated_by: note ? String(note.updated_by || '') : '',
      created_at: note ? note.created_at || null : null,
      updated_at: note ? note.updated_at || null : null,
      completed_at: note ? note.completed_at || null : null
    };
  }

  function newEditorDraft() {
    const f = state.filters;
    const type = f.type || (f.view === 'tasks' ? 'task' : f.view === 'ideas' ? 'idea' : 'note');
    const project = f.project_slug ? projectBySlug(f.project_slug) : null;
    const draft = editorDraftFromNote(null);
    draft.note_type = TYPES[type] ? type : 'note';
    draft.category_id = f.category_id && f.category_id !== 'none' ? String(f.category_id) : '';
    draft.list_id = f.list_id && f.list_id !== 'none' ? String(f.list_id) : '';
    draft.project_slug = project ? project.slug : '';
    draft.project_name = project ? project.name : '';
    draft.story_mode = project && project.is_story
      ? (project.story_structure || 'none')
      : 'none';
    draft.tags = f.tag ? f.tag : '';
    return draft;
  }

  function openEditor(note) {
    if (state.editor && state.editor.saving) return;
    const draft = note ? editorDraftFromNote(note) : newEditorDraft();
    state.editor = {
      draft: draft,
      saving: false,
      dirty: false,
      error: '',
      returnFocus: document.activeElement
    };
    document.body.classList.add('notes-modal-open');
    renderEditor();
    const modal = document.getElementById(MODAL_ID);
    if (modal) modal.classList.add('is-open');
    window.setTimeout(() => {
      const input = document.getElementById('notes-editor-title');
      if (input) input.focus();
    }, 60);
  }

  async function openEditorById(id) {
    const numeric = Number(id);
    if (!numeric) return;
    const cached = state.notes.find((note) => Number(note.id) === numeric);
    if (cached) {
      openEditor(cached);
      return;
    }
    try {
      const data = await api('/notes/' + numeric);
      if (data && data.note) openEditor(data.note);
    } catch (err) {
      toast('⚠️ ' + err.message);
    }
  }

  function markEditorDirty() {
    if (state.editor && !state.editor.saving) state.editor.dirty = true;
  }

  function closeEditor() {
    if (state.editor && state.editor.saving) return;
    if (state.editor && state.editor.dirty && !confirm('¿Descartar los cambios sin guardar?')) return;
    const returnFocus = state.editor && state.editor.returnFocus;
    const modal = document.getElementById(MODAL_ID);
    if (modal) {
      modal.classList.remove('is-open');
      modal.innerHTML = '';
    }
    document.body.classList.remove('notes-modal-open');
    state.editor = null;
    if (returnFocus && typeof returnFocus.focus === 'function') {
      try { returnFocus.focus(); } catch (_) {}
    }
  }

  function editorProjectContext(draft) {
    const project = projectBySlug(draft.project_slug);
    const isStory = !!(project && project.is_story);
    const structure = isStory && ['seasons', 'chapters'].includes(project.story_structure)
      ? project.story_structure
      : '';
    return { project, isStory, structure };
  }

  function renderEditor() {
    const modal = document.getElementById(MODAL_ID);
    if (!modal || !state.editor) return;
    const draft = state.editor.draft;
    const editing = !!draft.id;
    const context = editorProjectContext(draft);
    const categories = (state.meta && state.meta.categories) || [];
    const lists = (state.meta && state.meta.lists) || [];
    const projects = (state.meta && state.meta.projects) || [];

    const typeOptions = Object.keys(TYPES).map((key) => ({
      value: key, label: TYPES[key].icon + ' ' + TYPES[key].label
    }));
    const statusOptions = Object.keys(STATUSES).map((key) => ({
      value: key, label: STATUSES[key].icon + ' ' + STATUSES[key].label
    }));
    const priorityOptions = Object.keys(PRIORITIES).map((key) => ({
      value: key, label: PRIORITIES[key].label
    }));
    const categoryOptions = [{ value: '', label: 'Sin categoría' }].concat(
      categories.map((category) => ({ value: String(category.id), label: category.name }))
    );
    const listOptions = [{ value: '', label: 'Sin lista' }].concat(
      lists.map((list) => ({ value: String(list.id), label: list.name }))
    );
    const projectOptions = [{ value: '', label: 'Sin proyecto' }].concat(
      projects.map((project) => ({
        value: project.slug,
        label: project.name || project.slug
      }))
    );

    const checklistRows = draft.checklist.length
      ? draft.checklist.map((item, index) =>
          '<div class="notes-check-row" data-check-row data-check-id="' + esc(item.id) + '">' +
            '<input type="checkbox" data-check-done' + (item.done ? ' checked' : '') + ' title="Marcar paso" />' +
            '<input type="text" data-check-text value="' + esc(item.text) + '" maxlength="500" placeholder="Paso ' + (index + 1) + '" />' +
            '<button type="button" class="notes-row-remove" data-notes-action="check-remove" data-index="' + index + '" title="Quitar paso" aria-label="Quitar paso">✕</button>' +
          '</div>'
        ).join('')
      : '<p class="notes-editor-hint">Sin pasos. Agregá los que necesites para seguir el avance.</p>';

    const linkRows = draft.links.length
      ? draft.links.map((item, index) =>
          '<div class="notes-link-row" data-link-row>' +
            '<input type="text" data-link-label value="' + esc(item.label) + '" maxlength="120" placeholder="Etiqueta" />' +
            '<input type="url" data-link-url value="' + esc(item.url) + '" maxlength="2000" placeholder="https://…" />' +
            '<button type="button" class="notes-row-remove" data-notes-action="link-remove" data-index="' + index + '" title="Quitar enlace" aria-label="Quitar enlace">✕</button>' +
          '</div>'
        ).join('')
      : '<p class="notes-editor-hint">Sin enlaces. Podés sumar referencias, documentos o material externo.</p>';

    let storyFields = '';
    if (!draft.project_slug) {
      storyFields = '<p class="notes-editor-hint">Elegí un proyecto para habilitar la ubicación narrativa.</p>';
    } else if (!context.project) {
      storyFields = '<p class="notes-editor-hint">El proyecto no está en el catálogo de notas. Configuralo en “Estructura narrativa”.</p>';
    } else if (context.isStory && context.structure === 'seasons') {
      storyFields =
        '<div class="notes-field-pair">' +
          '<label class="notes-field"><span>Temporada</span><input type="number" name="season_number" min="1" max="999" value="' + esc(draft.season_number) + '" placeholder="1" /></label>' +
          '<label class="notes-field"><span>Episodio</span><input type="number" name="episode_number" min="1" max="9999" value="' + esc(draft.episode_number) + '" placeholder="1" /></label>' +
        '</div>' +
        '<p class="notes-editor-hint">Este proyecto usa temporadas + episodios. Los campos de capítulo no se guardan.</p>';
    } else if (context.isStory && context.structure === 'chapters') {
      storyFields =
        '<div class="notes-field-pair">' +
          '<label class="notes-field"><span>Capítulo</span><input type="number" name="chapter_number" min="1" max="99999" value="' + esc(draft.chapter_number) + '" placeholder="1" /></label>' +
          '<label class="notes-field is-wide"><span>Título del capítulo</span><input type="text" name="chapter_title" maxlength="200" value="' + esc(draft.chapter_title) + '" placeholder="Ej: La marea roja" /></label>' +
        '</div>' +
        '<p class="notes-editor-hint">Este proyecto usa solo capítulos. Los campos de temporada y episodio no se guardan.</p>';
    } else if (context.isStory) {
      storyFields = '<div class="notes-editor-note is-warn">' +
        '<span>⚠️</span><div><b>Falta definir la estructura</b><p>Este proyecto está marcado como historia, pero todavía no elegiste Temporadas + episodios o Solo capítulos.</p></div>' +
        '<button type="button" class="ows-btn ows-btn-ghost" data-notes-action="manage-projects">Configurar</button>' +
      '</div>';
    } else {
      storyFields = '<div class="notes-editor-note">' +
        '<span>📁</span><div><b>Proyecto sin estructura narrativa</b><p>Si es una historia, marcala como tal para usar temporadas/episodios o capítulos.</p></div>' +
        '<button type="button" class="ows-btn ows-btn-ghost" data-notes-action="manage-projects">Configurar</button>' +
      '</div>';
    }

    const metaLines = editing
      ? '<div class="notes-editor-meta">' +
          '<p><span>Creada por</span><b>' + esc(draft.created_by || '—') + '</b>' +
            (draft.created_at ? '<small>' + esc(fmtDateTime(draft.created_at)) + '</small>' : '') + '</p>' +
          '<p><span>Última edición</span><b>' + esc(draft.updated_by || draft.created_by || '—') + '</b>' +
            (draft.updated_at ? '<small>' + esc(fmtDateTime(draft.updated_at)) + '</small>' : '') + '</p>' +
          (draft.completed_at ? '<p><span>Completada</span><b>' + esc(fmtDateTime(draft.completed_at)) + '</b></p>' : '') +
        '</div>'
      : '<p class="notes-editor-hint">El autor se toma de tu sesión de administración.</p>';

    modal.innerHTML =
      '<div class="notes-modal-backdrop" aria-hidden="true"></div>' +
      '<div class="notes-modal-panel notes-editor" role="dialog" aria-modal="true" aria-labelledby="notes-editor-heading">' +
        '<header class="notes-modal-head">' +
          '<div>' +
            '<span class="ows-eyebrow">' + (editing ? 'Editar nota' : 'Nueva nota') + '</span>' +
            '<h3 id="notes-editor-heading">' + (editing ? esc(draft.title || 'Nota sin título') : '¿Qué hay que recordar?') + '</h3>' +
            '<p>' + (editing ? 'Los cambios quedan registrados con tu usuario.' : 'Podés guardar una tarea, una idea, una referencia o un apunte libre.') + '</p>' +
          '</div>' +
          '<button type="button" class="notes-modal-close" data-notes-action="close-editor" aria-label="Cerrar editor">✕</button>' +
        '</header>' +
        '<form id="notes-editor-form" class="notes-editor-form" data-notes-form="editor">' +
          '<div class="notes-editor-grid">' +
            '<div class="notes-editor-main">' +
              '<label class="notes-field">' +
                '<span>Título <b>*</b></span>' +
                '<input type="text" id="notes-editor-title" name="title" maxlength="200" value="' + esc(draft.title) + '" placeholder="Ej: Revisar el guion del episodio 4" required />' +
              '</label>' +
              '<label class="notes-field">' +
                '<span>Contenido</span>' +
                '<textarea name="body" rows="9" maxlength="50000" placeholder="Desarrollo, contexto, decisiones, enlaces internos…">' + esc(draft.body) + '</textarea>' +
              '</label>' +
              '<section class="notes-editor-block">' +
                '<div class="notes-editor-block-head">' +
                  '<h4>Checklist</h4>' +
                  '<button type="button" class="notes-text-btn" data-notes-action="check-add">＋ Agregar paso</button>' +
                '</div>' +
                '<div class="notes-check-list">' + checklistRows + '</div>' +
              '</section>' +
              '<section class="notes-editor-block">' +
                '<div class="notes-editor-block-head">' +
                  '<h4>Enlaces</h4>' +
                  '<button type="button" class="notes-text-btn" data-notes-action="link-add">＋ Agregar enlace</button>' +
                '</div>' +
                '<div class="notes-link-list">' + linkRows + '</div>' +
              '</section>' +
            '</div>' +
            '<aside class="notes-editor-side">' +
              '<section class="notes-editor-block">' +
                '<div class="notes-editor-block-head"><h4>Clasificación</h4></div>' +
                '<label class="notes-field"><span>Tipo</span><select name="note_type">' + optionsHtml(typeOptions, draft.note_type) + '</select></label>' +
                '<div class="notes-field-pair">' +
                  '<label class="notes-field"><span>Estado</span><select name="status">' + optionsHtml(statusOptions, draft.status) + '</select></label>' +
                  '<label class="notes-field"><span>Prioridad</span><select name="priority">' + optionsHtml(priorityOptions, draft.priority) + '</select></label>' +
                '</div>' +
              '</section>' +
              '<section class="notes-editor-block">' +
                '<div class="notes-editor-block-head"><h4>Organización</h4></div>' +
                '<label class="notes-field"><span>Categoría</span><select name="category_id">' + optionsHtml(categoryOptions, draft.category_id) + '</select></label>' +
                '<label class="notes-field"><span>Lista</span><select name="list_id">' + optionsHtml(listOptions, draft.list_id) + '</select></label>' +
                '<label class="notes-field"><span>Proyecto</span><select name="project_slug" data-notes-project-select>' + optionsHtml(projectOptions, draft.project_slug) + '</select></label>' +
                '<div class="notes-story-fields">' + storyFields + '</div>' +
              '</section>' +
              '<section class="notes-editor-block">' +
                '<div class="notes-editor-block-head"><h4>Fechas y etiquetas</h4></div>' +
                '<label class="notes-field"><span>Vencimiento</span><input type="date" name="due_date" value="' + esc(draft.due_date) + '" /></label>' +
                '<label class="notes-field"><span>Etiquetas</span><input type="text" name="tags" maxlength="600" value="' + esc(draft.tags) + '" placeholder="lore, arte, revisar (separadas por coma)" /></label>' +
                '<p class="notes-editor-hint">Hasta 24 etiquetas. Se normalizan al guardar.</p>' +
              '</section>' +
              '<section class="notes-editor-block">' +
                '<div class="notes-editor-block-head"><h4>Visibilidad</h4></div>' +
                '<label class="notes-toggle"><input type="checkbox" name="is_pinned"' + (draft.is_pinned ? ' checked' : '') + ' />' +
                  '<span><b>Fijar arriba</b><small>Queda primero en el tablero.</small></span></label>' +
                '<label class="notes-toggle"><input type="checkbox" name="is_private"' + (draft.is_private ? ' checked' : '') + ' />' +
                  '<span><b>Solo yo y el Owner</b><small>El resto del equipo no la ve.</small></span></label>' +
                '<label class="notes-toggle"><input type="checkbox" name="is_archived"' + (draft.is_archived ? ' checked' : '') + ' />' +
                  '<span><b>Archivar</b><small>Sale del tablero activo, queda en el archivo.</small></span></label>' +
                metaLines +
              '</section>' +
            '</aside>' +
          '</div>' +
          '<footer class="notes-modal-foot">' +
            '<span class="notes-editor-error" id="notes-editor-error" role="alert">' + esc(state.editor.error || '') + '</span>' +
            '<div class="notes-modal-actions">' +
              (editing ? '<button type="button" class="notes-danger-btn" data-notes-action="delete-editor">🗑️ Eliminar</button>' : '') +
              '<button type="button" class="ows-btn ows-btn-ghost" data-notes-action="close-editor">Cancelar</button>' +
              '<button type="submit" class="ows-btn" id="notes-editor-save">' + (editing ? 'Guardar cambios' : 'Crear nota') + '</button>' +
            '</div>' +
          '</footer>' +
        '</form>' +
      '</div>';
  }

  function fieldValue(form, name) {
    const field = form.elements.namedItem(name);
    return field && field.value != null ? String(field.value) : '';
  }

  function fieldChecked(form, name) {
    const field = form.elements.namedItem(name);
    return !!(field && field.checked);
  }

  function collectEditor() {
    if (!state.editor) return null;
    const draft = state.editor.draft;
    const form = document.getElementById('notes-editor-form');
    if (!form) return draft;

    draft.title = fieldValue(form, 'title');
    draft.body = fieldValue(form, 'body');
    draft.note_type = fieldValue(form, 'note_type') || 'note';
    draft.status = fieldValue(form, 'status') || 'open';
    draft.priority = fieldValue(form, 'priority') || 'normal';
    draft.category_id = fieldValue(form, 'category_id');
    draft.list_id = fieldValue(form, 'list_id');
    draft.project_slug = fieldValue(form, 'project_slug');
    const project = projectBySlug(draft.project_slug);
    draft.project_name = project ? String(project.name || '') : '';
    draft.season_number = fieldValue(form, 'season_number');
    draft.episode_number = fieldValue(form, 'episode_number');
    draft.chapter_number = fieldValue(form, 'chapter_number');
    draft.chapter_title = fieldValue(form, 'chapter_title');
    draft.tags = fieldValue(form, 'tags');
    draft.due_date = fieldValue(form, 'due_date');
    draft.is_pinned = fieldChecked(form, 'is_pinned');
    draft.is_private = fieldChecked(form, 'is_private');
    draft.is_archived = fieldChecked(form, 'is_archived');

    draft.checklist = Array.from(form.querySelectorAll('[data-check-row]')).map((row) => {
      const checkbox = row.querySelector('[data-check-done]');
      const text = row.querySelector('[data-check-text]');
      return {
        id: row.getAttribute('data-check-id') || newCheckId(),
        text: text ? text.value : '',
        done: !!(checkbox && checkbox.checked)
      };
    });

    draft.links = Array.from(form.querySelectorAll('[data-link-row]')).map((row) => {
      const label = row.querySelector('[data-link-label]');
      const url = row.querySelector('[data-link-url]');
      return {
        label: label ? label.value : '',
        url: url ? url.value : ''
      };
    });

    return draft;
  }

  function addChecklistItem() {
    const draft = collectEditor();
    if (!draft) return;
    markEditorDirty();
    draft.checklist.push({ id: newCheckId(), text: '', done: false });
    renderEditor();
    const rows = document.querySelectorAll('[data-check-row]');
    const last = rows[rows.length - 1];
    if (last) {
      const input = last.querySelector('[data-check-text]');
      if (input) input.focus();
    }
  }

  function removeChecklistItem(index) {
    const draft = collectEditor();
    if (!draft) return;
    markEditorDirty();
    draft.checklist.splice(Number(index), 1);
    renderEditor();
  }

  function addLinkItem() {
    const draft = collectEditor();
    if (!draft) return;
    markEditorDirty();
    draft.links.push({ label: '', url: '' });
    renderEditor();
    const rows = document.querySelectorAll('[data-link-row]');
    const last = rows[rows.length - 1];
    if (last) {
      const input = last.querySelector('[data-link-label]');
      if (input) input.focus();
    }
  }

  function removeLinkItem(index) {
    const draft = collectEditor();
    if (!draft) return;
    markEditorDirty();
    draft.links.splice(Number(index), 1);
    renderEditor();
  }

  function changeEditorProject(value) {
    const draft = collectEditor();
    if (!draft) return;
    const project = projectBySlug(value);
    draft.project_slug = value;
    draft.project_name = project ? String(project.name || '') : '';
    draft.story_mode = project && project.is_story
      ? (project.story_structure || 'none')
      : 'none';
    draft.season_number = '';
    draft.episode_number = '';
    draft.chapter_number = '';
    draft.chapter_title = '';
    renderEditor();
  }

  function parsePositiveInt(value) {
    const number = Math.trunc(Number(value));
    return Number.isFinite(number) && number > 0 ? number : null;
  }

  function editorPayload(draft) {
    return {
      title: String(draft.title || '').trim(),
      body: draft.body || '',
      note_type: draft.note_type || 'note',
      status: draft.status || 'open',
      priority: draft.priority || 'normal',
      category_id: draft.category_id ? Number(draft.category_id) : null,
      list_id: draft.list_id ? Number(draft.list_id) : null,
      project_slug: draft.project_slug || '',
      project_name: draft.project_name || '',
      season_number: parsePositiveInt(draft.season_number),
      episode_number: parsePositiveInt(draft.episode_number),
      chapter_number: parsePositiveInt(draft.chapter_number),
      chapter_title: draft.chapter_title || '',
      tags: splitTags(draft.tags),
      checklist: (draft.checklist || [])
        .map((item) => ({ id: item.id, text: String(item.text || '').trim(), done: item.done === true }))
        .filter((item) => item.text),
      links: (draft.links || [])
        .map((item) => ({
          label: String(item.label || '').trim(),
          url: String(item.url || '').trim()
        }))
        .filter((item) => item.url),
      due_date: draft.due_date || null,
      is_pinned: !!draft.is_pinned,
      is_archived: !!draft.is_archived,
      is_private: !!draft.is_private
    };
  }

  function setEditorError(message) {
    if (state.editor) state.editor.error = message || '';
    const host = document.getElementById('notes-editor-error');
    if (host) host.textContent = message || '';
  }

  function setEditorSaving(saving) {
    if (!state.editor) return;
    state.editor.saving = saving;
    const button = document.getElementById('notes-editor-save');
    if (button) {
      button.disabled = saving;
      button.textContent = saving
        ? 'Guardando…'
        : (state.editor.draft.id ? 'Guardar cambios' : 'Crear nota');
    }
    const form = document.getElementById('notes-editor-form');
    if (form) form.classList.toggle('is-saving', saving);
  }

  async function submitEditor() {
    if (!state.editor || state.editor.saving) return;
    const draft = collectEditor();
    if (!draft) return;

    if (!String(draft.title || '').trim()) {
      setEditorError('El título es obligatorio.');
      const title = document.getElementById('notes-editor-title');
      if (title) title.focus();
      return;
    }

    const badLink = (draft.links || []).find((item) =>
      item.url && !/^https?:\/\//i.test(String(item.url).trim()));
    if (badLink) {
      setEditorError('Los enlaces deben empezar con http:// o https://.');
      return;
    }

    const payload = editorPayload(draft);
    setEditorError('');
    setEditorSaving(true);

    try {
      const editing = !!draft.id;
      const path = editing ? '/notes/' + Number(draft.id) : '/notes';
      const data = await api(path, jsonOptions(editing ? 'PATCH' : 'POST', payload));
      const note = data && data.note ? data.note : null;
      state.editor.saving = false;
      state.editor.dirty = false;
      closeEditor();
      toast(editing ? '✅ Nota actualizada' : '✅ Nota creada');
      await refresh({ silent: true });
      if (!editing && note && note.id) {
        const grid = document.getElementById('notes-grid');
        if (grid) grid.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    } catch (err) {
      setEditorError(err.message);
      setEditorSaving(false);
      toast('⚠️ ' + err.message);
    }
  }

  async function deleteFromEditor() {
    if (!state.editor || state.editor.saving) return;
    const draft = collectEditor();
    if (!draft || !draft.id) return;
    const title = String(draft.title || 'esta nota').slice(0, 80);
    if (!confirm('¿Eliminar la nota “' + title + '” permanentemente?')) return;
    setEditorSaving(true);
    try {
      await api('/notes/' + Number(draft.id), { method: 'DELETE' });
      state.editor.saving = false;
      state.editor.dirty = false;
      closeEditor();
      toast('🗑️ Nota eliminada');
      state.selection.delete(Number(draft.id));
      await refresh({ silent: true });
    } catch (err) {
      setEditorError(err.message);
      setEditorSaving(false);
      toast('⚠️ ' + err.message);
    }
  }

  /* ── Gestores: categorías, listas y estructura narrativa ──────────── */

  function slugify(value) {
    return String(value == null ? '' : value)
      .trim()
      .toLowerCase()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 80);
  }

  function colorInputValue(value, fallback) {
    const raw = String(value == null ? '' : value).trim();
    if (/^#[0-9a-f]{6}$/i.test(raw)) return raw.toLowerCase();
    if (/^#[0-9a-f]{3}$/i.test(raw)) {
      return ('#' + raw[1] + raw[1] + raw[2] + raw[2] + raw[3] + raw[3]).toLowerCase();
    }
    return fallback || '#f59e0b';
  }

  function openManager(kind) {
    if (state.editor) return;
    state.manager = kind === 'projects'
      ? { kind: 'projects', search: '', error: '' }
      : { kind: 'taxonomy', categoryEdit: null, listEdit: null, error: '' };
    document.body.classList.add('notes-modal-open');
    renderManager();
  }

  function openProjectsFromEditor() {
    if (!state.editor) {
      openManager('projects');
      return;
    }
    const draft = collectEditor();
    state.manager = {
      kind: 'projects',
      search: '',
      error: '',
      returnEditorDraft: draft
    };
    renderManager();
  }

  function closeManager() {
    const manager = state.manager;
    const back = manager && manager.returnEditorDraft;
    state.manager = null;
    const modal = document.getElementById(MODAL_ID);
    if (!modal) return;
    modal.innerHTML = '';
    if (back && state.editor) {
      state.editor.draft = back;
      renderEditor();
      return;
    }
    modal.classList.remove('is-open');
    document.body.classList.remove('notes-modal-open');
  }

  function setManagerError(message) {
    if (state.manager) state.manager.error = message || '';
    const host = document.getElementById('notes-manager-error');
    if (host) host.textContent = message || '';
  }

  function managerShell(kindLabel, title, subtitle, bodyHtml, footerExtra) {
    return '<div class="notes-modal-backdrop" aria-hidden="true"></div>' +
      '<div class="notes-modal-panel notes-manager" role="dialog" aria-modal="true" aria-labelledby="notes-manager-heading">' +
        '<header class="notes-modal-head">' +
          '<div>' +
            '<span class="ows-eyebrow">' + esc(kindLabel) + '</span>' +
            '<h3 id="notes-manager-heading">' + esc(title) + '</h3>' +
            '<p>' + esc(subtitle) + '</p>' +
          '</div>' +
          '<button type="button" class="notes-modal-close" data-notes-action="close-manager" aria-label="Cerrar">✕</button>' +
        '</header>' +
        bodyHtml +
        '<footer class="notes-modal-foot notes-manager-foot">' +
          '<span class="notes-editor-error" id="notes-manager-error" role="alert"></span>' +
          '<div class="notes-modal-actions">' +
            (footerExtra || '') +
            '<button type="button" class="ows-btn ows-btn-ghost" data-notes-action="close-manager">Cerrar</button>' +
          '</div>' +
        '</footer>' +
      '</div>';
  }

  function renderManager() {
    const modal = document.getElementById(MODAL_ID);
    if (!modal || !state.manager) return;
    modal.classList.add('is-open');
    if (state.manager.kind === 'projects') renderProjectsManager();
    else renderTaxonomyManager();
  }

  function renderTaxonomyManager() {
    const modal = document.getElementById(MODAL_ID);
    if (!modal || !state.manager) return;
    const meta = state.meta || { categories: [], lists: [] };
    const catEdit = state.manager.categoryEdit;
    const listEdit = state.manager.listEdit;

    const categoryRows = (meta.categories || []).length
      ? meta.categories.map((category) =>
          '<div class="notes-manager-row">' +
            '<span class="notes-color-swatch" style="--notes-accent:' + esc(category.color) + '"></span>' +
            '<span class="notes-manager-row-text"><b>' + (category.icon ? esc(category.icon) + ' ' : '') + esc(category.name) + '</b>' +
              '<small>' + (Number(category.count) || 0) + ' nota(s) · ' + esc(category.created_by || '—') + '</small></span>' +
            '<button type="button" data-notes-action="cat-edit" data-id="' + Number(category.id) + '" title="Editar categoría">✏️</button>' +
            '<button type="button" class="is-danger" data-notes-action="cat-delete" data-id="' + Number(category.id) + '" title="Eliminar categoría">🗑️</button>' +
          '</div>'
        ).join('')
      : '<p class="notes-manager-empty">Sin categorías. Creá la primera para agrupar las notas.</p>';

    const listRows = (meta.lists || []).length
      ? meta.lists.map((list) =>
          '<div class="notes-manager-row">' +
            '<span class="notes-color-swatch" style="--notes-accent:' + esc(list.color) + '"></span>' +
            '<span class="notes-manager-row-text"><b>' + esc(list.name) + '</b>' +
              '<small>' + (Number(list.count) || 0) + ' nota(s)' + (list.description ? ' · ' + esc(list.description) : '') + '</small></span>' +
            '<button type="button" data-notes-action="list-edit" data-id="' + Number(list.id) + '" title="Editar lista">✏️</button>' +
            '<button type="button" class="is-danger" data-notes-action="list-delete" data-id="' + Number(list.id) + '" title="Eliminar lista">🗑️</button>' +
          '</div>'
        ).join('')
      : '<p class="notes-manager-empty">Sin listas. Usalas para agrupar tareas o material de un mismo frente.</p>';

    const body =
      '<div class="notes-manager-body">' +
        '<div class="notes-manager-grid">' +
          '<section class="notes-manager-col">' +
            '<div class="notes-manager-col-head"><h4>Categorías</h4><span>' + (meta.categories || []).length + '</span></div>' +
            '<form class="notes-manager-form" data-notes-form="category">' +
              '<h5>' + (catEdit ? 'Editar categoría' : 'Nueva categoría') + '</h5>' +
              '<div class="notes-manager-form-grid">' +
                '<label class="notes-field is-wide"><span>Nombre</span><input type="text" name="name" maxlength="60" required value="' + esc(catEdit ? catEdit.name : '') + '" placeholder="Ej: Arte" /></label>' +
                '<label class="notes-field"><span>Color</span><input type="color" name="color" value="' + colorInputValue(catEdit ? catEdit.color : '#f59e0b') + '" /></label>' +
                '<label class="notes-field"><span>Ícono</span><input type="text" name="icon" maxlength="8" value="' + esc(catEdit ? catEdit.icon : '') + '" placeholder="🎨" /></label>' +
              '</div>' +
              '<div class="notes-manager-form-actions">' +
                (catEdit ? '<button type="button" class="notes-text-btn" data-notes-action="cat-cancel">Cancelar</button>' : '') +
                '<button type="submit" class="ows-btn">' + (catEdit ? 'Guardar cambios' : '＋ Crear categoría') + '</button>' +
              '</div>' +
            '</form>' +
            '<div class="notes-manager-list">' + categoryRows + '</div>' +
          '</section>' +
          '<section class="notes-manager-col">' +
            '<div class="notes-manager-col-head"><h4>Listas</h4><span>' + (meta.lists || []).length + '</span></div>' +
            '<form class="notes-manager-form" data-notes-form="list">' +
              '<h5>' + (listEdit ? 'Editar lista' : 'Nueva lista') + '</h5>' +
              '<div class="notes-manager-form-grid">' +
                '<label class="notes-field is-wide"><span>Nombre</span><input type="text" name="name" maxlength="60" required value="' + esc(listEdit ? listEdit.name : '') + '" placeholder="Ej: Pendientes de arte" /></label>' +
                '<label class="notes-field is-wide"><span>Descripción</span><input type="text" name="description" maxlength="300" value="' + esc(listEdit ? listEdit.description : '') + '" placeholder="Para qué sirve esta lista" /></label>' +
                '<label class="notes-field"><span>Color</span><input type="color" name="color" value="' + colorInputValue(listEdit ? listEdit.color : '#38bdf8', '#38bdf8') + '" /></label>' +
              '</div>' +
              '<div class="notes-manager-form-actions">' +
                (listEdit ? '<button type="button" class="notes-text-btn" data-notes-action="list-cancel">Cancelar</button>' : '') +
                '<button type="submit" class="ows-btn">' + (listEdit ? 'Guardar cambios' : '＋ Crear lista') + '</button>' +
              '</div>' +
            '</form>' +
            '<div class="notes-manager-list">' + listRows + '</div>' +
          '</section>' +
        '</div>' +
      '</div>';

    modal.innerHTML = managerShell(
      'Notas',
      'Categorías y listas',
      'Organizá el tablero por áreas del estudio y por frentes de trabajo.',
      body
    );
  }

  function renderProjectsManager() {
    const modal = document.getElementById(MODAL_ID);
    if (!modal || !state.manager) return;
    const search = String(state.manager.search || '').toLowerCase();
    const projects = ((state.meta && state.meta.projects) || [])
      .slice()
      .sort((a, b) => String(a.name || a.slug).localeCompare(String(b.name || b.slug), 'es'))
      .filter((project) => {
        if (!search) return true;
        return (String(project.name || '') + ' ' + String(project.slug || '')).toLowerCase().includes(search);
      });

    const rows = projects.length
      ? projects.map((project) => {
          const structure = project.story_structure === 'chapters' ? 'chapters' : 'seasons';
          return '<div class="notes-project-row" data-project-row data-slug="' + esc(project.slug) + '" data-name="' + esc(project.name || project.slug) + '">' +
            '<div class="notes-project-info">' +
              '<b>' + (project.is_story ? '🎬 ' : '📁 ') + esc(project.name || project.slug) + '</b>' +
              '<small>' + esc(project.slug) + ' · ' + (Number(project.note_count) || 0) + ' nota(s)' +
                (project.is_story && Number(project.note_count) > 0 ? ' · al cambiar la estructura se limpian campos incompatibles' : '') + '</small>' +
            '</div>' +
            '<label class="notes-project-story"><input type="checkbox" data-project-story' + (project.is_story ? ' checked' : '') + ' /> <span>Historia</span></label>' +
            '<select data-project-structure aria-label="Estructura de ' + esc(project.name || project.slug) + '"' + (project.is_story ? '' : ' disabled') + '>' +
              '<option value="seasons"' + (structure === 'seasons' ? ' selected' : '') + '>Temporadas + episodios</option>' +
              '<option value="chapters"' + (structure === 'chapters' ? ' selected' : '') + '>Solo capítulos</option>' +
            '</select>' +
            '<button type="button" class="ows-btn ows-btn-ghost" data-notes-action="project-save" data-slug="' + esc(project.slug) + '">Guardar</button>' +
          '</div>';
        }).join('')
      : '<p class="notes-manager-empty">' +
          (search ? 'Ningún proyecto coincide con la búsqueda.' : 'Todavía no hay proyectos en el catálogo de notas.') +
        '</p>';

    const body =
      '<div class="notes-manager-body">' +
        '<div class="notes-story-warning">' +
          '<span>🎬</span>' +
          '<div><b>Una estructura por proyecto</b><p>Un proyecto narrativo puede usar <b>Temporadas + episodios</b> o <b>Solo capítulos</b>, nunca las dos. Al cambiar la estructura, el servidor limpia los campos que dejan de corresponder en todas las notas de ese proyecto.</p></div>' +
        '</div>' +
        '<div class="notes-manager-toolbar">' +
          '<label class="notes-search" for="notes-project-search">' +
            '<span aria-hidden="true">🔍</span>' +
            '<input type="text" id="notes-project-search" value="' + esc(state.manager.search || '') + '" placeholder="Buscar proyecto por nombre o slug…" autocomplete="off" />' +
          '</label>' +
          '<span class="notes-manager-count">' + projects.length + ' proyecto(s)</span>' +
        '</div>' +
        '<form class="notes-project-add" data-notes-form="project-add">' +
          '<h4>Agregar proyecto manual</h4>' +
          '<p>Para proyectos que todavía no están en el catálogo de OWS.</p>' +
          '<div class="notes-project-add-grid">' +
            '<label class="notes-field"><span>Nombre</span><input type="text" id="notes-project-add-name" name="project_name" maxlength="140" required placeholder="Ej: Ocean Cinemas" /></label>' +
            '<label class="notes-field"><span>Slug</span><input type="text" id="notes-project-add-slug" name="slug" maxlength="80" placeholder="ocean-cinemas" /></label>' +
            '<label class="notes-project-story"><input type="checkbox" name="is_story" data-project-add-story /> <span>Historia</span></label>' +
            '<label class="notes-field"><span>Estructura</span><select name="story_structure" data-project-add-structure disabled>' +
              '<option value="seasons">Temporadas + episodios</option>' +
              '<option value="chapters">Solo capítulos</option>' +
            '</select></label>' +
            '<button type="submit" class="ows-btn">＋ Agregar</button>' +
          '</div>' +
        '</form>' +
        '<div class="notes-project-list">' + rows + '</div>' +
      '</div>';

    modal.innerHTML = managerShell(
      'Notas',
      'Estructura narrativa',
      'Definí qué proyectos son historias y cómo se organizan sus notas.',
      body
    );
  }

  async function saveCategory(form) {
    if (!state.manager) return;
    const edit = state.manager.categoryEdit;
    const name = String(fieldValue(form, 'name') || '').trim();
    if (!name) {
      setManagerError('El nombre de la categoría es obligatorio.');
      return;
    }
    const payload = {
      name: name,
      color: fieldValue(form, 'color') || '#f59e0b',
      icon: fieldValue(form, 'icon') || ''
    };
    try {
      await api(edit ? '/note-categories/' + Number(edit.id) : '/note-categories',
        jsonOptions(edit ? 'PATCH' : 'POST', payload));
      state.manager.categoryEdit = null;
      setManagerError('');
      toast(edit ? '✅ Categoría actualizada' : '✅ Categoría creada');
      await loadMeta();
      renderTaxonomyManager();
      await loadNotes({ reset: true });
    } catch (err) {
      setManagerError(err.message);
      toast('⚠️ ' + err.message);
    }
  }

  async function saveList(form) {
    if (!state.manager) return;
    const edit = state.manager.listEdit;
    const name = String(fieldValue(form, 'name') || '').trim();
    if (!name) {
      setManagerError('El nombre de la lista es obligatorio.');
      return;
    }
    const payload = {
      name: name,
      description: fieldValue(form, 'description') || '',
      color: fieldValue(form, 'color') || '#38bdf8'
    };
    try {
      await api(edit ? '/note-lists/' + Number(edit.id) : '/note-lists',
        jsonOptions(edit ? 'PATCH' : 'POST', payload));
      state.manager.listEdit = null;
      setManagerError('');
      toast(edit ? '✅ Lista actualizada' : '✅ Lista creada');
      await loadMeta();
      renderTaxonomyManager();
      await loadNotes({ reset: true });
    } catch (err) {
      setManagerError(err.message);
      toast('⚠️ ' + err.message);
    }
  }

  async function deleteCategory(id) {
    const category = categoryById(id);
    if (!category) return;
    if (!confirm('¿Eliminar la categoría “' + category.name + '”? Las notas quedan sin categoría.')) return;
    try {
      await api('/note-categories/' + Number(id), { method: 'DELETE' });
      if (state.manager) state.manager.categoryEdit = null;
      toast('🗑️ Categoría eliminada');
      await loadMeta();
      renderTaxonomyManager();
      await loadNotes({ reset: true });
    } catch (err) {
      setManagerError(err.message);
      toast('⚠️ ' + err.message);
    }
  }

  async function deleteList(id) {
    const list = listById(id);
    if (!list) return;
    if (!confirm('¿Eliminar la lista “' + list.name + '”? Las notas quedan sin lista.')) return;
    try {
      await api('/note-lists/' + Number(id), { method: 'DELETE' });
      if (state.manager) state.manager.listEdit = null;
      toast('🗑️ Lista eliminada');
      await loadMeta();
      renderTaxonomyManager();
      await loadNotes({ reset: true });
    } catch (err) {
      setManagerError(err.message);
      toast('⚠️ ' + err.message);
    }
  }

  async function saveProjectRow(slug) {
    const rows = Array.from(document.querySelectorAll('[data-project-row]'));
    const row = rows.find((item) => item.getAttribute('data-slug') === slug);
    if (!row) return;
    const storyInput = row.querySelector('[data-project-story]');
    const structureInput = row.querySelector('[data-project-structure]');
    const isStory = !!(storyInput && storyInput.checked);
    let structure = structureInput ? structureInput.value : 'seasons';
    if (isStory && !['seasons', 'chapters'].includes(structure)) structure = 'seasons';
    if (!isStory) structure = '';
    const payload = {
      project_name: row.getAttribute('data-name') || slug,
      is_story: isStory,
      story_structure: structure
    };
    try {
      await api('/notes/projects/' + encodeURIComponent(slug), jsonOptions('PUT', payload));
      setManagerError('');
      toast(isStory
        ? '✅ ' + slug + ': ' + (structure === 'chapters' ? 'solo capítulos' : 'temporadas + episodios')
        : '✅ ' + slug + ': proyecto sin estructura narrativa');
      await loadMeta();
      await loadNotes({ reset: true });
      if (state.manager && state.manager.kind === 'projects') renderProjectsManager();
    } catch (err) {
      setManagerError(err.message);
      toast('⚠️ ' + err.message);
    }
  }

  async function saveNewProject(form) {
    const name = String(fieldValue(form, 'project_name') || '').trim();
    const slug = slugify(fieldValue(form, 'slug') || name);
    if (!name) {
      setManagerError('El nombre del proyecto es obligatorio.');
      return;
    }
    if (!slug) {
      setManagerError('El slug del proyecto es obligatorio.');
      return;
    }
    const storyInput = form.elements.namedItem('is_story');
    const isStory = !!(storyInput && storyInput.checked);
    const structureValue = fieldValue(form, 'story_structure') || 'seasons';
    const payload = {
      project_name: name,
      is_story: isStory,
      story_structure: isStory ? structureValue : ''
    };
    try {
      await api('/notes/projects/' + encodeURIComponent(slug), jsonOptions('PUT', payload));
      setManagerError('');
      toast('✅ Proyecto agregado: ' + name);
      await loadMeta();
      if (state.manager && state.manager.kind === 'projects') {
        state.manager.search = '';
        renderProjectsManager();
      }
    } catch (err) {
      setManagerError(err.message);
      toast('⚠️ ' + err.message);
    }
  }

  /* ── Eventos de la página ───────────────────────────────────────────── */

  function filtersChanged() {
    syncToolbar();
    renderStats();
    renderRail();
    renderActiveFilters();
    loadNotes({ reset: true });
  }

  function applyStat(key) {
    clearFilters();
    if (key === 'open' || key === 'doing') state.filters.status = key;
    else if (key === 'done') state.filters.view = 'done';
    else if (key === 'overdue') state.filters.view = 'overdue';
    else if (key === 'pinned') state.filters.view = 'pinned';
    else if (key === 'private') state.filters.view = 'private';
    filtersChanged();
  }

  function applyRail(kind, value) {
    const f = state.filters;
    if (kind === 'view') {
      f.view = value || 'all';
      f.status = '';
      f.type = '';
    } else if (kind === 'category') {
      f.category_id = String(f.category_id) === String(value) ? '' : value;
    } else if (kind === 'list') {
      f.list_id = String(f.list_id) === String(value) ? '' : value;
    } else if (kind === 'project') {
      f.project_slug = String(f.project_slug) === String(value) ? '' : value;
    } else if (kind === 'tag') {
      f.tag = String(f.tag) === String(value) ? '' : value;
    } else if (kind === 'author') {
      f.author = String(f.author).toLowerCase() === String(value).toLowerCase() ? '' : value;
    }
    filtersChanged();
  }

  function removeFilter(key) {
    const defaults = {
      view: 'all',
      q: '',
      category_id: '',
      list_id: '',
      project_slug: '',
      tag: '',
      author: '',
      status: '',
      type: '',
      priority: '',
      sort: 'updated',
      archived: '0'
    };
    if (!Object.prototype.hasOwnProperty.call(defaults, key)) return;
    if (key === 'q') state.searchValue = '';
    state.filters[key] = defaults[key];
    filtersChanged();
  }

  function toggleSelectVisible() {
    if (!state.notes.length) return;
    const visibleIds = state.notes.map((note) => Number(note.id));
    const allSelected = visibleIds.every((id) => state.selection.has(id));
    visibleIds.forEach((id) => {
      if (allSelected) state.selection.delete(id);
      else state.selection.add(id);
    });
    syncSelectionUi();
    renderBulk();
  }

  function onPageClick(event) {
    const page = pageEl();
    if (!page || !page.contains(event.target)) return;

    const actionEl = event.target.closest('[data-notes-action]');
    if (actionEl && page.contains(actionEl)) {
      const action = actionEl.getAttribute('data-notes-action');
      if (action === 'new') { openEditor(null); return; }
      if (action === 'refresh') { refresh(); return; }
      if (action === 'manage-taxonomy') { openManager('taxonomy'); return; }
      if (action === 'manage-projects') { openManager('projects'); return; }
      if (action === 'clear-filters') { clearFilters(); filtersChanged(); return; }
      if (action === 'retry') { loadNotes({ reset: true }); return; }
      if (action === 'retry-meta') { loadMeta(); return; }
      if (action === 'load-more') { loadNotes({ reset: false }); return; }
      if (action === 'select-visible') { toggleSelectVisible(); return; }
      if (action === 'edit') { openEditorById(actionEl.getAttribute('data-id')); return; }
      if (action === 'pin' || action === 'archive' || action === 'delete') {
        const id = Number(actionEl.getAttribute('data-id'));
        const note = state.notes.find((item) => Number(item.id) === id);
        if (!note) return;
        if (action === 'pin') {
          quickPatch(note, { is_pinned: !note.is_pinned },
            note.is_pinned ? '📌 Nota desfijada' : '📌 Nota fijada');
        } else if (action === 'archive') {
          const archived = actionEl.getAttribute('data-archived') === '1';
          quickPatch(note, { is_archived: !archived },
            archived ? '↩️ Nota desarchivada' : '📦 Nota archivada');
        } else {
          quickDelete(note);
        }
        return;
      }
    }

    const statEl = event.target.closest('[data-notes-stat]');
    if (statEl && page.contains(statEl)) {
      applyStat(statEl.getAttribute('data-notes-stat'));
      return;
    }

    const railEl = event.target.closest('[data-notes-rail]');
    if (railEl && page.contains(railEl)) {
      applyRail(railEl.getAttribute('data-notes-rail'), railEl.getAttribute('data-value'));
      return;
    }

    const removeEl = event.target.closest('[data-notes-remove-filter]');
    if (removeEl && page.contains(removeEl)) {
      removeFilter(removeEl.getAttribute('data-notes-remove-filter'));
      return;
    }

    const bulkEl = event.target.closest('[data-notes-bulk]');
    if (bulkEl && page.contains(bulkEl)) {
      runBulk(bulkEl.getAttribute('data-notes-bulk'));
      return;
    }

    if (event.target.closest('input, select, textarea, label, a')) return;
    const openEl = event.target.closest('[data-notes-open]');
    if (openEl && page.contains(openEl)) {
      openEditorById(openEl.getAttribute('data-notes-open'));
    }
  }

  function onPageInput(event) {
    if (event.target.id !== 'notes-search') return;
    state.searchValue = event.target.value;
    if (state.searchTimer) clearTimeout(state.searchTimer);
    state.searchTimer = setTimeout(() => {
      state.searchTimer = null;
      state.filters.q = String(state.searchValue || '').trim();
      renderActiveFilters();
      loadNotes({ reset: true });
    }, SEARCH_DEBOUNCE);
  }

  function onPageChange(event) {
    const target = event.target;
    if (target.matches('[data-notes-select]')) {
      const id = Number(target.getAttribute('data-notes-select'));
      if (!id) return;
      if (target.checked) state.selection.add(id);
      else state.selection.delete(id);
      syncSelectionUi();
      renderBulk();
      return;
    }

    const f = state.filters;
    if (target.id === 'notes-type') {
      f.type = target.value || '';
      f.view = 'all';
      filtersChanged();
    } else if (target.id === 'notes-status') {
      f.status = target.value || '';
      f.view = 'all';
      filtersChanged();
    } else if (target.id === 'notes-priority') {
      f.priority = target.value || '';
      filtersChanged();
    } else if (target.id === 'notes-sort') {
      f.sort = target.value || 'updated';
      filtersChanged();
    } else if (target.id === 'notes-archived') {
      f.archived = target.checked ? '1' : '0';
      filtersChanged();
    }
  }

  function onPageKeydown(event) {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const card = event.target.closest('[data-notes-open]');
    if (!card || !pageEl() || !pageEl().contains(card)) return;
    if (event.target.closest('input, select, textarea, button, a, label')) return;
    event.preventDefault();
    openEditorById(card.getAttribute('data-notes-open'));
  }

  /* ── Eventos de modales ─────────────────────────────────────────────── */

  function onModalClick(event) {
    const modal = document.getElementById(MODAL_ID);
    if (!modal) return;

    const actionEl = event.target.closest('[data-notes-action]');
    if (actionEl && modal.contains(actionEl)) {
      const action = actionEl.getAttribute('data-notes-action');
      if (action === 'close-editor') { closeEditor(); return; }
      if (action === 'delete-editor') { deleteFromEditor(); return; }
      if (action === 'check-add') { addChecklistItem(); return; }
      if (action === 'check-remove') { removeChecklistItem(actionEl.getAttribute('data-index')); return; }
      if (action === 'link-add') { addLinkItem(); return; }
      if (action === 'link-remove') { removeLinkItem(actionEl.getAttribute('data-index')); return; }
      if (action === 'manage-projects') { openProjectsFromEditor(); return; }
      if (action === 'close-manager') { closeManager(); return; }
      if (action === 'cat-cancel') {
        if (state.manager) state.manager.categoryEdit = null;
        renderTaxonomyManager();
        return;
      }
      if (action === 'list-cancel') {
        if (state.manager) state.manager.listEdit = null;
        renderTaxonomyManager();
        return;
      }
      if (action === 'cat-edit') {
        const category = categoryById(actionEl.getAttribute('data-id'));
        if (category && state.manager) {
          state.manager.categoryEdit = category;
          renderTaxonomyManager();
        }
        return;
      }
      if (action === 'cat-delete') { deleteCategory(actionEl.getAttribute('data-id')); return; }
      if (action === 'list-edit') {
        const list = listById(actionEl.getAttribute('data-id'));
        if (list && state.manager) {
          state.manager.listEdit = list;
          renderTaxonomyManager();
        }
        return;
      }
      if (action === 'list-delete') { deleteList(actionEl.getAttribute('data-id')); return; }
      if (action === 'project-save') { saveProjectRow(actionEl.getAttribute('data-slug')); return; }
    }

    if (event.target.classList && event.target.classList.contains('notes-modal-backdrop')) {
      if (state.manager) closeManager();
      else if (state.editor) closeEditor();
    }
  }

  function onModalChange(event) {
    const target = event.target;
    if (state.editor && target.closest && target.closest('#notes-editor-form')) markEditorDirty();
    if (target.matches('[data-notes-project-select]')) {
      changeEditorProject(target.value);
      return;
    }
    if (target.matches('[data-project-story]')) {
      const row = target.closest('[data-project-row]');
      const select = row && row.querySelector('[data-project-structure]');
      if (select) select.disabled = !target.checked;
      return;
    }
    if (target.matches('[data-project-add-story]')) {
      const select = document.querySelector('[data-project-add-structure]');
      if (select) select.disabled = !target.checked;
    }
  }

  function filterProjectRows(query) {
    const wanted = String(query || '').trim().toLowerCase();
    document.querySelectorAll('[data-project-row]').forEach((row) => {
      const haystack = (row.getAttribute('data-name') + ' ' + row.getAttribute('data-slug')).toLowerCase();
      row.classList.toggle('hidden', !!wanted && !haystack.includes(wanted));
    });
  }

  function onModalInput(event) {
    const target = event.target;
    if (state.editor && target.closest && target.closest('#notes-editor-form')) markEditorDirty();
    if (target.id === 'notes-project-search') {
      if (state.manager) state.manager.search = target.value;
      filterProjectRows(target.value);
      return;
    }
    if (target.id === 'notes-project-add-name') {
      const slug = document.getElementById('notes-project-add-slug');
      if (slug && slug.dataset.touched !== '1') slug.value = slugify(target.value);
      return;
    }
    if (target.id === 'notes-project-add-slug') {
      target.dataset.touched = '1';
    }
  }

  function onModalSubmit(event) {
    const form = event.target.closest('form');
    if (!form || !form.getAttribute('data-notes-form')) return;
    event.preventDefault();
    const kind = form.getAttribute('data-notes-form');
    if (kind === 'editor') submitEditor();
    else if (kind === 'category') saveCategory(form);
    else if (kind === 'list') saveList(form);
    else if (kind === 'project-add') saveNewProject(form);
  }

  function onGlobalKeydown(event) {
    if (event.key === 'Escape') {
      if (state.manager) {
        closeManager();
        event.preventDefault();
        return;
      }
      if (state.editor) {
        closeEditor();
        event.preventDefault();
      }
      return;
    }
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter' && state.editor) {
      event.preventDefault();
      submitEditor();
    }
  }

  /* ── API pública para admin-shell.js ───────────────────────────────── */

  window.owsNotesPageOpen = function () {
    open();
  };

  window.owsNotesRefresh = function () {
    return refresh({ silent: true });
  };

  window.owsNotesOpen = function (id) {
    open();
    openEditorById(id);
  };
})();
